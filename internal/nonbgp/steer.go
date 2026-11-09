package nonbgp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// SteerConfig is what the Steer controller needs from the config.
type SteerConfig struct {
	// Inject is true only in mode inject. Observe and suggest never call
	// the steerer.
	Inject bool
	// Allowlist holds the prefixes a route may fall inside.
	Allowlist []netip.Prefix
	// Max caps the routes on the router (max_improvements).
	Max int
	// NextHops maps a provider name to its gateway.
	NextHops map[string]netip.Addr
	// Live reports whether a prefix is still a synthetic prefix. A route
	// for one that aged out is removed even if the decision engine still
	// lists its improvement.
	Live func(netip.Prefix) bool
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// Steered is one static route this process put on the router.
type Steered struct {
	Prefix   netip.Prefix `json:"prefix"`
	Provider string       `json:"provider"`
	NextHop  netip.Addr   `json:"next_hop"`
	Since    time.Time    `json:"since"`
}

// Steer turns improvements into static routes. It installs only inside the
// allowlist and the cap, never a prefix more specific than the floor, and
// it removes every route it installed when told to or when its
// improvement ends. A nil *Steer does nothing.
type Steer struct {
	cfg SteerConfig
	drv plugin.Steerer
	log *slog.Logger

	mu     sync.Mutex
	active map[netip.Prefix]Steered
	swept  bool
}

// NewSteer returns a controller that drives drv. drv may be nil in
// observe and suggest, where nothing is installed.
func NewSteer(cfg SteerConfig, drv plugin.Steerer, log *slog.Logger) (*Steer, error) {
	if cfg.Inject {
		if drv == nil {
			return nil, errors.New("inject mode needs a steerer")
		}
		if len(cfg.Allowlist) == 0 {
			return nil, errors.New("inject mode needs a non-empty allowlist")
		}
		if cfg.Live == nil {
			return nil, errors.New("inject mode needs the synthetic table")
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	return &Steer{cfg: cfg, drv: drv, log: log, active: map[netip.Prefix]Steered{}}, nil
}

// Sync makes the routes on the router match imps. The first sync also
// removes tagged routes a previous process left behind. It returns the
// failures; a route whose removal failed stays tracked and is retried by the
// next sync.
func (s *Steer) Sync(ctx context.Context, imps []policy.Improvement) error {
	if s == nil || !s.cfg.Inject {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	want := make(map[netip.Prefix]policy.Improvement, len(imps))
	for _, im := range imps {
		want[im.Prefix.Masked()] = im
	}
	var errs []error
	if !s.swept {
		if err := s.sweepLocked(ctx); err != nil {
			return err
		}
	}
	for _, p := range netpfx.SortedKeys(s.active) {
		if _, ok := want[p]; ok && s.cfg.Live(p) {
			continue
		}
		if err := s.removeLocked(ctx, p); err != nil {
			errs = append(errs, err)
		}
	}
	for _, p := range netpfx.SortedKeys(want) {
		if err := s.installLocked(ctx, want[p]); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// sweepLocked removes every tagged route on the router: this process owns
// none yet, so each one is left by an earlier run. A wanted route is
// installed again afterwards, which keeps every route on the router tracked.
func (s *Steer) sweepLocked(ctx context.Context) error {
	owned, err := s.drv.Owned(ctx)
	if err != nil {
		return fmt.Errorf("non-BGP: list routes left on the router: %w", err)
	}
	var errs []error
	for _, p := range owned {
		p = p.Masked()
		if err := s.drv.Remove(ctx, p); err != nil {
			errs = append(errs, fmt.Errorf("non-BGP: remove left-over route %s: %w", p, err))
			continue
		}
		s.log.Warn("non-BGP: removed a route left on the router by an earlier run", "prefix", p)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	s.swept = true
	return nil
}

func (s *Steer) installLocked(ctx context.Context, im policy.Improvement) error {
	p := im.Prefix.Masked()
	cur, on := s.active[p]
	if on && cur.Provider == im.Provider {
		return nil
	}
	floor := FloorV4
	if p.Addr().Is6() {
		floor = FloorV6
	}
	nh, known := s.cfg.NextHops[im.Provider]
	switch {
	case p.Bits() == 0 || p.Bits() > floor:
		return fmt.Errorf("non-BGP: %s is more specific than /%d or a default route and is never steered", p, floor)
	case !netpfx.CoveredBy(s.cfg.Allowlist, p):
		return fmt.Errorf("non-BGP: %s is outside the allowlist", p)
	case !s.cfg.Live(p):
		return fmt.Errorf("non-BGP: %s is not a tracked synthetic prefix", p)
	case !known || nh.Is4() != p.Addr().Is4():
		return fmt.Errorf("non-BGP: provider %q has no next hop for %s", im.Provider, p)
	case !on && len(s.active) >= s.cfg.Max:
		return fmt.Errorf("non-BGP: %s refused, %d routes is the max_improvements cap", p, s.cfg.Max)
	}
	if err := s.drv.Install(ctx, plugin.SteerRoute{Prefix: p, NextHop: nh, Provider: im.Provider}); err != nil {
		return fmt.Errorf("non-BGP: install %s via %s: %w", p, im.Provider, err)
	}
	since := s.cfg.Now()
	if on {
		since = cur.Since
	}
	s.active[p] = Steered{Prefix: p, Provider: im.Provider, NextHop: nh, Since: since}
	s.log.Info("non-BGP: steered", "prefix", p, "provider", im.Provider, "next_hop", nh)
	return nil
}

func (s *Steer) removeLocked(ctx context.Context, p netip.Prefix) error {
	if err := s.drv.Remove(ctx, p); err != nil {
		return fmt.Errorf("non-BGP: remove %s: %w", p, err)
	}
	delete(s.active, p)
	s.log.Info("non-BGP: route removed", "prefix", p)
	return nil
}

func (s *Steer) removeAllLocked(ctx context.Context) error {
	var errs []error
	for _, p := range netpfx.SortedKeys(s.active) {
		if err := s.removeLocked(ctx, p); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// WithdrawAll removes every route this process installed. It is called on
// shutdown. It leaves a route this process did not install alone.
func (s *Steer) WithdrawAll(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.removeAllLocked(ctx)
}

// Active lists the routes this process has on the router, in prefix order.
func (s *Steer) Active() []Steered {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Steered, 0, len(s.active))
	for _, p := range netpfx.SortedKeys(s.active) {
		out = append(out, s.active[p])
	}
	return out
}
