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

// RouteTimeout bounds the router requests for one route: the listing, an
// install, or a removal. It covers what one route takes: the mikrotik
// steerer lists, deletes a duplicate tagged row, and patches, each with
// its own 10s timeout. Only Packeteer adds tagged rows, so more than one
// duplicate is not expected.
const RouteTimeout = 30 * time.Second

// Steered is one static route this process put on the router.
type Steered struct {
	Prefix   netip.Prefix
	Provider string
	NextHop  netip.Addr
	Since    time.Time
}

// Steer turns improvements into static routes. It installs only inside the
// allowlist and the cap, never a prefix more specific than the floor, and
// it removes every route it installed when told to or when its
// improvement ends. A nil *Steer does nothing.
type Steer struct {
	cfg SteerConfig
	drv plugin.Steerer
	log *slog.Logger

	// mu serializes passes and is held through router I/O.
	mu sync.Mutex
	// amu also guards writes to active, so Active (the status API) does
	// not wait for a pass on a slow router.
	amu    sync.RWMutex
	active map[netip.Prefix]Steered
	// leftover holds tagged routes an earlier process left that could not
	// be removed yet. They count against the cap until they are gone.
	leftover map[netip.Prefix]struct{}
	swept    bool
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
	return &Steer{cfg: cfg, drv: drv, log: log, active: map[netip.Prefix]Steered{}, leftover: map[netip.Prefix]struct{}{}}, nil
}

// Sync makes the routes on the router match imps. The first sync removes
// the tagged routes a previous process left behind; it runs in every mode
// with a steerer, so a restart in observe also cleans up after a crash.
// Observe and suggest install nothing. An improvement for a prefix that is
// no longer in the table is skipped. Sync returns the failures; a route
// whose removal failed stays tracked and is retried by the next sync.
func (s *Steer) Sync(ctx context.Context, imps []policy.Improvement) error {
	if s == nil || s.drv == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.swept {
		if err := s.listLeftoversLocked(ctx); err != nil {
			// The router's routes are unknown: nothing is installed on top of
			// them this round, and the next sync lists again.
			return err
		}
	}
	errs := s.removeLeftoversLocked(ctx)
	if !s.cfg.Inject {
		return errors.Join(errs...)
	}
	want := make(map[netip.Prefix]policy.Improvement, len(imps))
	for _, im := range imps {
		if p := im.Prefix.Masked(); s.cfg.Live(p) {
			want[p] = im
		}
	}
	for _, p := range netpfx.SortedKeys(s.active) {
		if _, ok := want[p]; ok {
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

// removeLeftoversLocked tries every left-over route once more.
func (s *Steer) removeLeftoversLocked(ctx context.Context) []error {
	var errs []error
	for _, p := range netpfx.SortedKeys(s.leftover) {
		if err := s.op(ctx, func(c context.Context) error { return s.drv.Remove(c, p) }); err != nil {
			errs = append(errs, fmt.Errorf("non-BGP: remove left-over route %s: %w", p, err))
			continue
		}
		delete(s.leftover, p)
		s.log.Warn("non-BGP: removed a route left on the router by an earlier run", "prefix", p)
	}
	return errs
}

// op runs one route's router requests under their own deadline.
// Cancelling ctx only ends a pass between routes, so a route is never cut
// off halfway. A deadline on ctx (the shutdown budget) still bounds them.
func (s *Steer) op(ctx context.Context, fn func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	end := time.Now().Add(RouteTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(end) {
		end = d
	}
	c, cancel := context.WithDeadline(context.WithoutCancel(ctx), end)
	defer cancel()
	return fn(c)
}

// listLeftoversLocked records every tagged route on the router: this
// process owns none yet, so each one is left by an earlier run. They are
// removed even when wanted; a wanted route is installed again afterwards,
// which keeps every route on the router tracked.
func (s *Steer) listLeftoversLocked(ctx context.Context) error {
	var owned []netip.Prefix
	err := s.op(ctx, func(c context.Context) error {
		var err error
		owned, err = s.drv.Owned(c)
		return err
	})
	if err != nil {
		return fmt.Errorf("non-BGP: list routes left on the router: %w", err)
	}
	for _, p := range owned {
		s.leftover[p.Masked()] = struct{}{}
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
	_, stale := s.leftover[p]
	floor := floorBits(p.Addr())
	nh, known := s.cfg.NextHops[im.Provider]
	switch {
	case p.Bits() == 0 || p.Bits() > floor:
		return fmt.Errorf("non-BGP: %s is more specific than /%d or a default route and is never steered", p, floor)
	case !netpfx.CoveredBy(s.cfg.Allowlist, p):
		return fmt.Errorf("non-BGP: %s is outside the allowlist", p)
	case !known || nh.Is4() != p.Addr().Is4():
		return fmt.Errorf("non-BGP: provider %q has no next hop for %s", im.Provider, p)
	case !on && !stale && len(s.active)+len(s.leftover) >= s.cfg.Max:
		return fmt.Errorf("non-BGP: %s refused, %d routes on the router is the max_improvements cap", p, s.cfg.Max)
	}
	if err := s.op(ctx, func(c context.Context) error { return s.drv.Install(c, plugin.SteerRoute{Prefix: p, NextHop: nh}) }); err != nil {
		return fmt.Errorf("non-BGP: install %s via %s: %w", p, im.Provider, err)
	}
	// The install replaced the left-over route for p, so it is tracked now.
	delete(s.leftover, p)
	since := s.cfg.Now()
	if on {
		since = cur.Since
	}
	s.amu.Lock()
	s.active[p] = Steered{Prefix: p, Provider: im.Provider, NextHop: nh, Since: since}
	s.amu.Unlock()
	s.log.Info("non-BGP: steered", "prefix", p, "provider", im.Provider, "next_hop", nh)
	return nil
}

func (s *Steer) removeLocked(ctx context.Context, p netip.Prefix) error {
	if err := s.op(ctx, func(c context.Context) error { return s.drv.Remove(c, p) }); err != nil {
		return fmt.Errorf("non-BGP: remove %s: %w", p, err)
	}
	s.amu.Lock()
	delete(s.active, p)
	s.amu.Unlock()
	s.log.Info("non-BGP: route removed", "prefix", p)
	return nil
}

func (s *Steer) removeAllLocked(ctx context.Context) error {
	var errs []error
	errs = append(errs, s.removeLeftoversLocked(ctx)...)
	for _, p := range netpfx.SortedKeys(s.active) {
		if err := s.removeLocked(ctx, p); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// WithdrawAll removes every route this process installed, and tries the
// left-over routes of an earlier run once more. It is called on shutdown.
// It leaves alone a tagged route that appeared after the start-up sweep.
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
	s.amu.RLock()
	defer s.amu.RUnlock()
	out := make([]Steered, 0, len(s.active))
	for _, p := range netpfx.SortedKeys(s.active) {
		out = append(out, s.active[p])
	}
	return out
}
