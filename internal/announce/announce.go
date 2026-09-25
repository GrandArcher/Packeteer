// Package announce turns decision-engine changes into announcer calls.
//
// It runs only in inject mode. Observe and suggest never touch the
// announcer. A route is published only when the decided prefix is allowlisted
// and present in the RIB, the provider has a next hop, and the improvement
// cap has room. The announced prefix is that exact prefix. Packeteer does
// not synthesize more-specifics. Every Sync re-checks prefixes already on
// the wire, including provider switches. A route already on the wire stays
// while the decision engine still wants it, even if the neighbor stopped
// advertising the prefix: that is what the router does once Packeteer's
// route is best, and withdrawing it would flap. A real leave arrives as the
// improvement leaving the wanted set, and Sync withdraws it. Every route
// carries the configured local preference and community; the announcer adds
// NO_EXPORT.
package announce

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"sync"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// RIB is the slice of the RIB view the controller needs. Ready is false when
// no BGP session is up. Contains reports an exact prefix a configured
// neighbor is still advertising. It is false both when the prefix has left
// and when the router has stopped sending it because Packeteer's route won.
// Sync uses Contains to refuse a new announcement. It does not, by itself,
// withdraw an improvement the decision engine still wants.
type RIB interface {
	Ready() bool
	Contains(netip.Prefix) bool
}

// Config is the injection policy. It is ignored unless Mode is inject.
type Config struct {
	Mode            string
	LocalPref       uint32
	Community       string
	MaxImprovements int
	Allowlist       []netip.Prefix
	NextHops        map[string]netip.Addr // provider name -> next hop
}

// Controller applies decision changes to an announcer.
type Controller struct {
	cfg Config
	ann plugin.Announcer
	rib RIB
	log *slog.Logger

	mu     sync.Mutex
	active map[netip.Prefix]slot // exact learned prefix -> what is on the wire
}

// slot is the route published for one learned prefix.
type slot struct {
	provider string
}

// New validates inject settings and returns a controller. ann and rib may be
// nil when Mode is not inject; Apply is then a no-op.
func New(cfg Config, ann plugin.Announcer, rib RIB, log *slog.Logger) (*Controller, error) {
	if cfg.Mode == config.ModeInject {
		if ann == nil {
			return nil, errors.New("announce: inject mode requires an announcer")
		}
		if rib == nil {
			return nil, errors.New("announce: inject mode requires a RIB view")
		}
		if cfg.LocalPref == 0 {
			return nil, errors.New("announce: inject mode requires local_pref")
		}
		if cfg.Community == "" {
			return nil, errors.New("announce: inject mode requires a community")
		}
		if cfg.MaxImprovements < 1 {
			return nil, errors.New("announce: max_improvements must be positive")
		}
	}
	if log == nil {
		log = slog.Default()
	}
	if cfg.NextHops == nil {
		cfg.NextHops = map[string]netip.Addr{}
	}
	return &Controller{cfg: cfg, ann: ann, rib: rib, log: log, active: map[netip.Prefix]slot{}}, nil
}

// Bind attaches an announcer that publishes on an existing speaker. srv is
// the RIB view's GoBGP server. Inject mode refuses to start when the
// announcer cannot bind.
func (c *Controller) Bind(srv any) error {
	if c == nil || c.cfg.Mode != config.ModeInject {
		return nil
	}
	b, ok := c.ann.(interface {
		Bind(any, string) error
	})
	if !ok {
		return fmt.Errorf("announce: announcer %T cannot publish on the embedded iBGP speaker", c.ann)
	}
	return b.Bind(srv, c.cfg.Community)
}

// Sync makes the announced set match imps, the decision engine's active
// improvements. In observe and suggest it returns immediately and does not
// call the announcer. When the RIB is not ready every announced route is
// withdrawn, even if imps is non-empty. Calling Sync again with the same
// improvements does not re-advertise. A prefix that is not in the RIB is not
// announced. One that is already announced is kept or moved while the
// improvement is still requested; a real RIB leave comes in as the
// improvement disappearing from imps.
func (c *Controller) Sync(ctx context.Context, imps []policy.Improvement) error {
	if c == nil || c.cfg.Mode != config.ModeInject {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.rib.Ready() {
		c.log.Warn("rib not ready; withdrawing announced routes")
		return c.withdrawAllLocked(ctx)
	}
	want := map[netip.Prefix]policy.Improvement{}
	for _, im := range imps {
		want[im.Prefix.Masked()] = im
	}
	var errs []error
	for p := range c.active {
		if _, ok := want[p]; !ok {
			if err := c.withdrawLocked(ctx, p); err != nil {
				errs = append(errs, err)
			}
		}
	}
	order := make([]netip.Prefix, 0, len(want))
	for p := range want {
		order = append(order, p)
	}
	sortPrefixes(order)
	for _, p := range order {
		im := want[p]
		if _, on := c.active[p]; !on && !c.rib.Contains(p) {
			errs = append(errs, fmt.Errorf("announce: %s is not in the RIB", p))
			continue
		}
		if s, on := c.active[p]; on && s.provider == im.Provider {
			continue
		}
		if !allowed(c.cfg.Allowlist, p) {
			if _, on := c.active[p]; on {
				if err := c.withdrawLocked(ctx, p); err != nil {
					errs = append(errs, err)
				}
			}
			errs = append(errs, fmt.Errorf("announce: %s is not allowlisted", p))
			continue
		}
		if err := c.announceLocked(ctx, im); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// WithdrawAll removes every announced route. It is safe to call more than once.
func (c *Controller) WithdrawAll(ctx context.Context) error {
	if c == nil || c.cfg.Mode != config.ModeInject || c.ann == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.withdrawAllLocked(ctx)
}

func (c *Controller) withdrawAllLocked(ctx context.Context) error {
	if err := c.ann.WithdrawAll(ctx); err != nil {
		return err
	}
	c.active = map[netip.Prefix]slot{}
	return nil
}

func (c *Controller) withdrawLocked(ctx context.Context, p netip.Prefix) error {
	p = p.Masked()
	if _, ok := c.active[p]; !ok {
		return nil
	}
	if err := c.ann.Withdraw(ctx, p); err != nil {
		return err
	}
	delete(c.active, p)
	return nil
}

func (c *Controller) announceLocked(ctx context.Context, imp policy.Improvement) error {
	p := imp.Prefix.Masked()
	if !allowed(c.cfg.Allowlist, p) {
		return fmt.Errorf("announce: %s is not allowlisted", p)
	}
	if _, on := c.active[p]; !on && !c.rib.Contains(p) {
		return fmt.Errorf("announce: %s is not in the RIB", p)
	}
	nh, ok := c.cfg.NextHops[imp.Provider]
	if !ok || !nh.IsValid() {
		return fmt.Errorf("announce: provider %q has no next hop", imp.Provider)
	}
	if _, exists := c.active[p]; !exists && len(c.active) >= c.cfg.MaxImprovements {
		return fmt.Errorf("announce: max_improvements (%d) reached", c.cfg.MaxImprovements)
	}
	rt := plugin.Route{
		Prefix:      p,
		NextHop:     nh,
		Provider:    imp.Provider,
		LocalPref:   c.cfg.LocalPref,
		Communities: []string{c.cfg.Community},
	}
	if err := c.ann.Announce(ctx, rt); err != nil {
		return err
	}
	c.active[p] = slot{provider: imp.Provider}
	c.log.Info("injected", "prefix", p, "provider", imp.Provider, "next_hop", nh, "local_pref", c.cfg.LocalPref)
	return nil
}

func sortPrefixes(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool {
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
}

// allowed reports whether p is an allowlist entry or covered by one.
// Announce publishes p itself, and only when that exact prefix is in the RIB.
func allowed(list []netip.Prefix, p netip.Prefix) bool {
	p = p.Masked()
	for _, a := range list {
		if a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
			return true
		}
	}
	return false
}
