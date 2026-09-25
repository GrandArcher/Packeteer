// Package announce turns decision-engine changes into announcer calls.
//
// It runs only in inject mode. Observe and suggest never touch the
// announcer. A route is published only when the decided prefix is allowlisted
// and present in the RIB, the provider has a next hop, and the improvement
// cap has room. Every route carries the configured local preference and
// community; the announcer adds NO_EXPORT.
//
// more_specific_bits, when non-zero, publishes the 2^n covering
// more-specifics of the decided prefix instead of the prefix itself. The
// parent must still be the prefix that is in the RIB and on the allowlist.
package announce

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// RIB is the slice of the RIB view the controller needs. Ready is false when
// no BGP session is up; Contains reports an exact prefix match.
type RIB interface {
	Ready() bool
	Contains(netip.Prefix) bool
}

// Config is the injection policy. It is ignored unless Mode is inject.
type Config struct {
	Mode             string
	LocalPref        uint32
	Community        string
	MoreSpecificBits int
	MaxImprovements  int
	Allowlist        []netip.Prefix
	NextHops         map[string]netip.Addr // provider name -> next hop
}

// Controller applies decision changes to an announcer.
type Controller struct {
	cfg Config
	ann plugin.Announcer
	rib RIB
	log *slog.Logger

	mu     sync.Mutex
	active map[netip.Prefix]slot // decided prefix -> what is on the wire
}

// slot is one decided prefix's published routes.
type slot struct {
	provider string
	prefixes []netip.Prefix
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
		if cfg.MoreSpecificBits < 0 || cfg.MoreSpecificBits > config.MaxMoreSpecificBits {
			return nil, fmt.Errorf("announce: more_specific_bits %d is out of range", cfg.MoreSpecificBits)
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
// improvements does not re-advertise.
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
	announced := c.active[p].prefixes
	if len(announced) == 0 {
		announced = []netip.Prefix{p}
	}
	var errs []error
	var left []netip.Prefix
	for _, q := range announced {
		if err := c.ann.Withdraw(ctx, q); err != nil {
			errs = append(errs, err)
			left = append(left, q)
			continue
		}
	}
	if len(left) == 0 {
		delete(c.active, p)
	} else if s, ok := c.active[p]; ok {
		s.prefixes = left
		c.active[p] = s
	}
	return errors.Join(errs...)
}

func (c *Controller) announceLocked(ctx context.Context, imp policy.Improvement) error {
	p := imp.Prefix.Masked()
	if !allowed(c.cfg.Allowlist, p) {
		return fmt.Errorf("announce: %s is not allowlisted", p)
	}
	if _, on := c.active[p]; !on && !c.rib.Contains(p) {
		// An active improvement may already have displaced the native path
		// (iBGP does not reflect our own route). A new one must be in the RIB.
		return fmt.Errorf("announce: %s is not in the RIB", p)
	}
	nh, ok := c.cfg.NextHops[imp.Provider]
	if !ok || !nh.IsValid() {
		return fmt.Errorf("announce: provider %q has no next hop", imp.Provider)
	}
	if _, exists := c.active[p]; !exists && len(c.active) >= c.cfg.MaxImprovements {
		return fmt.Errorf("announce: max_improvements (%d) reached", c.cfg.MaxImprovements)
	}
	prefixes, err := expand(p, c.cfg.MoreSpecificBits)
	if err != nil {
		return err
	}
	for _, q := range prefixes {
		if !allowed(c.cfg.Allowlist, q) {
			return fmt.Errorf("announce: more-specific %s of %s is not allowlisted", q, p)
		}
	}
	var announced []netip.Prefix
	for _, q := range prefixes {
		rt := plugin.Route{
			Prefix:      q,
			NextHop:     nh,
			Provider:    imp.Provider,
			LocalPref:   c.cfg.LocalPref,
			Communities: []string{c.cfg.Community},
		}
		if err := c.ann.Announce(ctx, rt); err != nil {
			for _, done := range announced {
				_ = c.ann.Withdraw(ctx, done)
			}
			return err
		}
		announced = append(announced, q)
	}
	// Drop any previous more-specifics that this round no longer publishes.
	prev := map[netip.Prefix]bool{}
	for _, q := range c.active[p].prefixes {
		prev[q] = true
	}
	for _, q := range announced {
		delete(prev, q)
	}
	for q := range prev {
		if err := c.ann.Withdraw(ctx, q); err != nil {
			c.log.Error("withdraw stale more-specific", "prefix", q, "err", err)
		}
	}
	c.active[p] = slot{provider: imp.Provider, prefixes: announced}
	c.log.Info("injected", "prefix", p, "announced", fmtPrefixes(announced), "provider", imp.Provider, "next_hop", nh, "local_pref", c.cfg.LocalPref)
	return nil
}

func fmtPrefixes(ps []netip.Prefix) string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return strings.Join(out, ",")
}

func sortPrefixes(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool {
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
}

func allowed(list []netip.Prefix, p netip.Prefix) bool {
	p = p.Masked()
	for _, a := range list {
		if a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// expand returns the prefixes to announce for p. bits == 0 returns p itself.
// bits > 0 returns the 2^bits more-specifics of length len(p)+bits that
// together cover p exactly.
func expand(p netip.Prefix, bits int) ([]netip.Prefix, error) {
	p = p.Masked()
	if !p.IsValid() {
		return nil, fmt.Errorf("announce: prefix %s is invalid", p)
	}
	if bits == 0 {
		return []netip.Prefix{p}, nil
	}
	if bits < 0 {
		return nil, fmt.Errorf("announce: more_specific_bits %d is negative", bits)
	}
	width := p.Addr().BitLen()
	newLen := p.Bits() + bits
	if newLen > width {
		return nil, fmt.Errorf("announce: more_specific_bits %d does not fit in %s", bits, p)
	}
	n := 1 << bits
	shift := width - newLen
	stride := new(big.Int).Lsh(big.NewInt(1), uint(shift))
	out := make([]netip.Prefix, 0, n)
	addr := p.Addr()
	for i := 0; i < n; i++ {
		child, err := addr.Prefix(newLen)
		if err != nil {
			return nil, err
		}
		out = append(out, child.Masked())
		if i+1 == n {
			break
		}
		next, err := addAddr(addr, stride)
		if err != nil {
			return nil, err
		}
		addr = next
	}
	return out, nil
}

func addAddr(a netip.Addr, delta *big.Int) (netip.Addr, error) {
	raw := a.AsSlice()
	sum := new(big.Int).Add(new(big.Int).SetBytes(raw), delta)
	if sum.Sign() < 0 || sum.BitLen() > len(raw)*8 {
		return netip.Addr{}, fmt.Errorf("announce: address overflow adding to %s", a)
	}
	buf := make([]byte, len(raw))
	sum.FillBytes(buf)
	out, ok := netip.AddrFromSlice(buf)
	if !ok {
		return netip.Addr{}, fmt.Errorf("announce: bad address after adding to %s", a)
	}
	return out, nil
}
