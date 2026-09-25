// Package vip implements the "vip" target source: prefixes, and prefixes
// whose learned AS path contains a listed ASN, probed on their own interval.
//
// Configured prefixes are returned even when no RIB is attached. ASN matches
// come only from the callback installed by the controller, and only while
// that callback returns routes. Expansion stops at max_targets and is cached
// until the RIB generation changes. A default route is never a target. This
// source does not announce; the decision engine still requires the prefix
// in the learned RIB before any injection.
package vip

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "vip"

// MinInterval is the shortest VIP cadence. Shorter than this would spin
// the scheduler and is rejected at load time.
const MinInterval = time.Second

// DefaultMaxTargets caps ASN expansion. A transit ASN can match most of
// the table; without a cap the probe round never finishes and every
// result, including non-VIP prefixes, goes stale. 100 targets is two
// providers of 10 packets at the default 100 packets/s, inside one
// default probe interval.
const DefaultMaxTargets = 100

// MaxTargetsLimit is the largest max_targets config accepts.
const MaxTargetsLimit = 10000

func init() { plugin.Sources.Register(TypeName, New) }

// Config is the vip source's config block.
type Config struct {
	Interval   time.Duration `yaml:"interval"`
	Prefixes   []prefixSpec  `yaml:"prefixes"`
	ASNs       []uint32      `yaml:"asns"`
	MaxTargets int           `yaml:"max_targets"`
}

type prefixSpec struct {
	Prefix string `yaml:"prefix"`
	Host   string `yaml:"host"`
}

// LearnedRoute is one prefix from the RIB view.
type LearnedRoute struct {
	Prefix netip.Prefix
	ASPath []uint32
}

// Source returns VIP targets.
type Source struct {
	plugin.Base
	log        *slog.Logger
	interval   time.Duration
	maxTargets int
	prefixes   []plugin.Target
	asns       map[uint32]struct{}

	mu         sync.Mutex
	snap       func() (uint64, []LearnedRoute)
	cacheGen   uint64
	cacheExtra []plugin.Target
	cacheOK    bool
}

// New is the plugin factory. It does no I/O.
func New(c plugin.Config, env plugin.Env) (plugin.TargetSource, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.Interval <= 0 {
		return nil, fmt.Errorf("interval is required and must be positive")
	}
	if cfg.Interval < MinInterval {
		return nil, fmt.Errorf("interval %s must be at least %s", cfg.Interval, MinInterval)
	}
	if cfg.MaxTargets == 0 {
		cfg.MaxTargets = DefaultMaxTargets
	}
	if cfg.MaxTargets < 1 || cfg.MaxTargets > MaxTargetsLimit {
		return nil, fmt.Errorf("max_targets %d must be between 1 and %d", cfg.MaxTargets, MaxTargetsLimit)
	}
	if len(cfg.Prefixes) == 0 && len(cfg.ASNs) == 0 {
		return nil, fmt.Errorf("at least one prefix or asn is required")
	}
	if env.Logger == nil {
		env.Logger = slog.Default()
	}
	s := &Source{log: env.Logger, interval: cfg.Interval, maxTargets: cfg.MaxTargets, asns: map[uint32]struct{}{}}
	seen := map[netip.Prefix]bool{}
	for i, t := range cfg.Prefixes {
		p, err := netip.ParsePrefix(t.Prefix)
		if err != nil {
			return nil, fmt.Errorf("prefixes[%d]: prefix %q is not a valid CIDR", i, t.Prefix)
		}
		if p != p.Masked() {
			return nil, fmt.Errorf("prefixes[%d]: prefix %q has host bits set (did you mean %s?)", i, t.Prefix, p.Masked())
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("prefixes[%d]: %s is a default route", i, p)
		}
		if seen[p] {
			return nil, fmt.Errorf("prefixes[%d]: duplicate prefix %s", i, p)
		}
		seen[p] = true
		tg := plugin.Target{Prefix: p, Interval: cfg.Interval}
		if t.Host != "" {
			h, err := netip.ParseAddr(t.Host)
			if err != nil || !p.Contains(h) {
				return nil, fmt.Errorf("prefixes[%d]: host %q must be an address inside %s", i, t.Host, p)
			}
			tg.Host = h
		}
		s.prefixes = append(s.prefixes, tg)
	}
	for i, asn := range cfg.ASNs {
		if asn == 0 {
			return nil, fmt.Errorf("asns[%d]: asn must be non-zero", i)
		}
		if _, dup := s.asns[asn]; dup {
			return nil, fmt.Errorf("asns[%d]: duplicate asn %d", i, asn)
		}
		s.asns[asn] = struct{}{}
	}
	if len(s.prefixes) > s.maxTargets {
		return nil, fmt.Errorf("prefixes has %d entries, which is above max_targets %d", len(s.prefixes), s.maxTargets)
	}
	return s, nil
}

// Interval is the probe cadence applied to every target from this source.
// The controller rejects a value that is not inside the staleness window.
func (s *Source) Interval() time.Duration { return s.interval }

// SetLearnedRoutes attaches the RIB. fn may be nil. The controller passes
// a callback that returns nothing unless the view is ready, and never a
// default route. The source also ignores a default route if one appears.
// A generation of zero does not cache the expansion.
func (s *Source) SetLearnedRoutes(fn func() []LearnedRoute) {
	if fn == nil {
		s.SetRouteSnapshot(nil)
		return
	}
	s.SetRouteSnapshot(func() (uint64, []LearnedRoute) { return 0, fn() })
}

// SetRouteSnapshot attaches a versioned RIB read. The same non-zero
// generation is not expanded again, so a short VIP interval does not walk
// the table on every wake. Generation zero always recomputes.
func (s *Source) SetRouteSnapshot(fn func() (uint64, []LearnedRoute)) {
	s.mu.Lock()
	s.snap = fn
	s.cacheOK = false
	s.mu.Unlock()
}

// Targets implements plugin.TargetSource.
func (s *Source) Targets(context.Context) ([]plugin.Target, error) {
	base := make([]plugin.Target, len(s.prefixes))
	copy(base, s.prefixes)
	if len(s.asns) == 0 {
		return base, nil
	}
	s.mu.Lock()
	fn := s.snap
	s.mu.Unlock()
	if fn == nil {
		return base, nil
	}
	gen, routes := fn()
	if gen != 0 {
		s.mu.Lock()
		if s.cacheOK && s.cacheGen == gen {
			extra := cloneTargets(s.cacheExtra)
			s.mu.Unlock()
			return append(base, extra...), nil
		}
		s.mu.Unlock()
	}
	extra, truncated := s.expand(base, routes)
	if gen != 0 {
		s.mu.Lock()
		s.cacheGen = gen
		s.cacheExtra = cloneTargets(extra)
		s.cacheOK = true
		s.mu.Unlock()
	}
	if truncated {
		s.log.Warn("vip target list truncated", "max_targets", s.maxTargets, "returned", len(base)+len(extra))
	}
	return append(base, extra...), nil
}

// expand adds learned prefixes whose AS path contains a listed ASN, up to
// maxTargets including the configured prefixes. It stops at the cap so a
// transit ASN does not walk the rest of the table into memory as targets.
func (s *Source) expand(base []plugin.Target, routes []LearnedRoute) (extra []plugin.Target, truncated bool) {
	seen := map[netip.Prefix]bool{}
	for _, t := range base {
		seen[t.Prefix] = true
	}
	for _, rt := range routes {
		p := rt.Prefix.Masked()
		if !p.IsValid() || p.Bits() == 0 || seen[p] {
			continue
		}
		if !pathContains(rt.ASPath, s.asns) {
			continue
		}
		if len(base)+len(extra) >= s.maxTargets {
			return extra, true
		}
		seen[p] = true
		extra = append(extra, plugin.Target{Prefix: p, Interval: s.interval})
	}
	return extra, false
}

func cloneTargets(in []plugin.Target) []plugin.Target {
	if len(in) == 0 {
		return nil
	}
	out := make([]plugin.Target, len(in))
	copy(out, in)
	return out
}

func pathContains(path []uint32, want map[uint32]struct{}) bool {
	for _, asn := range path {
		if _, ok := want[asn]; ok {
			return true
		}
	}
	return false
}
