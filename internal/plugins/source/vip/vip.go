// Package vip implements the "vip" target source: prefixes, and prefixes
// whose learned AS path contains a listed ASN, probed on their own interval.
//
// Configured prefixes are returned even when no RIB is attached. ASN matches
// come only from the callback installed by the controller, and only while
// that callback returns routes. A default route is never a target. This
// source does not announce; the decision engine still requires the prefix
// in the learned RIB before any injection.
package vip

import (
	"context"
	"fmt"
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

func init() { plugin.Sources.Register(TypeName, New) }

// Config is the vip source's config block.
type Config struct {
	Interval time.Duration `yaml:"interval"`
	Prefixes []prefixSpec  `yaml:"prefixes"`
	ASNs     []uint32      `yaml:"asns"`
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
	interval time.Duration
	prefixes []plugin.Target
	asns     map[uint32]struct{}

	mu     sync.RWMutex
	routes func() []LearnedRoute
}

// New is the plugin factory. It does no I/O.
func New(c plugin.Config, _ plugin.Env) (plugin.TargetSource, error) {
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
	if len(cfg.Prefixes) == 0 && len(cfg.ASNs) == 0 {
		return nil, fmt.Errorf("at least one prefix or asn is required")
	}
	s := &Source{interval: cfg.Interval, asns: map[uint32]struct{}{}}
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
	return s, nil
}

// SetLearnedRoutes attaches the RIB. fn may be nil. The controller passes
// a callback that returns nothing unless the view is ready, and never a
// default route. The source also ignores a default route if one appears.
func (s *Source) SetLearnedRoutes(fn func() []LearnedRoute) {
	s.mu.Lock()
	s.routes = fn
	s.mu.Unlock()
}

// Targets implements plugin.TargetSource.
func (s *Source) Targets(context.Context) ([]plugin.Target, error) {
	out := make([]plugin.Target, len(s.prefixes))
	copy(out, s.prefixes)
	if len(s.asns) == 0 {
		return out, nil
	}
	s.mu.RLock()
	fn := s.routes
	s.mu.RUnlock()
	if fn == nil {
		return out, nil
	}
	seen := map[netip.Prefix]bool{}
	for _, t := range out {
		seen[t.Prefix] = true
	}
	for _, rt := range fn() {
		p := rt.Prefix.Masked()
		if !p.IsValid() || p.Bits() == 0 || seen[p] {
			continue
		}
		if !pathContains(rt.ASPath, s.asns) {
			continue
		}
		seen[p] = true
		out = append(out, plugin.Target{Prefix: p, Interval: s.interval})
	}
	return out, nil
}

func pathContains(path []uint32, want map[uint32]struct{}) bool {
	for _, asn := range path {
		if _, ok := want[asn]; ok {
			return true
		}
	}
	return false
}
