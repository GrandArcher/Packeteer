// Package herdhints implements the "herd_hints" target source (#672).
//
// It probes routes other herd members see degraded: each hint is a route in
// this node's learned RIB view and the number of other members that see
// loss toward it, counted as the herd world view counts (verified members
// only when herd.identity is set). A hint only adds a probe target, within
// max_targets and the probe engine's rate limits. Any improvement still
// comes from this node's own measurements passing the normal thresholds,
// hold time, allowlist, and cap; herd data never reaches a decision, and
// this source announces nothing.
package herdhints

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "herd_hints"

// Defaults and bounds.
const (
	DefaultMinVantages = 2
	MaxMinVantages     = 64
	DefaultMaxTargets  = 16
	// MaxTargetsLimit equals the most hints herd keeps.
	MaxTargetsLimit = 1024
)

func init() { plugin.Sources.Register(TypeName, New) }

// Hint is a learned route other members see degraded, and how many
// members (one per ASN, counted as the herd world view counts them).
type Hint struct {
	Prefix   netip.Prefix
	Vantages int
}

// Config is the source's config block.
type Config struct {
	// MinVantages is how many other members must see a route degraded
	// before it is probed (default 2).
	MinVantages int `yaml:"min_vantages"`
	// MaxTargets caps the hinted routes probed at once (default 16).
	MaxTargets int `yaml:"max_targets"`
}

// Source returns the current hints as probe targets.
type Source struct {
	plugin.Base
	cfg Config

	mu    sync.Mutex
	hints func() []Hint
}

// New is the plugin factory. It does no I/O.
func New(c plugin.Config, _ plugin.Env) (plugin.TargetSource, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.MinVantages == 0 {
		cfg.MinVantages = DefaultMinVantages
	}
	if cfg.MaxTargets == 0 {
		cfg.MaxTargets = DefaultMaxTargets
	}
	if cfg.MinVantages < 1 || cfg.MinVantages > MaxMinVantages {
		return nil, fmt.Errorf("min_vantages %d must be between 1 and %d", cfg.MinVantages, MaxMinVantages)
	}
	if cfg.MaxTargets < 1 || cfg.MaxTargets > MaxTargetsLimit {
		return nil, fmt.Errorf("max_targets %d must be between 1 and %d", cfg.MaxTargets, MaxTargetsLimit)
	}
	return &Source{cfg: cfg}, nil
}

// SetHints installs the hint reader. It must not block: the probe engine
// calls Targets on its own path.
func (s *Source) SetHints(fn func() []Hint) {
	s.mu.Lock()
	s.hints = fn
	s.mu.Unlock()
}

// Targets returns the hinted routes seen by at least min_vantages other
// members, most vantages first as given, at most max_targets. The engine
// picks the probe addresses inside each route.
func (s *Source) Targets(context.Context) ([]plugin.Target, error) {
	s.mu.Lock()
	fn := s.hints
	s.mu.Unlock()
	if fn == nil {
		return nil, nil
	}
	var out []plugin.Target
	for _, h := range fn() {
		if len(out) >= s.cfg.MaxTargets {
			break
		}
		if h.Vantages >= s.cfg.MinVantages && h.Prefix.IsValid() && h.Prefix.Bits() > 0 {
			out = append(out, plugin.Target{Prefix: h.Prefix.Masked()})
		}
	}
	return out, nil
}
