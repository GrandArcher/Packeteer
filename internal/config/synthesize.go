package config

import (
	"net/netip"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
)

// Synthesize defaults and bounds (#122).
const (
	DefaultSynthesizeMaxBits     = 1
	SynthesizeMaxBitsLimit       = 8
	DefaultSynthesizeMaxPrefixV4 = 24
	DefaultSynthesizeMaxPrefixV6 = 48
)

// SynthesizeWarning is the warning logged at start, shown in the UI, and
// written in the docs wherever synthesize is on.
const SynthesizeWarning = "WARNING: synthesize is on. Synthesized more-specifics are NOT in the learned RIB and can cause hijack-like effects, RPKI-invalid announcements, and route leaks if misused."

// Synthesize is the opt-in synthesized more-specific injection (#122,
// docs/design/more-specific.md). It may announce a measured sub-range of a
// covering prefix a neighbor advertises exactly in the learned RIB, which
// is itself not in the learned RIB. Nil or disabled is off.
type Synthesize struct {
	Enabled bool `yaml:"enabled"`
	// CoveringPrefixes are the prefixes whose learned sub-prefixes may be
	// split. Each must be inside allowlist.prefixes.
	CoveringPrefixes []string `yaml:"covering_prefixes"`
	// MaxBits is how far past the covering prefix's length a synthesized
	// route may go. Zero is DefaultSynthesizeMaxBits.
	MaxBits int `yaml:"max_bits"`
	// MaxPrefixLen is the longest synthesized route per family.
	MaxPrefixLen SynthesizeMaxLen `yaml:"max_prefix_len"`
	// MarkerCommunity is added to every synthesized route, so an edge can
	// tell it from an exact learned prefix. Required when enabled.
	MarkerCommunity string `yaml:"marker_community"`
	// NoAdvertise adds NO_ADVERTISE to the NO_EXPORT every injected route
	// carries, so the edge keeps synthesized routes to itself.
	NoAdvertise bool `yaml:"no_advertise"`
}

// SynthesizeMaxLen is the longest synthesized prefix per family. Zero is
// the default (/24 and /48).
type SynthesizeMaxLen struct {
	V4 int `yaml:"v4"`
	V6 int `yaml:"v6"`
}

// Synthesizing reports whether synthesize is on.
func (c *Config) Synthesizing() bool { return c.Synthesize != nil && c.Synthesize.Enabled }

// RouteCap is the per-router route cap more_specific and synthesize share:
// more_specific.max_routes, or its default when that block is absent.
func (c *Config) RouteCap() int {
	if c.MoreSpecific != nil {
		return c.MoreSpecific.MaxRoutes
	}
	return DefaultMoreSpecificMaxRoutes
}

func (s *Synthesize) applyDefaults() {
	if s.MaxBits == 0 {
		s.MaxBits = DefaultSynthesizeMaxBits
	}
	if s.MaxPrefixLen.V4 == 0 {
		s.MaxPrefixLen.V4 = DefaultSynthesizeMaxPrefixV4
	}
	if s.MaxPrefixLen.V6 == 0 {
		s.MaxPrefixLen.V6 = DefaultSynthesizeMaxPrefixV6
	}
}

func (c *Config) validateSynthesize(add func(string, ...any)) {
	s := c.Synthesize
	if s == nil {
		return
	}
	if s.MaxBits < 1 || s.MaxBits > SynthesizeMaxBitsLimit {
		add("synthesize.max_bits %d must be between 1 and %d", s.MaxBits, SynthesizeMaxBitsLimit)
	}
	if s.MaxPrefixLen.V4 < 1 || s.MaxPrefixLen.V4 > 32 {
		add("synthesize.max_prefix_len.v4 %d must be between 1 and 32", s.MaxPrefixLen.V4)
	}
	if s.MaxPrefixLen.V6 < 1 || s.MaxPrefixLen.V6 > 128 {
		add("synthesize.max_prefix_len.v6 %d must be between 1 and 128", s.MaxPrefixLen.V6)
	}
	var allow []netip.Prefix
	for _, a := range c.Allowlist.Prefixes {
		if p, err := netip.ParsePrefix(a); err == nil {
			allow = append(allow, p.Masked())
		}
	}
	seen := map[netip.Prefix]bool{}
	for i, text := range s.CoveringPrefixes {
		p, err := netip.ParsePrefix(text)
		switch {
		case err != nil:
			add("synthesize.covering_prefixes[%d]: %q is not a valid CIDR", i, text)
			continue
		case p != p.Masked():
			add("synthesize.covering_prefixes[%d]: %q has host bits set (did you mean %s?)", i, text, p.Masked())
			continue
		case p.Bits() == 0:
			add("synthesize.covering_prefixes[%d]: the default route is never split", i)
			continue
		case seen[p]:
			add("synthesize.covering_prefixes[%d]: duplicate prefix %s", i, p)
			continue
		}
		seen[p] = true
		if !netpfx.CoveredBy(allow, p) {
			add("synthesize.covering_prefixes[%d]: %s is not inside allowlist.prefixes", i, p)
		}
	}
	if s.MarkerCommunity != "" {
		text, err := ExtraCommunityText(s.MarkerCommunity, c.PacketeerCommunity)
		if err != nil {
			add("synthesize.marker_community %q: %v", s.MarkerCommunity, err)
		} else {
			s.MarkerCommunity = text
		}
	}
	if !s.Enabled {
		return
	}
	if len(s.CoveringPrefixes) == 0 {
		add("synthesize.covering_prefixes: at least one prefix is required when synthesize is enabled")
	}
	if s.MarkerCommunity == "" {
		add("synthesize.marker_community is required when synthesize is enabled: it marks every synthesized route")
	}
	if !c.LeakWatching() {
		add("synthesize requires leak_watch enabled: a synthesized route that leaks must be withdrawn")
	}
}
