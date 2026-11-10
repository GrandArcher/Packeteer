package config

import (
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/onlyinvalid"
)

// RPKI is the shared RPKI origin-validation source (#158). It is off by
// default: nil, or enabled false, builds no source. Sources are an ordered
// fallback list; the first with fresh data answers. It never announces and
// never changes the learned RIB.
type RPKI struct {
	// Enabled turns the source on. False builds nothing.
	Enabled bool `yaml:"enabled"`
	// Sources are the origin-validation plugins, tried in order. At least
	// one is required when enabled.
	Sources []PluginSpec `yaml:"sources"`
	// AvoidInvalid makes Decide refuse a new improvement onto a provider
	// whose learned path for the prefix is RPKI-invalid. Off by default;
	// it never withdraws the learned prefix and never changes the RIB.
	AvoidInvalid bool `yaml:"avoid_invalid"`
	// DisplayFallback is asked for the prefix card only when no source has
	// fresh data (#200). Only ripestat is accepted. Its answers are display
	// only: they never reach Decide, avoid_invalid, leak watch, or the
	// exchange counts.
	DisplayFallback *PluginSpec `yaml:"display_fallback"`
	// OnlyInvalid reports RPKI-invalid routes that are the only path to a
	// destination, classed from evidence (#401). Nil or not enabled is
	// off. It never announces and never changes the learned RIB; an
	// approved slurm exception changes the validation data the RTR cache serves.
	OnlyInvalid *OnlyInvalid `yaml:"only_invalid"`
}

// OnlyInvalid is rpki.only_invalid (#401).
type OnlyInvalid struct {
	Enabled bool `yaml:"enabled"`
	// StableAfter is how long a learned path must be in the RIB for its
	// origin to count as stable evidence (default 720h).
	StableAfter time.Duration `yaml:"stable_after"`
	// HijackFeeds are hijack_feed plugins asked for incidents.
	HijackFeeds []PluginSpec `yaml:"hijack_feeds"`
	// SLURM allows proposing accept-invalid exceptions. Nil proposes
	// none.
	SLURM *OnlyInvalidSLURM `yaml:"slurm"`
}

// OnlyInvalidSLURM is rpki.only_invalid.slurm: where approved SLURM
// (RFC 8416) exceptions are written and which prefixes may get one.
type OnlyInvalidSLURM struct {
	Path     string   `yaml:"path"`
	Prefixes []string `yaml:"prefixes"`
	// ReviewAfter raises rpki.slurm_review for an exception older than
	// it. Omitted is onlyinvalid.DefaultReviewAfter; 0s turns the
	// reminder off.
	ReviewAfter *time.Duration `yaml:"review_after"`
}

// OnlyInvalidOn reports whether rpki.only_invalid is on.
func (c *Config) OnlyInvalidOn() bool {
	return c.RPKIOn() && c.RPKI.OnlyInvalid != nil && c.RPKI.OnlyInvalid.Enabled
}

// SLURMPrefixes parses rpki.only_invalid.slurm.prefixes. Validate has
// refused any that do not parse.
func (s *OnlyInvalidSLURM) SLURMPrefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(s.Prefixes))
	for _, v := range s.Prefixes {
		if p, err := netip.ParsePrefix(strings.TrimSpace(v)); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// displayOnlyRPKI is the one RPKI plugin type that is display only.
const displayOnlyRPKI = "ripestat"

// RPKIOn reports whether the RPKI source is on.
func (c *Config) RPKIOn() bool { return c.RPKI != nil && c.RPKI.Enabled }

func (c *Config) normalizeRPKI() {
	r := c.RPKI
	if r == nil {
		return
	}
	for i := range r.Sources {
		r.Sources[i].Type = strings.TrimSpace(r.Sources[i].Type)
	}
	if r.DisplayFallback != nil {
		r.DisplayFallback.Type = strings.TrimSpace(r.DisplayFallback.Type)
	}
	if o := r.OnlyInvalid; o != nil {
		if o.StableAfter == 0 {
			o.StableAfter = onlyinvalid.DefaultStableAfter
		}
		if o.SLURM != nil && o.SLURM.ReviewAfter == nil {
			d := onlyinvalid.DefaultReviewAfter
			o.SLURM.ReviewAfter = &d
		}
		for i := range o.HijackFeeds {
			o.HijackFeeds[i].Type = strings.TrimSpace(o.HijackFeeds[i].Type)
		}
	}
}

func (c *Config) validateRPKI(add func(string, ...any)) {
	r := c.RPKI
	if r == nil {
		return
	}
	if !r.Enabled {
		if len(r.Sources) > 0 || r.AvoidInvalid || r.DisplayFallback != nil || r.OnlyInvalid != nil {
			add("rpki.enabled is false but rpki.sources, rpki.avoid_invalid, rpki.display_fallback, or rpki.only_invalid is set")
		}
		return
	}
	if len(r.Sources) == 0 {
		add("rpki.sources: at least one source is required when rpki.enabled")
	}
	for i, s := range r.Sources {
		switch s.Type {
		case "":
			add("rpki.sources[%d]: type is required", i)
		case displayOnlyRPKI:
			add("rpki.sources[%d]: %s is display only; set it as rpki.display_fallback", i, displayOnlyRPKI)
		}
	}
	if f := r.DisplayFallback; f != nil && f.Type != displayOnlyRPKI {
		add("rpki.display_fallback: type must be %s", displayOnlyRPKI)
	}
	c.validateOnlyInvalid(add)
}

func (c *Config) validateOnlyInvalid(add func(string, ...any)) {
	o := c.RPKI.OnlyInvalid
	if o == nil {
		return
	}
	if !o.Enabled {
		if len(o.HijackFeeds) > 0 || o.SLURM != nil {
			add("rpki.only_invalid.enabled is false but hijack_feeds or slurm is set")
		}
		return
	}
	if o.StableAfter < onlyinvalid.MinStableAfter || o.StableAfter > onlyinvalid.MaxStableAfter {
		add("rpki.only_invalid.stable_after %s must be between %s and %s", o.StableAfter, onlyinvalid.MinStableAfter, onlyinvalid.MaxStableAfter)
	}
	names := map[string]bool{}
	for i, f := range o.HijackFeeds {
		if f.Type == "" {
			add("rpki.only_invalid.hijack_feeds[%d]: type is required", i)
			continue
		}
		if n := f.InstanceName(); names[n] {
			add("rpki.only_invalid.hijack_feeds[%d]: name %q is used twice; set name", i, n)
		} else {
			names[n] = true
		}
	}
	s := o.SLURM
	if s == nil {
		return
	}
	if c.IXP != nil {
		add("rpki.only_invalid.slurm cannot be combined with ixp: an exception changes what the exchange's RTR cache serves, and IXP mode may not change member routing")
	}
	if !filepath.IsAbs(s.Path) {
		add("rpki.only_invalid.slurm.path %q must be an absolute path (a mounted volume the RTR cache also reads)", s.Path)
	}
	if len(s.Prefixes) == 0 {
		add("rpki.only_invalid.slurm.prefixes: at least one prefix is required; an exception is allowed only inside them")
	}
	for i, v := range s.Prefixes {
		p, err := netip.ParsePrefix(strings.TrimSpace(v))
		switch {
		case err != nil:
			add("rpki.only_invalid.slurm.prefixes[%d]: %v", i, err)
		case p != p.Masked():
			add("rpki.only_invalid.slurm.prefixes[%d]: %s has host bits set", i, v)
		case p.Bits() == 0:
			add("rpki.only_invalid.slurm.prefixes[%d]: a default route would allow an exception anywhere", i)
		}
	}
	if r := s.ReviewAfter; r != nil && *r != 0 && (*r < onlyinvalid.MinReviewAfter || *r > onlyinvalid.MaxReviewAfter) {
		add("rpki.only_invalid.slurm.review_after %s must be 0s (no reminder) or between %s and %s", *r, onlyinvalid.MinReviewAfter, onlyinvalid.MaxReviewAfter)
	}
}
