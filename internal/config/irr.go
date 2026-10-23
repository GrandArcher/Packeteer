package config

import (
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/irr"
)

// IRR is the IRR origin check per learned path (#214). It is off by
// default: nil, or enabled false, builds no source. Sources are asked in
// order and their answers cached. It never announces and never changes
// the learned RIB.
type IRR struct {
	// Enabled turns the check on. False builds nothing.
	Enabled bool `yaml:"enabled"`
	// Sources are the IRR plugins (whois, file), in order. At least one is
	// required when enabled.
	Sources []PluginSpec `yaml:"sources"`
	// Refresh is how old a cached answer gets before it is looked up again
	// (default 6h).
	Refresh time.Duration `yaml:"refresh"`
	// Staleness is how long an answer is used after its data time; older
	// is unknown (default 24h).
	Staleness time.Duration `yaml:"staleness"`
	// ASSets maps a provider name to an as-set its paths' origins are
	// checked against. Display only.
	ASSets map[string]string `yaml:"as_sets"`
	// PreferRegistered makes Decide refuse a new improvement onto a
	// provider whose learned path for the prefix is not registered. Off by
	// default; unknown never blocks.
	PreferRegistered bool `yaml:"prefer_registered"`
}

// IRROn reports whether the IRR check is on.
func (c *Config) IRROn() bool { return c.IRR != nil && c.IRR.Enabled }

func (c *Config) normalizeIRR() {
	r := c.IRR
	if r == nil {
		return
	}
	for i := range r.Sources {
		r.Sources[i].Type = strings.TrimSpace(r.Sources[i].Type)
	}
	if !r.Enabled {
		return
	}
	if r.Refresh == 0 {
		r.Refresh = irr.DefaultRefresh
	}
	if r.Staleness == 0 {
		r.Staleness = max(irr.DefaultStaleness, r.Refresh)
	}
}

func (c *Config) validateIRR(add func(string, ...any)) {
	r := c.IRR
	if r == nil {
		return
	}
	if !r.Enabled {
		if len(r.Sources) > 0 || r.Refresh != 0 || r.Staleness != 0 || len(r.ASSets) > 0 || r.PreferRegistered {
			add("irr.enabled is false but irr.sources, irr.refresh, irr.staleness, irr.as_sets, or irr.prefer_registered is set")
		}
		return
	}
	if len(r.Sources) == 0 {
		add("irr.sources: at least one source is required when irr.enabled")
	}
	names := map[string]bool{}
	for i, s := range r.Sources {
		if s.Type == "" {
			add("irr.sources[%d]: type is required", i)
			continue
		}
		if n := s.InstanceName(); names[n] {
			add("irr.sources[%d]: name %q is used twice; set name", i, n)
		} else {
			names[n] = true
		}
	}
	if r.Refresh < irr.MinRefresh || r.Refresh > irr.MaxStaleness {
		add("irr.refresh %s must be between %s and %s", r.Refresh, irr.MinRefresh, irr.MaxStaleness)
	}
	if r.Staleness < r.Refresh || r.Staleness > irr.MaxStaleness {
		add("irr.staleness %s must be at least irr.refresh (%s) and at most %s", r.Staleness, r.Refresh, irr.MaxStaleness)
	}
	providers := map[string]bool{}
	for _, p := range c.Providers {
		providers[p.Name] = true
	}
	for name, set := range r.ASSets {
		if !providers[name] {
			add("irr.as_sets: %q is not a configured provider", name)
		}
		if !irr.ValidASSetName(set) {
			add("irr.as_sets.%s: %q is not an as-set name (for example AS-EXAMPLE or AS64500:AS-CUSTOMERS)", name, set)
		}
	}
}
