package config

import "strings"

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
}

func (c *Config) validateRPKI(add func(string, ...any)) {
	r := c.RPKI
	if r == nil {
		return
	}
	if !r.Enabled {
		if len(r.Sources) > 0 || r.AvoidInvalid || r.DisplayFallback != nil {
			add("rpki.enabled is false but rpki.sources, rpki.avoid_invalid, or rpki.display_fallback is set")
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
}
