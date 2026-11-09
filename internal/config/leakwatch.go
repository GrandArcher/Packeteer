package config

// LeakWatch watches for Packeteer's own routes outside the AS (#199).
// Each source reports routes seen outside the iBGP sessions; the core
// withdraws and holds out an injected route that shows up there. Nil or
// disabled is off, and then no source is built.
type LeakWatch struct {
	Enabled bool `yaml:"enabled"`
	// ASPathRule also flags an injected prefix seen with `asn` in its AS
	// path. Off by default: an operator with customers exports transit
	// routes, local ASN included, as a matter of course.
	ASPathRule bool         `yaml:"as_path_rule"`
	Sources    []PluginSpec `yaml:"sources"`
}

// LeakWatching reports whether the leak watch is on.
func (c *Config) LeakWatching() bool { return c.LeakWatch != nil && c.LeakWatch.Enabled }

func (c *Config) validateLeakWatch(add func(string, ...any)) {
	if !c.LeakWatching() {
		return
	}
	if c.PacketeerCommunity == "" {
		add("leak_watch requires packeteer_community: it is how a leaked route is recognised")
	}
	if len(c.LeakWatch.Sources) == 0 {
		add("leak_watch.sources: at least one source is required")
	}
}
