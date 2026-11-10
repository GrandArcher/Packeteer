package config

import (
	"time"
)

// Defaults and bounds for the nonbgp block (#300).
const (
	DefaultNonBGPWidenBits = 4
	MaxNonBGPWidenBits     = 8
	DefaultNonBGPIdle      = 30 * time.Minute
	MinNonBGPIdle          = time.Minute
	MaxNonBGPIdle          = 24 * time.Hour
	DefaultNonBGPMaxBlocks = 10000
	MaxNonBGPMaxBlocks     = 100000
)

// NonBGPWarning is logged at start, printed by -check, and shown on every
// page and in the config editor while the nonbgp block is set (#300).
const NonBGPWarning = "WARNING: non-BGP mode is on. Its static routes are derived from flow data, NOT from a learned BGP RIB view; " +
	"they can black-hole or misroute traffic, and they leak into BGP if the router redistributes static routes."

// NonBGP is the flow-driven mode for a site with two internet links whose
// router has no BGP (#300). A non-nil value, including an empty block, is
// that mode. Flow records name the destinations in use, each is tracked by
// a synthetic prefix (never more specific than /24 or /48), and an
// improvement becomes a static route on the router through its API. The
// default route carries everything else. Packeteer speaks no BGP here, but
// a router that redistributes static routes can still export them.
type NonBGP struct {
	// InstallRoutes is the explicit opt-in to static routes that come from
	// flow data, not from a learned BGP RIB view (owner exception for #300,
	// docs/design/nonbgp.md). mode inject requires it; without it nothing
	// is installed in any mode. Default false.
	InstallRoutes bool `yaml:"install_routes"`
	// DefaultProvider is the link the router's default route uses. It is
	// the native provider of every synthetic prefix.
	DefaultProvider string `yaml:"default_provider"`
	// Steerer installs the static routes. Required for mode inject.
	Steerer *PluginSpec `yaml:"steerer,omitempty"`
	// Covering looks up the announced prefix of a destination, the upper
	// bound for widening a synthetic prefix. Without it no prefix widens.
	Covering *PluginSpec `yaml:"covering,omitempty"`
	// WidenBits is how many bits a synthetic prefix may widen beyond its
	// /24 or /48 floor when flow data shows active addresses elsewhere
	// inside the announced prefix. 0 never widens. Default 4.
	WidenBits *int `yaml:"widen_bits,omitempty"`
	// Idle is how long a /24 or /48 block with no flow is kept. A prefix
	// narrows back, and is dropped, as its blocks age out. Default 30m.
	Idle time.Duration `yaml:"idle,omitempty"`
	// MaxBlocks caps the tracked /24 and /48 blocks. Blocks past it are
	// not tracked and are counted on /api/synthetic. Default 10000.
	MaxBlocks int `yaml:"max_blocks,omitempty"`
}

func (c *Config) defaultNonBGP() {
	n := c.NonBGP
	if n == nil {
		return
	}
	if n.WidenBits == nil {
		w := DefaultNonBGPWidenBits
		n.WidenBits = &w
	}
	if n.Idle == 0 {
		n.Idle = DefaultNonBGPIdle
	}
	if n.MaxBlocks == 0 {
		n.MaxBlocks = DefaultNonBGPMaxBlocks
	}
}

// validateNonBGP refuses a config that mixes the mode with anything that
// needs a BGP session, and checks the block. Observe stays valid without a
// steerer: it routes nothing.
func (c *Config) validateNonBGP(add func(string, ...any)) {
	n := c.NonBGP
	if n == nil {
		return
	}
	for _, f := range []struct {
		set  bool
		name string
	}{
		{len(c.BGP.Neighbors) > 0, "bgp.neighbors"},
		{len(c.RIBSources) > 0, "rib_sources"},
		{c.Announcer != nil, "announcer"},
		{c.Inbound != nil, "inbound"},
		{c.Mitigation != nil, "mitigation"},
		{c.MoreSpecific != nil, "more_specific"},
		{c.Synthesize != nil, "synthesize"},
		{c.ExternalPolicy != nil, "external_policy"},
		{c.LeakWatch != nil, "leak_watch"},
		{c.IXP != nil, "ixp"},
		{len(c.Exchanges) > 0, "exchanges"},
		{c.HA != nil, "ha"},
		{c.Federation != nil, "federation"},
	} {
		if f.set {
			add("nonbgp forbids %s: the router has no BGP session with Packeteer", f.name)
		}
	}
	if len(c.Providers) < 2 {
		add("nonbgp needs at least two providers (the two links)")
	}
	switch {
	case n.DefaultProvider == "":
		add("nonbgp.default_provider is required: the provider the router's default route uses")
	case !c.hasProvider(n.DefaultProvider):
		add("nonbgp.default_provider %q is not a configured provider", n.DefaultProvider)
	}
	if len(c.Sources) == 0 {
		add("nonbgp needs a flow entry in sources: flow records name the destinations")
	}
	for i, s := range c.Sources {
		if s.Type != "flow" {
			add("sources[%d]: nonbgp supports only type flow, got %q (other sources name prefixes that are not tracked)", i, s.Type)
		}
	}
	if n.Steerer != nil && n.Steerer.Type == "" {
		add("nonbgp.steerer: type is required")
	}
	if n.Covering != nil && n.Covering.Type == "" {
		add("nonbgp.covering: type is required")
	}
	if n.WidenBits != nil && (*n.WidenBits < 0 || *n.WidenBits > MaxNonBGPWidenBits) {
		add("nonbgp.widen_bits %d must be between 0 and %d", *n.WidenBits, MaxNonBGPWidenBits)
	}
	if n.Idle != 0 && (n.Idle < MinNonBGPIdle || n.Idle > MaxNonBGPIdle) {
		add("nonbgp.idle %s must be between %s and %s", n.Idle, MinNonBGPIdle, MaxNonBGPIdle)
	}
	if n.MaxBlocks < 0 || n.MaxBlocks > MaxNonBGPMaxBlocks {
		add("nonbgp.max_blocks %d must be between 0 (the default) and %d", n.MaxBlocks, MaxNonBGPMaxBlocks)
	}
	if c.Mode == ModeInject && n.Steerer == nil {
		add("mode inject with nonbgp requires nonbgp.steerer")
	}
	if c.Mode == ModeInject && !n.InstallRoutes {
		add("mode inject with nonbgp requires nonbgp.install_routes: true, the opt-in to static routes that are derived from flow data and not from a learned BGP RIB view (docs/nonbgp.md)")
	}
}

func (c *Config) hasProvider(name string) bool {
	for _, p := range c.Providers {
		if p.Name == name {
			return true
		}
	}
	return false
}
