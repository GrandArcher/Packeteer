package config

import (
	"net/netip"
	"strings"
	"time"
)

// Mitigation defaults and bounds (#28).
const (
	DefaultMitigationMaxRules = 10
	MaxMitigationMaxRules     = 1000
	DefaultMitigationTTL      = time.Hour
	DefaultMitigationMaxTTL   = 24 * time.Hour
	// MaxMitigationMaxTTL bounds max_ttl: a mitigation rule is intent held
	// in memory, and it must expire on its own.
	MaxMitigationMaxTTL = 7 * 24 * time.Hour
	MinMitigationTTL    = time.Second
)

// Mitigation is threat mitigation (#28): RTBH (blackhole), BGP redirect,
// and FlowSpec (drop, rate-limit, redirect) for exact learned prefixes,
// added through the ops API. Nil disables it.
type Mitigation struct {
	// Mode is observe (default) or inject. inject also needs the top-level
	// mode to be inject. observe accepts and lists rules and never
	// announces.
	Mode string `yaml:"mode"`
	// Allowlist is the mitigation allowlist. It is separate from
	// allowlist.prefixes: a rule's prefix must be covered by it. Required.
	Allowlist []string `yaml:"allowlist"`
	// MaxRules caps mitigation routes held at once, announced or not
	// (default 10). A FlowSpec rule with source countries counts once per
	// source network.
	MaxRules int `yaml:"max_rules"`
	// DefaultTTL is a rule's lifetime when the request names none
	// (default 1h). MaxTTL is the longest a request may ask for
	// (default 24h, at most 168h). Every rule expires.
	DefaultTTL time.Duration `yaml:"default_ttl"`
	MaxTTL     time.Duration `yaml:"max_ttl"`
	// LocalPref is set on mitigation routes (default: the top-level
	// local_pref). It must win on the edge over the native route.
	LocalPref uint32 `yaml:"local_pref"`
	// GeoIPDB is a MaxMind-format country database the operator mounts
	// (for example GeoLite2-Country.mmdb). FlowSpec rules with
	// source_countries need it. None is shipped.
	GeoIPDB string `yaml:"geoip_db"`
	// Announcer is the in-process mitigation announcer. Required in
	// inject.
	Announcer *PluginSpec `yaml:"announcer"`
}

// MitigationMode is the mitigation mode, or "" when it is not configured.
func (c *Config) MitigationMode() string {
	if c == nil || c.Mitigation == nil {
		return ""
	}
	return c.Mitigation.Mode
}

// MitigationAllowlist is the parsed mitigation allowlist. Invalid entries
// are left out; Validate reports them.
func (m *Mitigation) MitigationAllowlist() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range m.Allowlist {
		if p, err := netip.ParsePrefix(s); err == nil && p == p.Masked() {
			out = append(out, p)
		}
	}
	return out
}

func (c *Config) normalizeMitigation() {
	m := c.Mitigation
	if m == nil {
		return
	}
	if strings.TrimSpace(m.Mode) == "" {
		m.Mode = ModeObserve
	}
	if m.MaxRules == 0 {
		m.MaxRules = DefaultMitigationMaxRules
	}
	if m.MaxTTL == 0 {
		m.MaxTTL = DefaultMitigationMaxTTL
	}
	if m.DefaultTTL == 0 {
		m.DefaultTTL = min(DefaultMitigationTTL, m.MaxTTL)
	}
	if m.LocalPref == 0 {
		m.LocalPref = c.LocalPref
	}
}

func (c *Config) validateMitigation(add func(string, ...any)) {
	m := c.Mitigation
	if m == nil {
		return
	}
	switch m.Mode {
	case ModeObserve:
	case ModeInject:
		if c.Mode != ModeInject {
			add("mitigation.mode inject requires mode inject")
		}
		if m.Announcer == nil {
			add("mitigation.mode inject requires mitigation.announcer")
		}
		if m.LocalPref == 0 {
			add("mitigation.mode inject requires mitigation.local_pref or local_pref")
		}
	default:
		add("mitigation.mode %q is invalid (want %s or %s)", m.Mode, ModeObserve, ModeInject)
	}
	if m.Announcer != nil && m.Announcer.Type == "" {
		add("mitigation.announcer: type is required")
	}
	if len(m.Allowlist) == 0 {
		add("mitigation.allowlist: at least one prefix is required")
	}
	seen := map[netip.Prefix]bool{}
	for i, s := range m.Allowlist {
		p, err := netip.ParsePrefix(s)
		switch {
		case err != nil:
			add("mitigation.allowlist[%d]: %q is not a valid CIDR", i, s)
		case p != p.Masked():
			add("mitigation.allowlist[%d]: %q has host bits set (did you mean %s?)", i, s, p.Masked())
		case p.Bits() == 0:
			add("mitigation.allowlist[%d]: %s would allow every prefix", i, p)
		case seen[p]:
			add("mitigation.allowlist[%d]: duplicate prefix %s", i, p)
		default:
			seen[p] = true
		}
	}
	if m.MaxRules < 1 || m.MaxRules > MaxMitigationMaxRules {
		add("mitigation.max_rules %d must be between 1 and %d", m.MaxRules, MaxMitigationMaxRules)
	}
	if m.MaxTTL < MinMitigationTTL || m.MaxTTL > MaxMitigationMaxTTL {
		add("mitigation.max_ttl %s must be between %s and %s", m.MaxTTL, MinMitigationTTL, MaxMitigationMaxTTL)
	}
	if m.GeoIPDB != "" && !strings.HasPrefix(m.GeoIPDB, "/") {
		add("mitigation.geoip_db %q must be an absolute path (mount the file into the container)", m.GeoIPDB)
	}
	if m.DefaultTTL < MinMitigationTTL || m.DefaultTTL > m.MaxTTL {
		add("mitigation.default_ttl %s must be between %s and max_ttl (%s)", m.DefaultTTL, MinMitigationTTL, m.MaxTTL)
	}
}
