package config

import (
	"net/netip"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Anomaly detection defaults and bounds (#33).
const (
	DefaultAnomalyInterval          = 10 * time.Second
	MinAnomalyInterval              = time.Second
	MaxAnomalyInterval              = 5 * time.Minute
	DefaultAnomalyMaxActionsPerHour = 6
	MaxAnomalyMaxActionsPerHour     = 1000
	DefaultAnomalyMaxActive         = 4
	MaxAnomalyRules                 = 100
	maxAnomalyRuleName              = 64
)

// Anomaly is automatic traffic anomaly (DDoS) detection (#33). A detector
// plugin baselines flow volumes per destination prefix and IP protocol
// from a flow source. Every anomaly is reported (feed, events, history);
// a mitigation rule is added only when an explicit rule below matches it,
// and only through the mitigation controller, which keeps its own
// allowlist, exact learned-prefix check, cap, TTL, and mode. Nil disables
// detection.
type Anomaly struct {
	// Source names the target source that supplies flow counters. Empty
	// uses the only source of type flow.
	Source string `yaml:"source"`
	// Interval is the detection round (default 10s, 1s-5m).
	Interval time.Duration `yaml:"interval"`
	// Detector is the detector plugin. Required.
	Detector *PluginSpec `yaml:"detector"`
	// MaxActionsPerHour caps mitigation rules added by the detector in
	// any rolling hour (default 6).
	MaxActionsPerHour int `yaml:"max_actions_per_hour"`
	// MaxActive caps mitigation rules the detector holds at once
	// (default 4, at most mitigation.max_rules).
	MaxActive int `yaml:"max_active"`
	// Rules turn anomalies into mitigation rules. The first rule that
	// matches an anomaly is used. No rules: detection and alerts only.
	Rules []AnomalyRule `yaml:"rules"`
}

// AnomalyRule is one explicit anomaly-to-mitigation rule.
type AnomalyRule struct {
	Name string `yaml:"name"`
	// Prefixes the anomaly's destination prefix must be inside. Each must
	// be inside mitigation.allowlist. Required.
	Prefixes []string `yaml:"prefixes"`
	// Protocols the anomaly's protocol must be one of. Empty is any.
	Protocols []plugin.IPProtocol `yaml:"protocols"`
	// MinMbps is the smallest anomalous rate the rule acts on.
	MinMbps float64 `yaml:"min_mbps"`
	// Action, Target, and RateMbps are the mitigation request, as on
	// POST /api/mitigations. FlowSpec actions match the anomaly's
	// protocol when it is known.
	Action   string  `yaml:"action"`
	Target   string  `yaml:"target"`
	RateMbps float64 `yaml:"rate_mbps"`
	// TTL is the rule's lifetime (default mitigation.default_ttl). The
	// rule is removed earlier when the anomaly clears.
	TTL time.Duration `yaml:"ttl"`
}

// RulePrefixes is the parsed rule prefixes. Invalid entries are left out;
// Validate reports them.
func (r AnomalyRule) RulePrefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range r.Prefixes {
		if p, err := netip.ParsePrefix(s); err == nil && p == p.Masked() {
			out = append(out, p)
		}
	}
	return out
}

func (c *Config) normalizeAnomaly() {
	a := c.Anomaly
	if a == nil {
		return
	}
	a.Source = strings.TrimSpace(a.Source)
	if a.Interval == 0 {
		a.Interval = DefaultAnomalyInterval
	}
	if a.MaxActionsPerHour == 0 {
		a.MaxActionsPerHour = DefaultAnomalyMaxActionsPerHour
	}
	if a.MaxActive == 0 {
		a.MaxActive = DefaultAnomalyMaxActive
		if m := c.Mitigation; m != nil && m.MaxRules > 0 {
			a.MaxActive = min(a.MaxActive, m.MaxRules)
		}
	}
	for i := range a.Rules {
		r := &a.Rules[i]
		r.Name = strings.TrimSpace(r.Name)
		r.Action = strings.ToLower(strings.TrimSpace(r.Action))
		if r.TTL == 0 && c.Mitigation != nil {
			r.TTL = c.Mitigation.DefaultTTL
		}
	}
}

func (c *Config) validateAnomaly(add func(string, ...any)) {
	a := c.Anomaly
	if a == nil {
		return
	}
	if a.Detector == nil || a.Detector.Type == "" {
		add("anomaly.detector: type is required")
	}
	if a.Source != "" {
		found := false
		for _, s := range c.Sources {
			if s.InstanceName() == a.Source {
				found = true
			}
		}
		if !found {
			add("anomaly.source %q is not a configured source name", a.Source)
		}
	}
	if a.Interval < MinAnomalyInterval || a.Interval > MaxAnomalyInterval {
		add("anomaly.interval %s must be between %s and %s", a.Interval, MinAnomalyInterval, MaxAnomalyInterval)
	}
	if a.MaxActionsPerHour < 1 || a.MaxActionsPerHour > MaxAnomalyMaxActionsPerHour {
		add("anomaly.max_actions_per_hour %d must be between 1 and %d", a.MaxActionsPerHour, MaxAnomalyMaxActionsPerHour)
	}
	m := c.Mitigation
	maxActive := MaxMitigationMaxRules
	if m != nil {
		maxActive = m.MaxRules
	}
	if a.MaxActive < 1 || a.MaxActive > maxActive {
		add("anomaly.max_active %d must be between 1 and mitigation.max_rules (%d)", a.MaxActive, maxActive)
	}
	if len(a.Rules) > 0 && m == nil {
		add("anomaly.rules act only through threat mitigation: configure mitigation (its allowlist, cap, and mode apply)")
	}
	if len(a.Rules) > MaxAnomalyRules {
		add("anomaly.rules: at most %d rules", MaxAnomalyRules)
	}
	var allow []netip.Prefix
	if m != nil {
		allow = m.MitigationAllowlist()
	}
	names := map[string]bool{}
	for i, r := range a.Rules {
		at := func(format string, args ...any) {
			add("anomaly.rules[%d] (%s): "+format, append([]any{i, r.Name}, args...)...)
		}
		switch {
		case r.Name == "":
			at("name is required")
		case len(r.Name) > maxAnomalyRuleName:
			at("name is longer than %d characters", maxAnomalyRuleName)
		case names[r.Name]:
			at("duplicate name")
		}
		names[r.Name] = true
		if len(r.Prefixes) == 0 {
			at("prefixes: at least one prefix is required")
		}
		for j, s := range r.Prefixes {
			p, err := netip.ParsePrefix(s)
			switch {
			case err != nil:
				at("prefixes[%d]: %q is not a valid CIDR", j, s)
			case p != p.Masked():
				at("prefixes[%d]: %q has host bits set (did you mean %s?)", j, s, p.Masked())
			case p.Bits() == 0:
				at("prefixes[%d]: %s would match every prefix", j, p)
			case m != nil && !coveredBy(allow, p):
				at("prefixes[%d]: %s is not inside mitigation.allowlist", j, p)
			}
		}
		if len(r.Protocols) > plugin.MaxFlowSpecProtocols {
			at("at most %d protocols", plugin.MaxFlowSpecProtocols)
		}
		if !(r.MinMbps >= 0 && r.MinMbps <= 1e8) {
			at("min_mbps %v must be between 0 and 100000000", r.MinMbps)
		}
		switch r.Action {
		case plugin.MitigationBlackhole, plugin.MitigationFlowSpecDrop:
			if r.Target != "" || r.RateMbps != 0 {
				at("%s takes no target or rate_mbps", r.Action)
			}
		case plugin.MitigationRedirect, plugin.MitigationFlowSpecRedirect:
			if r.Target == "" {
				at("%s needs a target", r.Action)
			}
			if r.RateMbps != 0 {
				at("%s takes no rate_mbps", r.Action)
			}
		case plugin.MitigationFlowSpecRateLimit:
			if r.Target != "" {
				at("%s takes no target", r.Action)
			}
			if !(r.RateMbps > 0 && r.RateMbps <= plugin.MaxFlowSpecRateMbps) {
				at("rate_mbps %v must be above 0 and at most %d", r.RateMbps, plugin.MaxFlowSpecRateMbps)
			}
		default:
			at("action %q is invalid (want %s, %s, %s, %s, or %s)", r.Action, plugin.MitigationBlackhole, plugin.MitigationRedirect,
				plugin.MitigationFlowSpecDrop, plugin.MitigationFlowSpecRateLimit, plugin.MitigationFlowSpecRedirect)
		}
		if m != nil && (r.TTL < MinMitigationTTL || r.TTL > m.MaxTTL) {
			at("ttl %s must be between %s and mitigation.max_ttl (%s)", r.TTL, MinMitigationTTL, m.MaxTTL)
		}
	}
}
