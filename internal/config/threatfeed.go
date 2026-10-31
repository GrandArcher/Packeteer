package config

import (
	"net/netip"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Threat feed defaults and bounds (#134).
const (
	DefaultThreatFeedInterval          = 15 * time.Minute
	MinThreatFeedInterval              = time.Minute
	MaxThreatFeedInterval              = 24 * time.Hour
	DefaultThreatFeedMaxActive         = 4
	DefaultThreatFeedMaxActionsPerHour = 6
	MaxThreatFeedActionsPerHour        = 1000
	MaxThreatFeeds                     = 16
	MaxThreatFeedRules                 = 100
)

// Threat feed rule matches.
const (
	// ThreatMatchDestination: a listed network is the rule's destination.
	ThreatMatchDestination = "destination"
	// ThreatMatchSource: a listed network is a FlowSpec source match
	// toward each of the rule's prefixes.
	ThreatMatchSource = "source"
)

// ThreatFeeds turns external threat-intelligence lists into mitigation
// rules (#134). Feed plugins fetch the lists; a mitigation rule is added
// only when an explicit rule below names the feed, and only through the
// mitigation controller, which keeps its own allowlist, exact learned
// prefix check, cap, TTL, and mode. Nil disables it.
type ThreatFeeds struct {
	// Interval is how often every feed is fetched (default 15m, 1m-24h).
	Interval time.Duration `yaml:"interval"`
	// MaxActive caps mitigation rules the feeds hold at once (default 4,
	// at most mitigation.max_rules).
	MaxActive int `yaml:"max_active"`
	// MaxActionsPerHour caps mitigation rules added from feeds in any
	// rolling hour (default 6).
	MaxActionsPerHour int `yaml:"max_actions_per_hour"`
	// Feeds are the feed plugins. Each needs a unique name (or type).
	Feeds []PluginSpec `yaml:"feeds"`
	// Rules turn listed networks into mitigation rules. At least one.
	Rules []ThreatFeedRule `yaml:"rules"`
}

// ThreatFeedRule is one explicit feed-to-mitigation rule.
type ThreatFeedRule struct {
	Name string `yaml:"name"`
	// Feed is the name of the feed the rule reads.
	Feed string `yaml:"feed"`
	// Match is destination (default): a listed network inside Prefixes is
	// mitigated itself; or source: a listed network becomes the FlowSpec
	// source of a rule toward each of Prefixes.
	Match string `yaml:"match"`
	// Prefixes each must be inside mitigation.allowlist. Required.
	Prefixes []string `yaml:"prefixes"`
	// Action, Target, and RateMbps are the mitigation request, as on
	// POST /api/mitigations. Match source needs a FlowSpec action.
	Action   string  `yaml:"action"`
	Target   string  `yaml:"target"`
	RateMbps float64 `yaml:"rate_mbps"`
	// TTL is each rule's lifetime (default mitigation.default_ttl).
	TTL time.Duration `yaml:"ttl"`
}

// RulePrefixes is the parsed rule prefixes. Invalid entries are left out;
// Validate reports them.
func (r ThreatFeedRule) RulePrefixes() []netip.Prefix { return parseRulePrefixes(r.Prefixes) }

func (c *Config) normalizeThreatFeeds() {
	t := c.ThreatFeeds
	if t == nil {
		return
	}
	if t.Interval == 0 {
		t.Interval = DefaultThreatFeedInterval
	}
	if t.MaxActionsPerHour == 0 {
		t.MaxActionsPerHour = DefaultThreatFeedMaxActionsPerHour
	}
	if t.MaxActive == 0 {
		t.MaxActive = DefaultThreatFeedMaxActive
		if m := c.Mitigation; m != nil && m.MaxRules > 0 {
			t.MaxActive = min(t.MaxActive, m.MaxRules)
		}
	}
	for i := range t.Rules {
		r := &t.Rules[i]
		r.Name = strings.TrimSpace(r.Name)
		r.Feed = strings.TrimSpace(r.Feed)
		r.Match = strings.ToLower(strings.TrimSpace(r.Match))
		if r.Match == "" {
			r.Match = ThreatMatchDestination
		}
		r.Action = strings.ToLower(strings.TrimSpace(r.Action))
		if r.TTL == 0 && c.Mitigation != nil {
			r.TTL = c.Mitigation.DefaultTTL
		}
	}
}

func (c *Config) validateThreatFeeds(add func(string, ...any)) {
	t := c.ThreatFeeds
	if t == nil {
		return
	}
	m := c.Mitigation
	if m == nil {
		add("threat_feeds act only through threat mitigation: configure mitigation (its allowlist, cap, and mode apply)")
	}
	if t.Interval < MinThreatFeedInterval || t.Interval > MaxThreatFeedInterval {
		add("threat_feeds.interval %s must be between %s and %s", t.Interval, MinThreatFeedInterval, MaxThreatFeedInterval)
	}
	if t.MaxActionsPerHour < 1 || t.MaxActionsPerHour > MaxThreatFeedActionsPerHour {
		add("threat_feeds.max_actions_per_hour %d must be between 1 and %d", t.MaxActionsPerHour, MaxThreatFeedActionsPerHour)
	}
	maxActive := MaxMitigationMaxRules
	if m != nil {
		maxActive = m.MaxRules
	}
	if t.MaxActive < 1 || t.MaxActive > maxActive {
		add("threat_feeds.max_active %d must be between 1 and mitigation.max_rules (%d)", t.MaxActive, maxActive)
	}
	if len(t.Feeds) == 0 || len(t.Feeds) > MaxThreatFeeds {
		add("threat_feeds.feeds: between 1 and %d feeds", MaxThreatFeeds)
	}
	if len(t.Rules) == 0 || len(t.Rules) > MaxThreatFeedRules {
		add("threat_feeds.rules: between 1 and %d rules", MaxThreatFeedRules)
	}
	feeds, used := map[string]bool{}, map[string]bool{}
	for i, f := range t.Feeds {
		switch name := f.InstanceName(); {
		case f.Type == "":
			add("threat_feeds.feeds[%d]: type is required", i)
		case feeds[name]:
			add("threat_feeds.feeds[%d]: duplicate name %q", i, name)
		default:
			feeds[name] = true
		}
	}
	var allow []netip.Prefix
	if m != nil {
		allow = m.MitigationAllowlist()
	}
	names := map[string]bool{}
	for i, r := range t.Rules {
		at := func(format string, args ...any) {
			add("threat_feeds.rules[%d] (%s): "+format, append([]any{i, r.Name}, args...)...)
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
		if !feeds[r.Feed] {
			at("feed %q is not a configured feed name", r.Feed)
		}
		used[r.Feed] = true
		switch r.Match {
		case ThreatMatchDestination:
		case ThreatMatchSource:
			if !plugin.IsFlowSpec(r.Action) {
				at("match source needs a flowspec action, not %q", r.Action)
			}
		default:
			at("match %q is invalid (want %s or %s)", r.Match, ThreatMatchDestination, ThreatMatchSource)
		}
		validateRulePrefixes(at, r.Prefixes, m != nil, allow)
		validateRuleAction(at, r.Action, r.Target, r.RateMbps)
		if m != nil && (r.TTL < MinMitigationTTL || r.TTL > m.MaxTTL) {
			at("ttl %s must be between %s and mitigation.max_ttl (%s)", r.TTL, MinMitigationTTL, m.MaxTTL)
		}
	}
	for i, f := range t.Feeds {
		if name := f.InstanceName(); f.Type != "" && !used[name] {
			add("threat_feeds.feeds[%d] (%s): no rule reads this feed", i, name)
		}
	}
}
