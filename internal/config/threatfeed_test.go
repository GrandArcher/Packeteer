package config

import (
	"strings"
	"testing"
	"time"
)

const threatFeedBlock = `
threat_feeds:
  feeds:
    - name: drop
      type: http
      config: {url: "https://feeds.example.net/drop.txt"}
  rules:
    - name: r
      feed: drop
`

func TestThreatFeedDefaults(t *testing.T) {
	cfg, err := Parse([]byte(validYAML + mitigationBlock + "  max_rules: 2\n  default_ttl: 20m\n" + threatFeedBlock +
		"      prefixes: [203.0.113.0/25]\n      action: BLACKHOLE\n"))
	if err != nil {
		t.Fatal(err)
	}
	tf := cfg.ThreatFeeds
	if tf.Interval != DefaultThreatFeedInterval || tf.MaxActionsPerHour != DefaultThreatFeedMaxActionsPerHour || tf.MaxActive != 2 {
		t.Fatalf("defaults = %+v", tf)
	}
	r := tf.Rules[0]
	if r.Match != ThreatMatchDestination || r.Action != "blackhole" || r.TTL != 20*time.Minute {
		t.Fatalf("rule = %+v", r)
	}
	if got := r.RulePrefixes(); len(got) != 1 || got[0].String() != "203.0.113.0/25" {
		t.Fatalf("rule prefixes = %v", got)
	}
	if cfg.MitigationMode() != ModeObserve {
		t.Fatalf("mitigation mode = %s", cfg.MitigationMode())
	}
}

func TestThreatFeedErrors(t *testing.T) {
	base := validYAML + mitigationBlock + threatFeedBlock
	ok := "      prefixes: [203.0.113.0/24]\n      action: flowspec_drop\n"
	feeds := func(list string) string {
		return validYAML + mitigationBlock + "threat_feeds:\n  rules:\n    - {name: r, feed: drop, prefixes: [203.0.113.0/24], action: blackhole}\n  feeds:\n" + list
	}
	cases := map[string]struct{ yaml, want string }{
		"no mitigation":    {validYAML + threatFeedBlock + ok, "threat_feeds act only through threat mitigation"},
		"interval":         {base + ok + "  interval: 10s\n", "threat_feeds.interval 10s"},
		"max_actions":      {base + ok + "  max_actions_per_hour: 5000\n", "max_actions_per_hour 5000"},
		"max_active":       {base + ok + "  max_active: 11\n", "max_active 11 must be between 1 and mitigation.max_rules (10)"},
		"no rules":         {validYAML + mitigationBlock + "threat_feeds:\n  feeds: [{type: http}]\n", "between 1 and 100 rules"},
		"unknown feed":     {base + ok + "    - {name: r2, feed: nope, prefixes: [203.0.113.0/24], action: blackhole}\n", `feed "nope" is not a configured feed name`},
		"duplicate rule":   {base + ok + "    - {name: r, feed: drop, prefixes: [203.0.113.0/24], action: blackhole}\n", "duplicate name"},
		"bad match":        {base + ok + "      match: both\n", `match "both" is invalid`},
		"source unicast":   {base + "      match: source\n      prefixes: [203.0.113.0/24]\n      action: blackhole\n", "match source needs a flowspec action"},
		"outside allow":    {base + "      prefixes: [198.51.100.0/24]\n      action: blackhole\n", "198.51.100.0/24 is not inside mitigation.allowlist"},
		"no prefixes":      {base + "      action: blackhole\n", "at least one prefix"},
		"redirect target":  {base + "      prefixes: [203.0.113.0/24]\n      action: redirect\n", "redirect needs a target"},
		"bad action":       {base + "      prefixes: [203.0.113.0/24]\n      action: drop\n", `action "drop" is invalid`},
		"ttl over max":     {base + ok + "      ttl: 48h\n", "ttl 48h0m0s must be between"},
		"duplicate feed":   {feeds("    - {name: drop, type: http}\n    - {name: drop, type: http}\n"), `duplicate name "drop"`},
		"feed type needed": {feeds("    - {name: drop}\n"), "type is required"},
		"unused feed":      {feeds("    - {name: drop, type: http}\n    - {name: spare, type: http}\n"), "threat_feeds.feeds[1] (spare): no rule reads this feed"},
	}
	for name, c := range cases {
		_, err := Parse([]byte(c.yaml))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}
