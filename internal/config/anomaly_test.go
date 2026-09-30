package config

import (
	"strings"
	"testing"
	"time"
)

const anomalySources = `
sources:
  - type: flow
    config: {listen: "0.0.0.0:2055"}
`

const anomalyDetect = `
anomaly:
  detector:
    type: baseline
`

func TestAnomalyDefaults(t *testing.T) {
	cfg, err := Parse([]byte(validYAML + anomalySources + anomalyDetect))
	if err != nil {
		t.Fatal(err)
	}
	a := cfg.Anomaly
	if a.Interval != DefaultAnomalyInterval || a.MaxActionsPerHour != DefaultAnomalyMaxActionsPerHour || a.MaxActive != DefaultAnomalyMaxActive || len(a.Rules) != 0 {
		t.Fatalf("defaults = %+v", a)
	}
	// With mitigation, max_active defaults to at most max_rules and a
	// rule's TTL to default_ttl.
	cfg, err = Parse([]byte(validYAML + anomalySources + mitigationBlock + "  max_rules: 2\n  default_ttl: 20m\n" + anomalyDetect + `  rules:
    - name: udp
      prefixes: [203.0.113.0/25]
      protocols: [udp, 6]
      action: flowspec_drop
`))
	if err != nil {
		t.Fatal(err)
	}
	a = cfg.Anomaly
	if a.MaxActive != 2 || a.Rules[0].TTL != 20*time.Minute || len(a.Rules[0].Protocols) != 2 || a.Rules[0].Protocols[0] != 17 || a.Rules[0].Protocols[1] != 6 {
		t.Fatalf("anomaly = %+v", a)
	}
	if got := a.Rules[0].RulePrefixes(); len(got) != 1 || got[0].String() != "203.0.113.0/25" {
		t.Fatalf("rule prefixes = %v", got)
	}
}

func TestAnomalyErrors(t *testing.T) {
	rule := func(body string) string {
		return validYAML + anomalySources + mitigationBlock + anomalyDetect + "  rules:\n    - name: r\n" + body
	}
	cases := map[string]string{
		"no detector":         validYAML + anomalySources + "anomaly:\n  interval: 10s\n",
		"unknown source":      validYAML + anomalySources + anomalyDetect + "  source: nope\n",
		"interval":            validYAML + anomalySources + anomalyDetect + "  interval: 100ms\n",
		"max_actions":         validYAML + anomalySources + anomalyDetect + "  max_actions_per_hour: 5000\n",
		"max_active over cap": validYAML + anomalySources + mitigationBlock + "  max_rules: 2\n" + anomalyDetect + "  max_active: 3\n",
		"rules need mitigation": validYAML + anomalySources + anomalyDetect +
			"  rules:\n    - name: r\n      prefixes: [203.0.113.0/24]\n      action: blackhole\n",
		"outside allowlist":  rule("      prefixes: [198.51.100.0/24]\n      action: blackhole\n"),
		"host bits":          rule("      prefixes: [203.0.113.1/24]\n      action: blackhole\n"),
		"default route":      rule("      prefixes: [0.0.0.0/0]\n      action: blackhole\n"),
		"no prefixes":        rule("      action: blackhole\n"),
		"bad action":         rule("      prefixes: [203.0.113.0/24]\n      action: nuke\n"),
		"redirect no target": rule("      prefixes: [203.0.113.0/24]\n      action: redirect\n"),
		"rate limit no rate": rule("      prefixes: [203.0.113.0/24]\n      action: flowspec_rate_limit\n"),
		"drop with target":   rule("      prefixes: [203.0.113.0/24]\n      action: flowspec_drop\n      target: x\n"),
		"ttl over max":       rule("      prefixes: [203.0.113.0/24]\n      action: blackhole\n      ttl: 48h\n"),
		"bad protocol":       rule("      prefixes: [203.0.113.0/24]\n      action: blackhole\n      protocols: [bogus]\n"),
		"negative min_mbps":  rule("      prefixes: [203.0.113.0/24]\n      action: blackhole\n      min_mbps: -1\n"),
		"duplicate name": rule("      prefixes: [203.0.113.0/24]\n      action: blackhole\n" +
			"    - name: r\n      prefixes: [203.0.113.0/24]\n      action: blackhole\n"),
	}
	for name, y := range cases {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if name == "outside allowlist" && !strings.Contains(err.Error(), "mitigation.allowlist") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
