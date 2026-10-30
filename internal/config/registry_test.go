package config

import (
	"strings"
	"testing"
	"time"
)

const registryBlock = `
registry:
  enabled: true
  asns: [64496]
  as_set: AS-EXAMPLE
  irr: {source: ripe, mnt_by: EXAMPLE-MNT}
  sources:
    - {type: peeringdb}
    - {type: ripe}
`

// #289: the block parses with its defaults and leaves the mode alone; push
// is off unless set.
func TestRegistryParses(t *testing.T) {
	cfg, err := Parse([]byte(minimalYAML + registryBlock))
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Registry
	if !cfg.RegistryOn() || r.Interval != 24*time.Hour || r.HeadroomPercent != 20 || r.IRR.Source != "RIPE" || r.PushEnabled || len(r.Sources) != 2 {
		t.Fatalf("registry = %+v", r)
	}
	if cfg.Mode != ModeObserve || cfg.Announcer != nil {
		t.Fatalf("mode %s announcer %v", cfg.Mode, cfg.Announcer)
	}
	off, err := Parse([]byte(minimalYAML + "registry:\n  enabled: false\n"))
	if err != nil || off.RegistryOn() {
		t.Fatalf("disabled block = %v %v", off.Registry, err)
	}
}

func TestRegistryTestDatabasePushAccepted(t *testing.T) {
	y := "registry:\n  enabled: true\n  asns: [64496]\n  push_enabled: true\n  irr: {source: test, mnt_by: EXAMPLE-MNT}\n  sources: [{type: ripe, config: {source: TEST}}]\n"
	cfg, err := Parse([]byte(minimalYAML + y))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Registry.PushDatabase(); got != "TEST" {
		t.Fatalf("PushDatabase = %q, want TEST", got)
	}
}

func TestRegistryPushDatabase(t *testing.T) {
	for name, tc := range map[string]struct{ sources, want string }{
		"default ripe": {"[{type: ripe}]", "RIPE"},
		"lower case":   {"[{type: ripe, config: {source: test}}]", "TEST"},
		"no ripe":      {"[{type: peeringdb}]", ""},
		"bad config":   {"[{type: ripe, config: {source: [x]}}]", ""},
		"first ripe":   {"[{type: peeringdb}, {type: ripe, name: a, config: {source: TEST}}, {type: ripe, name: b}]", "TEST"},
	} {
		cfg, err := Parse([]byte(minimalYAML + "registry:\n  enabled: true\n  asns: [64496]\n  sources: " + tc.sources + "\n"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := cfg.Registry.PushDatabase(); got != tc.want {
			t.Errorf("%s: PushDatabase = %q, want %q", name, got, tc.want)
		}
	}
}

func TestRegistryRejects(t *testing.T) {
	for name, tc := range map[string]struct{ yaml, want string }{
		"no asns":         {"registry:\n  enabled: true\n", "registry.asns: at least one"},
		"zero asn":        {"registry:\n  enabled: true\n  asns: [0]\n", "0 is not an AS number"},
		"bad as-set":      {"registry:\n  enabled: true\n  asns: [64496]\n  as_set: nope\n", "not an as-set name"},
		"short interval":  {"registry:\n  enabled: true\n  asns: [64496]\n  interval: 1m\n", "registry.interval"},
		"headroom":        {"registry:\n  enabled: true\n  asns: [64496]\n  headroom_percent: 5000\n", "registry.headroom_percent"},
		"bad mnt":         {"registry:\n  enabled: true\n  asns: [64496]\n  irr: {mnt_by: 'a b'}\n", "not a maintainer name"},
		"no type":         {"registry:\n  enabled: true\n  asns: [64496]\n  sources: [{name: x}]\n", "registry.sources[0]: type is required"},
		"push no source":  {"registry:\n  enabled: true\n  asns: [64496]\n  push_enabled: true\n", "needs at least one registry.sources"},
		"push no mnt":     {"registry:\n  enabled: true\n  asns: [64496]\n  push_enabled: true\n  sources: [{type: ripe}]\n", "registry.irr.mnt_by is required"},
		"ripe db differs": {"registry:\n  enabled: true\n  asns: [64496]\n  push_enabled: true\n  irr: {source: TEST, mnt_by: EXAMPLE-MNT}\n  sources: [{type: ripe}]\n", "writes to RIPE and registry.irr.source is TEST"},
		"off but set":     {"registry:\n  asns: [64496]\n", "registry.enabled is false"},
		"ixp":             {"ixp: {}\nregistry:\n  enabled: true\n  asns: [64496]\n", "registry cannot be combined with ixp"},
		"unknown key":     {"registry:\n  enabled: true\n  asns: [64496]\n  write: true\n", "write"},
	} {
		_, err := Parse([]byte(minimalYAML + tc.yaml))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}
