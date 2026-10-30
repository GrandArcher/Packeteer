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

func TestRegistryRejects(t *testing.T) {
	for name, tc := range map[string]struct{ yaml, want string }{
		"no asns":        {"registry:\n  enabled: true\n", "registry.asns: at least one"},
		"zero asn":       {"registry:\n  enabled: true\n  asns: [0]\n", "0 is not an AS number"},
		"bad as-set":     {"registry:\n  enabled: true\n  asns: [64496]\n  as_set: nope\n", "not an as-set name"},
		"short interval": {"registry:\n  enabled: true\n  asns: [64496]\n  interval: 1m\n", "registry.interval"},
		"headroom":       {"registry:\n  enabled: true\n  asns: [64496]\n  headroom_percent: 5000\n", "registry.headroom_percent"},
		"bad mnt":        {"registry:\n  enabled: true\n  asns: [64496]\n  irr: {mnt_by: 'a b'}\n", "not a maintainer name"},
		"no type":        {"registry:\n  enabled: true\n  asns: [64496]\n  sources: [{name: x}]\n", "registry.sources[0]: type is required"},
		"push no source": {"registry:\n  enabled: true\n  asns: [64496]\n  push_enabled: true\n", "needs at least one registry.sources"},
		"push no mnt":    {"registry:\n  enabled: true\n  asns: [64496]\n  push_enabled: true\n  sources: [{type: ripe}]\n", "registry.irr.mnt_by is required"},
		"off but set":    {"registry:\n  asns: [64496]\n", "registry.enabled is false"},
		"ixp":            {"ixp: {}\nregistry:\n  enabled: true\n  asns: [64496]\n", "registry cannot be combined with ixp"},
		"unknown key":    {"registry:\n  enabled: true\n  asns: [64496]\n  write: true\n", "write"},
	} {
		_, err := Parse([]byte(minimalYAML + tc.yaml))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}
