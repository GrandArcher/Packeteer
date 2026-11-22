package config

import (
	"flag"
	"os"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden files")

const offloadRouter = `
    - neighbor: 192.0.2.1
      capacity: 1000
`

// offloadYAML is injectYAML (neighbor 192.0.2.1) with an offload_aware block.
func offloadYAML(head string) string {
	return injectYAML + "offload_aware:\n" + head + "  routers:" + offloadRouter
}

func TestOffloadAwareOffByDefault(t *testing.T) {
	for _, text := range []string{validYAML, minimalYAML, injectYAML, injectYAML + "offload_aware: {enabled: false}\n"} {
		cfg, err := Parse([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.OffloadEnforcing() {
			t.Fatalf("offload_aware enforcing without being enabled: %+v", cfg.OffloadAware)
		}
	}
	cfg, err := Parse([]byte(injectYAML + "offload_aware: {enabled: false, run: enforce}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OffloadEnforcing() {
		t.Fatal("a disabled block enforces")
	}
}

// The key is omitted from a marshaled config while the block is absent, so
// a config without it serializes as it did before the block existed.
func TestOffloadAwareAbsentLeavesOutputUnchanged(t *testing.T) {
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OffloadAware != nil {
		t.Fatalf("absent block parsed as %+v", cfg.OffloadAware)
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "offload") {
		t.Fatalf("marshaled config mentions offload_aware:\n%s", out)
	}
}

func TestOffloadAwareDefaults(t *testing.T) {
	cfg, err := Parse([]byte(offloadYAML("  enabled: true\n")))
	if err != nil {
		t.Fatal(err)
	}
	o := cfg.OffloadAware
	if o.Run != OffloadRunDryRun || o.Recheck != 5*time.Minute || cfg.OffloadEnforcing() {
		t.Fatalf("block defaults = %+v", o)
	}
	r := o.Routers[0]
	if r.Profile != "generic" || r.Reader != "static" || r.ReservePct != 10 || r.IPv6Offload || r.OffloadCommunity != "" || r.Capacity != 1000 {
		t.Fatalf("router defaults = %+v", r)
	}
	if cfg.Mode != ModeInject {
		t.Fatalf("mode = %s", cfg.Mode)
	}
}

func TestOffloadAwareEnforceNeedsInjectAndProfile(t *testing.T) {
	mikrotik := strings.Replace(offloadYAML("  enabled: true\n  run: enforce\n"), "capacity: 1000", "capacity: 1000\n      profile: mikrotik", 1)
	cfg, err := Parse([]byte(mikrotik))
	if err != nil {
		t.Fatalf("enforce on a mikrotik profile with mode inject: %v", err)
	}
	if !cfg.OffloadEnforcing() || cfg.Mode != ModeInject {
		t.Fatalf("enforcing = %v mode = %s", cfg.OffloadEnforcing(), cfg.Mode)
	}
	// A profile never changes mode: the same file in observe is refused.
	observe := strings.Replace(mikrotik, "mode: inject", "mode: observe", 1)
	observe = strings.Replace(observe, "announcer:\n  type: gobgp\n", "", 1)
	if _, err := Parse([]byte(observe)); err == nil || !strings.Contains(err.Error(), "enforce requires mode: inject") {
		t.Fatalf("enforce in observe: %v", err)
	}
	// run above the profile's highest level.
	if _, err := Parse([]byte(offloadYAML("  enabled: true\n  run: enforce\n"))); err == nil ||
		!strings.Contains(err.Error(), `offload_aware.routers[0]: run enforce is above the highest run level (dry_run) of profile "generic"`) {
		t.Fatalf("enforce on generic: %v", err)
	}
}

func TestOffloadAwareRefusesIXP(t *testing.T) {
	for _, extra := range []string{"offload_aware: {enabled: true, routers: [{neighbor: 192.0.2.1, capacity: 1000}]}\n", "offload_aware: {enabled: false}\n"} {
		_, err := Parse([]byte(minimalYAML + "ixp: {}\nbgp:\n  neighbors:\n    - address: 192.0.2.1\n" + extra))
		if err == nil || !strings.Contains(err.Error(), "offload_aware cannot be combined with ixp") {
			t.Fatalf("%q with ixp: %v", extra, err)
		}
	}
}

func TestOffloadAwareValidation(t *testing.T) {
	cases := []struct {
		name, yaml, want string
	}{
		{"bad run", offloadYAML("  enabled: true\n  run: live\n"), `offload_aware.run "live"`},
		{"recheck too short", offloadYAML("  enabled: true\n  recheck: 1s\n"), "offload_aware.recheck 1s must be between 10s and 1h0m0s"},
		{"recheck too long", offloadYAML("  enabled: true\n  recheck: 48h\n"), "offload_aware.recheck 48h0m0s"},
		{"recheck negative", offloadYAML("  enabled: true\n  recheck: -1m\n"), "offload_aware.recheck -1m0s"},
		{"no routers", injectYAML + "offload_aware: {enabled: true}\n", "at least one router"},
		{"bad neighbor", strings.Replace(offloadYAML("  enabled: true\n"), "neighbor: 192.0.2.1", "neighbor: edge1", 1), `"edge1" is not an IP address`},
		{"unknown neighbor", strings.Replace(offloadYAML("  enabled: true\n"), "neighbor: 192.0.2.1", "neighbor: 192.0.2.9", 1), "192.0.2.9 is not a bgp.neighbors address"},
		{"duplicate neighbor", offloadYAML("  enabled: true\n") + offloadRouter, "192.0.2.1 is listed twice"},
		{"unknown profile", offloadYAML("  enabled: true\n") + "      profile: nope\n", `unknown profile "nope"`},
		{"unknown reader", offloadYAML("  enabled: true\n") + "      reader: ssh\n", `unknown reader "ssh"`},
		{"zero capacity", strings.Replace(offloadYAML("  enabled: true\n"), "capacity: 1000", "capacity: 0", 1), "capacity 0 must be between"},
		{"huge capacity", strings.Replace(offloadYAML("  enabled: true\n"), "capacity: 1000", "capacity: 1000000000", 1), "capacity 1000000000 must be between"},
		{"reserve negative", offloadYAML("  enabled: true\n") + "      reserve_pct: -5\n", "reserve_pct -5 must be between 1 and 50"},
		{"reserve too big", offloadYAML("  enabled: true\n") + "      reserve_pct: 51\n", "reserve_pct 51 must be between 1 and 50"},
		{"bad community", offloadYAML("  enabled: true\n") + "      offload_community: nope\n", "offload_community"},
		{"unknown key", offloadYAML("  enabled: true\n  bogus: 1\n"), "bogus"},
		{"unknown router key", offloadYAML("  enabled: true\n") + "      bogus: 1\n", "bogus"},
	}
	for _, tc := range cases {
		_, err := Parse([]byte(tc.yaml))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
}

// The lab router file parses and its offload_aware block, with defaults
// applied, serializes to the golden text.
func TestOffloadAwareGolden(t *testing.T) {
	cfg, err := Load("testdata/offload_aware_lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeInject || cfg.OffloadEnforcing() {
		t.Fatalf("mode = %s enforcing = %v", cfg.Mode, cfg.OffloadEnforcing())
	}
	out, err := yaml.Marshal(map[string]any{"offload_aware": cfg.OffloadAware})
	if err != nil {
		t.Fatal(err)
	}
	const path = "testdata/offload_aware_lab.golden"
	if *updateGolden {
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/config -run OffloadAwareGolden -update)", err)
	}
	if string(out) != string(want) {
		t.Fatalf("offload_aware differs from %s:\n%s", path, out)
	}
}
