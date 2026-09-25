package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// validYAML uses documentation addresses (RFC 5737 / RFC 3849) and a
// private-use ASN only.
const validYAML = `
mode: observe
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
max_improvements: 50
hold_time: 15m
thresholds:
  min_loss_delta_pct: 1.0
  min_rtt_delta_ms: 15
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
  - name: transit-b
    source_ip: 2001:db8::11
    next_hop: 2001:db8::1
allowlist:
  prefixes: []
probe:
  interval: 30s
  timeout: 2s
  packets: 10
`

// minimalYAML omits every field that has a default.
const minimalYAML = `
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
`

const injectYAML = `
bgp:
  neighbors:
    - address: 192.0.2.1
mode: inject
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 200
hold_time: 15m
thresholds:
  min_loss_delta_pct: 1.0
  min_rtt_delta_ms: 15
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
allowlist:
  prefixes:
    - 198.51.100.0/24
    - 2001:db8:100::/48
announcer:
  type: gobgp
`

// edit returns base with the first occurrence of old replaced by new,
// failing the test if old is absent.
func edit(t *testing.T, base, old, new string) string {
	t.Helper()
	if !strings.Contains(base, old) {
		t.Fatalf("test bug: %q not found in base config", old)
	}
	return strings.Replace(base, old, new, 1)
}

func TestParseValid(t *testing.T) {
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Mode != ModeObserve {
		t.Errorf("Mode = %q, want %q", cfg.Mode, ModeObserve)
	}
	if cfg.ASN != 64512 {
		t.Errorf("ASN = %d, want 64512", cfg.ASN)
	}
	if cfg.HoldTime != 15*time.Minute {
		t.Errorf("HoldTime = %s, want 15m", cfg.HoldTime)
	}
	if len(cfg.Providers) != 2 || cfg.Providers[1].Name != "transit-b" {
		t.Errorf("Providers = %+v", cfg.Providers)
	}
	if cfg.Thresholds.MinRTTDeltaMs != 15 {
		t.Errorf("MinRTTDeltaMs = %v, want 15", cfg.Thresholds.MinRTTDeltaMs)
	}
}

func TestParseInjectValid(t *testing.T) {
	cfg, err := Parse([]byte(injectYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Mode != ModeInject || len(cfg.Allowlist.Prefixes) != 2 {
		t.Errorf("got mode %q allowlist %v", cfg.Mode, cfg.Allowlist.Prefixes)
	}
	if cfg.LocalPref != 200 || cfg.Announcer == nil || cfg.Announcer.Type != "gobgp" {
		t.Errorf("local_pref=%d announcer=%v", cfg.LocalPref, cfg.Announcer)
	}
}

func TestDefaults(t *testing.T) {
	cfg, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.MaxImprovements == nil || *cfg.MaxImprovements != DefaultMaxImprovements {
		t.Errorf("MaxImprovements = %v, want %d", cfg.MaxImprovements, DefaultMaxImprovements)
	}
	if cfg.Probe.Interval != DefaultProbeInterval {
		t.Errorf("Probe.Interval = %s, want %s", cfg.Probe.Interval, DefaultProbeInterval)
	}
	if cfg.Probe.Timeout != DefaultProbeTimeout {
		t.Errorf("Probe.Timeout = %s, want %s", cfg.Probe.Timeout, DefaultProbeTimeout)
	}
	if cfg.Probe.Packets != DefaultProbePackets {
		t.Errorf("Probe.Packets = %d, want %d", cfg.Probe.Packets, DefaultProbePackets)
	}
	if cfg.Probe.Workers != DefaultProbeWorkers || cfg.Probe.RateLimitPPS != DefaultProbeRateLimitPPS ||
		cfg.Probe.PerTargetConcurrency != DefaultProbePerTargetConcurrency {
		t.Errorf("probe defaults = %+v", cfg.Probe)
	}
	if cfg.Scorer == nil || cfg.Scorer.Type != "weighted" || cfg.ImprovementTTL != DefaultImprovementTTL {
		t.Errorf("scorer/ttl defaults = %+v %s", cfg.Scorer, cfg.ImprovementTTL)
	}
	if len(cfg.Probers) != 2 || cfg.Probers[0].Type != "icmp" || cfg.Probers[1].Type != "tcp" {
		t.Errorf("default probers = %+v", cfg.Probers)
	}
}

func TestLoadExampleConfig(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatalf("Load example: %v", err)
	}
	// The public example must never enable injection (docs/THREAT_MODEL.md).
	if cfg.Mode != ModeObserve {
		t.Fatalf("config.example.yaml mode = %q, must be %q", cfg.Mode, ModeObserve)
	}
	if len(cfg.Providers) == 0 {
		t.Fatal("config.example.yaml has no providers")
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil || !strings.Contains(err.Error(), "read") {
		t.Fatalf("err = %v, want read error", err)
	}
}

func TestLoadFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(minimalYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{"empty file", "", "config is empty"},
		{"invalid yaml", "mode: [observe\n", "parse yaml"},
		{"wrong type", edit(t, minimalYAML, "asn: 64512", "asn: sixty"), "parse yaml"},
		{"unknown field", minimalYAML + "bogus: true\n", "field bogus not found"},
		{"unknown nested field", edit(t, validYAML, "packets: 10", "packets: 10\n  jitter: 1"), "field jitter not found"},
		{"multiple documents", minimalYAML + "---\nmode: observe\n", "single YAML document"},
		{"missing mode", edit(t, minimalYAML, "mode: observe\n", ""), "mode is required"},
		{"empty mode", edit(t, minimalYAML, "mode: observe", `mode: ""`), "mode is required"},
		{"invalid mode", edit(t, minimalYAML, "mode: observe", "mode: yolo"), `mode "yolo" is invalid`},
		{"missing asn", edit(t, minimalYAML, "asn: 64512\n", ""), "asn is required"},
		{"missing router_id", edit(t, minimalYAML, "router_id: 192.0.2.10\n", ""), "router_id is required"},
		{"bad router_id", edit(t, minimalYAML, "router_id: 192.0.2.10", "router_id: 2001:db8::10"), "must be an IPv4 address"},
		{"bad community", edit(t, validYAML, `"64512:666"`, `"64512-666"`), "asn:value"},
		{"community out of range", edit(t, validYAML, `"64512:666"`, `"64512:70000"`), "0-65535"},
		{"max_improvements zero", edit(t, validYAML, "max_improvements: 50", "max_improvements: 0"), "max_improvements 0 must be between 1"},
		{"max_improvements negative", edit(t, validYAML, "max_improvements: 50", "max_improvements: -1"), "max_improvements -1 must be between 1"},
		{"max_improvements too large", edit(t, validYAML, "max_improvements: 50", "max_improvements: 10001"), "must be between 1 and 10000"},
		{"negative hold_time", edit(t, validYAML, "hold_time: 15m", "hold_time: -1m"), "hold_time -1m0s must not be negative"},
		{"loss threshold too high", edit(t, validYAML, "min_loss_delta_pct: 1.0", "min_loss_delta_pct: 101"), "min_loss_delta_pct 101 must be between 0 and 100"},
		{"negative rtt threshold", edit(t, validYAML, "min_rtt_delta_ms: 15", "min_rtt_delta_ms: -5"), "min_rtt_delta_ms -5 must not be negative"},
		{"no providers", edit(t, minimalYAML, "providers:\n  - name: transit-a\n    source_ip: 192.0.2.11\n    next_hop: 192.0.2.1\n", "providers: []\n"), "at least one provider"},
		{"provider missing name", edit(t, minimalYAML, "name: transit-a", `name: ""`), "providers[0]: name is required"},
		{"duplicate provider name", edit(t, validYAML, "name: transit-b", "name: transit-a"), "duplicate provider name"},
		{"duplicate source_ip", edit(t, injectYAML, "allowlist:", "  - name: transit-b\n    source_ip: 192.0.2.11\n    next_hop: 192.0.2.2\nallowlist:"), "duplicate source_ip 192.0.2.11"},
		{"bad source_ip", edit(t, minimalYAML, "source_ip: 192.0.2.11", "source_ip: 192.0.2.300"), `source_ip "192.0.2.300" is not a valid IP`},
		{"bad next_hop", edit(t, minimalYAML, "next_hop: 192.0.2.1", "next_hop: gateway"), `next_hop "gateway" is not a valid IP`},
		{"mixed address family", edit(t, minimalYAML, "next_hop: 192.0.2.1", "next_hop: 2001:db8::1"), "same address family"},
		{"bad allowlist cidr", edit(t, injectYAML, "198.51.100.0/24", "198.51.100.0/33"), "is not a valid CIDR"},
		{"allowlist not a cidr", edit(t, injectYAML, "198.51.100.0/24", "198.51.100.0"), "is not a valid CIDR"},
		{"allowlist host bits", edit(t, injectYAML, "198.51.100.0/24", "198.51.100.7/24"), "did you mean 198.51.100.0/24"},
		{"allowlist duplicate", edit(t, injectYAML, "2001:db8:100::/48", "198.51.100.0/24"), "duplicate prefix"},
		{"negative probe interval", edit(t, validYAML, "interval: 30s", "interval: -30s"), "probe.interval -30s must be positive"},
		{"negative probe timeout", edit(t, validYAML, "timeout: 2s", "timeout: -2s"), "probe.timeout -2s must be positive"},
		{"timeout not shorter than interval", edit(t, validYAML, "timeout: 2s", "timeout: 30s"), "must be shorter than probe.interval"},
		{"negative packets", edit(t, validYAML, "packets: 10", "packets: -1"), "probe.packets -1 must be between 1"},
		{"too many packets", edit(t, validYAML, "packets: 10", "packets: 1001"), "must be between 1 and 1000"},
		{"negative workers", edit(t, validYAML, "packets: 10", "packets: 10\n  workers: -1"), "probe.workers -1 must be between 1"},
		{"too many workers", edit(t, validYAML, "packets: 10", "packets: 10\n  workers: 5000"), "probe.workers 5000"},
		{"negative pps", edit(t, validYAML, "packets: 10", "packets: 10\n  rate_limit_pps: -5"), "probe.rate_limit_pps -5"},
		{"too high pps", edit(t, validYAML, "packets: 10", "packets: 10\n  rate_limit_pps: 200000"), "probe.rate_limit_pps 200000"},
		{"bad per-target", edit(t, validYAML, "packets: 10", "packets: 10\n  per_target_concurrency: 65"), "probe.per_target_concurrency 65"},
		{"bgp bad listen port", minimalYAML + "bgp: {listen_port: 70000}\n", "bgp.listen_port 70000"},
		{"bgp bad listen address", minimalYAML + "bgp: {listen_addresses: [nope]}\n", `bgp.listen_addresses[0]: "nope"`},
		{"bgp bad neighbor", minimalYAML + "bgp:\n  neighbors:\n    - address: router1\n", `bgp.neighbors[0]: address "router1"`},
		{"bgp duplicate neighbor", minimalYAML + "bgp:\n  neighbors:\n    - address: 192.0.2.1\n    - address: 192.0.2.1\n", "duplicate neighbor 192.0.2.1"},
		{"bgp bad port", minimalYAML + "bgp:\n  neighbors:\n    - {address: 192.0.2.1, port: -1}\n", "port -1 must be between"},
		{"bgp bad local address", minimalYAML + "bgp:\n  neighbors:\n    - {address: 192.0.2.1, local_address: x}\n", `local_address "x"`},
		{"bgp passive without listen", minimalYAML + "bgp:\n  neighbors:\n    - {address: 192.0.2.1, passive: true}\n", "passive requires bgp.listen_port"},
		{"bgp graceful restart is not a thing", minimalYAML + "bgp:\n  graceful_restart: true\n", "field graceful_restart not found"},
		{"inject without bgp", edit(t, injectYAML, "bgp:\n  neighbors:\n    - address: 192.0.2.1\n", ""), "mode inject requires at least one bgp.neighbors"},
		{"inject without allowlist", edit(t, injectYAML, "prefixes:\n    - 198.51.100.0/24\n    - 2001:db8:100::/48\n", "prefixes: []\n"), "mode inject requires a non-empty allowlist"},
		{"inject without community", edit(t, injectYAML, "packeteer_community: \"64512:666\"\n", ""), "mode inject requires packeteer_community"},
		{"inject without local_pref", edit(t, injectYAML, "local_pref: 200\n", ""), "mode inject requires local_pref"},
		{"inject without announcer", edit(t, injectYAML, "announcer:\n  type: gobgp\n", ""), "mode inject requires an announcer"},
		{"more_specific_bits too high", minimalYAML + "more_specific_bits: 9\n", "more_specific_bits 9 must be between 0 and 8"},
		{"inject without hold_time", edit(t, injectYAML, "hold_time: 15m\n", ""), "mode inject requires a positive hold_time"},
		{"inject without thresholds", edit(t, injectYAML, "min_rtt_delta_ms: 15", "min_rtt_delta_ms: 0"), "mode inject requires positive thresholds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatalf("Parse succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateReportsAllErrors(t *testing.T) {
	y := edit(t, minimalYAML, "mode: observe", "mode: yolo")
	y = edit(t, y, "router_id: 192.0.2.10", "router_id: nope")
	_, err := Parse([]byte(y))
	if err == nil {
		t.Fatal("want error")
	}
	for _, want := range []string{"mode", "router_id"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
}

func TestPluginSpecs(t *testing.T) {
	good := minimalYAML + `
probers:
  - type: icmp
  - type: exec
    name: custom
    config:
      command: my-prober
sources:
  - type: static
announcer:
  type: gobgp
`
	cfg, err := Parse([]byte(good))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Scorer == nil || cfg.Scorer.Type != "weighted" || cfg.ImprovementTTL != DefaultImprovementTTL {
		t.Errorf("scorer/ttl defaults = %+v %s", cfg.Scorer, cfg.ImprovementTTL)
	}
	if len(cfg.Probers) != 2 || cfg.Probers[1].InstanceName() != "custom" || cfg.Probers[0].InstanceName() != "icmp" {
		t.Errorf("Probers = %+v", cfg.Probers)
	}
	if cfg.Probers[1].Config.Kind == 0 {
		t.Error("plugin config node not captured")
	}
	if cfg.PluginDir != DefaultPluginDir {
		t.Errorf("PluginDir = %q", cfg.PluginDir)
	}

	tests := []struct{ name, yaml, wantErr string }{
		{"missing type", minimalYAML + "probers:\n  - name: x\n", "probers[0]: type is required"},
		{"duplicate instance", minimalYAML + "notifiers:\n  - type: webhook\n  - type: webhook\n", `notifiers[1]: duplicate instance name "webhook"`},
		{"unknown spec field", minimalYAML + "sources:\n  - type: static\n    prefixes: []\n", "field prefixes not found"},
		{"scorer missing type", minimalYAML + "scorer: {name: x}\n", "scorer: type is required"},
		{"announcer missing type", minimalYAML + "announcer: {name: x}\n", "announcer: type is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
