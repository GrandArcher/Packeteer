package config

import (
	"strings"
	"testing"
	"time"
)

const nonBGPYAML = `
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - name: isp-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
  - name: isp-b
    source_ip: 198.51.100.11
    next_hop: 198.51.100.1
sources:
  - type: flow
    config: {listen: "127.0.0.1:2055"}
nonbgp:
  default_provider: isp-a
`

const nonBGPInjectYAML = `
mode: inject
asn: 64512
router_id: 192.0.2.10
hold_time: 15m
packeteer_community: "64512:666"
local_pref: 200
thresholds:
  min_loss_delta_pct: 1.0
  min_rtt_delta_ms: 15
providers:
  - name: isp-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
  - name: isp-b
    source_ip: 198.51.100.11
    next_hop: 198.51.100.1
allowlist:
  prefixes: [203.0.113.0/24]
sources:
  - type: flow
    config: {listen: "127.0.0.1:2055"}
nonbgp:
  install_routes: true
  default_provider: isp-a
  steerer:
    type: mikrotik
`

func TestNonBGPObserveDefaults(t *testing.T) {
	cfg, err := Parse([]byte(nonBGPYAML))
	if err != nil {
		t.Fatal(err)
	}
	n := cfg.NonBGP
	if !(cfg.NonBGP != nil) || cfg.Mode != ModeObserve {
		t.Fatalf("nonbgp on = %v, mode %q", (cfg.NonBGP != nil), cfg.Mode)
	}
	if *n.WidenBits != DefaultNonBGPWidenBits || n.Idle != DefaultNonBGPIdle || n.MaxBlocks != DefaultNonBGPMaxBlocks {
		t.Fatalf("defaults = %d %s %d", *n.WidenBits, n.Idle, n.MaxBlocks)
	}
	if len(cfg.BGP.Neighbors) != 0 {
		t.Fatal("non-BGP mode must not need a BGP neighbor")
	}
}

func TestNonBGPInjectNeedsNoBGPSession(t *testing.T) {
	cfg, err := Parse([]byte(nonBGPInjectYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeInject || !cfg.NonBGP.InstallRoutes || len(cfg.BGP.Neighbors) != 0 || cfg.Announcer != nil {
		t.Fatalf("inject config = %+v", cfg)
	}
	obs, err := Parse([]byte(nonBGPYAML))
	if err != nil || obs.NonBGP.InstallRoutes {
		t.Fatalf("install_routes is not off by default: %v", err)
	}
}

func TestNonBGPInjectRails(t *testing.T) {
	for _, tc := range []struct{ old, new, want string }{
		{"  steerer:\n    type: mikrotik\n", "", "requires nonbgp.steerer"},
		{"  install_routes: true\n", "", "requires nonbgp.install_routes: true"},
		{"  install_routes: true\n", "  install_routes: false\n", "requires nonbgp.install_routes: true"},
		{"allowlist:\n  prefixes: [203.0.113.0/24]\n", "", "non-empty allowlist.prefixes"},
		{"hold_time: 15m", "hold_time: 0s", "positive hold_time"},
		{"min_rtt_delta_ms: 15", "min_rtt_delta_ms: 0", "positive thresholds"},
		{"packeteer_community: \"64512:666\"\n", "", "requires packeteer_community"},
		{"local_pref: 200\n", "", "requires local_pref"},
	} {
		_, err := Parse([]byte(edit(t, nonBGPInjectYAML, tc.old, tc.new)))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q -> %v, want %q", tc.new, err, tc.want)
		}
	}
}

func TestNonBGPRefusals(t *testing.T) {
	for _, tc := range []struct{ name, add, want string }{
		{"neighbors", "bgp:\n  neighbors:\n    - address: 192.0.2.1\n", "nonbgp forbids bgp.neighbors"},
		{"announcer", "announcer:\n  type: gobgp\n", "nonbgp forbids announcer"},
		{"inbound", "inbound: {}\n", "nonbgp forbids inbound"},
		{"mitigation", "mitigation: {}\n", "nonbgp forbids mitigation"},
		{"synthesize", "synthesize: {}\n", "nonbgp forbids synthesize"},
		{"ixp", "ixp: {}\n", "nonbgp forbids ixp"},
	} {
		_, err := Parse([]byte(nonBGPYAML + tc.add))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestNonBGPBlockChecks(t *testing.T) {
	for _, tc := range []struct{ old, new, want string }{
		{"  default_provider: isp-a", "  default_provider: nope", `"nope" is not a configured provider`},
		{"  default_provider: isp-a", "  default_provider: \"\"", "default_provider is required"},
		{"  default_provider: isp-a", "  default_provider: isp-a\n  widen_bits: 9", "widen_bits 9"},
		{"  default_provider: isp-a", "  default_provider: isp-a\n  idle: 1s", "nonbgp.idle"},
		{"  default_provider: isp-a", "  default_provider: isp-a\n  max_blocks: -1", "max_blocks"},
		{"  default_provider: isp-a", "  default_provider: isp-a\n  steerer: {}", "steerer: type is required"},
		{"  default_provider: isp-a", "  default_provider: isp-a\n  covering: {}", "covering: type is required"},
		{"  - type: flow\n    config: {listen: \"127.0.0.1:2055\"}", "  - type: static", "supports only type flow"},
	} {
		_, err := Parse([]byte(edit(t, nonBGPYAML, tc.old, tc.new)))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q -> %v, want %q", tc.new, err, tc.want)
		}
	}
	_, err := Parse([]byte(edit(t, nonBGPYAML, "  - name: isp-b\n    source_ip: 198.51.100.11\n    next_hop: 198.51.100.1\n", "")))
	if err == nil || !strings.Contains(err.Error(), "at least two providers") {
		t.Errorf("one provider: %v", err)
	}
	cfg, err := Parse([]byte(edit(t, nonBGPYAML, "  default_provider: isp-a", "  default_provider: isp-a\n  widen_bits: 0\n  idle: 2h")))
	if err != nil {
		t.Fatal(err)
	}
	if *cfg.NonBGP.WidenBits != 0 || cfg.NonBGP.Idle != 2*time.Hour {
		t.Fatalf("explicit values lost: %d %s", *cfg.NonBGP.WidenBits, cfg.NonBGP.Idle)
	}
}

func TestNonBGPRefusesHAAndFederation(t *testing.T) {
	for name, add := range map[string]string{
		"ha":         "ha:\n  type: lease\n",
		"federation": "federation:\n  type: mtls\n",
	} {
		_, err := Parse([]byte(nonBGPYAML + add))
		if err == nil || !strings.Contains(err.Error(), "nonbgp forbids "+name) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
