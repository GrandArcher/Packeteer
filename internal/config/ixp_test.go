package config

import (
	"strings"
	"testing"
	"time"
)

func TestIXPModeObserveWithoutRIB(t *testing.T) {
	cfg, err := Parse([]byte(minimalYAML + "ixp: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IXP == nil {
		t.Fatal("ixp block did not set IXP mode")
	}
	if cfg.Mode != ModeObserve {
		t.Fatalf("mode = %q, want observe", cfg.Mode)
	}
	if len(cfg.BGP.Neighbors) != 0 {
		t.Fatalf("neighbors = %d, IXP mode must not require a RIB session", len(cfg.BGP.Neighbors))
	}
	if cfg.Announcer != nil || cfg.Mitigation != nil || cfg.Inbound != nil || cfg.MoreSpecific != nil {
		t.Fatalf("announce path configured: announcer %v mitigation %v inbound %v more_specific %v",
			cfg.Announcer, cfg.Mitigation, cfg.Inbound, cfg.MoreSpecific)
	}

	// Neighbors are allowed. They are not required, and they are not a route-server feed.
	with := minimalYAML + "ixp: {}\nbgp:\n  neighbors:\n    - address: 192.0.2.1\n"
	cfg, err = Parse([]byte(with))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IXP == nil || len(cfg.BGP.Neighbors) != 1 || cfg.BGP.Neighbors[0].Address != "192.0.2.1" {
		t.Fatalf("ixp with a neighbor: %+v neighbors %v", cfg.IXP, cfg.BGP.Neighbors)
	}
}

func TestIXPModeAbsentUnlessBlockSet(t *testing.T) {
	for _, y := range []string{minimalYAML, minimalYAML + "ixp:\n", minimalYAML + "ixp: null\n"} {
		cfg, err := Parse([]byte(y))
		if err != nil {
			t.Fatalf("parse %q: %v", y, err)
		}
		if cfg.IXP != nil {
			t.Fatalf("yaml %q set IXP mode", y)
		}
	}
	cfg, err := Parse([]byte(injectYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IXP != nil || cfg.Mode != ModeInject || cfg.Announcer == nil {
		t.Fatalf("edge inject config changed: ixp %v mode %s announcer %v", cfg.IXP, cfg.Mode, cfg.Announcer)
	}
}

func TestIXPModeAllowsSuggest(t *testing.T) {
	y := strings.Replace(minimalYAML, "mode: observe", "mode: suggest", 1) + "ixp: {}\n"
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeSuggest || cfg.IXP == nil {
		t.Fatalf("mode %q ixp %v", cfg.Mode, cfg.IXP)
	}
}

func TestIXPModeRefusesAnnouncePaths(t *testing.T) {
	y := injectYAML + `
ixp: {}
mitigation:
  allowlist: [203.0.113.0/24]
inbound:
  prefixes: [198.51.100.0/24]
more_specific:
  enabled: false
`
	_, err := Parse([]byte(y))
	if err == nil {
		t.Fatal("expected ixp to refuse the announce paths")
	}
	for _, want := range []string{
		"ixp forbids mode inject",
		"ixp forbids announcer",
		"ixp forbids mitigation",
		"ixp forbids inbound",
		"ixp forbids more_specific",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}

	// A disabled more_specific block is still the block.
	_, err = Parse([]byte(minimalYAML + "ixp: {}\nmore_specific: {enabled: false}\n"))
	if err == nil || !strings.Contains(err.Error(), "ixp forbids more_specific") {
		t.Fatalf("disabled more_specific: %v", err)
	}
	// Observe-mode mitigation and inbound still steer or can be flipped. Both are refused.
	_, err = Parse([]byte(minimalYAML + "ixp: {}\n" + mitigationBlock))
	if err == nil || !strings.Contains(err.Error(), "ixp forbids mitigation") {
		t.Fatalf("observe mitigation: %v", err)
	}
	_, err = Parse([]byte(minimalYAML + "ixp: {}\n" + inboundBlock))
	if err == nil || !strings.Contains(err.Error(), "ixp forbids inbound") {
		t.Fatalf("observe inbound: %v", err)
	}
	_, err = Parse([]byte(minimalYAML + "ixp: {}\nannouncer: {type: gobgp}\n"))
	if err == nil || !strings.Contains(err.Error(), "ixp forbids announcer") {
		t.Fatalf("observe announcer: %v", err)
	}
}

func TestIXPModeRefusesSynthesize(t *testing.T) {
	_, err := Parse([]byte(minimalYAML + "ixp: {}\nsynthesize: {enabled: true}\n"))
	if err == nil || !strings.Contains(err.Error(), "ixp forbids synthesize") {
		t.Fatalf("err = %v", err)
	}
	// Without ixp, synthesize stays an unknown key. It is not accepted.
	_, err = Parse([]byte(minimalYAML + "synthesize: {enabled: true}\n"))
	if err == nil || !strings.Contains(err.Error(), "field synthesize not found") {
		t.Fatalf("err = %v", err)
	}
}

func TestIXPBlockRejectsUnknownKeys(t *testing.T) {
	_, err := Parse([]byte(minimalYAML + "ixp: {enabled: true}\n"))
	if err == nil || !strings.Contains(err.Error(), "field enabled not found") {
		t.Fatalf("err = %v", err)
	}
}

func TestIXPMembersConfig(t *testing.T) {
	y := minimalYAML + `
ixp:
  members:
    type: ixf
    config:
      url: https://ixp.example.invalid/members.json
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IXP == nil || cfg.IXP.Members == nil || cfg.IXP.Members.Type != "ixf" {
		t.Fatalf("%+v", cfg.IXP)
	}
	if cfg.Mode != ModeObserve || cfg.Announcer != nil {
		t.Fatalf("mode %s announcer %v", cfg.Mode, cfg.Announcer)
	}
	_, err = Parse([]byte(minimalYAML + "ixp:\n  members: {}\n"))
	if err == nil || !strings.Contains(err.Error(), "ixp.members: type is required") {
		t.Fatalf("missing type: %v", err)
	}
}

func fabricYAML(addr string) string {
	return minimalYAML + `
ixp:
  members:
    type: ixf
    config:
      url: https://ixp.example.invalid/members.json
  vantages:
    - name: lan1-v4
      vlan_id: 10
      address: ` + addr + `
  fabric:
    type: icmp
`
}

func TestIXPVantages(t *testing.T) {
	cfg, err := Parse([]byte(fabricYAML("192.0.2.8")))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IXP.Fabric == nil || cfg.IXP.Fabric.Type != "icmp" || len(cfg.IXP.Vantages) != 1 {
		t.Fatalf("%+v", cfg.IXP)
	}
	if cfg.IXP.Vantages[0].Name != "lan1-v4" || cfg.IXP.Vantages[0].VLANID != 10 || cfg.IXP.Vantages[0].Address != "192.0.2.8" {
		t.Fatalf("%+v", cfg.IXP.Vantages[0])
	}
	if cfg.Mode != ModeObserve || cfg.Announcer != nil {
		t.Fatalf("mode %s announcer %v", cfg.Mode, cfg.Announcer)
	}
	cfg, err = Parse([]byte(fabricYAML("10.1.1.8")))
	if err != nil || cfg.IXP.Vantages[0].Address != "10.1.1.8" {
		t.Fatalf("private LAN: %v %+v", err, cfg)
	}
	cfg, err = Parse([]byte(fabricYAML("2001:db8:0:0::8")))
	if err != nil || cfg.IXP.Vantages[0].Address != "2001:db8::8" {
		t.Fatalf("canonical v6: %v %+v", err, cfg)
	}
	cfg, err = Parse([]byte(fabricYAML("::ffff:192.0.2.8")))
	if err != nil || cfg.IXP.Vantages[0].Address != "192.0.2.8" {
		t.Fatalf("unmap: %v %+v", err, cfg)
	}

	bad := []struct{ body, want string }{
		{fabricYAML("not-an-ip"), "address is not an IP address"},
		{fabricYAML("127.0.0.1"), "not a usable vantage address"},
		{fabricYAML("169.254.1.1"), "not a usable vantage address"},
		{fabricYAML("224.0.0.1"), "not a usable vantage address"},
		{fabricYAML("192.0.2.8%eth0"), "address is not an IP address"},
		{strings.Replace(fabricYAML("192.0.2.8"), "vlan_id: 10", "vlan_id: 0", 1), "vlan_id is invalid"},
		{strings.Replace(fabricYAML("192.0.2.8"), "    type: icmp\n", "    type: \"\"\n", 1), "ixp.fabric: type is required"},
		{strings.Replace(fabricYAML("192.0.2.8"), "  fabric:\n    type: icmp\n", "", 1), "ixp.vantages requires ixp.fabric"},
		{strings.Replace(fabricYAML("192.0.2.8"), "  vantages:\n    - name: lan1-v4\n      vlan_id: 10\n      address: 192.0.2.8\n", "", 1), "ixp.fabric requires ixp.vantages"},
		{minimalYAML + "ixp:\n  fabric: {type: icmp}\n  vantages:\n    - {name: lan1-v4, vlan_id: 10, address: 192.0.2.8}\n", "ixp.fabric requires ixp.members"},
		{minimalYAML + "ixp: {probes: true}\n", "field probes not found"},
		{strings.Replace(minimalYAML, "mode: observe", "mode: inject", 1) + "ixp:\n  fabric: {type: icmp}\n  vantages:\n    - {name: lan1-v4, vlan_id: 10, address: 192.0.2.8}\n  members: {type: ixf, config: {url: https://ixp.example.invalid/members.json}}\nannouncer: {type: gobgp}\n", "ixp forbids mode inject"},
	}
	dup := strings.Replace(fabricYAML("192.0.2.8"), "  fabric:\n", "    - name: lan1-v4\n      vlan_id: 10\n      address: 192.0.2.9\n  fabric:\n", 1)
	bad = append(bad, struct{ body, want string }{dup, "is duplicated"})
	same := strings.Replace(fabricYAML("192.0.2.8"), "  fabric:\n", "    - name: lan1-v4b\n      vlan_id: 10\n      address: 192.0.2.8\n  fabric:\n", 1)
	bad = append(bad, struct{ body, want string }{same, "duplicated on this vlan"})
	for _, tc := range bad {
		_, err := Parse([]byte(tc.body))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("want %q in %v\n%s", tc.want, err, tc.body)
		}
	}
}

func TestIXPRouteServersConfig(t *testing.T) {
	y := minimalYAML + `
ixp:
  routeservers:
    type: birdseye
    config:
      servers:
        - {name: rs1, url: "http://192.0.2.5", asn: 64496}
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IXP == nil || cfg.IXP.RouteServers == nil || cfg.IXP.RouteServers.Type != "birdseye" {
		t.Fatalf("%+v", cfg.IXP)
	}
	if cfg.Mode != ModeObserve || cfg.Announcer != nil || len(cfg.BGP.Neighbors) != 0 {
		t.Fatalf("mode %s announcer %v neighbors %d", cfg.Mode, cfg.Announcer, len(cfg.BGP.Neighbors))
	}
	_, err = Parse([]byte(minimalYAML + "ixp:\n  routeservers: {}\n"))
	if err == nil || !strings.Contains(err.Error(), "ixp.routeservers: type is required") {
		t.Fatalf("missing type: %v", err)
	}
	inject := strings.Replace(minimalYAML, "mode: observe", "mode: inject", 1) + "ixp:\n  routeservers: {type: birdseye}\nannouncer: {type: gobgp}\n"
	if _, err = Parse([]byte(inject)); err == nil || !strings.Contains(err.Error(), "ixp forbids mode inject") {
		t.Fatalf("inject: %v", err)
	}
}

const ixpCorrelateBlock = `ixp:
  members:
    type: ixf
    config:
      url: https://ixp.example.invalid/members.json
  vantages:
    - {name: lan1-v4, vlan_id: 10, address: 192.0.2.8}
  fabric: {type: icmp}
  correlate:
    type: topology
    config:
      min_members: 4
      bundles:
        - {name: core-1, switches: [1, 2]}
`

func TestIXPCorrelateConfig(t *testing.T) {
	cfg, err := Parse([]byte(minimalYAML + ixpCorrelateBlock))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IXP == nil || cfg.IXP.Correlate == nil || cfg.IXP.Correlate.Type != "topology" {
		t.Fatalf("%+v", cfg.IXP)
	}

	noFabric := "ixp:\n  correlate: {type: topology}\n"
	_, err = Parse([]byte(minimalYAML + noFabric))
	if err == nil || !strings.Contains(err.Error(), "ixp.correlate requires ixp.fabric") {
		t.Fatalf("no fabric: %v", err)
	}
	_, err = Parse([]byte(minimalYAML + "ixp:\n  correlate: {}\n"))
	if err == nil || !strings.Contains(err.Error(), "ixp.correlate: type is required") {
		t.Fatalf("no type: %v", err)
	}
	inject := strings.Replace(minimalYAML, "mode: observe", "mode: inject", 1) + ixpCorrelateBlock + "announcer: {type: gobgp}\n"
	_, err = Parse([]byte(inject))
	if err == nil || !strings.Contains(err.Error(), "ixp forbids mode inject") || !strings.Contains(err.Error(), "ixp forbids announcer") {
		t.Fatalf("inject with correlate: %v", err)
	}
}

const ixpFederation = `domain: site-a
federation:
  type: mtls
  config: {}
`

const ixpCoreBlock = `ixp:
  core:
    type: icmp
    config:
      interval: 30s
  core_links:
    - {name: a-to-b, peer: site-b, address: 192.0.2.40, source: 192.0.2.30, max_rtt: 40ms}
`

func TestIXPCoreConfig(t *testing.T) {
	cfg, err := Parse([]byte(minimalYAML + ixpFederation + ixpCoreBlock))
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.IXP.CoreLinks[0]
	if cfg.IXP.Core.Type != "icmp" || l.Peer != "site-b" || l.MaxLossPct != DefaultCoreMaxLossPct || l.MaxRTT != 40*time.Millisecond {
		t.Fatalf("core = %+v links = %+v", cfg.IXP.Core, cfg.IXP.CoreLinks)
	}

	for _, tc := range []struct{ name, yaml, want string }{
		{"links without core", ixpFederation + "ixp:\n  core_links:\n    - {name: l, peer: site-b, address: 192.0.2.40}\n", "ixp.core_links requires ixp.core"},
		{"core without links", ixpFederation + "ixp:\n  core: {type: icmp}\n", "ixp.core requires ixp.core_links"},
		{"no type", ixpFederation + "ixp:\n  core: {}\n  core_links:\n    - {name: l, peer: site-b, address: 192.0.2.40}\n", "ixp.core: type is required"},
		{"no federation", ixpCoreBlock, "ixp.core requires federation"},
		{"own name", ixpFederation + strings.Replace(ixpCoreBlock, "peer: site-b", "peer: site-a", 1), "is this instance"},
		{"bad peer", ixpFederation + strings.Replace(ixpCoreBlock, "peer: site-b", "peer: site/b", 1), "peer is invalid"},
		{"bad address", ixpFederation + strings.Replace(ixpCoreBlock, "address: 192.0.2.40", "address: 0.0.0.0", 1), "address is not a usable"},
		{"bad source", ixpFederation + strings.Replace(ixpCoreBlock, "source: 192.0.2.30", "source: nope", 1), "source is not a usable"},
		{"duplicate name", ixpFederation + ixpCoreBlock + "    - {name: a-to-b, peer: site-c, address: 192.0.2.41}\n", "duplicated"},
		{"loss over 100", ixpFederation + strings.Replace(ixpCoreBlock, "max_rtt: 40ms", "max_loss_pct: 101", 1), "max_loss_pct"},
		{"negative rtt", ixpFederation + strings.Replace(ixpCoreBlock, "max_rtt: 40ms", "max_rtt: -1s", 1), "max_rtt"},
	} {
		if _, err := Parse([]byte(minimalYAML + tc.yaml)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}

	inject := strings.Replace(minimalYAML, "mode: observe", "mode: inject", 1) + ixpFederation + ixpCoreBlock + "announcer: {type: gobgp}\n"
	if _, err := Parse([]byte(inject)); err == nil || !strings.Contains(err.Error(), "ixp forbids mode inject") {
		t.Fatalf("inject with core: %v", err)
	}
}
