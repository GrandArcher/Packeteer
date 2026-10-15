package config

import (
	"strings"
	"testing"
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
