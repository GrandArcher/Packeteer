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
