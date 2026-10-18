package configedit

import (
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
)

func TestFormKeepsIXPBlock(t *testing.T) {
	y := observeYAML + "ixp: {}\n"
	f, err := ParseForm([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	f.HoldTime = "20m"
	out, err := ApplyForm([]byte(y), f)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(out)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if cfg.IXP == nil || cfg.Mode != config.ModeObserve || cfg.HoldTime != 20*time.Minute {
		t.Fatalf("ixp %v mode %s hold %s", cfg.IXP, cfg.Mode, cfg.HoldTime)
	}
	if cfg.Announcer != nil || len(cfg.Allowlist.Prefixes) != 0 {
		t.Fatalf("form opened an announce path: announcer %v allowlist %v", cfg.Announcer, cfg.Allowlist.Prefixes)
	}
}

func TestFormKeepsIXPMembers(t *testing.T) {
	y := observeYAML + `
ixp:
  members:
    type: ixf
    config:
      url: https://ixp.example.invalid/members.json
`
	f, err := ParseForm([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	f.HoldTime = "20m"
	out, err := ApplyForm([]byte(y), f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "type: ixf") || !strings.Contains(string(out), "https://ixp.example.invalid/members.json") {
		t.Fatalf("form dropped members:\n%s", out)
	}
	cfg, err := config.Parse(out)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if cfg.IXP == nil || cfg.IXP.Members == nil || cfg.IXP.Members.Type != "ixf" || cfg.HoldTime != 20*time.Minute {
		t.Fatalf("ixp %+v hold %s", cfg.IXP, cfg.HoldTime)
	}
}

func TestFormKeepsIXPVantages(t *testing.T) {
	y := observeYAML + `
ixp:
  members:
    type: ixf
    config:
      url: https://ixp.example.invalid/members.json
  vantages:
    - name: lan1-v4
      vlan_id: 10
      address: 192.0.2.8
  fabric:
    type: icmp
    config:
      interval: 1m
`
	f, err := ParseForm([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	f.HoldTime = "20m"
	out, err := ApplyForm([]byte(y), f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "lan1-v4") || !strings.Contains(string(out), "192.0.2.8") || !strings.Contains(string(out), "type: icmp") {
		t.Fatalf("form dropped vantages:\n%s", out)
	}
	cfg, err := config.Parse(out)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if cfg.IXP == nil || len(cfg.IXP.Vantages) != 1 || cfg.IXP.Vantages[0].Address != "192.0.2.8" || cfg.IXP.Fabric == nil || cfg.HoldTime != 20*time.Minute {
		t.Fatalf("ixp %+v hold %s", cfg.IXP, cfg.HoldTime)
	}
}

func TestEditorRefusesIXPInject(t *testing.T) {
	y := observeYAML + "ixp: {}\n"
	e, _ := editor(t, y)
	f, err := ParseForm([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	f.Mode = "inject"
	out, err := ApplyForm([]byte(y), f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "ixp:") || !strings.Contains(string(out), "mode: inject") {
		t.Fatalf("form dropped ixp or mode:\n%s", out)
	}
	res := e.Check(out)
	if res.Valid {
		t.Fatalf("editor accepted IXP inject: %+v", res)
	}
	got := strings.Join(res.Errors, "; ")
	if !strings.Contains(got, "ixp forbids mode inject") {
		t.Fatalf("errors = %q", got)
	}
}

func TestFormKeepsLookup(t *testing.T) {
	y := observeYAML + `
lookup:
  type: peeringdb
  config:
    exchanges:
      - {name: example-ix, ix_id: 1}
`
	f, err := ParseForm([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	f.HoldTime = "20m"
	out, err := ApplyForm([]byte(y), f)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(out)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if cfg.Lookup == nil || cfg.Lookup.Type != "peeringdb" || cfg.HoldTime != 20*time.Minute || !strings.Contains(string(out), "ix_id: 1") {
		t.Fatalf("lookup %+v hold %s\n%s", cfg.Lookup, cfg.HoldTime, out)
	}
}
