package config

import (
	"strings"
	"testing"
	"time"
)

// fedYAML is POP pop-a with one local provider, one provider in pop-b,
// and a global commit across both. Documentation addresses only.
const fedYAML = `
mode: observe
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
domain: pop-a
inter_dc_rtt:
  pop-b: 12ms
providers:
  - name: x-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
  - name: x-b
    domain: pop-b
    next_hop: 192.0.2.253
global_commit:
  - name: carrier-x
    commit_mbps: 1000
    providers: [x-a, x-b]
federation:
  type: mtls
  config:
    peers:
      - name: pop-b
        url: https://192.0.2.20:9443
`

func TestFederationConfigValid(t *testing.T) {
	cfg, err := Parse([]byte(fedYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Instance != "pop-a" {
		t.Errorf("instance = %q, want the domain", cfg.Instance)
	}
	if cfg.InterDCRTT["pop-b"] != 12*time.Millisecond {
		t.Errorf("inter_dc_rtt = %v", cfg.InterDCRTT)
	}
	if cfg.Remote(cfg.Providers[0]) || !cfg.Remote(cfg.Providers[1]) {
		t.Errorf("remote: x-a %v x-b %v", cfg.Remote(cfg.Providers[0]), cfg.Remote(cfg.Providers[1]))
	}
	if len(cfg.GlobalCommits) != 1 || cfg.GlobalCommits[0].CommitMbps != 1000 {
		t.Errorf("global_commit = %+v", cfg.GlobalCommits)
	}
	if cfg.Mode != ModeObserve {
		t.Errorf("mode = %s, federation must not change the observe default", cfg.Mode)
	}
}

func TestFederationConfigStandaloneUnchanged(t *testing.T) {
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Federation != nil || cfg.Domain != "" || cfg.Instance != "" {
		t.Fatalf("standalone config grew federation settings: %+v", cfg)
	}
	for _, p := range cfg.Providers {
		if cfg.Remote(p) {
			t.Fatalf("%s is remote in a standalone config", p.Name)
		}
	}
}

func TestFederationConfigInvalid(t *testing.T) {
	cases := []struct {
		name, from, to, want string
	}{
		{"no domain", "domain: pop-a\n", "", "federation requires domain"},
		{"bad domain", "domain: pop-a\n", "domain: -pop\n", `domain "-pop"`},
		{"no rtt for remote domain", "  pop-b: 12ms\n", "  pop-c: 12ms\n", "inter_dc_rtt has no entry for domain pop-b"},
		{"rtt to own domain", "  pop-b: 12ms\n", "  pop-b: 12ms\n  pop-a: 1ms\n", "is this instance's own domain"},
		{"rtt too large", "pop-b: 12ms", "pop-b: 11s", "must be between 0 and"},
		{"remote with source_ip", "    domain: pop-b\n", "    domain: pop-b\n    source_ip: 192.0.2.12\n", "source_ip must be empty"},
		{"remote without federation", "federation:\n  type: mtls\n  config:\n    peers:\n      - name: pop-b\n        url: https://192.0.2.20:9443\n", "", "needs federation"},
		{"federation without type", "  type: mtls\n", "", "federation.type is required"},
		{"global commit one member", "providers: [x-a, x-b]", "providers: [x-a]", "needs at least two providers"},
		{"global commit unknown provider", "providers: [x-a, x-b]", "providers: [x-a, x-c]", `provider "x-c" is not configured`},
		{"global commit no local member", "providers: [x-a, x-b]", "providers: [x-b, x-b]", "needs at least one provider in this instance's domain"},
		{"global commit zero", "commit_mbps: 1000", "commit_mbps: 0", "commit_mbps 0 must be above 0"},
		{"remote add_path", "    next_hop: 192.0.2.253\n", "    next_hop: 192.0.2.253\n    add_path: true\n", "add_path does not apply"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			y := strings.Replace(fedYAML, tc.from, tc.to, 1)
			if y == fedYAML {
				t.Fatalf("replacement %q not found", tc.from)
			}
			_, err := Parse([]byte(y))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
