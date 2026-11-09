package config

import (
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/irr"
)

// #214: the irr block is off by default; an enabled one gets the cache
// defaults and keeps its ordered sources and per-provider as-sets.
func TestIRRParses(t *testing.T) {
	cfg, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IRR != nil || cfg.IRROn() {
		t.Fatalf("irr = %+v, want absent (off)", cfg.IRR)
	}
	cfg, err = Parse([]byte(minimalYAML + "irr:\n  enabled: true\n  prefer_registered: true\n  as_sets: {transit-a: AS64500:AS-CUSTOMERS}\n  sources:\n    - {type: \" file \", config: {path: /etc/packeteer/irr.db}}\n    - {type: whois, name: radb, config: {address: \"whois.example.net:43\"}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.IRR
	if !cfg.IRROn() || !r.PreferRegistered || len(r.Sources) != 2 || r.Sources[0].Type != "file" || r.Sources[1].InstanceName() != "radb" ||
		r.Refresh != irr.DefaultRefresh || r.Staleness != irr.DefaultStaleness || r.ASSets["transit-a"] != "AS64500:AS-CUSTOMERS" {
		t.Fatalf("irr = %+v", r)
	}
	cfg, err = Parse([]byte(minimalYAML + "irr:\n  enabled: true\n  refresh: 48h\n  sources: [{type: file}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IRR.Staleness != 48*time.Hour {
		t.Fatalf("staleness default = %s, want refresh when longer than 24h", cfg.IRR.Staleness)
	}
}

func TestIRRValidation(t *testing.T) {
	src := "  sources: [{type: file}]\n"
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"enabled without sources", "irr: {enabled: true}\n", "irr.sources: at least one source is required when irr.enabled"},
		{"source without type", "irr:\n  enabled: true\n  sources: [{}]\n", "irr.sources[0]: type is required"},
		{"duplicate names", "irr:\n  enabled: true\n  sources: [{type: whois}, {type: whois}]\n", `irr.sources[1]: name "whois" is used twice; set name`},
		{"disabled with settings", "irr:\n  prefer_registered: true\n", "irr.enabled is false but irr.sources, irr.refresh, irr.staleness, irr.as_sets, or irr.prefer_registered is set"},
		{"refresh too short", "irr:\n  enabled: true\n  refresh: 10s\n" + src, "irr.refresh 10s must be between 1m0s and 720h0m0s"},
		{"staleness below refresh", "irr:\n  enabled: true\n  refresh: 2h\n  staleness: 1h\n" + src, "irr.staleness 1h0m0s must be at least irr.refresh (2h0m0s)"},
		{"as-set for an unknown provider", "irr:\n  enabled: true\n  as_sets: {nope: AS-EXAMPLE}\n" + src, `irr.as_sets: "nope" is not a configured provider`},
		{"bad as-set name", "irr:\n  enabled: true\n  as_sets: {transit-a: AS64500}\n" + src, `irr.as_sets.transit-a: "AS64500" is not an as-set name`},
		{"unknown key", "irr: {enabled: true, bogus: 1}\n", "field bogus not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(minimalYAML + tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}
