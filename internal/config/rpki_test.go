package config

import (
	"strings"
	"testing"
)

// #158: the rpki block is off by default and enabled explicitly.
func TestRPKIOffByDefault(t *testing.T) {
	for _, y := range []string{minimalYAML, injectYAML} {
		cfg, err := Parse([]byte(y))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.RPKI != nil || cfg.RPKIOn() {
			t.Fatalf("rpki = %+v, want absent (off)", cfg.RPKI)
		}
	}
}

func TestRPKIParses(t *testing.T) {
	y := minimalYAML + "rpki:\n  enabled: true\n  avoid_invalid: true\n  sources:\n    - type: rtr\n      config:\n        address: 192.0.2.20:3323\n    - {type: rtr}\n"
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.RPKI
	if r == nil || !r.Enabled || !r.AvoidInvalid || len(r.Sources) != 2 || r.Sources[0].Type != "rtr" {
		t.Fatalf("rpki = %+v", r)
	}
	if !cfg.RPKIOn() {
		t.Fatal("RPKIOn = false for an enabled block")
	}
	cfg, err = Parse([]byte(minimalYAML + "rpki:\n  enabled: true\n  sources: [{type: json, config: {url: \"http://192.0.2.20:8323/json\"}}]\n  display_fallback: {type: \" ripestat \"}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if f := cfg.RPKI.DisplayFallback; f == nil || f.Type != "ripestat" || cfg.RPKI.Sources[0].Type != "json" {
		t.Fatalf("rpki = %+v", cfg.RPKI)
	}
}

func TestRPKIValidation(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"enabled without sources", minimalYAML + "rpki: {enabled: true}\n", "rpki.sources: at least one source is required when rpki.enabled"},
		{"source without type", minimalYAML + "rpki:\n  enabled: true\n  sources:\n    - {}\n", "rpki.sources[0]: type is required"},
		{"disabled with sources", minimalYAML + "rpki:\n  avoid_invalid: true\n", "rpki.enabled is false but rpki.sources, rpki.avoid_invalid, or rpki.display_fallback is set"},
		{"disabled with display fallback", minimalYAML + "rpki:\n  display_fallback: {type: ripestat}\n", "rpki.enabled is false but rpki.sources, rpki.avoid_invalid, or rpki.display_fallback is set"},
		{"ripestat as a source", minimalYAML + "rpki:\n  enabled: true\n  sources:\n    - {type: rtr}\n    - {type: ripestat}\n", "rpki.sources[1]: ripestat is display only; set it as rpki.display_fallback"},
		{"rtr as display fallback", minimalYAML + "rpki:\n  enabled: true\n  sources: [{type: rtr}]\n  display_fallback: {type: rtr}\n", "rpki.display_fallback: type must be ripestat"},
		{"unknown key", minimalYAML + "rpki: {enabled: true, bogus: 1}\n", "field bogus not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatalf("Parse succeeded, want error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}
