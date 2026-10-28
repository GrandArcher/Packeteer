package config

import (
	"strings"
	"testing"
)

const synthBlock = `
leak_watch:
  enabled: true
  sources:
    - type: rislive
synthesize:
  enabled: true
  covering_prefixes: [198.51.100.0/24]
  marker_community: "64512:667"
`

func TestSynthesizeOffByDefault(t *testing.T) {
	for _, text := range []string{validYAML, injectYAML} {
		cfg, err := Parse([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Synthesizing() || cfg.Synthesize != nil {
			t.Fatalf("synthesize on without a block: %+v", cfg.Synthesize)
		}
		if cfg.RouteCap() != DefaultMoreSpecificMaxRoutes {
			t.Fatalf("route cap = %d", cfg.RouteCap())
		}
	}
	cfg, err := Parse([]byte(injectYAML + "synthesize: {covering_prefixes: [198.51.100.0/24]}\n"))
	if err != nil {
		t.Fatalf("disabled block rejected: %v", err)
	}
	if cfg.Synthesizing() {
		t.Fatal("synthesize on with enabled unset")
	}
}

func TestSynthesizeDefaultsAndRouteCap(t *testing.T) {
	cfg, err := Parse([]byte(injectYAML + synthBlock + "more_specific: {max_routes: 7}\n"))
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.Synthesize
	if !cfg.Synthesizing() || s.MaxBits != 1 || s.MaxPrefixLen.V4 != 24 || s.MaxPrefixLen.V6 != 48 || s.NoAdvertise {
		t.Fatalf("defaults = %+v", s)
	}
	if cfg.RouteCap() != 7 {
		t.Fatalf("route cap = %d, want more_specific.max_routes", cfg.RouteCap())
	}
	if cfg.Mode != ModeInject {
		t.Fatalf("mode = %s", cfg.Mode)
	}
}

func TestSynthesizeValidation(t *testing.T) {
	cases := []struct {
		name, yaml, want string
	}{
		{"covering outside allowlist", strings.Replace(synthBlock, "[198.51.100.0/24]", "[203.0.113.0/24]", 1), "203.0.113.0/24 is not inside allowlist.prefixes"},
		{"covering wider than allowlist", strings.Replace(synthBlock, "[198.51.100.0/24]", "[198.51.0.0/16]", 1), "198.51.0.0/16 is not inside allowlist.prefixes"},
		{"host bits", strings.Replace(synthBlock, "[198.51.100.0/24]", "[198.51.100.1/24]", 1), "has host bits set"},
		{"bad cidr", strings.Replace(synthBlock, "[198.51.100.0/24]", "[nope]", 1), "is not a valid CIDR"},
		{"duplicate", strings.Replace(synthBlock, "[198.51.100.0/24]", "[198.51.100.0/24, 198.51.100.0/24]", 1), "duplicate prefix"},
		{"default route", strings.Replace(synthBlock, "[198.51.100.0/24]", "[0.0.0.0/0]", 1), "default route is never split"},
		{"no covering", strings.Replace(synthBlock, "[198.51.100.0/24]", "[]", 1), "at least one prefix is required"},
		{"no marker", strings.Replace(synthBlock, `  marker_community: "64512:667"`+"\n", "", 1), "marker_community is required"},
		{"marker is packeteer", strings.Replace(synthBlock, "64512:667", "64512:666", 1), "duplicates packeteer_community"},
		{"marker well-known", strings.Replace(synthBlock, "64512:667", "65535:65281", 1), "reserved"},
		{"max_bits high", synthBlock + "  max_bits: 9\n", "synthesize.max_bits 9 must be between 1 and 8"},
		{"max_bits negative", synthBlock + "  max_bits: -1\n", "synthesize.max_bits -1"},
		{"v4 too long", synthBlock + "  max_prefix_len: {v4: 33}\n", "max_prefix_len.v4 33"},
		{"v6 too long", synthBlock + "  max_prefix_len: {v6: 129}\n", "max_prefix_len.v6 129"},
		{"no leak watch", strings.Replace(synthBlock, "  enabled: true\n  sources:\n    - type: rislive\n", "  enabled: false\n", 1), "synthesize requires leak_watch enabled"},
		{"more_specific_bits still rejected", synthBlock + "more_specific_bits: 1\n", "more_specific_bits is removed"},
		{"unknown key", synthBlock + "  bits: 2\n", "field bits not found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(injectYAML + tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
	cfg, err := Parse([]byte(injectYAML + synthBlock + "  max_bits: 8\n  max_prefix_len: {v4: 32, v6: 128}\n  no_advertise: true\n"))
	if err != nil {
		t.Fatalf("upper bounds rejected: %v", err)
	}
	if s := cfg.Synthesize; s.MaxBits != 8 || s.MaxPrefixLen.V4 != 32 || s.MaxPrefixLen.V6 != 128 || !s.NoAdvertise || s.MarkerCommunity != "64512:667" {
		t.Fatalf("synthesize = %+v", s)
	}
}

// The shipped example config observes and does not turn synthesize on.
func TestExampleConfigDoesNotSynthesize(t *testing.T) {
	cfg, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeObserve || cfg.Synthesizing() {
		t.Fatalf("example: mode %s, synthesize %+v", cfg.Mode, cfg.Synthesize)
	}
}
