package config

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/onlyinvalid"
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
		{"disabled with sources", minimalYAML + "rpki:\n  avoid_invalid: true\n", "rpki.enabled is false but rpki.sources, rpki.avoid_invalid, rpki.display_fallback, or rpki.only_invalid is set"},
		{"disabled with display fallback", minimalYAML + "rpki:\n  display_fallback: {type: ripestat}\n", "rpki.enabled is false but rpki.sources, rpki.avoid_invalid, rpki.display_fallback, or rpki.only_invalid is set"},
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

const rpkiOn = "rpki:\n  enabled: true\n  sources: [{type: rtr, config: {address: \"192.0.2.20:3323\"}}]\n"

// #401: rpki.only_invalid is off unless enabled, takes the stable_after
// default, and the SLURM block lists the prefixes an exception may cover.
func TestOnlyInvalidParses(t *testing.T) {
	cfg, err := Parse([]byte(minimalYAML + rpkiOn))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OnlyInvalidOn() {
		t.Fatal("only_invalid on without the block")
	}
	y := minimalYAML + rpkiOn + "  only_invalid:\n    enabled: true\n    hijack_feeds: [{type: \" file \", config: {path: /etc/packeteer/hijacks.json}}]\n" +
		"    slurm:\n      path: /var/lib/packeteer/slurm.json\n      prefixes: [198.51.100.0/24, \"2001:db8::/32\"]\n      review_after: 720h\n"
	cfg, err = Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	o := cfg.RPKI.OnlyInvalid
	if !cfg.OnlyInvalidOn() || o.StableAfter != 720*time.Hour || o.HijackFeeds[0].Type != "file" || *o.SLURM.ReviewAfter != 720*time.Hour {
		t.Fatalf("only_invalid = %+v", o)
	}
	if got := o.SLURM.SLURMPrefixes(); len(got) != 2 || got[0] != netip.MustParsePrefix("198.51.100.0/24") || got[1] != netip.MustParsePrefix("2001:db8::/32") {
		t.Fatalf("prefixes = %v", got)
	}
	cfg, err = Parse([]byte(strings.Replace(y, "      review_after: 720h\n", "", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if got := *cfg.RPKI.OnlyInvalid.SLURM.ReviewAfter; got != onlyinvalid.DefaultReviewAfter {
		t.Fatalf("review_after default = %s", got)
	}
	cfg, err = Parse([]byte(strings.Replace(y, "review_after: 720h", "review_after: 0s", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if got := *cfg.RPKI.OnlyInvalid.SLURM.ReviewAfter; got != 0 {
		t.Fatalf("review_after 0s = %s, want off", got)
	}
}

func TestOnlyInvalidValidation(t *testing.T) {
	on := minimalYAML + rpkiOn + "  only_invalid:\n    enabled: true\n"
	slurm := on + "    slurm:\n      path: /var/lib/packeteer/slurm.json\n"
	tests := []struct{ name, yaml, want string }{
		{"without rpki", minimalYAML + "rpki:\n  only_invalid: {enabled: true}\n", "rpki.enabled is false but"},
		{"disabled with slurm", minimalYAML + rpkiOn + "  only_invalid:\n    slurm: {path: /x}\n", "rpki.only_invalid.enabled is false but hijack_feeds or slurm is set"},
		{"short stable_after", on + "    stable_after: 1m\n", "rpki.only_invalid.stable_after 1m0s must be between 1h0m0s and 8760h0m0s"},
		{"feed without type", on + "    hijack_feeds: [{}]\n", "rpki.only_invalid.hijack_feeds[0]: type is required"},
		{"feed name twice", on + "    hijack_feeds: [{type: file}, {type: file}]\n", "rpki.only_invalid.hijack_feeds[1]: name \"file\" is used twice"},
		{"with ixp", slurm + "      prefixes: [198.51.100.0/24]\nixp: {}\n", "rpki.only_invalid.slurm cannot be combined with ixp"},
		{"relative path", on + "    slurm: {path: slurm.json, prefixes: [198.51.100.0/24]}\n", "rpki.only_invalid.slurm.path \"slurm.json\" must be an absolute path"},
		{"no prefixes", slurm, "rpki.only_invalid.slurm.prefixes: at least one prefix is required"},
		{"host bits", slurm + "      prefixes: [198.51.100.1/24]\n", "rpki.only_invalid.slurm.prefixes[0]: 198.51.100.1/24 has host bits set"},
		{"default route", slurm + "      prefixes: [0.0.0.0/0]\n", "rpki.only_invalid.slurm.prefixes[0]: a default route"},
		{"short review_after", slurm + "      prefixes: [198.51.100.0/24]\n      review_after: 1h\n", "rpki.only_invalid.slurm.review_after 1h0m0s must be 0s (no reminder) or between 24h0m0s and 8760h0m0s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}
