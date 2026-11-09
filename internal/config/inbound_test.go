package config

import (
	"strings"
	"testing"
)

const inboundBlock = `
telemetry:
  - type: fixed
inbound:
  prefixes: [198.51.100.0/24]
  announcer:
    type: gobgp
`

func TestInboundDefaults(t *testing.T) {
	cfg, err := Parse([]byte(validYAML + inboundBlock))
	if err != nil {
		t.Fatal(err)
	}
	in := cfg.Inbound
	if in.Mode != ModeObserve || cfg.InboundMode() != ModeObserve {
		t.Fatalf("inbound mode = %q, want observe by default", in.Mode)
	}
	if in.LocalPref != DefaultInboundLocalPref || in.ReleasePct != DefaultInboundReleasePct || in.MaxImprovements != 50 {
		t.Fatalf("defaults = %+v", in)
	}
	d := in.Damping
	if d.Disabled || d.Confirm != DefaultInboundConfirm || d.Backoff != DefaultInboundBackoff || d.MaxHold != 8*cfg.HoldTime || in.Performance != nil || len(in.Moderated) != 0 {
		t.Fatalf("damping defaults = %+v, performance %+v", d, in.Performance)
	}
	cfg, err = Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Inbound != nil || cfg.InboundMode() != "" {
		t.Fatal("inbound must be off unless configured")
	}
}

func TestInboundInjectValid(t *testing.T) {
	y := injectYAML + inboundBlock + "  mode: inject\n  max_improvements: 10\n"
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Inbound.Mode != ModeInject || cfg.Inbound.MaxImprovements != 10 {
		t.Fatalf("inbound = %+v", cfg.Inbound)
	}
}

func TestInboundErrors(t *testing.T) {
	inject := injectYAML + inboundBlock
	cases := map[string]struct{ yaml, want string }{
		"inject needs top-level inject": {validYAML + inboundBlock + "  mode: inject\n", "inbound.mode inject requires mode inject"},
		"bad mode":                      {validYAML + inboundBlock + "  mode: steer\n", `inbound.mode "steer" is invalid`},
		"no telemetry":                  {validYAML + "inbound:\n  prefixes: [198.51.100.0/24]\n", "inbound requires a telemetry plugin"},
		"no prefixes":                   {validYAML + "telemetry: [{type: fixed}]\ninbound: {mode: observe}\n", "inbound.prefixes: at least one prefix"},
		"host bits":                     {validYAML + "telemetry: [{type: fixed}]\ninbound: {prefixes: [198.51.100.1/24]}\n", "host bits"},
		"duplicate":                     {validYAML + "telemetry: [{type: fixed}]\ninbound: {prefixes: [198.51.100.0/24, 198.51.100.0/24]}\n", "duplicate prefix"},
		"not allowlisted":               {edit(t, inject, "prefixes: [198.51.100.0/24]", "prefixes: [203.0.113.0/24]") + "  mode: inject\n", "not covered by allowlist"},
		"no announcer":                  {injectYAML + "telemetry: [{type: fixed}]\ninbound: {mode: inject, prefixes: [198.51.100.0/24]}\n", "requires inbound.announcer"},
		"release_pct":                   {inject + "  release_pct: 150\n", "inbound.release_pct"},
		"cap above global":              {inject + "  max_improvements: 51\n", "inbound.max_improvements 51"},
		"announcer type":                {validYAML + "telemetry: [{type: fixed}]\ninbound: {prefixes: [198.51.100.0/24], announcer: {name: x}}\n", "inbound.announcer: type is required"},
		"unknown key":                   {inject + "  prepend: 3\n", "field prepend not found"},
		"perf release_pct":              {inject + "  performance: {release_pct: 101}\n", "inbound.performance.release_pct"},
		"perf both off":                 {inject + "  performance: {loss_pct: -1, latency_ms: -1}\n", "cannot both be disabled"},
		"perf min_prefixes":             {inject + "  performance: {min_prefixes: -2}\n", "min_prefixes -2"},
		"backoff":                       {inject + "  damping: {backoff: 0.5}\n", "inbound.damping.backoff"},
		"max_hold":                      {inject + "  damping: {max_hold: 1m}\n", "inbound.damping.max_hold"},
		"confirm":                       {inject + "  damping: {confirm: -1s}\n", "inbound.damping.confirm"},
		"moderated":                     {inject + "  moderated: [bandwidth]\n", `inbound.moderated[0]: "bandwidth" is invalid`},
		"moderated perf":                {inject + "  moderated: [performance]\n", "performance needs inbound.performance"},
		"moderated dup":                 {inject + "  moderated: [commit, Commit]\n", "duplicate trigger"},
	}
	for name, tc := range cases {
		_, err := Parse([]byte(tc.yaml))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

func TestInboundPerformanceAndModerated(t *testing.T) {
	// Performance alone needs no telemetry.
	y := validYAML + "inbound:\n  prefixes: [198.51.100.0/24]\n  performance: {}\n  moderated: [Performance]\n  damping: {disabled: true}\n"
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	pf := cfg.Inbound.Performance
	if pf.LossPct != DefaultInboundPerfLossPct || pf.LatencyMs != DefaultInboundPerfLatencyMs ||
		pf.MinPrefixes != DefaultInboundPerfMinPrefixes || pf.ReleasePct != DefaultInboundPerfReleasePct {
		t.Fatalf("performance defaults = %+v", pf)
	}
	if cfg.Inbound.Moderated[0] != InboundTriggerPerformance || cfg.Inbound.Damping.Confirm != 0 {
		t.Fatalf("inbound = %+v", cfg.Inbound)
	}
	if _, err := Parse([]byte(validYAML + "inbound:\n  prefixes: [198.51.100.0/24]\n  moderated: [commit]\n")); err == nil ||
		!strings.Contains(err.Error(), "commit needs a telemetry plugin") {
		t.Fatalf("err = %v", err)
	}
}
