package policy

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// #158: with avoid_invalid on, a provider whose learned path for the
// prefix is RPKI-invalid is not chosen for a new improvement.
func TestRPKIAvoidInvalidBlocksImprovement(t *testing.T) {
	c := cfg()
	c.Mode = "inject"
	c.Allowlist = []netip.Prefix{pA}
	c.RPKIAvoidInvalid = true
	input := in(results(t0, pA, m{"a", 0, 80}, m{"b", 0, 20}, m{"c", 0, 50}), map[netip.Prefix]string{pA: "a"})
	input.RPKI = map[netip.Prefix]map[string]plugin.RPKIAnswer{pA: {"b": {State: plugin.RPKIInvalid}}}
	st, out := Decide(State{}, input, c, scorer(t), t0)
	imp, ok := st.Improvements[pA]
	if !ok || imp.Provider != "c" {
		t.Fatalf("want improvement via c (b invalid), got %+v ok=%v", imp, ok)
	}
	d := decision(t, out, pA)
	for _, cand := range d.Candidates {
		if cand.Provider == "b" && (cand.Usable || !strings.Contains(cand.Why, "RPKI invalid") || cand.RPKI != plugin.RPKIInvalid) {
			t.Fatalf("b candidate = %+v", cand)
		}
	}
}

// With avoid_invalid off the validity is still shown, with the source that
// answered and its data time (#200), but never blocks.
func TestRPKIInvalidShownButNotBlocking(t *testing.T) {
	c := cfg()
	input := in(results(t0, pA, m{"a", 0, 80}, m{"b", 0, 20}), map[netip.Prefix]string{pA: "a"})
	fetched := t0.Add(-3 * time.Minute)
	input.RPKI = map[netip.Prefix]map[string]plugin.RPKIAnswer{pA: {"b": {State: plugin.RPKIInvalid, Source: "routinator", Updated: fetched}}}
	st, out := Decide(State{}, input, c, scorer(t), t0)
	if imp, ok := st.Improvements[pA]; !ok || imp.Provider != "b" {
		t.Fatalf("off should not block: %+v", st.Improvements)
	}
	d := decision(t, out, pA)
	for _, cand := range d.Candidates {
		if cand.Provider == "b" && (cand.RPKI != plugin.RPKIInvalid || cand.RPKISource != "routinator" || !cand.RPKIUpdated.Equal(fetched)) {
			t.Fatalf("b candidate missing its validity or source: %+v", cand)
		}
	}
}

// An active improvement whose provider's path becomes invalid is retired.
func TestRPKIInvalidRetiresActiveImprovement(t *testing.T) {
	c := cfg()
	c.RPKIAvoidInvalid = true
	input := in(results(t0, pA, m{"a", 0, 80}, m{"b", 0, 20}), map[netip.Prefix]string{pA: "a"})
	st, _ := Decide(State{}, input, c, scorer(t), t0)
	if _, ok := st.Improvements[pA]; !ok {
		t.Fatal("setup: no improvement")
	}
	now := t0.Add(time.Minute)
	input = in(results(now, pA, m{"a", 0, 80}, m{"b", 0, 20}), map[netip.Prefix]string{pA: "a"})
	input.RPKI = map[netip.Prefix]map[string]plugin.RPKIAnswer{pA: {"b": {State: plugin.RPKIInvalid}}}
	st, out := Decide(st, input, c, scorer(t), now)
	if _, ok := st.Improvements[pA]; ok {
		t.Fatal("improvement kept on an invalid path")
	}
	if len(out.Changes) != 1 || out.Changes[0].Action != ActionRetire || !strings.Contains(out.Changes[0].Old.Reason, "RPKI invalid") {
		t.Fatalf("changes = %+v", out.Changes)
	}
}

// The native provider is never blocked by its own validity.
func TestRPKIIgnoresNative(t *testing.T) {
	c := cfg()
	c.RPKIAvoidInvalid = true
	input := in(results(t0, pA, m{"a", 0, 80}, m{"b", 0, 20}), map[netip.Prefix]string{pA: "a"})
	input.RPKI = map[netip.Prefix]map[string]plugin.RPKIAnswer{pA: {"a": {State: plugin.RPKIInvalid}}}
	st, _ := Decide(State{}, input, c, scorer(t), t0)
	if imp, ok := st.Improvements[pA]; !ok || imp.Provider != "b" {
		t.Fatalf("native marked invalid blocked the decision: %+v", st.Improvements)
	}
}
