package policy

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// #214: with prefer_registered on, a provider whose learned path is not
// registered in the IRR is not chosen for a new improvement; an unknown
// path still is (fail open).
func TestIRRPreferRegisteredBlocksImprovement(t *testing.T) {
	c := cfg()
	c.Mode = "inject"
	c.Allowlist = []netip.Prefix{pA}
	c.IRRPreferRegistered = true
	input := in(results(t0, pA, m{"a", 0, 80}, m{"b", 0, 20}, m{"c", 0, 50}), map[netip.Prefix]string{pA: "a"})
	input.IRR = map[netip.Prefix]map[string]plugin.IRRAnswer{pA: {
		"b": {State: plugin.IRRNotRegistered, Source: "radb"},
		"c": {State: plugin.IRRUnknown},
	}}
	st, out := Decide(State{}, input, c, scorer(t), t0)
	if imp, ok := st.Improvements[pA]; !ok || imp.Provider != "c" {
		t.Fatalf("want improvement via c (b not registered, c unknown), got %+v ok=%v", imp, ok)
	}
	for _, cand := range decision(t, out, pA).Candidates {
		if cand.Provider == "b" && (cand.Usable || cand.Why != "IRR not registered" || cand.IRR != plugin.IRRNotRegistered || cand.IRRSource != "radb") {
			t.Fatalf("b candidate = %+v", cand)
		}
	}
}

// With prefer_registered off the state and its source are shown but never
// block.
func TestIRRShownButNotBlocking(t *testing.T) {
	c := cfg()
	input := in(results(t0, pA, m{"a", 0, 80}, m{"b", 0, 20}), map[netip.Prefix]string{pA: "a"})
	at := t0.Add(-time.Hour)
	input.IRR = map[netip.Prefix]map[string]plugin.IRRAnswer{pA: {"b": {State: plugin.IRRNotRegistered, Source: "radb", Updated: at}}}
	st, out := Decide(State{}, input, c, scorer(t), t0)
	if imp, ok := st.Improvements[pA]; !ok || imp.Provider != "b" {
		t.Fatalf("off should not block: %+v", st.Improvements)
	}
	for _, cand := range decision(t, out, pA).Candidates {
		if cand.Provider == "b" && (!cand.Usable || cand.IRR != plugin.IRRNotRegistered || cand.IRRSource != "radb" || !cand.IRRUpdated.Equal(at)) {
			t.Fatalf("b candidate missing its IRR state: %+v", cand)
		}
	}
}

// An active improvement whose provider's path stops being registered is
// retired through the normal path, and the native provider is never
// blocked by its own state.
func TestIRRNotRegisteredRetiresActiveImprovement(t *testing.T) {
	c := cfg()
	c.IRRPreferRegistered = true
	input := in(results(t0, pA, m{"a", 0, 80}, m{"b", 0, 20}), map[netip.Prefix]string{pA: "a"})
	input.IRR = map[netip.Prefix]map[string]plugin.IRRAnswer{pA: {"a": {State: plugin.IRRNotRegistered}, "b": {State: plugin.IRRRegistered}}}
	st, _ := Decide(State{}, input, c, scorer(t), t0)
	if imp, ok := st.Improvements[pA]; !ok || imp.Provider != "b" {
		t.Fatalf("setup: %+v", st.Improvements)
	}
	now := t0.Add(time.Minute)
	input = in(results(now, pA, m{"a", 0, 80}, m{"b", 0, 20}), map[netip.Prefix]string{pA: "a"})
	input.IRR = map[netip.Prefix]map[string]plugin.IRRAnswer{pA: {"b": {State: plugin.IRRNotRegistered}}}
	st, out := Decide(st, input, c, scorer(t), now)
	if _, ok := st.Improvements[pA]; ok {
		t.Fatal("improvement kept on a path that is not registered")
	}
	if len(out.Changes) != 1 || out.Changes[0].Action != ActionRetire || !strings.Contains(out.Changes[0].Old.Reason, "IRR not registered") {
		t.Fatalf("changes = %+v", out.Changes)
	}
}
