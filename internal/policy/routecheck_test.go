package policy

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// A provider the BMP route check found without a path is never chosen.
func TestNoRouteBlocksImprovement(t *testing.T) {
	c := cfg()
	c.Mode = "inject"
	c.Allowlist = []netip.Prefix{pA}
	res := results(t0, pA, m{"a", 0, 80}, m{"b", 0, 20}, m{"c", 0, 50})
	input := in(res, map[netip.Prefix]string{pA: "a"})
	input.NoRoute = map[netip.Prefix]map[string]bool{pA: {"b": true}}
	st, out := Decide(State{}, input, c, scorer(t), t0)
	imp, ok := st.Improvements[pA]
	if !ok || imp.Provider != "c" {
		t.Fatalf("want improvement via c (b has no route), got %+v ok=%v", imp, ok)
	}
	d := decision(t, out, pA)
	for _, cand := range d.Candidates {
		if cand.Provider == "b" && (cand.Usable || !strings.Contains(cand.Why, "no route")) {
			t.Fatalf("b candidate = %+v", cand)
		}
	}
	input.NoRoute[pA]["c"] = true
	if st, _ := Decide(State{}, input, c, scorer(t), t0); len(st.Improvements) != 0 {
		t.Fatalf("improved with no routed alternative: %+v", st.Improvements)
	}
}

// An active improvement whose provider withdraws the prefix is retired at
// once, even inside hold_time.
func TestNoRouteRetiresActiveImprovement(t *testing.T) {
	c := cfg()
	res := results(t0, pA, m{"a", 0, 80}, m{"b", 0, 20})
	st, _ := Decide(State{}, in(res, map[netip.Prefix]string{pA: "a"}), c, scorer(t), t0)
	if _, ok := st.Improvements[pA]; !ok {
		t.Fatal("setup: no improvement")
	}
	now := t0.Add(time.Minute)
	input := in(results(now, pA, m{"a", 0, 80}, m{"b", 0, 20}), map[netip.Prefix]string{pA: "a"})
	input.NoRoute = map[netip.Prefix]map[string]bool{pA: {"b": true}}
	st, out := Decide(st, input, c, scorer(t), now)
	if _, ok := st.Improvements[pA]; ok {
		t.Fatal("improvement kept on a provider with no route")
	}
	if len(out.Changes) != 1 || out.Changes[0].Action != ActionRetire || !strings.Contains(out.Changes[0].Old.Reason, "no route") {
		t.Fatalf("changes = %+v", out.Changes)
	}
}

// The native provider is never marked: the RIB already holds its path.
func TestNoRouteIgnoresNative(t *testing.T) {
	c := cfg()
	input := in(results(t0, pA, m{"a", 0, 80}, m{"b", 0, 20}), map[netip.Prefix]string{pA: "a"})
	input.NoRoute = map[netip.Prefix]map[string]bool{pA: {"a": true}}
	st, _ := Decide(State{}, input, c, scorer(t), t0)
	if imp, ok := st.Improvements[pA]; !ok || imp.Provider != "b" {
		t.Fatalf("native marked unusable blocked the decision: %+v", st.Improvements)
	}
}
