package policy

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// A provider whose every egress router lost its session (#27) is not a
// candidate, and an active improvement on it is retired inside hold_time.
func TestEgressDownBlocksAndRetires(t *testing.T) {
	c := cfg()
	input := in(results(t0, pA, m{"a", 0, 80}, m{"b", 0, 20}, m{"c", 0, 50}), map[netip.Prefix]string{pA: "a"})
	input.EgressDown = map[string]bool{"b": true}
	st, out := Decide(State{}, input, c, scorer(t), t0)
	if imp, ok := st.Improvements[pA]; !ok || imp.Provider != "c" {
		t.Fatalf("want improvement via c (b's egress is down), got %+v ok=%v", imp, ok)
	}
	for _, cand := range decision(t, out, pA).Candidates {
		if cand.Provider == "b" && (cand.Usable || cand.Why != "egress router down") {
			t.Fatalf("b candidate = %+v", cand)
		}
	}

	st, _ = Decide(State{}, in(results(t0, pA, m{"a", 0, 80}, m{"b", 0, 20}), map[netip.Prefix]string{pA: "a"}), c, scorer(t), t0)
	if imp, ok := st.Improvements[pA]; !ok || imp.Provider != "b" {
		t.Fatal("setup: no improvement via b")
	}
	now := t0.Add(time.Minute)
	input = in(results(now, pA, m{"a", 0, 80}, m{"b", 0, 20}), map[netip.Prefix]string{pA: "a"})
	input.EgressDown = map[string]bool{"b": true}
	st, out = Decide(st, input, c, scorer(t), now)
	if _, ok := st.Improvements[pA]; ok {
		t.Fatal("improvement kept on a provider whose egress router is down")
	}
	if len(out.Changes) != 1 || out.Changes[0].Action != ActionRetire || !strings.Contains(out.Changes[0].Old.Reason, "egress router down") {
		t.Fatalf("changes = %+v", out.Changes)
	}
}

// The native provider is never marked: its paths already left the view
// with the session.
func TestEgressDownIgnoresNative(t *testing.T) {
	input := in(results(t0, pA, m{"a", 0, 80}, m{"b", 0, 20}), map[netip.Prefix]string{pA: "a"})
	input.EgressDown = map[string]bool{"a": true}
	st, _ := Decide(State{}, input, cfg(), scorer(t), t0)
	if imp, ok := st.Improvements[pA]; !ok || imp.Provider != "b" {
		t.Fatalf("native egress down blocked the decision: %+v", st.Improvements)
	}
}
