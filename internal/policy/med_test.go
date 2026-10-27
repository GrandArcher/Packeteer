package policy

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// medCfg is the MED tie break with a margin of 20 (20 ms with the
// weighted defaults).
func medCfg() Config {
	c := cfg()
	c.MEDTieBreak, c.MEDMargin = true, 20
	return c
}

// medIn is input for pA with every provider up and the given MEDs.
func medIn(native string, meds map[string]NeighborMED, ms ...m) Input {
	input := in(results(t0, pA, ms...), map[netip.Prefix]string{pA: native})
	input.ProviderUp = map[string]bool{"a": true, "b": true, "c": true, "d": true}
	input.MED = map[netip.Prefix]map[string]NeighborMED{pA: meds}
	return input
}

// Links a and b go to one transit (AS 64496); c and d are other ASes.
var twoLinks = map[string]NeighborMED{"a": {ASN: 64496, MED: 10}, "b": {ASN: 64496, MED: 50}}

func TestMEDKeepsNativeTheNeighborPrefersWithinMargin(t *testing.T) {
	// b beats a by 18 ms: past min_rtt_delta (15) but inside the margin.
	input := medIn("a", twoLinks, m{"a", 0, 50}, m{"b", 0, 32})
	st, out := Decide(NewState(), input, medCfg(), scorer(t), t0)
	if len(st.Improvements) != 0 {
		t.Fatalf("moved against the neighbor's MED inside the margin: %+v", st.Improvements)
	}
	d := decision(t, out, pA)
	want := "med: AS64496 prefers a (MED 10) over b (MED 50) and the scores are within thresholds.med_margin 20; native path kept"
	if d.Action != ActionNone || d.Reason != want {
		t.Fatalf("decision = %+v, want reason %q", d, want)
	}
	if d.Candidates[0].MED == nil || *d.Candidates[0].MED != 10 || d.Candidates[0].MEDASN != 64496 {
		t.Fatalf("candidate MED not shown: %+v", d.Candidates[0])
	}

	ex := explainRound(t, medCfg(), input)
	g := wantGate(t, ex, GateMED, GateFail, "AS64496 prefers a")
	if g.Limit != "thresholds.med_margin 20" || ex.BlockedBy != GateMED {
		t.Fatalf("med gate = %+v, blocked by %q", g, ex.BlockedBy)
	}
	if !strings.Contains(ex.Counterfactual, "would move to b if it scored more than thresholds.med_margin 20 better") {
		t.Fatalf("counterfactual = %q", ex.Counterfactual)
	}
	wantGate(t, ex, GateConfirm, GateSkip, "the neighbor's MED kept the native path")

	off := medCfg()
	off.MEDTieBreak = false
	st, _ = Decide(NewState(), input, off, scorer(t), t0)
	if imp, ok := st.Improvements[pA]; !ok || imp.Provider != "b" || imp.MEDOverride != nil {
		t.Fatalf("tie break off: %+v", st.Improvements)
	}
	for _, g := range explainRound(t, off, input).Gates {
		if g.Name == GateMED {
			t.Fatalf("med gate listed with the tie break off: %+v", g)
		}
	}
}

func TestMEDOverrideBeyondMarginIsReported(t *testing.T) {
	input := medIn("a", twoLinks, m{"a", 0, 80}, m{"b", 0, 30})
	st, out := Decide(NewState(), input, medCfg(), scorer(t), t0)
	want := MEDOverride{ASN: 64496, Preferred: "a", PreferredMED: 10, Chosen: "b", ChosenMED: 50, ScoreGap: 50}
	imp, ok := st.Improvements[pA]
	if !ok || imp.Provider != "b" || imp.MEDOverride == nil || *imp.MEDOverride != want {
		t.Fatalf("improvement = %+v, want override %+v", imp, want)
	}
	if len(out.Changes) != 1 || out.Changes[0].New.MEDOverride == nil {
		t.Fatalf("change does not carry the override: %+v", out.Changes)
	}
	if d := decision(t, out, pA); d.Action != ActionImprove || d.MEDOverride == nil || *d.MEDOverride != want {
		t.Fatalf("decision = %+v", d)
	}
	if got := want.String(); got != "overrides AS64496 MED: b (MED 50) over a (MED 10), score 50.0 better" {
		t.Fatalf("String = %q", got)
	}
	// The kept improvement still shows the override.
	_, out = Decide(st, medIn("a", twoLinks, m{"a", 0, 80}, m{"b", 0, 30}), medCfg(), scorer(t), t0.Add(time.Minute))
	if d := decision(t, out, pA); d.Action != ActionKeep || d.MEDOverride == nil {
		t.Fatalf("kept decision = %+v", d)
	}
}

func TestMEDBreaksTiesBetweenExitsOfOneNeighbor(t *testing.T) {
	// a scores best, b is 10 behind with the lower MED: b is taken and
	// nothing is overridden.
	meds := map[string]NeighborMED{"a": {ASN: 64496, MED: 50}, "b": {ASN: 64496, MED: 10}, "c": {ASN: 64497, MED: 0}}
	input := medIn("c", meds, m{"a", 0, 30}, m{"b", 0, 40}, m{"c", 0, 80})
	st, _ := Decide(NewState(), input, medCfg(), scorer(t), t0)
	if imp := st.Improvements[pA]; imp.Provider != "b" || imp.MEDOverride != nil {
		t.Fatalf("improvement = %+v, want b without an override", imp)
	}
	off := medCfg()
	off.MEDTieBreak = false
	if st, _ := Decide(NewState(), input, off, scorer(t), t0); st.Improvements[pA].Provider != "a" {
		t.Fatalf("tie break off: %+v", st.Improvements[pA])
	}
	// MEDs of different neighbor ASes are not compared.
	meds["b"] = NeighborMED{ASN: 64499, MED: 10}
	if st, _ := Decide(NewState(), input, medCfg(), scorer(t), t0); st.Improvements[pA].Provider != "a" || st.Improvements[pA].MEDOverride != nil {
		t.Fatalf("other AS: %+v", st.Improvements[pA])
	}
}

func TestMEDNeedsAMEDOnBothExits(t *testing.T) {
	input := medIn("a", map[string]NeighborMED{"b": {ASN: 64496, MED: 50}}, m{"a", 0, 50}, m{"b", 0, 32})
	st, _ := Decide(NewState(), input, medCfg(), scorer(t), t0)
	if imp := st.Improvements[pA]; imp.Provider != "b" || imp.MEDOverride != nil {
		t.Fatalf("improvement = %+v, want b: native has no MED", imp)
	}
}

func TestMEDOnPerformanceSwitch(t *testing.T) {
	active := func() State {
		s := NewState()
		s.Improvements[pA] = Improvement{Prefix: pA, Provider: "c", Native: "d", Since: t0.Add(-time.Hour), nativeSeen: t0, nativeHeld: true}
		return s
	}
	meds := map[string]NeighborMED{"a": {ASN: 64496, MED: 50}, "b": {ASN: 64496, MED: 10}}
	// a is best, b 15 behind with the lower MED: the switch goes to b.
	st, out := Decide(active(), medIn("d", meds, m{"a", 0, 30}, m{"b", 0, 45}, m{"c", 0, 80}, m{"d", 0, 100}), medCfg(), scorer(t), t0)
	if imp := st.Improvements[pA]; imp.Provider != "b" || imp.MEDOverride != nil || out.Changes[0].Action != ActionSwitch {
		t.Fatalf("switch = %+v %+v, want b", imp, out.Changes)
	}
	// b 40 behind: past the margin, the switch goes to a and reports it.
	st, _ = Decide(active(), medIn("d", meds, m{"a", 0, 20}, m{"b", 0, 60}, m{"c", 0, 80}, m{"d", 0, 100}), medCfg(), scorer(t), t0)
	imp := st.Improvements[pA]
	if imp.Provider != "a" || imp.MEDOverride == nil || imp.MEDOverride.Preferred != "b" || imp.MEDOverride.ScoreGap != 40 {
		t.Fatalf("switch = %+v, want a overriding b", imp)
	}
}
