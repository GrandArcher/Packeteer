package policy

import (
	"net/netip"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func weightedScorer(t *testing.T, y string) plugin.Scorer {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	s, err := weighted.New(c, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Two prefixes both clear the thresholds and one slot is left. pA has the
// larger score gain; pB carries far more traffic.
func weightsInput() (Input, Config) {
	res := append(results(t0, pA, m{"a", 0, 100}, m{"b", 0, 20}), results(t0, pB, m{"a", 0, 60}, m{"b", 0, 30})...)
	input := in(res, map[netip.Prefix]string{pA: "a", pB: "a"})
	input.VolumeMbps = map[netip.Prefix]float64{pA: 5, pB: 800}
	c := cfg()
	c.MaxImprovements = 1
	return input, c
}

func TestImprovementWeightsPickWhoSurvivesTheCap(t *testing.T) {
	input, c := weightsInput()
	for _, tc := range []struct {
		name   string
		scorer string
		want   netip.Prefix
		capped netip.Prefix
	}{
		{"no weights: largest gain", "", pA, pB},
		{"performance only: same as gain", "improvement_weights: {performance: 1}", pA, pB},
		{"volume weight: heavier prefix", "improvement_weights: {performance: 1, volume: 1}", pB, pA},
		{"volume only", "improvement_weights: {performance: 0, volume: 1}", pB, pA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, out := Decide(NewState(), input, c, weightedScorer(t, tc.scorer), t0)
			if len(st.Improvements) != 1 {
				t.Fatalf("cap 1: improvements = %v", st.Improvements)
			}
			if _, ok := st.Improvements[tc.want]; !ok {
				t.Fatalf("want %s admitted, got %v", tc.want, st.Improvements)
			}
			if d := decision(t, out, tc.capped); d.Action != ActionCapped {
				t.Fatalf("%s action = %s (%s), want capped", tc.capped, d.Action, d.Reason)
			}
			if tc.scorer == "" && decision(t, out, tc.want).Weight != 0 {
				t.Fatal("weight reported without improvement_weights")
			}
		})
	}
}

func TestImprovementWeightsReported(t *testing.T) {
	input, c := weightsInput()
	_, out := Decide(NewState(), input, c, weightedScorer(t, "improvement_weights: {performance: 1, volume: 1}"), t0)
	// pB: gain 30 + 800 Mbps.
	if w := decision(t, out, pB).Weight; w != 830 {
		t.Fatalf("pB weight = %v", w)
	}
	if w := decision(t, out, pA).Weight; w != 85 {
		t.Fatalf("pA weight = %v", w)
	}
}

// Weights never displace an active improvement, and never admit a prefix
// the RIB or the allowlist refuses, however heavy it is.
func TestImprovementWeightsKeepSafety(t *testing.T) {
	sc := weightedScorer(t, "improvement_weights: {volume: 1000}")
	input, c := weightsInput()
	st, _ := Decide(NewState(), input, c, weightedScorer(t, ""), t0)
	if _, ok := st.Improvements[pA]; !ok {
		t.Fatal("setup: pA not active")
	}
	st2, out := Decide(st, input, c, sc, t0.Add(1))
	if _, ok := st2.Improvements[pA]; !ok || len(st2.Improvements) != 1 {
		t.Fatalf("active pA displaced by weight: %v", st2.Improvements)
	}
	if d := decision(t, out, pB); d.Action != ActionCapped {
		t.Fatalf("pB = %s, want capped", d.Action)
	}

	// Not in the RIB: never admitted, whatever its weight.
	input, c = weightsInput()
	delete(input.Native, pB)
	st, _ = Decide(NewState(), input, c, sc, t0)
	if _, ok := st.Improvements[pB]; ok {
		t.Fatal("prefix not in the learned RIB admitted")
	}
	if _, ok := st.Improvements[pA]; !ok {
		t.Fatal("pA should take the slot")
	}

	// Inject: not allowlisted, never admitted.
	input, c = weightsInput()
	c.Mode = "inject"
	c.Allowlist = []netip.Prefix{pA}
	st, out = Decide(NewState(), input, c, sc, t0)
	if _, ok := st.Improvements[pB]; ok {
		t.Fatal("non-allowlisted prefix admitted")
	}
	if d := decision(t, out, pB); d.Action == ActionImprove || d.Action == ActionCapped {
		t.Fatalf("pB action = %s", d.Action)
	}

	// The cap still binds: with room for both, both; with 0, none.
	input, c = weightsInput()
	c.MaxImprovements = 0
	if st, _ := Decide(NewState(), input, c, sc, t0); len(st.Improvements) != 0 {
		t.Fatalf("cap 0 admitted %v", st.Improvements)
	}
	c.MaxImprovements = 5
	if st, _ := Decide(NewState(), input, c, sc, t0); len(st.Improvements) != 2 {
		t.Fatalf("room for both: %v", st.Improvements)
	}
}

// Static pins still go before performance moves, whatever the weights.
func TestImprovementWeightsStayInLane(t *testing.T) {
	sc := weightedScorer(t, "improvement_weights: {volume: 1000}")
	input, c := weightsInput()
	input.Policies = map[netip.Prefix]plugin.PolicyVerdict{pA: {Action: plugin.PolicyStatic, Providers: []string{"b"}, Rule: "pin", MaxLossPct: 100}}
	st, _ := Decide(NewState(), input, c, sc, t0)
	if imp, ok := st.Improvements[pA]; !ok || imp.Cause != plugin.CauseStatic {
		t.Fatalf("static pin lost its slot to a heavier performance move: %v", st.Improvements)
	}
}

// WeightVolumeMbps orders moves like VolumeMbps does, and feeds nothing
// else: no cost annotation gets a volume from it.
func TestImprovementWeightsOwnVolume(t *testing.T) {
	input, c := weightsInput()
	input.WeightVolumeMbps, input.VolumeMbps = input.VolumeMbps, nil
	c.Providers = []ProviderPolicy{{Name: "a", Cost: 10, HasCost: true}, {Name: "b", Cost: 2, HasCost: true}}
	st, out := Decide(NewState(), input, c, weightedScorer(t, "improvement_weights: {volume: 1}"), t0)
	imp, ok := st.Improvements[pB]
	if !ok || len(st.Improvements) != 1 {
		t.Fatalf("improvements = %v, want %s", st.Improvements, pB)
	}
	if w := decision(t, out, pB).Weight; w != 830 {
		t.Fatalf("pB weight = %v", w)
	}
	if imp.CostDelta != 8 || imp.EstSavings != 0 {
		t.Fatalf("cost annotation read the weights' volume: %+v", imp)
	}
}
