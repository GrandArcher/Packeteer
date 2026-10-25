package policy

import (
	"net/netip"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// A provider path's reordered ratio (#224) reaches every candidate and,
// only through reorder_weight, the score: with the default scorer the
// faster but reordering provider still wins; with a weight it does not.
func TestReorderInput(t *testing.T) {
	native := map[netip.Prefix]string{pA: "a"}
	input := in(results(t0, pA, m{"a", 0, 60}, m{"b", 0, 30}), native)
	input.Reorder = map[string]float64{"a": 0, "b": 10}

	_, out := Decide(NewState(), input, cfg(), scorer(t), t0)
	d := decision(t, out, pA)
	if d.Action != "improve" || d.Recommended != "b" {
		t.Fatalf("default scorer: action %s recommended %s", d.Action, d.Recommended)
	}
	for _, c := range d.Candidates {
		switch c.Provider {
		case "a":
			if c.ReorderPct != 0 {
				t.Fatalf("a reorder_pct %v", c.ReorderPct)
			}
		case "b":
			if c.ReorderPct != 10 || c.Score != 30 {
				t.Fatalf("b reorder_pct %v score %v", c.ReorderPct, c.Score)
			}
		}
	}

	c, err := plugin.ConfigFromYAML("reorder_weight: 5")
	if err != nil {
		t.Fatal(err)
	}
	weighs, err := weighted.New(c, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	_, out = Decide(NewState(), input, cfg(), weighs, t0)
	d = decision(t, out, pA)
	if d.Action == "improve" || d.Recommended == "b" {
		t.Fatalf("weighted reordering: action %s recommended %s", d.Action, d.Recommended)
	}
	for _, c := range d.Candidates {
		if c.Provider == "b" && c.Score != 30+50 {
			t.Fatalf("b score %v, want 80", c.Score)
		}
	}

	// Without a reading every path scores as zero reordering.
	input.Reorder = nil
	_, out = Decide(NewState(), input, cfg(), weighs, t0)
	if d := decision(t, out, pA); d.Recommended != "b" {
		t.Fatalf("no reading: recommended %s", d.Recommended)
	}
}

// A provider without a fresh reading is unknown, not free of reordering.
// Scored as zero, unmeasured b would beat c, whose 4% costs 20 points.
// Instead no candidate of that prefix carries a reading, and c, the
// fastest, is recommended. A prefix b is not measured for keeps them.
func TestReorderMissingReading(t *testing.T) {
	c, err := plugin.ConfigFromYAML("reorder_weight: 5")
	if err != nil {
		t.Fatal(err)
	}
	weighs, err := weighted.New(c, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	native := map[netip.Prefix]string{pA: "a", pB: "a"}
	res := append(results(t0, pA, m{"a", 0, 60}, m{"b", 0, 40}, m{"c", 0, 30}), results(t0, pB, m{"a", 0, 60}, m{"c", 0, 30})...)
	input := in(res, native)
	input.Reorder = map[string]float64{"a": 10, "c": 4}

	_, out := Decide(NewState(), input, cfg(), weighs, t0)
	d := decision(t, out, pA)
	if d.Action != "improve" || d.Recommended != "c" {
		t.Fatalf("b unmeasured: action %s recommended %s", d.Action, d.Recommended)
	}
	for _, c := range d.Candidates {
		if c.ReorderPct != 0 {
			t.Fatalf("b unmeasured: %s carries reorder_pct %v", c.Provider, c.ReorderPct)
		}
	}
	score := map[string]float64{"a": 60 + 5*10, "c": 30 + 5*4}
	for _, c := range decision(t, out, pB).Candidates {
		if c.ReorderPct != input.Reorder[c.Provider] || c.Score != score[c.Provider] {
			t.Fatalf("all measured: %s reorder_pct %v score %v", c.Provider, c.ReorderPct, c.Score)
		}
	}
}
