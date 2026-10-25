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
	input.Reorder = map[string]float64{"b": 10}

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
