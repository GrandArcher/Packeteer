package policy

import (
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/probe"
)

// Pausing retires every improvement at once, inside hold_time and with no
// cooldown, and makes none; resuming lets the next round improve again.
func TestPauseRetiresEverythingAndResumeRestores(t *testing.T) {
	native := map[netip.Prefix]string{pA: "a", pB: "a"}
	round := func(at time.Time) Input {
		var res []probe.Result
		res = append(res, results(at, pA, m{"a", 0, 100}, m{"b", 0, 40})...)
		res = append(res, results(at, pB, m{"a", 0, 200}, m{"b", 0, 50})...)
		return in(res, native)
	}
	c := cfg()
	c.MaxImprovements = 10
	e := NewEngine(c, scorer(t))
	e.Evaluate(round(t0), t0)
	if n := len(e.Improvements()); n != 2 {
		t.Fatalf("improvements before pause = %d", n)
	}

	e.SetPaused(true)
	later := t0.Add(time.Second)
	changes := e.Evaluate(round(later), later)
	if n := len(e.Improvements()); n != 0 {
		t.Fatalf("improvements while paused = %d", n)
	}
	if len(changes) != 2 {
		t.Fatalf("changes = %+v", changes)
	}
	for _, ch := range changes {
		if ch.Action != ActionRetire || ch.Old.Reason != "optimization paused" {
			t.Errorf("change %+v", ch)
		}
	}
	e.mu.RLock()
	cooling := len(e.state.Cooldown)
	e.mu.RUnlock()
	if cooling != 0 {
		t.Fatalf("pause started %d cooldowns", cooling)
	}

	// A paused round makes no new move and says why.
	again := later.Add(time.Second)
	e.Evaluate(round(again), again)
	d, ex, _, ok := e.Explain(pA)
	if !ok || d.Action != ActionCapped || d.Reason != "optimization paused" {
		t.Fatalf("paused decision %+v", d)
	}
	gate := false
	for _, g := range ex.Gates {
		if g.Name == GateCap {
			gate = g.Status == GateFail && g.Limit == "optimization paused"
		}
	}
	if !gate || ex.Counterfactual != "would move to b when optimization resumes" {
		t.Errorf("explain %+v", ex)
	}

	e.SetPaused(false)
	resumed := again.Add(time.Second)
	e.Evaluate(round(resumed), resumed)
	if n := len(e.Improvements()); n != 2 {
		t.Fatalf("improvements after resume = %d", n)
	}
}
