package policy

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// ovCfg limits provider b to 85% of its interface capacity in inject mode.
func ovCfg() Config {
	c := cfg()
	c.Mode = "inject"
	c.Allowlist = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24")}
	c.HoldTime = time.Minute
	c.Providers = []ProviderPolicy{{Name: "a"}, {Name: "b", CapacityThresholdPct: 85}, {Name: "c"}}
	return c
}

// ovInput measures a at 100 ms and b at 40 ms for pA (a gain of 60) and a
// at 60 ms and b at 40 ms for pB (a gain of 20), with b's interface at
// outMbps of 1000 Mbps and each prefix carrying vol Mbps.
func ovInput(at time.Time, outMbps, vol float64) Input {
	res := append(results(at, pA, m{"a", 0, 100}, m{"b", 0, 40}), results(at, pB, m{"a", 0, 60}, m{"b", 0, 40})...)
	input := in(res, map[netip.Prefix]string{pA: "a", pB: "a"})
	input.Load = map[string]Load{"b": {CapacityMbps: 1000, OutMbps: outMbps, Updated: at}}
	input.WeightVolumeMbps = map[netip.Prefix]float64{pA: vol, pB: vol}
	return input
}

func TestOverloadRefusesSteerThatPassesTheLimit(t *testing.T) {
	// 800 + 60 Mbps is 86% of 1000, over the 85% limit: both are refused.
	st, out := Decide(NewState(), ovInput(t0, 800, 60), ovCfg(), scorer(t), t0)
	if len(st.Improvements) != 0 {
		t.Fatalf("a steer past the limit was made: %+v", st.Improvements)
	}
	if len(out.Overloads) != 2 {
		t.Fatalf("overloads = %+v, want one refusal per prefix", out.Overloads)
	}
	o := out.Overloads[0]
	if o.Action != OverloadRefused || o.Provider != "b" || o.Prefix != pA || o.UsedPct != 80 || o.ProjectedPct != 86 || o.LimitPct != 85 || o.VolumeMbps != 60 {
		t.Fatalf("overload = %+v", o)
	}
	d := decision(t, out, pA)
	if d.Action != ActionNone || d.Recommended != "b" || !strings.HasPrefix(d.Reason, overloadRefused+"b would reach 86% of its 1000 Mbps interface") {
		t.Fatalf("decision = %+v", d)
	}
	// 800 + 40 Mbps is 84%: allowed. A second prefix of the same size is not.
	st, out = Decide(NewState(), ovInput(t0, 800, 40), ovCfg(), scorer(t), t0)
	if _, ok := st.Improvements[pA]; !ok || len(st.Improvements) != 1 {
		t.Fatalf("a steer inside the limit was refused: %+v", st.Improvements)
	}
	if len(out.Overloads) != 1 || out.Overloads[0].Prefix != pB {
		t.Fatalf("overloads = %+v, want only pB refused", out.Overloads)
	}
}

func TestOverloadCountsSteersAdmittedInTheSameRound(t *testing.T) {
	// Each prefix is 30 Mbps. 800 + 30 = 83% passes; the second would make 86%.
	st, out := Decide(NewState(), ovInput(t0, 800, 30), ovCfg(), scorer(t), t0)
	if _, ok := st.Improvements[pA]; !ok || len(st.Improvements) != 1 {
		t.Fatalf("improvements = %+v, want only the larger gain pA", st.Improvements)
	}
	if len(out.Overloads) != 1 || out.Overloads[0].Prefix != pB || out.Overloads[0].UsedPct != 83 {
		t.Fatalf("overloads = %+v, want pB refused at 83%% used", out.Overloads)
	}
}

func TestOverloadWithoutAReadingTakesNoSteer(t *testing.T) {
	for name, mutate := range map[string]func(*Input){
		"no row":        func(i *Input) { i.Load = nil },
		"no capacity":   func(i *Input) { i.Load["b"] = Load{OutMbps: 10, Updated: t0} },
		"stale reading": func(i *Input) { i.Load["b"] = Load{CapacityMbps: 1000, OutMbps: 10, Updated: t0.Add(-time.Hour)} },
	} {
		input := ovInput(t0, 10, 10)
		mutate(&input)
		st, out := Decide(NewState(), input, ovCfg(), scorer(t), t0)
		if len(st.Improvements) != 0 || len(out.Overloads) != 2 || !strings.HasPrefix(out.Overloads[0].Reason, overloadRefused+"b: ") {
			t.Errorf("%s: improvements %+v overloads %+v", name, st.Improvements, out.Overloads)
		}
	}
}

func TestOverloadLeavesUnlimitedProvidersAndOtherCausesAlone(t *testing.T) {
	c := ovCfg()
	c.Providers[1].CapacityThresholdPct = 0
	st, out := Decide(NewState(), ovInput(t0, 990, 60), c, scorer(t), t0)
	if len(st.Improvements) != 2 || len(out.Overloads) != 0 {
		t.Fatalf("no limit: improvements %+v overloads %+v", st.Improvements, out.Overloads)
	}
	// A static pin is the operator's choice and is not refused.
	input := ovInput(t0, 990, 60)
	input.Policies = map[netip.Prefix]plugin.PolicyVerdict{pA: {Action: plugin.PolicyStatic, Providers: []string{"b"}, Rule: "pin", MaxLossPct: 100}}
	st, out = Decide(NewState(), input, ovCfg(), scorer(t), t0)
	if imp := st.Improvements[pA]; imp.Cause != plugin.CauseStatic || imp.Provider != "b" {
		t.Fatalf("static pin = %+v, want it on b", imp)
	}
	for _, o := range out.Overloads {
		if o.Prefix == pA {
			t.Fatalf("a static pin was refused: %+v", o)
		}
	}
}

// steered returns a state with pA and pB steered to b at t0.
func steered(t *testing.T) State {
	t.Helper()
	st, _ := Decide(NewState(), ovInput(t0, 100, 60), ovCfg(), scorer(t), t0)
	if len(st.Improvements) != 2 {
		t.Fatalf("setup: improvements = %+v", st.Improvements)
	}
	return st
}

func TestOverloadShedsLowestGainFirstAfterHoldTime(t *testing.T) {
	st := steered(t)
	// b is at 90%: 900 Mbps. Shedding pB (60 Mbps) brings it to 84%.
	later := t0.Add(2 * time.Minute)
	next, out := Decide(st, ovInput(later, 900, 60), ovCfg(), scorer(t), later)
	if _, ok := next.Improvements[pB]; ok {
		t.Fatalf("the lowest-gain steer was kept: %+v", next.Improvements)
	}
	if _, ok := next.Improvements[pA]; !ok {
		t.Fatalf("the higher-gain steer was shed too: %+v", next.Improvements)
	}
	if len(out.Overloads) != 1 {
		t.Fatalf("overloads = %+v", out.Overloads)
	}
	o := out.Overloads[0]
	if o.Action != OverloadShed || o.Prefix != pB || o.UsedPct != 90 || o.ProjectedPct != 84 || o.Provider != "b" {
		t.Fatalf("overload = %+v", o)
	}
	d := decision(t, out, pB)
	if d.Action != ActionRetire || !strings.Contains(d.Reason, "steer shed, lowest gain first") {
		t.Fatalf("decision = %+v", d)
	}
	if until := next.Cooldown[pB]; !until.Equal(later.Add(time.Minute)) {
		t.Fatalf("cooldown = %v, want hold_time after the shed", until)
	}
	// The shed prefix is not steered back while b is full or in cooldown.
	again := later.Add(10 * time.Second)
	next, _ = Decide(next, ovInput(again, 900, 60), ovCfg(), scorer(t), again)
	if _, ok := next.Improvements[pB]; ok {
		t.Fatalf("the shed prefix came back: %+v", next.Improvements)
	}
}

// sheds counts the steers an evaluation shed.
func sheds(out Output) int {
	n := 0
	for _, o := range out.Overloads {
		if o.Action == OverloadShed {
			n++
		}
	}
	return n
}

func TestOverloadKeepsASteerInsideHoldTime(t *testing.T) {
	st := steered(t)
	soon := t0.Add(30 * time.Second)
	next, out := Decide(st, ovInput(soon, 990, 60), ovCfg(), scorer(t), soon)
	if len(next.Improvements) != 2 || len(out.Overloads) != 0 {
		t.Fatalf("shed inside hold_time: %+v %+v", next.Improvements, out.Overloads)
	}
}

func TestOverloadShedsOncePerSample(t *testing.T) {
	st := steered(t)
	shedAt := t0.Add(2 * time.Minute)
	// b stays at 99%: pB's 60 Mbps leaves it at 93%, still over the limit.
	st, out := Decide(st, ovInput(shedAt, 990, 60), ovCfg(), scorer(t), shedAt)
	if sheds(out) != 2 || len(st.Improvements) != 0 {
		t.Fatalf("overloads = %+v improvements = %+v, want both shed", out.Overloads, st.Improvements)
	}
	// With one steer left, a second look at the same sample must not shed
	// again: re-steer one and check.
	st = steered(t)
	st, out = Decide(st, ovInput(shedAt, 900, 60), ovCfg(), scorer(t), shedAt)
	if sheds(out) != 1 || len(st.Improvements) != 1 {
		t.Fatalf("first look: overloads = %+v improvements = %+v", out.Overloads, st.Improvements)
	}
	// The same reading again, past hold_time: the shed is not in it yet.
	input := ovInput(shedAt, 900, 60)
	later := shedAt.Add(2 * time.Minute)
	st, out = Decide(st, input, ovCfg(), scorer(t), later)
	if sheds(out) != 0 || len(st.Improvements) != 1 {
		t.Fatalf("same sample shed again: overloads = %+v improvements = %+v", out.Overloads, st.Improvements)
	}
	// A newer sample inside hold_time of the shed is not enough either.
	fresh := shedAt.Add(30 * time.Second)
	st, out = Decide(st, ovInput(fresh, 900, 60), ovCfg(), scorer(t), fresh)
	if sheds(out) != 0 || len(st.Improvements) != 1 {
		t.Fatalf("shed inside hold_time of the last shed: overloads = %+v improvements = %+v", out.Overloads, st.Improvements)
	}
	// A newer sample after hold_time that is still over the limit sheds.
	fresh = shedAt.Add(2 * time.Minute)
	st, out = Decide(st, ovInput(fresh, 900, 60), ovCfg(), scorer(t), fresh)
	if sheds(out) != 1 || len(st.Improvements) != 0 {
		t.Fatalf("second shed: overloads = %+v improvements = %+v", out.Overloads, st.Improvements)
	}
}

func TestOverloadCountsSteersTheSampleDoesNotHold(t *testing.T) {
	// pA was steered at t0 with 60 Mbps; the sample b reports is older, so
	// its 760 Mbps does not hold pA yet. pB (60 more) would make 880, while
	// 760 + 60 alone would be allowed.
	st, _ := Decide(NewState(), ovInput(t0, 100, 60), func() Config { c := ovCfg(); c.Providers[1].CapacityThresholdPct = 0; return c }(), scorer(t), t0)
	if len(st.Improvements) != 2 {
		t.Fatalf("setup: %+v", st.Improvements)
	}
	delete(st.Improvements, pB)
	now := t0.Add(time.Minute)
	input := ovInput(now, 760, 60)
	input.Load["b"] = Load{CapacityMbps: 1000, OutMbps: 760, Updated: t0.Add(-time.Second)}
	_, out := Decide(st, input, ovCfg(), scorer(t), now)
	var got *Overload
	for i := range out.Overloads {
		if out.Overloads[i].Prefix == pB {
			got = &out.Overloads[i]
		}
	}
	if got == nil || got.Action != OverloadRefused || got.UsedPct != 82 {
		t.Fatalf("overloads = %+v, want pB refused with pA's 60 Mbps counted (82%% used)", out.Overloads)
	}
	// Observe mode moves no traffic, so the recommendation adds nothing.
	c := ovCfg()
	c.Mode = "observe"
	_, out = Decide(st, input, c, scorer(t), now)
	if len(out.Overloads) != 0 {
		t.Fatalf("observe counted a steer that is not on the wire: %+v", out.Overloads)
	}
}

func TestOverloadRefusesSwitchOntoFullProvider(t *testing.T) {
	// pA is steered to c. Later b is faster and its interface is nearly full.
	c := ovCfg()
	c.Providers = append(c.Providers, ProviderPolicy{Name: "d"})
	first := in(results(t0, pA, m{"a", 0, 200}, m{"b", 0, 150}, m{"c", 0, 40}), map[netip.Prefix]string{pA: "a"})
	st, _ := Decide(NewState(), first, c, scorer(t), t0)
	if st.Improvements[pA].Provider != "c" {
		t.Fatalf("setup: %+v", st.Improvements)
	}
	later := t0.Add(2 * time.Minute)
	second := in(results(later, pA, m{"a", 0, 200}, m{"b", 0, 10}, m{"c", 0, 40}), map[netip.Prefix]string{pA: "a"})
	second.Load = map[string]Load{"b": {CapacityMbps: 1000, OutMbps: 860, Updated: later}}
	second.WeightVolumeMbps = map[netip.Prefix]float64{pA: 10}
	next, out := Decide(st, second, c, scorer(t), later)
	d := decision(t, out, pA)
	if next.Improvements[pA].Provider != "c" || d.Action != ActionKeep || d.Recommended != "b" || !strings.HasPrefix(d.Reason, overloadRefused) {
		t.Fatalf("improvement %+v decision %+v, want the steer kept on c and the switch refused", next.Improvements[pA], d)
	}
	if len(out.Overloads) != 1 || out.Overloads[0].Action != OverloadRefused {
		t.Fatalf("overloads = %+v", out.Overloads)
	}
	// With room on b the switch goes ahead.
	second.Load["b"] = Load{CapacityMbps: 1000, OutMbps: 300, Updated: later}
	next, _ = Decide(st, second, c, scorer(t), later)
	if next.Improvements[pA].Provider != "b" {
		t.Fatalf("improvement = %+v, want a switch to b", next.Improvements[pA])
	}
}

func TestOverloadRefusalExplained(t *testing.T) {
	_, out := Decide(NewState(), ovInput(t0, 800, 60), ovCfg(), scorer(t), t0)
	i, ok := findDecision(out.Decisions, pA)
	if !ok {
		t.Fatal("no decision for pA")
	}
	ex := buildExplain(out.Decisions[i], out.facts[i], ovCfg(), 0)
	if ex.BlockedBy != GateOverload || ex.Outcome != OutcomeHeld {
		t.Fatalf("blocked by %q outcome %q, want %s held", ex.BlockedBy, ex.Outcome, GateOverload)
	}
	var found bool
	for _, g := range ex.Gates {
		switch g.Name {
		case GateOverload:
			found = g.Status == GateFail && strings.Contains(g.Detail, "would reach 86%")
		case GateCap:
			if g.Status != GateSkip {
				t.Errorf("cap gate = %+v, want skipped", g)
			}
		}
	}
	if !found {
		t.Fatalf("gates = %+v, want a failed overload gate", ex.Gates)
	}
	if !strings.Contains(ex.Counterfactual, "interface_capacity_threshold_pct") {
		t.Fatalf("counterfactual = %q", ex.Counterfactual)
	}
	// A decision the limit did not touch lists no overload gate.
	_, plain := Decide(NewState(), ovInput(t0, 100, 10), ovCfg(), scorer(t), t0)
	j, _ := findDecision(plain.Decisions, pA)
	for _, g := range buildExplain(plain.Decisions[j], plain.facts[j], ovCfg(), 1).Gates {
		if g.Name == GateOverload {
			t.Fatalf("overload gate listed for a decision it did not refuse: %+v", g)
		}
	}
}
