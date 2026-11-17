package policy

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// portCfg has a transit "a" over its commit and two peers of an exchange
// port "ix" (#151). The peers carry no telemetry of their own; the port's
// row is named like the exchange.
func portCfg(capacity, commit float64) Config {
	c := cfg()
	zero := ProviderPolicy{Cost: 0, HasCost: true}
	pa, pb := zero, zero
	pa.Name, pa.Port = "ix-a", "ix"
	pb.Name, pb.Port = "ix-b", "ix"
	c.Providers = []ProviderPolicy{{Name: "a", Precedence: 10, Cost: 10, HasCost: true}, pa, pb}
	c.Ports = []PortPolicy{{Name: "ix", CapacityMbps: capacity, CommitMbps: commit}}
	return c
}

func portInput(rows ...plugin.Usage) Input {
	input := in(results(t0, pA, m{"a", 0, 40}, m{"ix-a", 0, 45}, m{"ix-b", 0, 45}), map[netip.Prefix]string{pA: "a"})
	input.ProviderUp = map[string]bool{"a": true, "ix-a": true, "ix-b": true}
	input.Usage = append([]plugin.Usage{billable("a", 100, 150)}, rows...)
	input.VolumeMbps = map[netip.Prefix]float64{pA: 60}
	return input
}

func TestCommitSteersOntoPortOnlyWhileThePortHasRoom(t *testing.T) {
	// Port: 500 of a 600 Mbps commit, 1000 Mbps capacity. 60 Mbps fits.
	st, out := Decide(NewState(), portInput(billable("ix", 1, 500)), portCfg(1000, 600), commitScorer(t, ""), t0)
	imp := st.Improvements[pA]
	if d := decision(t, out, pA); d.Action != ActionImprove || imp.Cause != plugin.CauseCommit || (imp.Provider != "ix-a" && imp.Provider != "ix-b") {
		t.Fatalf("decision %+v improvement %+v", d, imp)
	}
	// 560 of 600: the same move would push the port over its commit.
	st, out = Decide(NewState(), portInput(billable("ix", 1, 560)), portCfg(1000, 600), commitScorer(t, ""), t0)
	if len(st.Improvements) != 0 || decision(t, out, pA).Action != ActionNone {
		t.Fatalf("a move over the port commit was made: %+v %+v", decision(t, out, pA), st.Improvements)
	}
	// No telemetry row for the port: headroom unknown, nothing moves.
	st, _ = Decide(NewState(), portInput(), portCfg(1000, 600), commitScorer(t, ""), t0)
	if len(st.Improvements) != 0 {
		t.Fatalf("a move onto a port with no reading was made: %+v", st.Improvements)
	}
}

func TestCostSteersOntoFlatPricedPortUntilCapacity(t *testing.T) {
	c := portCfg(1000, 0)
	input := portInput(billable("ix", 1, 100))
	st, _ := Decide(NewState(), input, c, costScorer(t, ""), t0)
	imp := st.Improvements[pA]
	if imp.Cause != plugin.CauseCost || (imp.Provider != "ix-a" && imp.Provider != "ix-b") {
		t.Fatalf("improvement %+v, want a cost steer onto a port peer", imp)
	}
	// 960 of 1000 Mbps in use: 60 more would exceed the port.
	st, _ = Decide(NewState(), portInput(billable("ix", 1, 960)), c, costScorer(t, ""), t0)
	if len(st.Improvements) != 0 {
		t.Fatalf("a cost move over the port capacity was made: %+v", st.Improvements)
	}
}

// perfPortInput has ix-a 30 ms faster than native transit a for pA, which
// carries vol Mbps. rows are the telemetry rows, the port's among them.
func perfPortInput(at time.Time, vol float64, rows ...plugin.Usage) Input {
	input := in(results(at, pA, m{"a", 0, 60}, m{"ix-a", 0, 30}, m{"ix-b", 0, 45}), map[netip.Prefix]string{pA: "a"})
	input.ProviderUp = map[string]bool{"a": true, "ix-a": true, "ix-b": true}
	input.Usage = rows
	if vol > 0 {
		input.WeightVolumeMbps = map[netip.Prefix]float64{pA: vol}
	}
	return input
}

func TestPerformanceMoveOntoPortNeedsHeadroom(t *testing.T) {
	for _, mode := range []string{"observe", "inject"} {
		c := portCfg(1000, 600)
		c.Mode, c.Allowlist = mode, []netip.Prefix{pA}
		for _, tc := range []struct {
			name string
			in   Input
			want string // reason prefix of a refusal, "" for a move
		}{
			{"room under capacity and commit", perfPortInput(t0, 60, billable("ix", 1, 500)), ""},
			{"over the commit", perfPortInput(t0, 60, billable("ix", 1, 560)), "exchange port: ix 95th would reach 620 of its 600 Mbps commit with this 60 Mbps steer onto ix-a"},
			{"over the capacity", perfPortInput(t0, 60, func() plugin.Usage { u := billable("ix", 1, 300); u.OutMbps = 960; return u }()),
				"exchange port: ix would carry 1020 of its 1000 Mbps capacity with this 60 Mbps steer onto ix-a"},
			{"no port row", perfPortInput(t0, 60), "exchange port: ix: no port telemetry, so no new steer goes onto ix-a"},
			{"stale port row", perfPortInput(t0, 60, billable("ix", 1, 100)), "exchange port: ix: port reading is stale"},
			{"no volume", perfPortInput(t0, 0, billable("ix", 1, 100)), "exchange port: ix: the prefix has no known volume"},
		} {
			now := t0
			if tc.name == "stale port row" {
				now = t0.Add(time.Hour)
				tc.in = perfPortInput(now, 60, billable("ix", 1, 100))
			}
			st, out := Decide(NewState(), tc.in, c, scorer(t), now)
			d := decision(t, out, pA)
			if tc.want == "" {
				if imp := st.Improvements[pA]; d.Action != ActionImprove || imp.Provider != "ix-a" || imp.Cause != plugin.CausePerformance {
					t.Fatalf("%s %s: decision %+v improvement %+v, want a performance move to ix-a", mode, tc.name, d, imp)
				}
				continue
			}
			if len(st.Improvements) != 0 || d.Action != ActionNone || d.Recommended != "ix-a" || !strings.HasPrefix(d.Reason, tc.want) {
				t.Fatalf("%s %s: decision %+v improvements %+v, want refused with %q", mode, tc.name, d, st.Improvements, tc.want)
			}
			if i, ok := findDecision(out.Decisions, pA); !ok || buildExplain(out.Decisions[i], out.facts[i], c, 0).BlockedBy != GatePort {
				t.Fatalf("%s %s: explanation does not name the port gate", mode, tc.name)
			}
		}
	}
}

func TestPortBooksEveryMoveOfOneEvaluation(t *testing.T) {
	// Two prefixes of 60 Mbps; the port has 500 of a 600 Mbps commit, so
	// only the first in prefix order fits.
	c := portCfg(1000, 600)
	input := perfPortInput(t0, 60, billable("ix", 1, 500))
	input.Results = append(input.Results, results(t0, pB, m{"a", 0, 60}, m{"ix-a", 0, 30}, m{"ix-b", 0, 45})...)
	input.Native[pB] = "a"
	input.WeightVolumeMbps[pB] = 60
	st, out := Decide(NewState(), input, c, scorer(t), t0)
	if st.Improvements[pA].Provider != "ix-a" || len(st.Improvements) != 1 {
		t.Fatalf("improvements %+v, want only pA on ix-a", st.Improvements)
	}
	if d := decision(t, out, pB); !strings.HasPrefix(d.Reason, "exchange port: ix 95th would reach 620") {
		t.Fatalf("pB decision %+v, want refused by the port", d)
	}
}

func TestPortCountsSteersTheSampleDoesNotHold(t *testing.T) {
	// pA was steered onto ix-a at t0. The port row of the next round is
	// stamped at t0, before the steer could show in it. A 60 Mbps pB then
	// fits 500+60 of 600 only if pA's 60 is not counted.
	later := t0.Add(time.Minute)
	for _, tc := range []struct {
		mode    string
		since   time.Time
		refused bool
	}{
		{"observe", t0.Add(-time.Hour), true}, // nothing is on the wire in observe
		{"inject", t0.Add(-time.Hour), false}, // in the sample
		{"inject", t0.Add(time.Second), true}, // newer than the sample
	} {
		c := portCfg(1000, 600)
		c.Mode, c.Allowlist = tc.mode, []netip.Prefix{pA, pB}
		st := NewState()
		st.Improvements[pA] = Improvement{Prefix: pA, Provider: "ix-a", Native: "a", Since: tc.since, Cause: plugin.CausePerformance}
		input := perfPortInput(later, 60, billable("ix", 1, 500))
		input.Results = append(input.Results, results(later, pB, m{"a", 0, 60}, m{"ix-a", 0, 30}, m{"ix-b", 0, 45})...)
		input.Native[pB] = "a"
		input.WeightVolumeMbps[pB] = 60
		next, out := Decide(st, input, c, scorer(t), later)
		_, moved := next.Improvements[pB]
		if moved == tc.refused || next.Improvements[pA].Provider != "ix-a" {
			t.Fatalf("%s since %s: improvements %+v decision %+v, refused want %v", tc.mode, tc.since, next.Improvements, decision(t, out, pB), tc.refused)
		}
	}
}

func TestSwitchBetweenPeersOfOnePortIsNotChecked(t *testing.T) {
	// The port is over its commit, but moving pA from ix-b to ix-a keeps
	// its traffic on the same port.
	c := portCfg(1000, 600)
	st := NewState()
	st.Improvements[pA] = Improvement{Prefix: pA, Provider: "ix-b", Native: "a", Since: t0, Cause: plugin.CausePerformance}
	later := t0.Add(time.Hour)
	input := in(results(later, pA, m{"a", 0, 90}, m{"ix-a", 0, 20}, m{"ix-b", 0, 60}), map[netip.Prefix]string{pA: "a"})
	input.ProviderUp = map[string]bool{"a": true, "ix-a": true, "ix-b": true}
	input.Usage = []plugin.Usage{func() plugin.Usage { u := billable("ix", 1, 700); u.Updated = later; return u }()}
	input.WeightVolumeMbps = map[netip.Prefix]float64{pA: 60}
	next, out := Decide(st, input, c, scorer(t), later)
	if next.Improvements[pA].Provider != "ix-a" {
		t.Fatalf("improvement %+v decision %+v, want a switch to ix-a", next.Improvements[pA], decision(t, out, pA))
	}
}

func TestPinOntoPortNeedsHeadroom(t *testing.T) {
	pinned := func(u plugin.Usage) Input {
		input := perfPortInput(t0, 60, u)
		// Equal paths: only the pin moves the prefix.
		input.Results = results(t0, pA, m{"a", 0, 40}, m{"ix-a", 0, 40}, m{"ix-b", 0, 40})
		input.Policies = map[netip.Prefix]plugin.PolicyVerdict{pA: {Action: plugin.PolicyStatic, Providers: []string{"ix-b"}, Rule: "api pin-1", MaxLossPct: 5}}
		return input
	}
	c := portCfg(1000, 600)
	st, _ := Decide(NewState(), pinned(billable("ix", 1, 500)), c, scorer(t), t0)
	if imp := st.Improvements[pA]; imp.Provider != "ix-b" || imp.Cause != plugin.CauseStatic {
		t.Fatalf("improvement %+v, want the pin on ix-b", imp)
	}
	st, out := Decide(NewState(), pinned(billable("ix", 1, 580)), c, scorer(t), t0)
	d := decision(t, out, pA)
	if len(st.Improvements) != 0 || !strings.HasPrefix(d.Reason, "exchange port: ix 95th would reach 640 of its 600 Mbps commit") {
		t.Fatalf("decision %+v improvements %+v, want the pin refused by the port", d, st.Improvements)
	}
	i, _ := findDecision(out.Decisions, pA)
	if ex := buildExplain(out.Decisions[i], out.facts[i], c, 0); ex.BlockedBy != GatePort || !strings.Contains(ex.Counterfactual, "exchange port has room") {
		t.Fatalf("explain %+v, want blocked by the port", ex)
	}
}

func TestEnginePortRefusal(t *testing.T) {
	e := NewEngine(portCfg(1000, 600), scorer(t))
	if why := e.PortRefusal(pA, "ix-a", t0); !strings.Contains(why, "ix: no port telemetry") {
		t.Fatalf("before any evaluation: %q, want refused for no reading", why)
	}
	input := perfPortInput(t0, 60, billable("ix", 1, 580))
	input.Results = results(t0, pA, m{"a", 0, 40}, m{"ix-a", 0, 40}, m{"ix-b", 0, 40})
	e.Evaluate(input, t0)
	if why := e.PortRefusal(pA, "ix-a", t0); !strings.HasPrefix(why, "exchange port: ix 95th would reach 640 of its 600 Mbps commit") {
		t.Fatalf("full port: %q", why)
	}
	if why := e.PortRefusal(pA, "a", t0); why != "" {
		t.Fatalf("a transit is not on a port: %q", why)
	}
}

func TestNothingMovesOffAPortOverItsCommit(t *testing.T) {
	// The port is at 700 of its 600 Mbps commit and pA sits on ix-a's
	// native path; transit a has room. The port is report only: no commit
	// or cost move takes pA off it.
	c := portCfg(1000, 600)
	for _, name := range []string{"commit", "cost"} {
		sc := commitScorer(t, "")
		if name == "cost" {
			sc = costScorer(t, "")
		}
		input := in(results(t0, pA, m{"a", 0, 40}, m{"ix-a", 0, 40}, m{"ix-b", 0, 40}), map[netip.Prefix]string{pA: "ix-a"})
		input.ProviderUp = map[string]bool{"a": true, "ix-a": true, "ix-b": true}
		input.Usage = []plugin.Usage{billable("a", 1000, 100), billable("ix", 1, 700)}
		input.VolumeMbps = map[netip.Prefix]float64{pA: 60}
		st, out := Decide(NewState(), input, c, sc, t0)
		if len(st.Improvements) != 0 || len(out.Changes) != 0 {
			t.Fatalf("%s: improvements %+v, want none off the port", name, st.Improvements)
		}
	}
}

func TestActiveSteerSwitchOntoPortNeedsHeadroom(t *testing.T) {
	// pA is steered to transit b. A pin onto ix-b (static) and a faster
	// ix-a under a commit steer (performance) each want to move it onto the
	// port; neither may while the port is full, and the steer stays on b.
	later := t0.Add(time.Hour)
	row := func(name string, commit, p95 float64) plugin.Usage {
		u := billable(name, commit, p95)
		u.Updated = later
		return u
	}
	for _, cause := range []string{plugin.CauseStatic, plugin.CauseCommit} {
		c := portCfg(1000, 600)
		c.Providers = append(c.Providers, ProviderPolicy{Name: "b", Precedence: 10, Cost: 10, HasCost: true})
		sc := scorer(t)
		if cause == plugin.CauseCommit {
			sc = commitScorer(t, "")
		}
		for _, tc := range []struct {
			p95  float64
			want string
		}{{580, "b"}, {100, "ix-a"}} {
			st := NewState()
			st.Improvements[pA] = Improvement{Prefix: pA, Provider: "b", Native: "a", Since: t0, Cause: cause}
			input := in(results(later, pA, m{"a", 0, 90}, m{"b", 0, 80}, m{"ix-a", 0, 20}, m{"ix-b", 0, 80}), map[netip.Prefix]string{pA: "a"})
			input.ProviderUp = map[string]bool{"a": true, "b": true, "ix-a": true, "ix-b": true}
			input.Usage = []plugin.Usage{row("a", 100, 150), row("b", 1000, 100), row("ix", 1, tc.p95)}
			input.VolumeMbps = map[netip.Prefix]float64{pA: 60}
			if cause == plugin.CauseStatic {
				tc.want = map[string]string{"b": "b", "ix-a": "ix-b"}[tc.want]
				input.Policies = map[netip.Prefix]plugin.PolicyVerdict{pA: {Action: plugin.PolicyStatic, Providers: []string{"ix-b"}, Rule: "api pin-1", MaxLossPct: 5}}
			}
			next, out := Decide(st, input, c, sc, later)
			d := decision(t, out, pA)
			if next.Improvements[pA].Provider != tc.want {
				t.Fatalf("%s port at %v: improvement %+v decision %+v, want on %s", cause, tc.p95, next.Improvements[pA], d, tc.want)
			}
			if tc.want == "b" && (d.Action != ActionKeep || !strings.HasPrefix(d.Reason, portRefused)) {
				t.Fatalf("%s port at %v: decision %+v, want kept with the port as the reason", cause, tc.p95, d)
			}
		}
	}
}

func TestSteerBackOntoItsNativePortIsCounted(t *testing.T) {
	// pB's native exit is ix-a, on the port, and it is steered to transit
	// b. This round pB comes back onto the port, by a retire to its native
	// path or a switch to ix-b, and pA wants 60 Mbps onto ix-a. The port
	// reads 500 of its 600 Mbps commit. In inject pB is not in that reading,
	// so pA would take the port to 620 and is refused. In observe nothing
	// moved, the reading holds pB, and pA fits.
	later := t0.Add(time.Hour)
	for _, back := range []struct {
		name         string
		ixA, b, ixB  float64
		wantProvider string
	}{
		{"retire to native", 30, 80, 90, ""},
		{"switch to ix-b", 80, 70, 40, "ix-b"},
	} {
		for _, tc := range []struct {
			mode    string
			refused bool
		}{{"observe", false}, {"inject", true}} {
			c := portCfg(1000, 600)
			c.Mode, c.Allowlist = tc.mode, []netip.Prefix{pA, pB}
			c.Providers = append(c.Providers, ProviderPolicy{Name: "b", Precedence: 10})
			st := NewState()
			st.Improvements[pB] = Improvement{Prefix: pB, Provider: "b", Native: "ix-a", Since: t0, Cause: plugin.CausePerformance}
			input := in(results(later, pA, m{"a", 0, 60}, m{"b", 0, 60}, m{"ix-a", 0, 30}, m{"ix-b", 0, 45}), map[netip.Prefix]string{pA: "a", pB: "ix-a"})
			input.Results = append(input.Results, results(later, pB, m{"a", 0, 90}, m{"b", 0, back.b}, m{"ix-a", 0, back.ixA}, m{"ix-b", 0, back.ixB})...)
			input.ProviderUp = map[string]bool{"a": true, "b": true, "ix-a": true, "ix-b": true}
			u := billable("ix", 1, 500)
			u.Updated = later.Add(-time.Second)
			input.Usage = []plugin.Usage{u}
			input.WeightVolumeMbps = map[netip.Prefix]float64{pA: 60, pB: 60}
			next, out := Decide(st, input, c, scorer(t), later)
			if got := next.Improvements[pB].Provider; got != back.wantProvider {
				t.Fatalf("%s %s: pB on %q, want %q (%+v)", back.name, tc.mode, got, back.wantProvider, decision(t, out, pB))
			}
			d := decision(t, out, pA)
			_, moved := next.Improvements[pA]
			if moved == tc.refused || (tc.refused && !strings.HasPrefix(d.Reason, "exchange port: ix 95th would reach 620 of its 600 Mbps commit")) {
				t.Fatalf("%s %s: pA decision %+v moved %v, refused want %v", back.name, tc.mode, d, moved, tc.refused)
			}
		}
	}
}

func TestPlannedMoveHoldsPortRoomUnderCostPrecedence(t *testing.T) {
	// Cost precedence: the cost planner moves pB (native transit a, 60
	// Mbps) onto the flat-priced port without seeing pA's performance move
	// (pA's native c has no cost, so the planner leaves pA alone). The port
	// has 60 Mbps of room under its commit, so pA's move onto ix-a is
	// refused.
	c := portCfg(1000, 600)
	c.Providers = append(c.Providers, ProviderPolicy{Name: "c", Precedence: 10})
	input := in(results(t0, pA, m{"a", 0, 60}, m{"c", 0, 60}, m{"ix-a", 0, 30}, m{"ix-b", 0, 60}), map[netip.Prefix]string{pA: "c", pB: "a"})
	input.Results = append(input.Results, results(t0, pB, m{"a", 0, 40}, m{"c", 0, 40}, m{"ix-a", 0, 40}, m{"ix-b", 0, 40})...)
	input.ProviderUp = map[string]bool{"a": true, "c": true, "ix-a": true, "ix-b": true}
	input.Usage = []plugin.Usage{billable("a", 1000, 100), billable("ix", 1, 540)}
	input.VolumeMbps = map[netip.Prefix]float64{pA: 60, pB: 60}
	st, out := Decide(NewState(), input, c, costScorer(t, "precedence: cost\n"), t0)
	if imp := st.Improvements[pB]; imp.Cause != plugin.CauseCost || (imp.Provider != "ix-a" && imp.Provider != "ix-b") {
		t.Fatalf("pB improvement %+v, want a cost move onto the port (%+v)", imp, decision(t, out, pB))
	}
	if d := decision(t, out, pA); len(st.Improvements) != 1 || !strings.HasPrefix(d.Reason, "exchange port: ix 95th would reach 660 of its 600 Mbps commit") {
		t.Fatalf("improvements %+v pA decision %+v, want pA refused by the port", st.Improvements, d)
	}
	// In inject with pB outside the allowlist the cost move is not queued
	// and gives its room back: pA's performance move fits.
	c.Mode, c.Allowlist = "inject", []netip.Prefix{pA}
	st, out = Decide(NewState(), input, c, costScorer(t, "precedence: cost\n"), t0)
	if imp := st.Improvements[pA]; imp.Provider != "ix-a" || len(st.Improvements) != 1 {
		t.Fatalf("improvements %+v pA decision %+v, want only pA's move onto ix-a", st.Improvements, decision(t, out, pA))
	}
}

func TestHoldSwitchSeesTheRoundsPlannedMoves(t *testing.T) {
	// pB is a commit steer on transit b (native a) and ix-a is now much
	// faster, so it switches for performance. The planner also plans a new
	// commit move of pA (60 Mbps) off a onto the port. The port reads 500 of
	// its 600 Mbps commit: room for one of the two.
	later := t0.Add(time.Hour)
	row := func(name string, commit, p95 float64) plugin.Usage {
		u := billable(name, commit, p95)
		u.Updated = later
		return u
	}
	c := portCfg(1000, 600)
	c.Providers = append(c.Providers, ProviderPolicy{Name: "b", Precedence: 1000})
	st := NewState()
	st.Improvements[pB] = Improvement{Prefix: pB, Provider: "b", Native: "a", Since: t0, Cause: plugin.CauseCommit}
	input := in(results(later, pA, m{"a", 0, 40}, m{"b", 0, 40}, m{"ix-a", 0, 40}, m{"ix-b", 0, 40}), map[netip.Prefix]string{pA: "a", pB: "a"})
	input.Results = append(input.Results, results(later, pB, m{"a", 0, 90}, m{"b", 0, 90}, m{"ix-a", 0, 20}, m{"ix-b", 0, 90})...)
	input.ProviderUp = map[string]bool{"a": true, "b": true, "ix-a": true, "ix-b": true}
	input.Usage = []plugin.Usage{row("a", 100, 190), row("b", 1000, 990), row("ix", 1, 500)}
	input.VolumeMbps = map[netip.Prefix]float64{pA: 60, pB: 60}
	next, out := Decide(st, input, c, commitScorer(t, ""), later)
	onPort := 0
	for _, imp := range next.Improvements {
		if imp.Provider == "ix-a" || imp.Provider == "ix-b" {
			onPort++
		}
	}
	if onPort != 1 || next.Improvements[pA].Provider != "ix-a" || next.Improvements[pB].Provider != "b" {
		t.Fatalf("improvements %+v, want only pA's planned move on the port", next.Improvements)
	}
	if d := decision(t, out, pB); d.Action != ActionKeep || !strings.HasPrefix(d.Reason, "exchange port: ix 95th would reach 620 of its 600 Mbps commit") {
		t.Fatalf("pB decision %+v, want the switch refused by the port", d)
	}
}
