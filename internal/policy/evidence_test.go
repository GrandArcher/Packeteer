package policy

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// conf is a rated sample confidence as the probe engine stores it: a full
// reply set from the named prober type.
func conf(protocol string) probe.Confidence {
	c := probe.Confidence{Protocol: protocol, Replies: 10, Sent: 10, Level: probe.ConfidenceMedium, Score: 0.5}
	if c.BeyondICMP() {
		c.Level, c.Score = probe.ConfidenceHigh, 1
	}
	return c
}

// measured is results() with a prober type per provider, in order.
func measured(at time.Time, p netip.Prefix, protocols []string, ms ...m) []probe.Result {
	out := results(at, p, ms...)
	for i := range out {
		out[i].Confidence = conf(protocols[i])
	}
	return out
}

func candidate(t *testing.T, d Decision, name string) Candidate {
	t.Helper()
	c, ok := findCandidate(d.Candidates, name)
	if !ok {
		t.Fatalf("no candidate %s in %+v", name, d.Candidates)
	}
	return c
}

func TestRequireEvidenceOffKeepsICMPMoves(t *testing.T) {
	input := in(measured(t0, pA, []string{"icmp", "icmp"}, m{"a", 0, 50}, m{"b", 0, 30}), natA())
	_, out := Decide(NewState(), input, cfg(), scorer(t), t0)
	d := decision(t, out, pA)
	if d.Action != ActionImprove || len(out.Changes) != 1 {
		t.Fatalf("icmp-only win with the rule off = %+v", d)
	}
	// Every candidate carries its confidence, with no passive state when
	// no span or flow source observed the prefix.
	for _, name := range []string{"a", "b"} {
		if c := candidate(t, d, name).Confidence; c.Protocol != "icmp" || c.Level != probe.ConfidenceMedium || c.Passive != "" {
			t.Fatalf("candidate %s confidence = %+v", name, c)
		}
	}
}

func TestRequireEvidenceRefusesICMPOnlyWin(t *testing.T) {
	c := cfg()
	c.RequireEvidence = true
	c.ConfirmRounds = 2
	cases := []struct {
		name      string
		protocols []string
		action    string
		reason    string
	}{
		{"both icmp", []string{"icmp", "icmp"}, ActionNone, "require_evidence: no evidence beyond ICMP for a (icmp, 10/10 replies) and b (icmp, 10/10 replies)"},
		{"challenger tcp, native icmp", []string{"icmp", "tcp"}, ActionNone, "require_evidence: no evidence beyond ICMP for a (icmp, 10/10 replies)"},
		{"native udp, challenger icmp", []string{"udp", "icmp"}, ActionNone, "require_evidence: no evidence beyond ICMP for b (icmp, 10/10 replies)"},
		{"exec prober is not beyond icmp", []string{"exec", "tcp"}, ActionNone, "require_evidence: no evidence beyond ICMP for a (exec, 10/10 replies)"},
		{"both tcp", []string{"tcp", "tcp"}, ActionNone, "confirming b (1/2)"},
		{"tcp and udp", []string{"udp", "tcp"}, ActionNone, "confirming b (1/2)"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			input := in(measured(t0, pA, tt.protocols, m{"a", 0, 50}, m{"b", 0, 30}), natA())
			st, out := Decide(NewState(), input, c, scorer(t), t0)
			d := decision(t, out, pA)
			if d.Action != tt.action || d.Reason != tt.reason || d.Recommended != "b" || len(out.Changes) != 0 {
				t.Fatalf("decision = %+v changes = %+v", d, out.Changes)
			}
			// An ICMP-only win does not start the confirm streak; a win with
			// evidence does.
			_, streak := st.confirm[pA]
			if streak != strings.HasPrefix(tt.reason, "confirming") {
				t.Fatalf("confirm streak = %v for %q", streak, tt.reason)
			}
		})
	}
}

func TestRequireEvidenceICMPOnlyWinNeverImproves(t *testing.T) {
	// Acceptance (#202): with the rule on an ICMP-only win does not create
	// an improvement, at the default confirm_rounds and over later rounds.
	c := cfg()
	c.RequireEvidence = true
	st := NewState()
	for i := range 3 {
		at := t0.Add(time.Duration(i) * time.Minute)
		var out Output
		st, out = Decide(st, in(measured(at, pA, []string{"icmp", "icmp"}, m{"a", 5, 50}, m{"b", 0, 30}), natA()), c, scorer(t), at)
		if d := decision(t, out, pA); d.Action != ActionNone || len(out.Changes) != 0 || len(st.Improvements) != 0 {
			t.Fatalf("round %d: %+v", i, d)
		}
	}
}

func TestPassiveAgreementStandsInForTCP(t *testing.T) {
	c := cfg()
	c.RequireEvidence = true
	// The native path shows loss and the span or flow source sees the
	// prefix as a problem: the two agree, so the ICMP sample on the native
	// path counts as evidence.
	input := in(measured(t0, pA, []string{"icmp", "tcp"}, m{"a", 5, 50}, m{"b", 0, 30}), natA())
	input.Passive = map[netip.Prefix]bool{pA: true}
	_, out := Decide(NewState(), input, c, scorer(t), t0)
	d := decision(t, out, pA)
	if d.Action != ActionImprove {
		t.Fatalf("agreeing passive evidence did not allow the move: %+v", d)
	}
	a, b := candidate(t, d, "a").Confidence, candidate(t, d, "b").Confidence
	if a.Passive != probe.PassiveAgree || a.Level != probe.ConfidenceHigh || !a.BeyondICMP() {
		t.Fatalf("native confidence = %+v", a)
	}
	// Passive traffic flows on the native path only, so the challenger's
	// confidence is unchanged.
	if b.Passive != "" || b.Level != probe.ConfidenceHigh {
		t.Fatalf("challenger confidence = %+v", b)
	}

	// The native path shows ICMP loss but the observed TCP traffic is
	// clean: the loss is not trusted and the move is refused.
	input.Passive = map[netip.Prefix]bool{pA: false}
	_, out = Decide(NewState(), input, c, scorer(t), t0)
	d = decision(t, out, pA)
	if d.Action != ActionNone || !strings.Contains(d.Reason, "a (icmp, 10/10 replies, passive disagrees)") {
		t.Fatalf("disagreeing passive evidence = %+v", d)
	}
	if a := candidate(t, d, "a").Confidence; a.Passive != probe.PassiveDisagree || a.Level != probe.ConfidenceLow {
		t.Fatalf("native confidence = %+v", a)
	}

	// Clean on both sides agrees too: an RTT win on a lossless native path.
	input = in(measured(t0, pA, []string{"icmp", "tcp"}, m{"a", 0, 50}, m{"b", 0, 30}), natA())
	input.Passive = map[netip.Prefix]bool{pA: false}
	_, out = Decide(NewState(), input, c, scorer(t), t0)
	if d := decision(t, out, pA); d.Action != ActionImprove || candidate(t, d, "a").Confidence.Passive != probe.PassiveAgree {
		t.Fatalf("clean passive and clean probe = %+v", d)
	}
}

func TestPassiveFollowsTheCarrier(t *testing.T) {
	res := measured(t0, pA, []string{"icmp", "icmp"}, m{"a", 0, 50}, m{"b", 0, 20})
	st := NewState()
	st.Improvements[pA] = Improvement{Prefix: pA, Provider: "b", Native: "a", Since: t0.Add(-time.Hour), Cause: plugin.CausePerformance}
	input := in(res, natA())
	input.Passive = map[netip.Prefix]bool{pA: false}

	// Observe: the router still forwards on the native path, so passive
	// evidence describes a.
	_, out := Decide(st, input, cfg(), scorer(t), t0)
	d := decision(t, out, pA)
	if candidate(t, d, "a").Confidence.Passive != probe.PassiveAgree || candidate(t, d, "b").Confidence.Passive != "" {
		t.Fatalf("observe: %+v", d.Candidates)
	}

	// Inject: the improvement's provider carries the traffic.
	c := cfg()
	c.Mode, c.Allowlist = "inject", []netip.Prefix{pA}
	_, out = Decide(st, input, c, scorer(t), t0)
	d = decision(t, out, pA)
	if candidate(t, d, "b").Confidence.Passive != probe.PassiveAgree || candidate(t, d, "a").Confidence.Passive != "" {
		t.Fatalf("inject: %+v", d.Candidates)
	}

	// A failed sample on the carrier takes no passive state.
	bad := measured(t0, pA, []string{"icmp", "icmp"}, m{"a", 0, 50}, m{"b", 0, 20})
	bad[0].Err, bad[0].Confidence = "boom", probe.Confidence{Level: probe.ConfidenceNone}
	input = in(bad, natA())
	input.Passive = map[netip.Prefix]bool{pA: true}
	_, out = Decide(NewState(), input, cfg(), scorer(t), t0)
	if a := candidate(t, decision(t, out, pA), "a").Confidence; a.Passive != "" || a.Level != probe.ConfidenceNone {
		t.Fatalf("failed sample = %+v", a)
	}
}

func TestRequireEvidenceOnPerformanceSwitch(t *testing.T) {
	c := cfg()
	c.RequireEvidence = true
	active := func() State {
		st := NewState()
		st.Improvements[pA] = Improvement{Prefix: pA, Provider: "b", Native: "a", Since: t0.Add(-time.Hour), Cause: plugin.CausePerformance}
		return st
	}
	native := map[netip.Prefix]string{pA: "a"}

	// c beats the current b, but c is measured by ICMP only: the switch is
	// refused and the improvement stays on b.
	res := measured(t0, pA, []string{"icmp", "tcp", "icmp"}, m{"a", 0, 90}, m{"b", 0, 50}, m{"c", 0, 20})
	st, out := Decide(active(), in(res, native), c, scorer(t), t0)
	d := decision(t, out, pA)
	if d.Action != ActionKeep || d.Reason != "require_evidence: no evidence beyond ICMP for c (icmp, 10/10 replies)" || d.Recommended != "c" || len(out.Changes) != 0 || st.Improvements[pA].Provider != "b" {
		t.Fatalf("switch onto an icmp-only path = %+v changes = %+v", d, out.Changes)
	}

	// Measured by TCP, the switch happens after hold_time.
	res = measured(t0, pA, []string{"icmp", "tcp", "tcp"}, m{"a", 0, 90}, m{"b", 0, 50}, m{"c", 0, 20})
	st, out = Decide(active(), in(res, native), c, scorer(t), t0)
	if d := decision(t, out, pA); d.Action != ActionSwitch || st.Improvements[pA].Provider != "c" {
		t.Fatalf("switch with evidence = %+v", d)
	}

	// Flip-back is a withdraw and does not wait for evidence: the native
	// path measured by ICMP only still retires the improvement.
	res = measured(t0, pA, []string{"icmp", "tcp"}, m{"a", 0, 20}, m{"b", 0, 50})
	st, out = Decide(active(), in(res, native), c, scorer(t), t0)
	if d := decision(t, out, pA); d.Action != ActionRetire || d.Reason != "native path better again" || len(st.Improvements) != 0 {
		t.Fatalf("flip-back = %+v", d)
	}
}

func TestExplainEvidenceGate(t *testing.T) {
	input := in(measured(t0, pA, []string{"icmp", "tcp"}, m{"a", 0, 50}, m{"b", 0, 30}), natA())
	ex := explainRound(t, cfg(), input)
	g := wantGate(t, ex, GateEvidence, GatePass, "a: icmp, 10/10 replies; b: tcp, 10/10 replies")
	if g.Limit != "display only" || ex.Outcome != OutcomeMoved {
		t.Fatalf("display-only evidence = %+v explain = %+v", g, ex)
	}
	for _, s := range ex.Samples {
		want := map[string][2]string{"a": {probe.ConfidenceMedium, "icmp, 10/10 replies"}, "b": {probe.ConfidenceHigh, "tcp, 10/10 replies"}}[s.Provider]
		if s.Confidence != want[0] || s.Evidence != want[1] {
			t.Fatalf("sample = %+v", s)
		}
	}

	c := cfg()
	c.RequireEvidence = true
	ex = explainRound(t, c, input)
	g = wantGate(t, ex, GateEvidence, GateFail, "no evidence beyond ICMP for a (icmp, 10/10 replies)")
	if g.Limit != "require_evidence: a tcp or udp reply, or passive agreement, on both paths" || ex.BlockedBy != GateEvidence || ex.Outcome != OutcomeHeld {
		t.Fatalf("evidence = %+v explain = %+v", g, ex)
	}
	if want := "would move to b once a is measured by a tcp or udp reply or agrees with passive TCP evidence, or with thresholds.require_evidence off"; ex.Counterfactual != want {
		t.Fatalf("counterfactual = %q", ex.Counterfactual)
	}
	wantGate(t, ex, GateThresholds, GatePass, "b vs a")
	wantGate(t, ex, GateConfirm, GateSkip, "not reached: thresholds.require_evidence refused the move")
	wantGate(t, ex, GateHoldTime, GateSkip, "not reached: thresholds.require_evidence refused the move")

	// With passive agreement on the native path the gate passes and the
	// sample says so.
	input.Passive = map[netip.Prefix]bool{pA: false}
	ex = explainRound(t, c, input)
	wantGate(t, ex, GateEvidence, GatePass, "a: icmp, 10/10 replies, passive agrees; b: tcp, 10/10 replies")
	if ex.Outcome != OutcomeMoved {
		t.Fatalf("explain = %+v", ex)
	}

	// No challenger: the gate is not reached.
	ex = explainRound(t, c, in(measured(t0, pA, []string{"icmp"}, m{"a", 0, 50}), natA()))
	wantGate(t, ex, GateEvidence, GateSkip, "not reached: no other provider has a usable measurement")

	// A static pin does not use the rule.
	input = in(measured(t0, pA, []string{"icmp", "icmp"}, m{"a", 0, 50}, m{"b", 0, 30}), natA())
	input.Policies = map[netip.Prefix]plugin.PolicyVerdict{pA: {Action: plugin.PolicyStatic, Providers: []string{"b"}, Rule: "pin-b"}}
	ex = explainRound(t, c, input)
	wantGate(t, ex, GateEvidence, GateSkip, "a static policy pin does not use the evidence rule")
	if ex.Outcome != OutcomeMoved {
		t.Fatalf("static pin with the rule on = %+v", ex)
	}
}

func TestRequireEvidenceLeavesCostAndCooldown(t *testing.T) {
	c := costCfg()
	c.RequireEvidence = true
	icmp := []string{"icmp", "icmp", "icmp"}

	// Cost precedence: the performance move to b is refused, and the cost
	// planner still steers to the cheapest path inside the floor.
	input := in(measured(t0, pA, icmp, m{"a", 0, 90}, m{"b", 0, 30}, m{"c", 0, 35}), natA())
	st, out := Decide(NewState(), input, c, costScorer(t, "precedence: cost"), t0)
	if imp := st.Improvements[pA]; imp.Provider != "c" || imp.Cause != plugin.CauseCost {
		t.Fatalf("cost steer with the rule on = %+v (decision %+v)", imp, decision(t, out, pA))
	}

	// A cheap native path inside the floor keeps its cost reason.
	for i, cost := range []float64{1, 5, 8} {
		c.Providers[i].Cost = cost
	}
	input = in(measured(t0, pA, icmp, m{"a", 0, 50}, m{"b", 0, 30}, m{"c", 0, 60}), natA())
	st, out = Decide(NewState(), input, c, costScorer(t, "precedence: cost\nfloor: {max_rtt: 25ms}"), t0)
	if d := decision(t, out, pA); d.Reason != "native path inside performance floor (cost precedence)" || d.Cause != plugin.CauseCost || len(st.Improvements) != 0 {
		t.Fatalf("cheap native inside the floor = %+v", d)
	}

	// A cooldown after flip-back is named, not the rule.
	c = cfg()
	c.RequireEvidence = true
	st = NewState()
	st.Cooldown[pA] = t0.Add(10 * time.Minute)
	_, out = Decide(st, in(measured(t0, pA, icmp, m{"a", 0, 50}, m{"b", 0, 30}), natA()), c, scorer(t), t0)
	if d := decision(t, out, pA); !strings.HasPrefix(d.Reason, "cooldown after flip-back until ") {
		t.Fatalf("cooldown with the rule on = %+v", d)
	}
}

func TestExplainEvidenceOnlyWhenRefused(t *testing.T) {
	c := cfg()
	c.RequireEvidence = true

	// Flip-back inside hold_time: the native path is ICMP only, but
	// flip-back does not use the rule, so hold_time holds it.
	e := NewEngine(c, scorer(t))
	e.Evaluate(in(measured(t0, pA, []string{"tcp", "tcp"}, m{"a", 0, 90}, m{"b", 0, 30}), natA()), t0)
	at := t0.Add(5 * time.Minute)
	e.Evaluate(in(measured(at, pA, []string{"icmp", "icmp"}, m{"a", 0, 20}, m{"b", 0, 90}), natA()), at)
	_, ex, _, _ := e.Explain(pA)
	if ex.Reason != "native better but hold_time not elapsed" || ex.BlockedBy != GateHoldTime || ex.Counterfactual != "would be eligible in 10m0s" {
		t.Fatalf("flip-back in hold_time = %+v", ex)
	}
	wantGate(t, ex, GateEvidence, GateSkip, "not used: a flip-back to the native path does not wait for evidence")
	wantGate(t, ex, GateHoldTime, GateFail, "held 5m0s")

	// Thresholds not met: the rule was never reached.
	c.MinRTTDelta = 30 * time.Millisecond
	ex = explainRound(t, c, in(measured(t0, pA, []string{"icmp", "icmp"}, m{"a", 0, 50}, m{"b", 0, 30}), natA()))
	if ex.BlockedBy != GateThresholds {
		t.Fatalf("thresholds not met = %+v", ex)
	}
	wantGate(t, ex, GateEvidence, GateSkip, "not reached: no better path passed the thresholds")
	for _, n := range []string{GateConfirm, GateHoldTime, GateCap} {
		wantGate(t, ex, n, GateSkip, "not reached: no better path passed the thresholds")
	}

	// A cooldown stops the move before the rule.
	c = cfg()
	c.RequireEvidence = true
	e = NewEngine(c, scorer(t))
	e.Evaluate(in(measured(t0, pA, []string{"tcp", "tcp"}, m{"a", 0, 90}, m{"b", 0, 30}), natA()), t0)
	flip := t0.Add(20 * time.Minute)
	e.Evaluate(in(measured(flip, pA, []string{"tcp", "tcp"}, m{"a", 0, 20}, m{"b", 0, 90}), natA()), flip)
	again := flip.Add(time.Minute)
	e.Evaluate(in(measured(again, pA, []string{"icmp", "icmp"}, m{"a", 0, 90}, m{"b", 0, 30}), natA()), again)
	_, ex, _, _ = e.Explain(pA)
	if !strings.HasPrefix(ex.Reason, "cooldown after flip-back until ") || ex.BlockedBy != GateHoldTime {
		t.Fatalf("cooldown = %+v", ex)
	}
	wantGate(t, ex, GateEvidence, GateSkip, "not reached: cooldown after flip-back until ")
}

func TestRequireEvidenceOnSwitchOffPlannedSteer(t *testing.T) {
	at := t0.Add(time.Hour)
	for _, cause := range []string{plugin.CauseCommit, plugin.CauseCost} {
		t.Run(cause, func(t *testing.T) {
			c := cfg()
			c.RequireEvidence = true
			c.Providers = []ProviderPolicy{{Name: "a", Cost: 10, HasCost: true}, {Name: "b", Cost: 5, HasCost: true}, {Name: "c", Cost: 2, HasCost: true}}
			stay := []plugin.PlanMove{{Prefix: pA, Provider: "c", Cause: cause, Reason: "plan c", ReliefMbps: 60, Savings: 1}}
			r := &rogueCost{rogue{moves: stay}}
			e := NewEngine(c, r)
			tcp := []string{"tcp", "tcp", "tcp"}
			e.Evaluate(in(measured(t0, pA, tcp, m{"a", 0, 40}, m{"b", 0, 50}, m{"c", 0, 45}), natA()), t0)

			// b beats the native path, but a and b are ICMP only: no
			// performance switch, and the planner keeps its steer on c.
			e.Evaluate(in(measured(at, pA, []string{"icmp", "icmp", "tcp"}, m{"a", 0, 90}, m{"b", 0, 30}, m{"c", 0, 35}), natA()), at)
			d, ex, _, _ := e.Explain(pA)
			if d.Action != ActionKeep || d.Current != "c" || d.Cause != cause || d.Reason != "plan c" {
				t.Fatalf("refused switch = %+v", d)
			}
			wantGate(t, ex, GateEvidence, GateSkip, "refused a performance switch: no evidence beyond ICMP for a (icmp, 10/10 replies) and b (icmp, 10/10 replies)")

			// Measured by TCP, the same win switches to b.
			e.Evaluate(in(measured(at.Add(time.Minute), pA, tcp, m{"a", 0, 90}, m{"b", 0, 30}, m{"c", 0, 35}), natA()), at.Add(time.Minute))
			if d, _, _, _ := e.Explain(pA); d.Action != ActionSwitch || d.Current != "b" || d.Cause != plugin.CausePerformance {
				t.Fatalf("switch with evidence = %+v", d)
			}
		})
	}
}
