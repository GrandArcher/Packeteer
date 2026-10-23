package policy

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func gateOf(t *testing.T, ex Explain, name string) Gate {
	t.Helper()
	for _, g := range ex.Gates {
		if g.Name == name {
			return g
		}
	}
	t.Fatalf("no %s gate in %+v", name, ex.Gates)
	return Gate{}
}

// explainRound evaluates input once on a fresh engine and explains pA.
func explainRound(t *testing.T, c Config, input Input) Explain {
	t.Helper()
	e := NewEngine(c, scorer(t))
	e.Evaluate(input, t0)
	ex, ok := e.Explain(pA)
	if !ok {
		t.Fatal("no explanation for pA")
	}
	return ex
}

func natA() map[netip.Prefix]string { return map[netip.Prefix]string{pA: "a"} }

func wantGate(t *testing.T, ex Explain, name, status, detail string) Gate {
	t.Helper()
	g := gateOf(t, ex, name)
	if g.Status != status || !strings.Contains(g.Detail+" "+g.Value, detail) {
		t.Fatalf("%s gate = %+v, want %s containing %q", name, g, status, detail)
	}
	return g
}

func TestExplainGateOrder(t *testing.T) {
	ex := explainRound(t, cfg(), in(results(t0, pA, m{"a", 0, 50}, m{"b", 0, 30}), natA()))
	var names []string
	for _, g := range ex.Gates {
		names = append(names, g.Name)
	}
	want := "rib freshness thresholds confirm_rounds hold_time cap policy allowlist route_check rpki"
	if strings.Join(names, " ") != want {
		t.Fatalf("gates = %v, want %s", names, want)
	}
}

func TestExplainMoved(t *testing.T) {
	e := NewEngine(cfg(), scorer(t))
	changes := e.Evaluate(in(results(t0, pA, m{"a", 0, 50}, m{"b", 0, 30}), natA()), t0)
	ex, _ := e.Explain(pA)
	if ex.Outcome != OutcomeMoved || ex.BlockedBy != "" || ex.Counterfactual != "" {
		t.Fatalf("explain = %+v", ex)
	}
	for _, name := range []string{GateRIB, GateFreshness, GateThresholds, GateConfirm, GateHoldTime, GateCap, GatePolicy, GateRouteCheck} {
		if g := gateOf(t, ex, name); g.Status != GatePass {
			t.Fatalf("%s = %+v, want pass", name, g)
		}
	}
	th := gateOf(t, ex, GateThresholds)
	if !strings.Contains(th.Value, "b vs a: loss gain 0 pt, rtt gain 20 ms (40%)") || !strings.Contains(th.Limit, "rtt gain >= 15 ms") {
		t.Fatalf("thresholds = %+v", th)
	}
	if len(changes) != 1 || changes[0].Explain == nil || changes[0].Explain.Outcome != OutcomeMoved {
		t.Fatalf("change explain = %+v", changes)
	}
	roles := map[string]string{}
	for _, s := range ex.Samples {
		roles[s.Provider] = s.Role
	}
	if roles["a"] != "current" || roles["b"] != "challenger" {
		t.Fatalf("roles = %v", roles)
	}
}

func TestExplainRIBGate(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*Input)
		detail string
	}{
		"absent":      {func(i *Input) { i.Native = map[netip.Prefix]string{} }, "not in the learned RIB"},
		"no provider": {func(i *Input) { i.Native = map[netip.Prefix]string{pA: ""} }, "matches no provider"},
	} {
		t.Run(name, func(t *testing.T) {
			input := in(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}), natA())
			tc.mutate(&input)
			ex := explainRound(t, cfg(), input)
			wantGate(t, ex, GateRIB, GateFail, tc.detail)
			if ex.Outcome != OutcomeHeld || ex.BlockedBy != GateRIB || !strings.Contains(ex.Counterfactual, "advertises 198.51.100.0/24") {
				t.Fatalf("explain = %+v", ex)
			}
			wantGate(t, ex, GateThresholds, GateSkip, "not reached")
		})
	}
	input := in(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}), natA())
	input.RIBEnabled = false
	wantGate(t, explainRound(t, cfg(), input), GateRIB, GateSkip, "ranked only")
}

func TestExplainFreshnessGate(t *testing.T) {
	t.Run("current path stale", func(t *testing.T) {
		input := in(results(t0.Add(-10*time.Minute), pA, m{"a", 0, 90}, m{"b", 0, 30}), natA())
		ex := explainRound(t, cfg(), input)
		g := wantGate(t, ex, GateFreshness, GateFail, "a: stale")
		if g.Value != "oldest result 10m0s" || g.Limit != "max_result_age 2m0s" {
			t.Fatalf("freshness = %+v", g)
		}
		if ex.BlockedBy != GateFreshness || !strings.Contains(ex.Counterfactual, "within 2m0s") {
			t.Fatalf("explain = %+v", ex)
		}
	})
	t.Run("better provider stale", func(t *testing.T) {
		res := append(results(t0, pA, m{"a", 0, 90}), results(t0.Add(-10*time.Minute), pA, m{"b", 0, 30})...)
		ex := explainRound(t, cfg(), in(res, natA()))
		wantGate(t, ex, GateFreshness, GateFail, "b would win but has no fresh measurement")
		if ex.BlockedBy != GateFreshness {
			t.Fatalf("blocked by %q", ex.BlockedBy)
		}
	})
	t.Run("probe error on current path", func(t *testing.T) {
		input := in(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}), natA())
		input.Results[0].Err = "boom"
		wantGate(t, explainRound(t, cfg(), input), GateFreshness, GateFail, "a: probe error")
	})
}

func TestExplainThresholdsGate(t *testing.T) {
	t.Run("rtt gain short of the threshold", func(t *testing.T) {
		ex := explainRound(t, cfg(), in(results(t0, pA, m{"a", 0, 50}, m{"b", 0, 40}), natA()))
		g := wantGate(t, ex, GateThresholds, GateFail, "neither threshold is met")
		if !strings.Contains(g.Value, "rtt gain 10 ms") {
			t.Fatalf("thresholds = %+v", g)
		}
		if ex.BlockedBy != GateThresholds {
			t.Fatalf("blocked by %q", ex.BlockedBy)
		}
		want := "would move to b if its RTT delta reached >= 15 ms (now 10 ms) with loss no higher than 0%, or its loss were >= 1 pt lower (now 0 pt)"
		if ex.Counterfactual != want {
			t.Fatalf("counterfactual = %q, want %q", ex.Counterfactual, want)
		}
	})
	t.Run("percent threshold raises the needed delta", func(t *testing.T) {
		c := cfg()
		c.MinRTTDeltaPct = 50
		ex := explainRound(t, c, in(results(t0, pA, m{"a", 0, 100}, m{"b", 0, 70}), natA()))
		g := wantGate(t, ex, GateThresholds, GateFail, "neither threshold is met")
		if !strings.Contains(g.Limit, "rtt gain >= 15 ms and >= 50% of the current rtt") || !strings.Contains(g.Value, "rtt gain 30 ms (30%)") {
			t.Fatalf("thresholds = %+v", g)
		}
		if !strings.Contains(ex.Counterfactual, "RTT delta reached >= 50 ms (now 30 ms)") {
			t.Fatalf("counterfactual = %q", ex.Counterfactual)
		}
	})
	t.Run("score not lower", func(t *testing.T) {
		res := results(t0, pA, m{"a", 0, 60}, m{"b", 0, 40})
		res[1].Stats.Jitter = 500 * time.Millisecond
		ex := explainRound(t, cfg(), in(res, natA()))
		wantGate(t, ex, GateThresholds, GateFail, "score is not lower")
		if !strings.Contains(ex.Counterfactual, "if its score were lower than a") {
			t.Fatalf("counterfactual = %q", ex.Counterfactual)
		}
	})
	t.Run("no second provider", func(t *testing.T) {
		ex := explainRound(t, cfg(), in(results(t0, pA, m{"a", 0, 60}), natA()))
		wantGate(t, ex, GateThresholds, GateFail, "no other provider has a usable measurement")
		if !strings.Contains(ex.Counterfactual, "second provider") {
			t.Fatalf("counterfactual = %q", ex.Counterfactual)
		}
	})
}

func TestExplainConfirmGate(t *testing.T) {
	c := cfg()
	c.ConfirmRounds = 3
	e := NewEngine(c, scorer(t))
	e.Evaluate(in(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}), natA()), t0)
	ex, _ := e.Explain(pA)
	g := wantGate(t, ex, GateConfirm, GateFail, "1 of 3")
	if g.Limit != "3 fresh round(s) in a row" || ex.BlockedBy != GateConfirm || ex.Outcome != OutcomeHeld {
		t.Fatalf("confirm = %+v explain = %+v", g, ex)
	}
	if ex.Counterfactual != "would move to b after 2 more fresh winning round(s)" {
		t.Fatalf("counterfactual = %q", ex.Counterfactual)
	}
	e.Evaluate(in(results(t0.Add(time.Second), pA, m{"a", 0, 90}, m{"b", 0, 30}), natA()), t0.Add(time.Second))
	ex, _ = e.Explain(pA)
	wantGate(t, ex, GateConfirm, GateFail, "2 of 3")
}

func TestExplainHoldTimeGate(t *testing.T) {
	t.Run("active improvement inside hold_time", func(t *testing.T) {
		e := NewEngine(cfg(), scorer(t))
		e.Evaluate(in(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}), natA()), t0)
		at := t0.Add(5 * time.Minute)
		e.Evaluate(in(results(at, pA, m{"a", 0, 20}, m{"b", 0, 90}), natA()), at)
		ex, _ := e.Explain(pA)
		g := wantGate(t, ex, GateHoldTime, GateFail, "held 5m0s")
		if g.Limit != "hold_time 15m0s" || ex.Outcome != OutcomeKept || ex.BlockedBy != GateHoldTime {
			t.Fatalf("hold = %+v explain = %+v", g, ex)
		}
		if ex.Counterfactual != "would be eligible in 10m0s" {
			t.Fatalf("counterfactual = %q", ex.Counterfactual)
		}
		wantGate(t, ex, GateConfirm, GatePass, "flip-back")
	})
	t.Run("flip-back retire carries its checks to history", func(t *testing.T) {
		e := NewEngine(cfg(), scorer(t))
		e.Evaluate(in(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}), natA()), t0)
		flip := t0.Add(20 * time.Minute)
		changes := e.Evaluate(in(results(flip, pA, m{"a", 0, 20}, m{"b", 0, 90}), natA()), flip)
		if len(changes) != 1 || changes[0].Action != ActionRetire || changes[0].Explain == nil {
			t.Fatalf("changes = %+v", changes)
		}
		ex := changes[0].Explain
		if ex.Outcome != OutcomeRetired || ex.BlockedBy != "" || ex.Reason != "native path better again" {
			t.Fatalf("explain = %+v", ex)
		}
		wantGate(t, *ex, GateThresholds, GatePass, "a vs b")
		wantGate(t, *ex, GateHoldTime, GatePass, "held 20m0s")
	})
	t.Run("cooldown after a flip-back", func(t *testing.T) {
		e := NewEngine(cfg(), scorer(t))
		e.Evaluate(in(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}), natA()), t0)
		flip := t0.Add(20 * time.Minute)
		e.Evaluate(in(results(flip, pA, m{"a", 0, 20}, m{"b", 0, 90}), natA()), flip)
		again := flip.Add(time.Minute)
		e.Evaluate(in(results(again, pA, m{"a", 0, 90}, m{"b", 0, 30}), natA()), again)
		ex, _ := e.Explain(pA)
		g := wantGate(t, ex, GateHoldTime, GateFail, "14m0s left")
		if g.Limit != "cooldown after a flip-back (hold_time)" || ex.BlockedBy != GateHoldTime || ex.Outcome != OutcomeHeld {
			t.Fatalf("hold = %+v explain = %+v", g, ex)
		}
	})
	t.Run("flap quarantine", func(t *testing.T) {
		c := cfg()
		c.Flap = FlapConfig{MaxFlips: 3, Window: time.Hour, Cooldown: 30 * time.Minute, MaxCooldown: 4 * time.Hour}
		e := NewEngine(c, scorer(t))
		e.state.quarantine[pA] = Quarantine{Prefix: pA, Since: t0, Until: t0.Add(30 * time.Minute), Flips: 4, Strikes: 1}
		e.Evaluate(in(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}), natA()), t0)
		ex, _ := e.Explain(pA)
		g := wantGate(t, ex, GateHoldTime, GateFail, "30m0s left")
		if g.Limit != "flap quarantine" || ex.BlockedBy != GateHoldTime {
			t.Fatalf("hold = %+v explain = %+v", g, ex)
		}
	})
}

func TestExplainCapGate(t *testing.T) {
	c := cfg()
	c.MaxImprovements = 1
	e := NewEngine(c, scorer(t))
	res := append(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}), results(t0, pB, m{"a", 0, 90}, m{"b", 0, 40})...)
	e.Evaluate(in(res, map[netip.Prefix]string{pA: "a", pB: "a"}), t0)
	moved, _ := e.Explain(pA)
	capped, _ := e.Explain(pB)
	if moved.Outcome != OutcomeMoved || gateOf(t, moved, GateCap).Value != "1 in use" {
		t.Fatalf("moved = %+v", moved)
	}
	g := wantGate(t, capped, GateCap, GateFail, "1 in use")
	if g.Limit != "max_improvements 1" || capped.BlockedBy != GateCap || capped.Outcome != OutcomeHeld {
		t.Fatalf("cap = %+v explain = %+v", g, capped)
	}
	if want := "would move to b when an improvement ends or max_improvements is above 1 (1 in use)"; capped.Counterfactual != want {
		t.Fatalf("counterfactual = %q, want %q", capped.Counterfactual, want)
	}
}

func TestExplainPolicyGate(t *testing.T) {
	res := results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30})
	t.Run("ignore", func(t *testing.T) {
		input := in(res, natA())
		input.Policies = map[netip.Prefix]plugin.PolicyVerdict{pA: {Action: plugin.PolicyIgnore, Rule: "keep-native"}}
		ex := explainRound(t, cfg(), input)
		g := wantGate(t, ex, GatePolicy, GateFail, "native routing")
		if !strings.Contains(g.Value, "ignore") || ex.BlockedBy != GatePolicy {
			t.Fatalf("policy = %+v explain = %+v", g, ex)
		}
	})
	t.Run("deny removes the winner", func(t *testing.T) {
		input := in(res, natA())
		input.Policies = map[netip.Prefix]plugin.PolicyVerdict{pA: {Action: plugin.PolicyDeny, Providers: []string{"b"}, Rule: "no-b"}}
		ex := explainRound(t, cfg(), input)
		wantGate(t, ex, GatePolicy, GateFail, "b would win but the policy does not allow it")
		if ex.BlockedBy != GatePolicy {
			t.Fatalf("blocked by %q", ex.BlockedBy)
		}
	})
	t.Run("maintenance excludes the winner", func(t *testing.T) {
		input := in(res, natA())
		input.Maintenance = []string{"b"}
		ex := explainRound(t, cfg(), input)
		wantGate(t, ex, GatePolicy, GateFail, "b would win but is excluded")
		if ex.BlockedBy != GatePolicy {
			t.Fatalf("blocked by %q", ex.BlockedBy)
		}
	})
	t.Run("no policy", func(t *testing.T) {
		wantGate(t, explainRound(t, cfg(), in(res, natA())), GatePolicy, GatePass, "no routing policy matched")
	})
}

func TestExplainAllowlistGate(t *testing.T) {
	c := cfg()
	c.Mode = "inject"
	c.Allowlist = []netip.Prefix{pB}
	input := in(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}), natA())
	ex := explainRound(t, c, input)
	g := wantGate(t, ex, GateAllowlist, GateFail, "not covered")
	if g.Limit != "allowlist.prefixes" || ex.BlockedBy != GateAllowlist || ex.Outcome != OutcomeHeld {
		t.Fatalf("allowlist = %+v explain = %+v", g, ex)
	}
	if want := "would move to b if allowlist.prefixes covered 198.51.100.0/24"; ex.Counterfactual != want {
		t.Fatalf("counterfactual = %q, want %q", ex.Counterfactual, want)
	}
	c.Allowlist = []netip.Prefix{pA}
	wantGate(t, explainRound(t, c, input), GateAllowlist, GatePass, "covered")
	wantGate(t, explainRound(t, cfg(), input), GateAllowlist, GateSkip, "nothing is announced")
}

func TestExplainRouteCheckGate(t *testing.T) {
	input := in(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}), natA())
	input.NoRoute = map[netip.Prefix]map[string]bool{pA: {"b": true}}
	ex := explainRound(t, cfg(), input)
	wantGate(t, ex, GateRouteCheck, GateFail, "b failed the route check")
	if ex.BlockedBy != GateRouteCheck || ex.Outcome != OutcomeHeld {
		t.Fatalf("explain = %+v", ex)
	}
	input.NoRoute = nil
	input.EgressDown = map[string]bool{"b": true}
	wantGate(t, explainRound(t, cfg(), input), GateRouteCheck, GateFail, "b failed the route check")
}

func TestExplainRPKIGate(t *testing.T) {
	input := in(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}), natA())
	wantGate(t, explainRound(t, cfg(), input), GateRPKI, GateSkip, "RPKI is off")

	input.RPKI = map[netip.Prefix]map[string]plugin.RPKIAnswer{pA: {"b": {State: plugin.RPKIInvalid}}}
	ex := explainRound(t, cfg(), input)
	g := wantGate(t, ex, GateRPKI, GatePass, "b invalid")
	if g.Limit != "display only" || ex.Outcome != OutcomeMoved {
		t.Fatalf("display-only rpki = %+v explain = %+v", g, ex)
	}

	c := cfg()
	c.RPKIAvoidInvalid = true
	ex = explainRound(t, c, input)
	wantGate(t, ex, GateRPKI, GateFail, "b would win but its path is RPKI invalid")
	if ex.BlockedBy != GateRPKI || ex.Outcome != OutcomeHeld {
		t.Fatalf("explain = %+v", ex)
	}
}

// A static pin or a planned move does not use the thresholds or
// confirm_rounds, and says so.
func TestExplainStaticPinSkipsThresholds(t *testing.T) {
	input := in(results(t0, pA, m{"a", 0, 40}, m{"b", 0, 40}), natA())
	input.Policies = map[netip.Prefix]plugin.PolicyVerdict{pA: {Action: plugin.PolicyStatic, Providers: []string{"b"}, Rule: "pin-b", MaxLossPct: 5}}
	ex := explainRound(t, cfg(), input)
	if ex.Outcome != OutcomeMoved {
		t.Fatalf("explain = %+v", ex)
	}
	wantGate(t, ex, GateThresholds, GateSkip, "static policy pin")
	wantGate(t, ex, GateConfirm, GateSkip, "static move")
}

func TestExplainUnknownPrefix(t *testing.T) {
	e := NewEngine(cfg(), scorer(t))
	e.Evaluate(in(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}), natA()), t0)
	if _, ok := e.Explain(pB); ok {
		t.Fatal("explanation for a prefix with no decision")
	}
}

// Every outcome Decide reports for the prefix must agree with its
// explanation: a moved decision has no blocking gate, a held one names the
// gate its counterfactual is about.
func TestExplainAgreesWithDecision(t *testing.T) {
	c := cfg()
	c.ConfirmRounds = 2
	e := NewEngine(c, scorer(t))
	for i, ms := range [][]m{
		{{"a", 0, 90}, {"b", 0, 30}},
		{{"a", 0, 90}, {"b", 0, 30}},
		{{"a", 0, 30}, {"b", 0, 90}},
	} {
		at := t0.Add(time.Duration(i) * time.Minute)
		e.Evaluate(in(results(at, pA, ms...), natA()), at)
		ds, _ := e.Decisions()
		ex, _ := e.Explain(pA)
		switch ds[0].Action {
		case ActionImprove, ActionSwitch:
			if ex.Outcome != OutcomeMoved || ex.BlockedBy != "" {
				t.Fatalf("round %d: %+v vs %+v", i, ds[0], ex)
			}
		case ActionKeep, ActionNone, ActionCapped:
			if ex.BlockedBy == "" || ex.Counterfactual == "" {
				t.Fatalf("round %d: %+v vs %+v", i, ds[0], ex)
			}
		}
		if ex.Reason != ds[0].Reason {
			t.Fatalf("round %d: reason %q != %q", i, ex.Reason, ds[0].Reason)
		}
	}
}
