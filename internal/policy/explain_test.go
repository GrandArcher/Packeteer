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
	_, ex, _, ok := e.Explain(pA)
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
	want := "rib freshness thresholds confirm_rounds hold_time cap policy allowlist route_check rpki irr"
	if strings.Join(names, " ") != want {
		t.Fatalf("gates = %v, want %s", names, want)
	}
}

func TestExplainMoved(t *testing.T) {
	e := NewEngine(cfg(), scorer(t))
	changes := e.Evaluate(in(results(t0, pA, m{"a", 0, 50}, m{"b", 0, 30}), natA()), t0)
	_, ex, _, _ := e.Explain(pA)
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
	ex := explainRound(t, cfg(), input)
	wantGate(t, ex, GateRIB, GateFail, "ranked only")
	if ex.BlockedBy != GateRIB || !strings.Contains(ex.Counterfactual, "bgp.neighbors") {
		t.Fatalf("no-RIB explain = %+v", ex)
	}
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
	t.Run("max_result_age unset", func(t *testing.T) {
		c := cfg()
		c.MaxResultAge = 0
		input := in(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}), natA())
		input.ProviderUp = map[string]bool{"a": false, "b": true}
		ex := explainRound(t, c, input)
		g := wantGate(t, ex, GateFreshness, GateFail, "a: provider down")
		if g.Limit != "" || ex.BlockedBy != GateFreshness {
			t.Fatalf("freshness = %+v explain = %+v", g, ex)
		}
		if want := "would be compared once every provider has a fresh result and the current path is usable"; ex.Counterfactual != want {
			t.Fatalf("counterfactual = %q, want %q", ex.Counterfactual, want)
		}
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
	t.Run("no threshold configured", func(t *testing.T) {
		c := cfg()
		c.MinLossDeltaPct, c.MinRTTDelta = 0, 0
		ex := explainRound(t, c, in(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}), natA()))
		g := wantGate(t, ex, GateThresholds, GateFail, "no threshold is configured")
		if g.Limit != "no threshold configured" || ex.Counterfactual != "would move to b once thresholds.min_loss_delta_pct or thresholds.min_rtt_delta_ms is set" {
			t.Fatalf("thresholds = %+v counterfactual = %q", g, ex.Counterfactual)
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
	_, ex, _, _ := e.Explain(pA)
	g := wantGate(t, ex, GateConfirm, GateFail, "1 of 3")
	if g.Limit != "3 fresh round(s) in a row" || ex.BlockedBy != GateConfirm || ex.Outcome != OutcomeHeld {
		t.Fatalf("confirm = %+v explain = %+v", g, ex)
	}
	if ex.Counterfactual != "would move to b after 2 more fresh winning round(s)" {
		t.Fatalf("counterfactual = %q", ex.Counterfactual)
	}
	e.Evaluate(in(results(t0.Add(time.Second), pA, m{"a", 0, 90}, m{"b", 0, 30}), natA()), t0.Add(time.Second))
	_, ex, _, _ = e.Explain(pA)
	wantGate(t, ex, GateConfirm, GateFail, "2 of 3")
}

func TestExplainHoldTimeGate(t *testing.T) {
	t.Run("active improvement inside hold_time", func(t *testing.T) {
		e := NewEngine(cfg(), scorer(t))
		e.Evaluate(in(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}), natA()), t0)
		at := t0.Add(5 * time.Minute)
		e.Evaluate(in(results(at, pA, m{"a", 0, 20}, m{"b", 0, 90}), natA()), at)
		_, ex, _, _ := e.Explain(pA)
		g := wantGate(t, ex, GateHoldTime, GateFail, "held 5m0s")
		if g.Limit != "hold_time 15m0s" || ex.Outcome != OutcomeKept || ex.BlockedBy != GateHoldTime {
			t.Fatalf("hold = %+v explain = %+v", g, ex)
		}
		if ex.Counterfactual != "would be eligible in 10m0s" {
			t.Fatalf("counterfactual = %q", ex.Counterfactual)
		}
		wantGate(t, ex, GateConfirm, GatePass, "flip-back")
	})
	t.Run("flip-back retire passes the hold time", func(t *testing.T) {
		e := NewEngine(cfg(), scorer(t))
		e.Evaluate(in(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}), natA()), t0)
		flip := t0.Add(20 * time.Minute)
		changes := e.Evaluate(in(results(flip, pA, m{"a", 0, 20}, m{"b", 0, 90}), natA()), flip)
		if len(changes) != 1 || changes[0].Action != ActionRetire || changes[0].Explain != nil {
			t.Fatalf("changes = %+v", changes)
		}
		_, ex, _, _ := e.Explain(pA)
		if ex.Outcome != OutcomeRetired || ex.BlockedBy != "" || ex.Reason != "native path better again" {
			t.Fatalf("explain = %+v", ex)
		}
		wantGate(t, ex, GateThresholds, GatePass, "a vs b")
		wantGate(t, ex, GateHoldTime, GatePass, "held 20m0s")
	})
	t.Run("cooldown after a flip-back", func(t *testing.T) {
		e := NewEngine(cfg(), scorer(t))
		e.Evaluate(in(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}), natA()), t0)
		flip := t0.Add(20 * time.Minute)
		e.Evaluate(in(results(flip, pA, m{"a", 0, 20}, m{"b", 0, 90}), natA()), flip)
		again := flip.Add(time.Minute)
		e.Evaluate(in(results(again, pA, m{"a", 0, 90}, m{"b", 0, 30}), natA()), again)
		_, ex, _, _ := e.Explain(pA)
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
		_, ex, _, _ := e.Explain(pA)
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
	_, moved, _, _ := e.Explain(pA)
	_, capped, _, _ := e.Explain(pB)
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

// #214: a faster provider whose path is not registered in the IRR is
// refused by irr.prefer_registered, and the explanation names the IRR
// gate, not the thresholds the provider would have passed.
func TestExplainIRRGate(t *testing.T) {
	input := in(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}), natA())
	wantGate(t, explainRound(t, cfg(), input), GateIRR, GateSkip, "IRR is off")

	input.IRR = map[netip.Prefix]map[string]plugin.IRRAnswer{pA: {"b": {State: plugin.IRRNotRegistered, Source: "radb"}}}
	ex := explainRound(t, cfg(), input)
	g := wantGate(t, ex, GateIRR, GatePass, "b not_registered")
	if g.Limit != "display only" || ex.Outcome != OutcomeMoved {
		t.Fatalf("display-only irr = %+v explain = %+v", g, ex)
	}

	c := cfg()
	c.IRRPreferRegistered = true
	ex = explainRound(t, c, input)
	g = wantGate(t, ex, GateIRR, GateFail, "b would win but its path is not registered in the IRR")
	if g.Limit != "prefer_registered: no move onto a not registered path" || ex.BlockedBy != GateIRR || ex.Outcome != OutcomeHeld {
		t.Fatalf("irr = %+v explain = %+v", g, ex)
	}
	if want := "would move if the provider's path were registered in the IRR, or with irr.prefer_registered off"; ex.Counterfactual != want {
		t.Fatalf("counterfactual = %q, want %q", ex.Counterfactual, want)
	}
	wantGate(t, ex, GateThresholds, GateFail, "no other provider has a usable measurement")
	for _, s := range ex.Samples {
		if s.Provider == "b" && (s.Usable || s.Why != "IRR not registered") {
			t.Fatalf("sample b = %+v", s)
		}
	}
}

// A static pin Decide recommended but could not apply was stopped by the
// allowlist or the cooldown, not by the policy that pinned it.
func TestExplainStaticPinStopped(t *testing.T) {
	pin := func(c Config) (Config, Input) {
		input := withPolicy(in(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}, m{"c", 0, 50}), natA()), pA, verdict(plugin.PolicyStatic, "c"))
		c.Mode, c.Allowlist = "inject", []netip.Prefix{pA}
		return c, input
	}
	t.Run("not allowlisted", func(t *testing.T) {
		c, input := pin(cfg())
		c.Allowlist = []netip.Prefix{pB}
		ex := explainRound(t, c, input)
		if ex.Outcome != OutcomeHeld || ex.BlockedBy != GateAllowlist || ex.Reason != "policy static but prefix not allowlisted" {
			t.Fatalf("explain = %+v", ex)
		}
		wantGate(t, ex, GatePolicy, GatePass, "r1")
		wantGate(t, ex, GateAllowlist, GateFail, "not covered")
		wantGate(t, ex, GateHoldTime, GatePass, "no cooldown")
		if want := "would move to c if allowlist.prefixes covered 198.51.100.0/24"; ex.Counterfactual != want {
			t.Fatalf("counterfactual = %q, want %q", ex.Counterfactual, want)
		}
	})
	t.Run("cooldown", func(t *testing.T) {
		c, input := pin(cfg())
		e := NewEngine(c, scorer(t))
		e.state.Cooldown[pA] = t0.Add(10 * time.Minute)
		e.Evaluate(input, t0)
		_, ex, _, _ := e.Explain(pA)
		if ex.BlockedBy != GateHoldTime || !strings.HasPrefix(ex.Reason, "cooldown until") || ex.Counterfactual != "would be eligible in 10m0s" {
			t.Fatalf("explain = %+v", ex)
		}
		wantGate(t, ex, GatePolicy, GatePass, "r1")
		wantGate(t, ex, GateHoldTime, GateFail, "10m0s left")
	})
	t.Run("capped", func(t *testing.T) {
		c, input := pin(cfg())
		c.MaxImprovements, c.Allowlist = 1, []netip.Prefix{pA, pB}
		input.Results = append(input.Results, results(t0, pB, m{"a", 0, 90}, m{"b", 0, 30})...)
		input.Native[pB] = "a"
		e := NewEngine(c, scorer(t))
		e.Evaluate(in(results(t0, pB, m{"a", 0, 90}, m{"b", 0, 30}), map[netip.Prefix]string{pB: "a"}), t0)
		e.Evaluate(input, t0.Add(time.Minute))
		_, ex, _, _ := e.Explain(pA)
		if ex.BlockedBy != GateCap || ex.Outcome != OutcomeHeld {
			t.Fatalf("explain = %+v", ex)
		}
		wantGate(t, ex, GatePolicy, GatePass, "r1")
		wantGate(t, ex, GateCap, GateFail, "1 in use")
		if want := "would move to c when an improvement ends or max_improvements is above 1 (1 in use)"; ex.Counterfactual != want {
			t.Fatalf("counterfactual = %q, want %q", ex.Counterfactual, want)
		}
	})
	t.Run("pin not usable stays a policy hold", func(t *testing.T) {
		c, input := pin(cfg())
		input.ProviderUp = map[string]bool{"a": true, "b": true}
		ex := explainRound(t, c, input)
		if ex.BlockedBy != GatePolicy {
			t.Fatalf("explain = %+v", ex)
		}
		wantGate(t, ex, GatePolicy, GateFail, "c not usable (provider down)")
	})
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
	if _, _, _, ok := e.Explain(pB); ok {
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
		_, ex, _, _ := e.Explain(pA)
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
