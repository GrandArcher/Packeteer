package policy

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func verdict(action string, providers ...string) plugin.PolicyVerdict {
	return plugin.PolicyVerdict{Action: action, Providers: providers, Rule: "r1", Match: "prefix 198.51.100.0/24"}
}

func withPolicy(input Input, p netip.Prefix, v plugin.PolicyVerdict) Input {
	if input.Policies == nil {
		input.Policies = map[netip.Prefix]plugin.PolicyVerdict{}
	}
	input.Policies[p] = v
	return input
}

// Native a is slow; b is the fastest alternative, c the second.
func routingInput() Input {
	return in(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}, m{"c", 0, 50}), map[netip.Prefix]string{pA: "a"})
}

func TestRoutingPolicyNewDecisions(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*Input, *Config)
		wantAction string
		wantProv   string
		wantCause  string
		wantReason string
	}{
		{"no policy", nil, ActionImprove, "b", plugin.CausePerformance, "b: loss"},
		{"ignore", func(i *Input, _ *Config) { *i = withPolicy(*i, pA, verdict(plugin.PolicyIgnore)) },
			ActionNone, "", "", "policy ignore (r1)"},
		{"deny best provider", func(i *Input, _ *Config) { *i = withPolicy(*i, pA, verdict(plugin.PolicyDeny, "b")) },
			ActionImprove, "c", plugin.CausePerformance, "c: loss"},
		{"deny every alternative", func(i *Input, _ *Config) { *i = withPolicy(*i, pA, verdict(plugin.PolicyDeny, "b", "c")) },
			ActionNone, "", "", "native path is best"},
		{"deny native does not block steering off it", func(i *Input, _ *Config) { *i = withPolicy(*i, pA, verdict(plugin.PolicyDeny, "a")) },
			ActionImprove, "b", plugin.CausePerformance, ""},
		{"allow one alternative", func(i *Input, _ *Config) { *i = withPolicy(*i, pA, verdict(plugin.PolicyAllow, "c")) },
			ActionImprove, "c", plugin.CausePerformance, ""},
		{"allow only native", func(i *Input, _ *Config) { *i = withPolicy(*i, pA, verdict(plugin.PolicyAllow, "a")) },
			ActionNone, "", "", "native path is best"},
		{"static beats a faster path", func(i *Input, _ *Config) { *i = withPolicy(*i, pA, verdict(plugin.PolicyStatic, "c")) },
			ActionImprove, "c", plugin.CauseStatic, "policy static (r1)"},
		{"static pins native", func(i *Input, _ *Config) { *i = withPolicy(*i, pA, verdict(plugin.PolicyStatic, "a")) },
			ActionNone, "", plugin.CauseStatic, "native is the pinned provider"},
		{"static provider down", func(i *Input, _ *Config) {
			*i = withPolicy(*i, pA, verdict(plugin.PolicyStatic, "c"))
			i.ProviderUp = map[string]bool{"a": true, "b": true}
		}, ActionNone, "", plugin.CauseStatic, "c not usable (provider down)"},
		{"static provider excluded", func(i *Input, c *Config) {
			*i = withPolicy(*i, pA, verdict(plugin.PolicyStatic, "c"))
			c.Excluded = map[string]bool{"c": true}
		}, ActionNone, "", plugin.CauseStatic, "c not usable (excluded)"},
		{"static provider in maintenance", func(i *Input, _ *Config) {
			*i = withPolicy(*i, pA, verdict(plugin.PolicyStatic, "c"))
			i.Maintenance = []string{"c"}
		}, ActionNone, "", plugin.CauseStatic, "c not usable (excluded)"},
		{"static needs the allowlist in inject", func(i *Input, c *Config) {
			*i = withPolicy(*i, pA, verdict(plugin.PolicyStatic, "c"))
			c.Mode, c.Allowlist = "inject", []netip.Prefix{pB}
		}, ActionNone, "", plugin.CauseStatic, "not allowlisted"},
		{"static needs the prefix in the RIB", func(i *Input, _ *Config) {
			*i = withPolicy(*i, pA, verdict(plugin.PolicyStatic, "c"))
			i.Native = map[netip.Prefix]string{}
		}, ActionNone, "", "", "prefix not in RIB"},
		{"static needs a RIB", func(i *Input, _ *Config) {
			*i = withPolicy(*i, pA, verdict(plugin.PolicyStatic, "c"))
			i.RIBEnabled = false
		}, ActionNone, "", "", "ranking only"},
		{"vip still needs the thresholds", func(i *Input, _ *Config) {
			*i = withPolicy(*i, pA, verdict(plugin.PolicyVIP))
			i.Results = results(t0, pA, m{"a", 0, 40}, m{"b", 0, 30})
		}, ActionNone, "", "", "native path is best"},
		{"vip", func(i *Input, _ *Config) { *i = withPolicy(*i, pA, verdict(plugin.PolicyVIP)) },
			ActionImprove, "b", plugin.CausePerformance, ""},
		{"maintenance moves off the best provider", func(i *Input, _ *Config) { i.Maintenance = []string{"b"} },
			ActionImprove, "c", plugin.CausePerformance, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, c := routingInput(), cfg()
			if tt.mutate != nil {
				tt.mutate(&input, &c)
			}
			st, out := Decide(NewState(), input, c, scorer(t), t0)
			d := decision(t, out, pA)
			if d.Action != tt.wantAction || d.Cause != tt.wantCause || !strings.Contains(d.Reason, tt.wantReason) {
				t.Fatalf("decision = %+v", d)
			}
			imp, ok := st.Improvements[pA]
			if tt.wantProv == "" {
				if ok {
					t.Fatalf("unexpected improvement %+v", imp)
				}
				return
			}
			if !ok || imp.Provider != tt.wantProv || imp.Cause != tt.wantCause || imp.Native != "a" {
				t.Fatalf("improvement = %+v", imp)
			}
			if _, hasPolicy := input.Policies[pA]; hasPolicy && d.Policy == "" {
				t.Fatal("decision does not describe the policy")
			}
		})
	}
}

func TestRoutingPolicyActiveImprovement(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*Input)
		wantAction string
		wantProv   string // "" when retired
		wantCause  string
		wantReason string
	}{
		{"no policy keeps", nil, ActionKeep, "b", plugin.CausePerformance, "still valid"},
		{"vip keeps", func(i *Input) { *i = withPolicy(*i, pA, verdict(plugin.PolicyVIP)) }, ActionKeep, "b", plugin.CausePerformance, ""},
		{"ignore retires", func(i *Input) { *i = withPolicy(*i, pA, verdict(plugin.PolicyIgnore)) }, ActionRetire, "", "", "policy ignore"},
		{"deny retires", func(i *Input) { *i = withPolicy(*i, pA, verdict(plugin.PolicyDeny, "b")) }, ActionRetire, "", "", "unusable"},
		{"allow elsewhere retires", func(i *Input) { *i = withPolicy(*i, pA, verdict(plugin.PolicyAllow, "c")) }, ActionRetire, "", "", "unusable"},
		{"allow same keeps", func(i *Input) { *i = withPolicy(*i, pA, verdict(plugin.PolicyAllow, "b")) }, ActionKeep, "b", plugin.CausePerformance, ""},
		{"static on current provider relabels", func(i *Input) { *i = withPolicy(*i, pA, verdict(plugin.PolicyStatic, "b")) }, ActionKeep, "b", plugin.CauseStatic, "policy static"},
		{"static switches at once", func(i *Input) { *i = withPolicy(*i, pA, verdict(plugin.PolicyStatic, "c")) }, ActionSwitch, "c", plugin.CauseStatic, "policy static"},
		{"static to native retires", func(i *Input) { *i = withPolicy(*i, pA, verdict(plugin.PolicyStatic, "a")) }, ActionRetire, "", "", "native is the pinned provider"},
		{"maintenance retires", func(i *Input) { i.Maintenance = []string{"b"} }, ActionRetire, "", "", "provider in maintenance"},
		{"maintenance elsewhere keeps", func(i *Input) { i.Maintenance = []string{"c"} }, ActionKeep, "b", plugin.CausePerformance, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cfg()
			st, _ := Decide(NewState(), routingInput(), c, scorer(t), t0)
			if st.Improvements[pA].Provider != "b" {
				t.Fatalf("setup: %+v", st.Improvements)
			}
			input := routingInput()
			if tt.mutate != nil {
				tt.mutate(&input)
			}
			// Inside hold_time: policy changes must not wait for it.
			now := t0.Add(time.Minute)
			input.Results = results(now, pA, m{"a", 0, 90}, m{"b", 0, 30}, m{"c", 0, 50})
			st, out := Decide(st, input, c, scorer(t), now)
			d := decision(t, out, pA)
			if d.Action != tt.wantAction || !strings.Contains(d.Reason, tt.wantReason) {
				t.Fatalf("decision = %+v", d)
			}
			imp, ok := st.Improvements[pA]
			if tt.wantProv == "" {
				if ok {
					t.Fatalf("not retired: %+v", imp)
				}
				if len(out.Changes) != 1 || out.Changes[0].Action != ActionRetire {
					t.Fatalf("changes = %+v", out.Changes)
				}
				return
			}
			if !ok || imp.Provider != tt.wantProv || imp.Cause != tt.wantCause {
				t.Fatalf("improvement = %+v", imp)
			}
		})
	}
}

func TestMaintenanceMovesImprovementOff(t *testing.T) {
	c := cfg()
	st, _ := Decide(NewState(), routingInput(), c, scorer(t), t0)
	now := t0
	for round := 1; round <= 3; round++ {
		now = now.Add(30 * time.Second)
		input := routingInput()
		input.Results = results(now, pA, m{"a", 0, 90}, m{"b", 0, 30}, m{"c", 0, 50})
		input.Maintenance = []string{"b"}
		var out Output
		st, out = Decide(st, input, c, scorer(t), now)
		for _, ch := range out.Changes {
			if ch.New.Provider == "b" {
				t.Fatalf("round %d: change onto provider in maintenance: %+v", round, ch)
			}
		}
		for _, imp := range st.Improvements {
			if imp.Provider == "b" {
				t.Fatalf("round %d: improvement on provider in maintenance: %+v", round, imp)
			}
		}
	}
	if imp := st.Improvements[pA]; imp.Provider != "c" {
		t.Fatalf("improvement did not move to c: %+v", st.Improvements)
	}
	// The window closes. c stays until a flip is justified; b is usable again.
	now = now.Add(time.Minute)
	input := routingInput()
	input.Results = results(now, pA, m{"a", 0, 90}, m{"b", 0, 30}, m{"c", 0, 50})
	st, _ = Decide(st, input, c, scorer(t), now)
	if st.Improvements[pA].Provider != "c" {
		t.Fatalf("after window: %+v", st.Improvements)
	}
}

// During maintenance no improvement of any cause may point at the excluded
// provider: performance, static, or a planner move.
func TestMaintenanceBlocksEveryCause(t *testing.T) {
	c := commitCfg()
	input := commitInput()
	input.Results = append(results(t0, pA, m{"a", 0, 40}, m{"b", 0, 45}, m{"c", 0, 90}),
		results(t0, pB, m{"a", 0, 90}, m{"b", 0, 30}, m{"c", 0, 60})...)
	input.Results = append(input.Results, results(t0, pC, m{"a", 0, 60}, m{"b", 0, 55}, m{"c", 0, 60})...)
	input.Native = map[netip.Prefix]string{pA: "a", pB: "a", pC: "a"}
	input.Policies = map[netip.Prefix]plugin.PolicyVerdict{pC: verdict(plugin.PolicyStatic, "b")}
	input.Maintenance = []string{"b"}
	moves := []plugin.PlanMove{
		{Prefix: pA, Provider: "b", Reason: "stub", ReliefMbps: 60},
		{Prefix: pB, Provider: "b", Reason: "stub", ReliefMbps: 60},
	}
	st, out := Decide(NewState(), input, c, planBare{moves: moves}, t0)
	for _, imp := range st.Improvements {
		if imp.Provider == "b" {
			t.Fatalf("improvement on provider in maintenance: %+v", imp)
		}
	}
	for _, ch := range out.Changes {
		if ch.New.Provider == "b" {
			t.Fatalf("change onto provider in maintenance: %+v", ch)
		}
	}
	// pB still moves off slow native a, just not onto b.
	if st.Improvements[pB].Provider != "c" {
		t.Fatalf("pB = %+v", st.Improvements[pB])
	}
	if d := decision(t, out, pC); !strings.Contains(d.Reason, "not usable") {
		t.Fatalf("static pC = %+v", d)
	}
}

func TestPolicyFiltersPlannerMoves(t *testing.T) {
	mv := plugin.PlanMove{Prefix: pA, Provider: "b", Reason: "stub", ReliefMbps: 60}
	for _, tt := range []struct {
		name string
		v    plugin.PolicyVerdict
	}{
		{"deny", verdict(plugin.PolicyDeny, "b")},
		{"allow", verdict(plugin.PolicyAllow, "c")},
		{"ignore", verdict(plugin.PolicyIgnore)},
		{"static native", verdict(plugin.PolicyStatic, "a")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := withPolicy(commitInput(), pA, tt.v)
			st, _ := Decide(NewState(), input, commitCfg(), planBare{moves: []plugin.PlanMove{mv}}, t0)
			if imp, ok := st.Improvements[pA]; ok && imp.Provider == "b" {
				t.Fatalf("planner move accepted: %+v", imp)
			}
		})
	}
	// Without a policy the same move is taken, so the stub is not inert.
	st, _ := Decide(NewState(), commitInput(), commitCfg(), planBare{moves: []plugin.PlanMove{mv}}, t0)
	if st.Improvements[pA].Provider != "b" {
		t.Fatalf("control: %+v", st.Improvements)
	}
}

func TestStaticLifecycle(t *testing.T) {
	c := cfg()
	c.ImprovementTTL = 10 * time.Minute
	pin := func(now time.Time, up map[string]bool) Input {
		input := withPolicy(routingInput(), pA, verdict(plugin.PolicyStatic, "c"))
		input.Results = results(now, pA, m{"a", 0, 90}, m{"b", 0, 30}, m{"c", 0, 50})
		if up != nil {
			input.ProviderUp = up
		}
		return input
	}
	st, _ := Decide(NewState(), pin(t0, nil), c, scorer(t), t0)
	if st.Improvements[pA].Cause != plugin.CauseStatic {
		t.Fatalf("not pinned: %+v", st.Improvements)
	}
	// Past improvement_ttl a pin is kept: it does not depend on native.
	now := t0.Add(time.Hour)
	st, out := Decide(st, pin(now, nil), c, scorer(t), now)
	if len(out.Changes) != 0 || st.Improvements[pA].Provider != "c" {
		t.Fatalf("pin churned past ttl: %+v", out.Changes)
	}
	// The pinned path fails: withdraw, and wait out hold_time.
	now = now.Add(time.Minute)
	st, out = Decide(st, pin(now, map[string]bool{"a": true, "b": true}), c, scorer(t), now)
	if _, ok := st.Improvements[pA]; ok || len(out.Changes) != 1 {
		t.Fatalf("not retired: %+v", out.Changes)
	}
	now = now.Add(time.Minute)
	st, out = Decide(st, pin(now, nil), c, scorer(t), now)
	if _, ok := st.Improvements[pA]; ok || !strings.Contains(decision(t, out, pA).Reason, "cooldown") {
		t.Fatalf("re-pinned during cooldown: %+v", decision(t, out, pA))
	}
	now = now.Add(c.HoldTime)
	st, _ = Decide(st, pin(now, nil), c, scorer(t), now)
	if st.Improvements[pA].Provider != "c" {
		t.Fatalf("not re-pinned after hold: %+v", st.Improvements)
	}
	// Policy removed: the pin goes, even inside hold_time.
	now = now.Add(time.Second)
	input := routingInput()
	input.Results = results(now, pA, m{"a", 0, 90}, m{"b", 0, 30}, m{"c", 0, 50})
	st, out = Decide(st, input, c, scorer(t), now)
	if _, ok := st.Improvements[pA]; ok || !strings.Contains(decision(t, out, pA).Reason, "static policy removed") {
		t.Fatalf("pin survived its policy: %+v", decision(t, out, pA))
	}
}

func TestPolicyCapRanking(t *testing.T) {
	c := cfg()
	c.MaxImprovements = 1
	// pA gains far more than pB.
	res := append(results(t0, pA, m{"a", 20, 90}, m{"b", 0, 30}), results(t0, pB, m{"a", 0, 90}, m{"b", 0, 60})...)
	native := map[netip.Prefix]string{pA: "a", pB: "a"}

	st, _ := Decide(NewState(), in(res, native), c, scorer(t), t0)
	if _, ok := st.Improvements[pA]; !ok {
		t.Fatalf("control: biggest gain should win: %+v", st.Improvements)
	}

	vip := withPolicy(in(res, native), pB, verdict(plugin.PolicyVIP))
	st, out := Decide(NewState(), vip, c, scorer(t), t0)
	if _, ok := st.Improvements[pB]; !ok || decision(t, out, pA).Action != ActionCapped {
		t.Fatalf("vip did not take the slot: %+v", st.Improvements)
	}

	static := withPolicy(in(res, native), pB, verdict(plugin.PolicyStatic, "b"))
	static = withPolicy(static, pA, verdict(plugin.PolicyVIP))
	st, _ = Decide(NewState(), static, c, scorer(t), t0)
	if imp := st.Improvements[pB]; imp.Cause != plugin.CauseStatic || len(st.Improvements) != 1 {
		t.Fatalf("static did not take the slot: %+v", st.Improvements)
	}
}

func TestApplyPolicyLeavesNativeAndUnusable(t *testing.T) {
	cands := []Candidate{
		{Provider: "a", Usable: true, Score: 1},
		{Provider: "b", Usable: true, Score: 2},
		{Provider: "c", Usable: false, Why: "stale"},
	}
	applyPolicy(cands, verdict(plugin.PolicyDeny, "a", "b", "c"), "a")
	if !cands[0].Usable || cands[1].Usable || cands[1].Why != "policy deny (r1)" || cands[2].Why != "stale" {
		t.Fatalf("cands = %+v", cands)
	}
}
