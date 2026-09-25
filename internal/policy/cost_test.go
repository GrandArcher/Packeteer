package policy

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/cost"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func costScorer(t *testing.T, y string) plugin.Scorer {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	s, err := cost.New(c, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// costCfg prices a at 10, b at 5, and c at 2 per Mbps.
func costCfg() Config {
	c := cfg()
	c.Providers = []ProviderPolicy{
		{Name: "a", Cost: 10, HasCost: true},
		{Name: "b", Cost: 5, HasCost: true},
		{Name: "c", Cost: 2, HasCost: true},
	}
	return c
}

func TestCostCheapestWinsOnlyInsideFloor(t *testing.T) {
	for _, tc := range []struct {
		name   string
		scorer string
		native string
		paths  []m
		mutate func(*Config, *Input)
		want   string // provider of the cost steer; "" means none
	}{
		{name: "cheaper inside floor", native: "a",
			paths: []m{{"a", 0, 40}, {"b", 0, 45}, {"c", 0, 80}}, want: "b"},
		{name: "cheapest inside floor wins", native: "a",
			paths: []m{{"a", 0, 40}, {"b", 0, 45}, {"c", 0, 48}}, want: "c"},
		{name: "cheaper path outside rtt floor", native: "a",
			paths: []m{{"a", 0, 40}, {"b", 0, 55}, {"c", 0, 80}}},
		{name: "cheaper path outside loss floor", native: "a",
			paths: []m{{"a", 0, 40}, {"b", 0.5, 40}, {"c", 0.5, 40}}},
		{name: "loss floor widened", native: "a", scorer: "floor: {max_loss_pct: 1}",
			paths: []m{{"a", 0, 40}, {"b", 0.5, 40}, {"c", 2, 40}}, want: "b"},
		{name: "rtt floor widened", native: "a", scorer: "floor: {max_rtt: 50ms}",
			paths: []m{{"a", 0, 40}, {"b", 0, 55}, {"c", 0, 80}}, want: "c"},
		{name: "native already cheapest", native: "c",
			paths: []m{{"a", 0, 40}, {"b", 0, 40}, {"c", 0, 40}}},
		{name: "native has no cost", native: "a",
			paths:  []m{{"a", 0, 40}, {"b", 0, 40}, {"c", 0, 40}},
			mutate: func(c *Config, _ *Input) { c.Providers[0].HasCost = false }},
		{name: "cheaper provider has no cost", native: "a",
			paths:  []m{{"a", 0, 40}, {"b", 0, 40}, {"c", 0, 80}},
			mutate: func(c *Config, _ *Input) { c.Providers[1].HasCost = false }},
		{name: "cheaper provider excluded", native: "a",
			paths:  []m{{"a", 0, 40}, {"b", 0, 40}, {"c", 0, 80}},
			mutate: func(c *Config, _ *Input) { c.Excluded = map[string]bool{"b": true} }},
		{name: "cheaper provider down", native: "a",
			paths:  []m{{"a", 0, 40}, {"b", 0, 40}, {"c", 0, 80}},
			mutate: func(_ *Config, in *Input) { in.ProviderUp = map[string]bool{"a": true, "b": false, "c": true} }},
		{name: "prefix not in RIB", native: "",
			paths: []m{{"a", 0, 40}, {"b", 0, 40}, {"c", 0, 40}}},
		{name: "not allowlisted in inject", native: "a",
			paths:  []m{{"a", 0, 40}, {"b", 0, 40}, {"c", 0, 40}},
			mutate: func(c *Config, _ *Input) { c.Mode, c.Allowlist = "inject", []netip.Prefix{pB} }},
		{name: "allowlisted in inject", native: "a",
			paths: []m{{"a", 0, 40}, {"b", 0, 40}, {"c", 0, 40}}, want: "c",
			mutate: func(c *Config, _ *Input) { c.Mode, c.Allowlist = "inject", []netip.Prefix{pA} }},
		{name: "cap zero", native: "a",
			paths:  []m{{"a", 0, 40}, {"b", 0, 40}, {"c", 0, 40}},
			mutate: func(c *Config, _ *Input) { c.MaxImprovements = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := costCfg()
			native := map[netip.Prefix]string{}
			if tc.native != "" {
				native[pA] = tc.native
			}
			input := in(results(t0, pA, tc.paths...), native)
			if tc.mutate != nil {
				tc.mutate(&c, &input)
			}
			st, out := Decide(NewState(), input, c, costScorer(t, tc.scorer), t0)
			imp, ok := st.Improvements[pA]
			if tc.want == "" {
				if ok {
					t.Fatalf("unexpected steer %+v (decision %+v)", imp, decision(t, out, pA))
				}
				return
			}
			if !ok || imp.Provider != tc.want || imp.Cause != plugin.CauseCost {
				t.Fatalf("steer %+v, want cost to %s (decision %+v)", imp, tc.want, decision(t, out, pA))
			}
			if d := decision(t, out, pA); d.Action != ActionImprove || d.Cause != plugin.CauseCost {
				t.Fatalf("decision %+v", d)
			}
		})
	}
}

func TestCostPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		scorer     string
		costs      [3]float64 // a, b, c
		paths      []m
		wantProv   string
		wantCause  string
		wantReason string
	}{
		{name: "performance precedence: performance move wins",
			costs: [3]float64{10, 5, 2}, paths: []m{{"a", 0, 90}, {"b", 0, 30}, {"c", 0, 35}},
			wantProv: "b", wantCause: plugin.CausePerformance},
		{name: "cost precedence: cheapest inside the floor replaces performance",
			scorer: "precedence: cost",
			costs:  [3]float64{10, 5, 2}, paths: []m{{"a", 0, 90}, {"b", 0, 30}, {"c", 0, 35}},
			wantProv: "c", wantCause: plugin.CauseCost},
		{name: "cost precedence: cheaper path outside floor is not used",
			scorer: "precedence: cost",
			costs:  [3]float64{10, 5, 2}, paths: []m{{"a", 0, 90}, {"b", 0, 30}, {"c", 0, 80}},
			wantProv: "b", wantCause: plugin.CauseCost},
		{name: "cost precedence: performance rescues a cheap native outside the floor",
			scorer: "precedence: cost",
			costs:  [3]float64{1, 5, 8}, paths: []m{{"a", 0, 90}, {"b", 0, 30}, {"c", 0, 60}},
			wantProv: "b", wantCause: plugin.CausePerformance},
		{name: "cost precedence: cheap native inside the floor stays",
			scorer: "precedence: cost\nfloor: {max_rtt: 25ms}",
			costs:  [3]float64{1, 5, 8}, paths: []m{{"a", 0, 50}, {"b", 0, 30}, {"c", 0, 60}},
			wantReason: "inside performance floor"},
		{name: "performance precedence: same inputs move for performance",
			scorer: "floor: {max_rtt: 25ms}",
			costs:  [3]float64{1, 5, 8}, paths: []m{{"a", 0, 50}, {"b", 0, 30}, {"c", 0, 60}},
			wantProv: "b", wantCause: plugin.CausePerformance},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := costCfg()
			for i := range c.Providers {
				c.Providers[i].Cost = tc.costs[i]
			}
			input := in(results(t0, pA, tc.paths...), map[netip.Prefix]string{pA: "a"})
			st, out := Decide(NewState(), input, c, costScorer(t, tc.scorer), t0)
			d := decision(t, out, pA)
			imp, ok := st.Improvements[pA]
			if tc.wantProv == "" {
				if ok || !strings.Contains(d.Reason, tc.wantReason) {
					t.Fatalf("want native kept (%q): imp %+v decision %+v", tc.wantReason, imp, d)
				}
				return
			}
			if !ok || imp.Provider != tc.wantProv || imp.Cause != tc.wantCause {
				t.Fatalf("imp %+v, want %s/%s (decision %+v)", imp, tc.wantProv, tc.wantCause, d)
			}
			if len(out.Changes) != 1 || out.Changes[0].Action != ActionImprove {
				t.Fatalf("changes %+v", out.Changes)
			}
		})
	}
}

func TestCostSteerLifecycle(t *testing.T) {
	c := costCfg()
	s := costScorer(t, "")
	native := map[netip.Prefix]string{pA: "a"}
	input := in(results(t0, pA, m{"a", 0, 40}, m{"b", 0, 45}, m{"c", 0, 80}), native)
	input.VolumeMbps = map[netip.Prefix]float64{pA: 50}
	st, _ := Decide(NewState(), input, c, s, t0)
	imp := st.Improvements[pA]
	if imp.Provider != "b" || imp.CostDelta != 5 || imp.EstSavings != 250 {
		t.Fatalf("improvement %+v", imp)
	}

	// Still cheapest inside the floor: kept.
	t1 := t0.Add(time.Minute)
	input.Results = results(t1, pA, m{"a", 0, 40}, m{"b", 0, 45}, m{"c", 0, 80})
	st, out := Decide(st, input, c, s, t1)
	if d := decision(t, out, pA); d.Action != ActionKeep || st.Improvements[pA].Provider != "b" || len(out.Changes) != 0 {
		t.Fatalf("keep: %+v %+v", d, out.Changes)
	}

	// Leaving the floor withdraws at once, inside hold_time, with a cooldown.
	t2 := t1.Add(time.Minute)
	input.Results = results(t2, pA, m{"a", 0, 40}, m{"b", 0, 70}, m{"c", 0, 80})
	st, out = Decide(st, input, c, s, t2)
	if _, ok := st.Improvements[pA]; ok || len(out.Changes) != 1 || out.Changes[0].Action != ActionRetire {
		t.Fatalf("floor exit not withdrawn: %+v", out.Changes)
	}
	if !strings.Contains(out.Changes[0].Old.Reason, "outside performance floor") {
		t.Fatalf("reason %q", out.Changes[0].Old.Reason)
	}
	if _, cool := st.Cooldown[pA]; !cool {
		t.Fatal("no cooldown after floor exit")
	}
	t3 := t2.Add(time.Minute)
	input.Results = results(t3, pA, m{"a", 0, 40}, m{"b", 0, 45}, m{"c", 0, 80})
	st2, out2 := Decide(st, input, c, s, t3)
	if len(st2.Improvements) != 0 {
		t.Fatal("cost steer returned during cooldown")
	}
	if d := decision(t, out2, pA); d.Cause != plugin.CauseCost || !strings.Contains(d.Reason, "cooldown") {
		t.Fatalf("cooldown decision %+v", d)
	}

	// Switching back to weighted withdraws cost improvements.
	st, _ = Decide(NewState(), input, c, s, t3)
	if st.Improvements[pA].Cause != plugin.CauseCost {
		t.Fatalf("setup %+v", st.Improvements)
	}
	st, out = Decide(st, input, c, scorer(t), t3)
	if len(st.Improvements) != 0 || len(out.Changes) != 1 || !strings.Contains(out.Changes[0].Old.Reason, "cost mode disabled") {
		t.Fatalf("weighted rollback: %+v %+v", st.Improvements, out.Changes)
	}

	// RIB loss withdraws it too.
	st, _ = Decide(NewState(), input, c, s, t3)
	input.RIBReady = false
	st, out = Decide(st, input, c, s, t3)
	if len(st.Improvements) != 0 || len(out.Changes) != 1 {
		t.Fatalf("rib loss: %+v", out.Changes)
	}
}

func TestPerformanceDisplacesCostAtCap(t *testing.T) {
	c := costCfg()
	c.MaxImprovements = 1
	s := costScorer(t, "")
	input := in(results(t0, pB, m{"a", 0, 40}, m{"b", 0, 40}, m{"c", 0, 40}), map[netip.Prefix]string{pB: "a"})
	st, _ := Decide(NewState(), input, c, s, t0)
	if st.Improvements[pB].Cause != plugin.CauseCost {
		t.Fatalf("setup %+v", st.Improvements)
	}
	t1 := t0.Add(time.Minute)
	res := results(t1, pB, m{"a", 0, 40}, m{"b", 0, 40}, m{"c", 0, 40})
	res = append(res, results(t1, pA, m{"a", 0, 90}, m{"b", 0, 30}, m{"c", 0, 80})...)
	input = in(res, map[netip.Prefix]string{pA: "a", pB: "a"})
	st, _ = Decide(st, input, c, s, t1)
	if len(st.Improvements) != 1 || st.Improvements[pA].Cause != plugin.CausePerformance {
		t.Fatalf("improvements %+v", st.Improvements)
	}
}

// rogue is a planner that proposes whatever it is told.
type rogue struct {
	plugin.Base
	moves  []plugin.PlanMove
	policy bool
}

func (r *rogue) Score(p plugin.PathStats) float64 {
	return p.LossPct*100 + float64(p.RTTAvg)/float64(time.Millisecond)
}
func (r *rogue) Plan(plugin.PlanInput) []plugin.PlanMove { return r.moves }

type rogueCost struct{ rogue }

func (r *rogueCost) Floor() (float64, time.Duration) { return 0, 10 * time.Millisecond }
func (r *rogueCost) CostFirst() bool                 { return false }

func TestDecideEnforcesCostRules(t *testing.T) {
	input := in(results(t0, pA, m{"a", 0, 40}, m{"b", 0, 45}, m{"c", 0, 90}), map[netip.Prefix]string{pA: "a"})
	for _, tc := range []struct {
		name string
		s    plugin.Scorer
	}{
		{"no cost policy", &rogue{moves: []plugin.PlanMove{{Prefix: pA, Provider: "b", Cause: plugin.CauseCost}}}},
		{"outside floor", &rogueCost{rogue{moves: []plugin.PlanMove{{Prefix: pA, Provider: "c", Cause: plugin.CauseCost}}}}},
		{"not cheaper", func() plugin.Scorer {
			r := &rogueCost{rogue{moves: []plugin.PlanMove{{Prefix: pA, Provider: "b", Cause: plugin.CauseCost}}}}
			return r
		}()},
		{"onto native", &rogueCost{rogue{moves: []plugin.PlanMove{{Prefix: pA, Provider: "a", Cause: plugin.CauseCost}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := costCfg()
			if tc.name == "not cheaper" {
				c.Providers[1].Cost = 20
			}
			st, _ := Decide(NewState(), input, c, tc.s, t0)
			if len(st.Improvements) != 0 {
				t.Fatalf("accepted %+v", st.Improvements)
			}
		})
	}
	// Control: a valid cost move from the same planner is accepted.
	ok := &rogueCost{rogue{moves: []plugin.PlanMove{{Prefix: pA, Provider: "b", Cause: plugin.CauseCost}}}}
	if st, _ := Decide(NewState(), input, costCfg(), ok, t0); st.Improvements[pA].Cause != plugin.CauseCost {
		t.Fatalf("valid move refused: %+v", st.Improvements)
	}
}

// TestCostSteerPastHoldTime covers an active cost steer once hold_time has
// elapsed. It must not be read back as locked performance context, which
// would withdraw it and re-announce it every other hold_time.
func TestCostSteerPastHoldTime(t *testing.T) {
	type step struct {
		paths    []m
		action   string
		provider string
	}
	for _, tc := range []struct {
		name  string
		costs [3]float64 // a, b, c
		first []m
		want  string
		steps []step
	}{
		{name: "cheapest inside floor stays",
			costs: [3]float64{10, 5, 2},
			first: []m{{"a", 0, 40}, {"b", 0, 45}, {"c", 0, 80}}, want: "b",
			steps: []step{
				{[]m{{"a", 0, 40}, {"b", 0, 45}, {"c", 0, 80}}, ActionKeep, "b"},
				{[]m{{"a", 0, 40}, {"b", 0, 45}, {"c", 0, 80}}, ActionKeep, "b"},
				{[]m{{"a", 0, 40}, {"b", 0, 45}, {"c", 0, 80}}, ActionKeep, "b"},
			}},
		{name: "equal price keeps the current provider",
			costs: [3]float64{10, 2, 2},
			first: []m{{"a", 0, 40}, {"b", 0, 80}, {"c", 0, 45}}, want: "c",
			steps: []step{
				{[]m{{"a", 0, 40}, {"b", 0, 42}, {"c", 0, 45}}, ActionKeep, "c"},
				{[]m{{"a", 0, 40}, {"b", 0, 42}, {"c", 0, 45}}, ActionKeep, "c"},
			}},
		{name: "cheaper path inside floor switches",
			costs: [3]float64{10, 5, 2},
			first: []m{{"a", 0, 40}, {"b", 0, 45}, {"c", 0, 80}}, want: "b",
			steps: []step{
				{[]m{{"a", 0, 40}, {"b", 0, 45}, {"c", 0, 48}}, ActionSwitch, "c"},
				{[]m{{"a", 0, 40}, {"b", 0, 45}, {"c", 0, 48}}, ActionKeep, "c"},
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := costCfg()
			c.HoldTime = 5 * time.Second
			for i := range c.Providers {
				c.Providers[i].Cost = tc.costs[i]
			}
			s := costScorer(t, "")
			input := in(results(t0, pA, tc.first...), map[netip.Prefix]string{pA: "a"})
			st, _ := Decide(NewState(), input, c, s, t0)
			if imp := st.Improvements[pA]; imp.Provider != tc.want || imp.Cause != plugin.CauseCost {
				t.Fatalf("setup %+v", st.Improvements)
			}
			now := t0
			for i, sp := range tc.steps {
				now = now.Add(2 * c.HoldTime)
				input.Results = results(now, pA, sp.paths...)
				var out Output
				st, out = Decide(st, input, c, s, now)
				d := decision(t, out, pA)
				imp, ok := st.Improvements[pA]
				if !ok || imp.Provider != sp.provider || imp.Cause != plugin.CauseCost || d.Action != sp.action {
					t.Fatalf("step %d: imp %+v decision %+v changes %+v", i, imp, d, out.Changes)
				}
				if sp.action == ActionKeep && len(out.Changes) != 0 {
					t.Fatalf("step %d: keep produced changes %+v", i, out.Changes)
				}
				if sp.action == ActionSwitch && (len(out.Changes) != 1 || out.Changes[0].Action != ActionSwitch) {
					t.Fatalf("step %d: changes %+v", i, out.Changes)
				}
			}
		})
	}
}

// TestCostSteerScorerSwitch retires a cost steer with an accurate reason
// when the scorer is replaced by a planner that has no cost policy.
func TestCostSteerScorerSwitch(t *testing.T) {
	input := in(results(t0, pA, m{"a", 0, 40}, m{"b", 0, 45}, m{"c", 0, 80}), map[netip.Prefix]string{pA: "a"})
	st, _ := Decide(NewState(), input, costCfg(), costScorer(t, ""), t0)
	if st.Improvements[pA].Cause != plugin.CauseCost {
		t.Fatalf("setup %+v", st.Improvements)
	}
	st, out := Decide(st, input, costCfg(), &rogue{}, t0.Add(time.Minute))
	if len(st.Improvements) != 0 || len(out.Changes) != 1 || out.Changes[0].Old.Reason != "cost mode disabled" {
		t.Fatalf("scorer switch: %+v %+v", st.Improvements, out.Changes)
	}
	if _, cool := st.Cooldown[pA]; cool {
		t.Fatal("scorer switch should not set a flip-back cooldown")
	}
}
