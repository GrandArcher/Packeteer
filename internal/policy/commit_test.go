package policy

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/commit"
	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func commitScorer(t *testing.T, y string) plugin.Scorer {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	s, err := commit.New(c, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func commitCfg() Config {
	c := cfg()
	c.Providers = []ProviderPolicy{
		{Name: "a", Precedence: 10},
		{Name: "b", Precedence: 10},
		{Name: "c", Precedence: 100},
	}
	return c
}

func billable(name string, commitMbps, used float64) plugin.Usage {
	return plugin.Usage{
		Provider: name, CommitMbps: commitMbps, Samples: 20, Single: true,
		UsageMbps: used, Updated: t0, Mode: plugin.PercentileGreaterSeparate,
	}
}

func TestCommitMoveWithoutLossRegression(t *testing.T) {
	// 10 ms is inside the 15 ms latency threshold, so performance does not move.
	res := results(t0, pA, m{"a", 0, 40}, m{"b", 0, 50})
	input := in(res, map[netip.Prefix]string{pA: "a"})
	input.Usage = []plugin.Usage{billable("a", 100, 150), billable("b", 100, 20)}
	input.VolumeMbps = map[netip.Prefix]float64{pA: 60}
	st, out := Decide(NewState(), input, commitCfg(), commitScorer(t, ""), t0)
	d := decision(t, out, pA)
	if d.Action != ActionImprove || d.Current != "b" || d.Cause != plugin.CauseCommit {
		t.Fatalf("decision %+v", d)
	}
	if !strings.Contains(d.Reason, "commit:") {
		t.Fatalf("reason %q", d.Reason)
	}
	imp := st.Improvements[pA]
	if imp.Provider != "b" || imp.Native != "a" || imp.Cause != plugin.CauseCommit {
		t.Fatalf("improvement %+v", imp)
	}

	// Same traffic onto a lossier path must stay put.
	input.Results = results(t0, pA, m{"a", 0, 40}, m{"b", 2, 50})
	st, out = Decide(NewState(), input, commitCfg(), commitScorer(t, ""), t0)
	if decision(t, out, pA).Action != ActionNone || len(st.Improvements) != 0 {
		t.Fatalf("loss regression was steered: %+v %+v", decision(t, out, pA), st.Improvements)
	}
	st, out = Decide(NewState(), input, commitCfg(), commitScorer(t, "loss_override: true"), t0)
	if decision(t, out, pA).Action != ActionImprove || st.Improvements[pA].Cause != plugin.CauseCommit {
		t.Fatalf("loss_override: %+v", decision(t, out, pA))
	}
}

func TestCommitDoesNotOverridePerformanceOrLeaveTheRIB(t *testing.T) {
	c, s := commitCfg(), commitScorer(t, "")
	input := in(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}), map[netip.Prefix]string{pA: "a"})
	input.Usage = []plugin.Usage{billable("a", 100, 180), billable("b", 100, 10)}
	input.VolumeMbps = map[netip.Prefix]float64{pA: 60}
	st, out := Decide(NewState(), input, c, s, t0)
	d := decision(t, out, pA)
	if d.Action != ActionImprove || d.Cause != plugin.CausePerformance || st.Improvements[pA].Provider != "b" {
		t.Fatalf("performance should win: %+v imp %+v", d, st.Improvements[pA])
	}

	input.Native = map[netip.Prefix]string{}
	st, out = Decide(NewState(), input, c, s, t0)
	if decision(t, out, pA).Action != ActionNone || len(st.Improvements) != 0 || !strings.Contains(decision(t, out, pA).Reason, "not in RIB") {
		t.Fatalf("prefix absent from the RIB was steered: %+v %+v", decision(t, out, pA), st.Improvements)
	}
}

func TestCommitObeysAllowlistAndCap(t *testing.T) {
	s := commitScorer(t, "")
	c := commitCfg()
	c.Mode = "inject"
	c.Allowlist = []netip.Prefix{pB}
	input := in(results(t0, pA, m{"a", 0, 40}, m{"b", 0, 50}), map[netip.Prefix]string{pA: "a"})
	input.Usage = []plugin.Usage{billable("a", 100, 150), billable("b", 100, 20)}
	input.VolumeMbps = map[netip.Prefix]float64{pA: 60}
	st, out := Decide(NewState(), input, c, s, t0)
	if len(st.Improvements) != 0 || !strings.Contains(decision(t, out, pA).Reason, "not allowlisted") {
		t.Fatalf("allowlist: %+v %+v", decision(t, out, pA), st.Improvements)
	}

	c = commitCfg()
	c.MaxImprovements = 1
	var res []probe.Result
	res = append(res, results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30})...)
	res = append(res, results(t0, pB, m{"a", 0, 40}, m{"b", 0, 45})...)
	input = in(res, map[netip.Prefix]string{pA: "a", pB: "a"})
	input.Usage = []plugin.Usage{billable("a", 100, 200), billable("b", 100, 10)}
	input.VolumeMbps = map[netip.Prefix]float64{pA: 10, pB: 80}
	st, out = Decide(NewState(), input, c, s, t0)
	if st.Improvements[pA].Cause != plugin.CausePerformance {
		t.Fatalf("performance slot %+v", st.Improvements[pA])
	}
	if _, ok := st.Improvements[pB]; ok || decision(t, out, pB).Action != ActionCapped {
		t.Fatalf("commit move should be capped: %+v", decision(t, out, pB))
	}
}

func TestWeightedScorerDoesNotCommit(t *testing.T) {
	input := in(results(t0, pA, m{"a", 0, 40}, m{"b", 0, 50}), map[netip.Prefix]string{pA: "a"})
	input.Usage = []plugin.Usage{billable("a", 100, 180), billable("b", 100, 10)}
	input.VolumeMbps = map[netip.Prefix]float64{pA: 60}
	w, err := weighted.New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	st, out := Decide(NewState(), input, commitCfg(), w, t0)
	if decision(t, out, pA).Action != ActionNone || len(st.Improvements) != 0 {
		t.Fatalf("weighted scorer steered for commit: %+v", decision(t, out, pA))
	}
}

func TestDisablingCommitWithdrawsItsImprovements(t *testing.T) {
	prev := NewState()
	prev.Improvements[pA] = Improvement{
		Prefix: pA, Provider: "b", Native: "a", Since: t0, Cause: plugin.CauseCommit, Reason: "commit",
	}
	input := in(results(t0.Add(time.Minute), pA, m{"a", 0, 40}, m{"b", 0, 50}), map[netip.Prefix]string{pA: "a"})
	w, err := weighted.New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	st, out := Decide(prev, input, cfg(), w, t0.Add(time.Minute))
	if _, ok := st.Improvements[pA]; ok || !strings.Contains(decision(t, out, pA).Reason, "commit control disabled") {
		t.Fatalf("disable: %+v %+v", decision(t, out, pA), st.Improvements)
	}
	if _, cool := st.Cooldown[pA]; cool {
		t.Fatal("disabling commit control started a cooldown")
	}
}

func TestCommitHoldThenRelease(t *testing.T) {
	c, s := commitCfg(), commitScorer(t, "")
	input := in(results(t0, pA, m{"a", 0, 40}, m{"b", 0, 50}), map[netip.Prefix]string{pA: "a"})
	input.Usage = []plugin.Usage{billable("a", 100, 150), billable("b", 100, 20)}
	input.VolumeMbps = map[netip.Prefix]float64{pA: 60}
	st, out := Decide(NewState(), input, c, s, t0)
	if st.Improvements[pA].Cause != plugin.CauseCommit {
		t.Fatalf("create: %+v", decision(t, out, pA))
	}
	// Telemetry has caught up: native can take the prefix back without
	// crossing its commit. Hold time keeps the steer.
	input.Usage = []plugin.Usage{billable("a", 100, 30), billable("b", 100, 80)}
	input.Results = results(t0.Add(time.Minute), pA, m{"a", 0, 40}, m{"b", 0, 50})
	st, out = Decide(st, input, c, s, t0.Add(time.Minute))
	if decision(t, out, pA).Action != ActionKeep || !strings.Contains(decision(t, out, pA).Reason, "hold_time") {
		t.Fatalf("hold: %+v", decision(t, out, pA))
	}
	input.Results = results(t0.Add(20*time.Minute), pA, m{"a", 0, 40}, m{"b", 0, 50})
	st, out = Decide(st, input, c, s, t0.Add(20*time.Minute))
	if _, ok := st.Improvements[pA]; ok || !strings.Contains(decision(t, out, pA).Reason, "commit relieved") {
		t.Fatalf("release: %+v %+v", decision(t, out, pA), st.Improvements)
	}
	if _, cool := st.Cooldown[pA]; !cool {
		t.Fatal("release did not start a cooldown")
	}
}

func TestCommitLossRegressionStartsCooldown(t *testing.T) {
	c, s := commitCfg(), commitScorer(t, "")
	prev := NewState()
	prev.Improvements[pA] = Improvement{
		Prefix: pA, Provider: "b", Native: "a", Since: t0, Cause: plugin.CauseCommit,
	}
	now := t0.Add(time.Minute)
	input := in(results(now, pA, m{"a", 0, 40}, m{"b", 0.5, 50}), map[netip.Prefix]string{pA: "a"})
	input.Usage = []plugin.Usage{billable("a", 100, 150), billable("b", 100, 20)}
	input.VolumeMbps = map[netip.Prefix]float64{pA: 60}
	// Under min_loss_delta_pct (1). One noisy probe must not withdraw.
	st, out := Decide(prev, input, c, s, now)
	if decision(t, out, pA).Action == ActionRetire || st.Improvements[pA].Provider != "b" {
		t.Fatalf("sub-threshold loss withdrew: %+v %+v", decision(t, out, pA), st.Improvements)
	}

	// A real margin withdraws at once, including inside hold_time, and the
	// cooldown stops the same steer coming back when the next sample is clean.
	now = now.Add(time.Minute)
	input.Results = results(now, pA, m{"a", 0, 40}, m{"b", 10, 50})
	st, out = Decide(st, input, c, s, now)
	if _, ok := st.Improvements[pA]; ok || !strings.Contains(decision(t, out, pA).Reason, "loss regressed") {
		t.Fatalf("loss: %+v %+v", decision(t, out, pA), st.Improvements)
	}
	until, cool := st.Cooldown[pA]
	if !cool || !until.Equal(now.Add(c.HoldTime)) {
		t.Fatalf("cooldown = %s ok=%v, want %s", until, cool, now.Add(c.HoldTime))
	}
	now = now.Add(time.Minute)
	input.Results = results(now, pA, m{"a", 0, 40}, m{"b", 0, 50})
	st, out = Decide(st, input, c, s, now)
	if _, ok := st.Improvements[pA]; ok || decision(t, out, pA).Action == ActionImprove || !strings.Contains(decision(t, out, pA).Reason, "cooldown") {
		t.Fatalf("steer flapped back during cooldown: %+v %+v", decision(t, out, pA), st.Improvements)
	}

	now = until
	input.Results = results(now, pA, m{"a", 0, 40}, m{"b", 0, 50})
	// The 95th has to be fresh. A row timestamped at t0 is older than max_age
	// once hold_time (15m) has elapsed.
	for i := range input.Usage {
		input.Usage[i].Updated = now
	}
	st, out = Decide(st, input, c, s, now)
	if st.Improvements[pA].Cause != plugin.CauseCommit || decision(t, out, pA).Action != ActionImprove {
		t.Fatalf("after cooldown: %+v %+v", decision(t, out, pA), st.Improvements[pA])
	}
}

func TestGroupBalanceDecisionStaysInGroup(t *testing.T) {
	c := commitCfg()
	c.Providers = []ProviderPolicy{
		{Name: "a", Group: "edge", Precedence: 10},
		{Name: "b", Group: "edge", Precedence: 10},
		{Name: "c", Precedence: 10},
	}
	input := in(results(t0, pA, m{"a", 0, 40}, m{"b", 0, 42}, m{"c", 0, 41}), map[netip.Prefix]string{pA: "a"})
	input.Usage = []plugin.Usage{billable("a", 100, 90), billable("b", 100, 10), billable("c", 100, 5)}
	input.VolumeMbps = map[netip.Prefix]float64{pA: 30}
	st, out := Decide(NewState(), input, c, commitScorer(t, "balance: equal\nbalance_slack: 0.05"), t0)
	d := decision(t, out, pA)
	if d.Action != ActionImprove || d.Current != "b" || d.Cause != plugin.CauseCommit || !strings.Contains(d.Reason, "balance:") {
		t.Fatalf("balance decision %+v", d)
	}
	if st.Improvements[pA].Provider != "b" {
		t.Fatalf("improvement %+v", st.Improvements[pA])
	}
}

// planStub is a planner that returns a fixed set of moves. It exists so
// Decide's own loss and native checks are tested apart from the commit scorer.
type planStub struct {
	plugin.Base
	moves []plugin.PlanMove
	allow bool
	// override is false when the stub does not implement LossOverride.
	override bool
}

func (p planStub) Score(s plugin.PathStats) float64 {
	return s.LossPct*100 + float64(s.RTTAvg)/float64(time.Millisecond)
}

func (p planStub) Plan(plugin.PlanInput) []plugin.PlanMove { return p.moves }

func (p planStub) AllowLoss() bool {
	if !p.override {
		return false
	}
	return p.allow
}

// planBare does not implement LossOverride. Decide must refuse a higher-loss move.
type planBare struct {
	plugin.Base
	moves []plugin.PlanMove
}

func (p planBare) Score(s plugin.PathStats) float64 {
	return s.LossPct*100 + float64(s.RTTAvg)/float64(time.Millisecond)
}

func (p planBare) Plan(plugin.PlanInput) []plugin.PlanMove { return p.moves }

func commitInput() Input {
	input := in(results(t0, pA, m{"a", 0, 40}, m{"b", 0, 50}, m{"c", 0, 45}), map[netip.Prefix]string{pA: "a"})
	input.Usage = []plugin.Usage{billable("a", 100, 150), billable("b", 100, 20), billable("c", 100, 20)}
	input.VolumeMbps = map[netip.Prefix]float64{pA: 60}
	return input
}

func TestDecideRefusesHigherLossAndNativeCommitMoves(t *testing.T) {
	c := commitCfg()
	input := commitInput()
	input.Results = results(t0, pA, m{"a", 0, 40}, m{"b", 2, 50})
	mv := plugin.PlanMove{Prefix: pA, Provider: "b", Reason: "stub", ReliefMbps: 60}

	st, out := Decide(NewState(), input, c, planBare{moves: []plugin.PlanMove{mv}}, t0)
	if len(st.Improvements) != 0 || !strings.Contains(decision(t, out, pA).Reason, "refused") {
		t.Fatalf("bare planner higher loss: %+v %+v", decision(t, out, pA), st.Improvements)
	}

	st, out = Decide(NewState(), input, c, planStub{moves: []plugin.PlanMove{mv}, override: true, allow: true}, t0)
	if st.Improvements[pA].Provider != "b" || st.Improvements[pA].Cause != plugin.CauseCommit {
		t.Fatalf("loss override: %+v", st.Improvements)
	}

	input = commitInput()
	native := plugin.PlanMove{Prefix: pA, Provider: "a", Reason: "stub", ReliefMbps: 60}
	st, out = Decide(NewState(), input, c, planStub{moves: []plugin.PlanMove{native}, override: true, allow: true}, t0)
	if len(st.Improvements) != 0 {
		t.Fatalf("steered onto native: %+v", st.Improvements)
	}
}

func TestCommitCapTieBreakIsTheLowerPrefix(t *testing.T) {
	c, s := commitCfg(), commitScorer(t, "")
	c.MaxImprovements = 1
	var res []probe.Result
	res = append(res, results(t0, pA, m{"a", 0, 40}, m{"b", 0, 45})...)
	res = append(res, results(t0, pB, m{"a", 0, 40}, m{"b", 0, 45})...)
	input := in(res, map[netip.Prefix]string{pA: "a", pB: "a"})
	input.Usage = []plugin.Usage{billable("a", 100, 220), billable("b", 200, 10)}
	input.VolumeMbps = map[netip.Prefix]float64{pA: 60, pB: 60}
	for i := 0; i < 20; i++ {
		st, out := Decide(NewState(), input, c, s, t0)
		if st.Improvements[pA].Cause != plugin.CauseCommit {
			t.Fatalf("iter %d winner %+v", i, st.Improvements)
		}
		if _, ok := st.Improvements[pB]; ok || decision(t, out, pB).Action != ActionCapped {
			t.Fatalf("iter %d loser %+v decision %+v", i, st.Improvements[pB], decision(t, out, pB))
		}
	}
}

func TestPerformanceDisplacesCommitWhenTheCapBinds(t *testing.T) {
	c, s := commitCfg(), commitScorer(t, "")
	c.MaxImprovements = 2
	prev := NewState()
	prev.Improvements[pB] = Improvement{Prefix: pB, Provider: "b", Native: "a", Since: t0, Cause: plugin.CauseCommit}
	prev.Improvements[pC] = Improvement{Prefix: pC, Provider: "b", Native: "a", Since: t0, Cause: plugin.CauseCommit}
	var res []probe.Result
	res = append(res, results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30})...)
	res = append(res, results(t0, pB, m{"a", 0, 40}, m{"b", 0, 45})...)
	res = append(res, results(t0, pC, m{"a", 0, 40}, m{"b", 0, 45})...)
	input := in(res, map[netip.Prefix]string{pA: "a", pB: "a", pC: "a"})
	input.Usage = []plugin.Usage{billable("a", 100, 200), billable("b", 400, 10)}
	input.VolumeMbps = map[netip.Prefix]float64{pA: 70, pB: 10, pC: 80}
	st, out := Decide(prev, input, c, s, t0)
	if st.Improvements[pA].Cause != plugin.CausePerformance {
		t.Fatalf("performance did not take a slot: %+v", st.Improvements)
	}
	if _, ok := st.Improvements[pB]; ok || !strings.Contains(decision(t, out, pB).Reason, "displaced") {
		t.Fatalf("smaller commit steer was kept: %+v %+v", decision(t, out, pB), st.Improvements[pB])
	}
	if _, cool := st.Cooldown[pB]; !cool {
		t.Fatal("displaced commit steer has no cooldown")
	}
	if st.Improvements[pC].Cause != plugin.CauseCommit {
		t.Fatalf("larger commit steer was dropped: %+v", st.Improvements[pC])
	}
}

func TestLockedPerformanceVolumeIsNotMovedAgain(t *testing.T) {
	c, s := commitCfg(), commitScorer(t, "")
	// pA is a performance move of 60 Mbps. That brings a from 150 to 90,
	// under the commit of 100, so pB must not also be commit-steered.
	var res []probe.Result
	res = append(res, results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30})...)
	res = append(res, results(t0, pB, m{"a", 0, 40}, m{"b", 0, 45})...)
	input := in(res, map[netip.Prefix]string{pA: "a", pB: "a"})
	input.Usage = []plugin.Usage{billable("a", 100, 150), billable("b", 100, 10)}
	input.VolumeMbps = map[netip.Prefix]float64{pA: 60, pB: 40}
	st, out := Decide(NewState(), input, c, s, t0)
	if st.Improvements[pA].Cause != plugin.CausePerformance {
		t.Fatalf("performance: %+v", decision(t, out, pA))
	}
	if _, ok := st.Improvements[pB]; ok {
		t.Fatalf("commit moved traffic the performance steer already shifts: %+v", st.Improvements[pB])
	}
}

func TestCommitSafetyRetirements(t *testing.T) {
	base := func() State {
		s := NewState()
		s.Improvements[pA] = Improvement{Prefix: pA, Provider: "b", Native: "a", Since: t0, Cause: plugin.CauseCommit}
		return s
	}
	at := t0.Add(time.Minute)
	cases := []struct {
		name   string
		mutate func(*Input, *Config)
		reason string
	}{
		{"rib down", func(i *Input, _ *Config) { i.RIBReady = false }, "rib not ready"},
		{"provider down", func(i *Input, _ *Config) { i.ProviderUp = map[string]bool{"a": true, "c": true} }, "provider down"},
		{"cc_disable", func(_ *Input, c *Config) {
			c.Providers = []ProviderPolicy{{Name: "a"}, {Name: "b", CCDisable: true}}
		}, "commit control"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := in(results(at, pA, m{"a", 0, 40}, m{"b", 0, 50}), map[netip.Prefix]string{pA: "a"})
			c := commitCfg()
			tc.mutate(&input, &c)
			st, out := Decide(base(), input, c, commitScorer(t, ""), at)
			if _, ok := st.Improvements[pA]; ok || len(out.Changes) != 1 || out.Changes[0].Action != ActionRetire || !strings.Contains(out.Changes[0].Old.Reason, tc.reason) {
				t.Fatalf("%s: %+v", tc.name, out.Changes)
			}
		})
	}
}
