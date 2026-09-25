package commit

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var (
	t0 = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	p1 = netip.MustParsePrefix("198.51.100.0/24")
	p2 = netip.MustParsePrefix("203.0.113.0/24")
	p3 = netip.MustParsePrefix("192.0.2.0/24")
)

func build(t *testing.T, y string) *Scorer {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(c, plugin.Env{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	cs, ok := s.(*Scorer)
	if !ok {
		t.Fatalf("type %T", s)
	}
	return cs
}

func usage(name string, commit, billable float64) plugin.Usage {
	return plugin.Usage{
		Provider: name, CommitMbps: commit, Samples: 20, Single: true,
		UsageMbps: billable, Mode: plugin.PercentileGreaterSeparate, Updated: t0,
	}
}

func prov(name, group string, prec int, u plugin.Usage) plugin.PlanProvider {
	return plugin.PlanProvider{
		Name: name, Group: group, Precedence: prec, Up: true, HaveRow: true, Usage: u,
	}
}

func path(name string, loss float64) plugin.PlanPath {
	return plugin.PlanPath{Provider: name, LossPct: loss, RTT: 40 * time.Millisecond, Usable: true}
}

func prefix(p netip.Prefix, native string, mbps float64, paths ...plugin.PlanPath) plugin.PlanPrefix {
	return plugin.PlanPrefix{Prefix: p, Native: native, Current: native, VolumeMbps: mbps, Paths: paths}
}

func movesTo(moves []plugin.PlanMove) map[netip.Prefix]string {
	out := map[netip.Prefix]string{}
	for _, m := range moves {
		if _, dup := out[m.Prefix]; dup {
			panic("duplicate move " + m.Prefix.String())
		}
		out[m.Prefix] = m.Provider
	}
	return out
}

func TestScoreMatchesWeightedLoss(t *testing.T) {
	s := build(t, "")
	hi := s.Score(plugin.PathStats{LossPct: 1, RTTAvg: 10 * time.Millisecond})
	lo := s.Score(plugin.PathStats{LossPct: 0, RTTAvg: 80 * time.Millisecond})
	if hi <= lo {
		t.Fatalf("loss did not dominate: high-loss %v low-loss %v", hi, lo)
	}
}

func TestConfigRejects(t *testing.T) {
	cases := []struct{ y, want string }{
		{"loss_weight: -1", "must not be negative"},
		{"loss_weight: 0\nrtt_weight: 0\njitter_weight: 0", "at least one weight"},
		{"balance: round-robin", "balance"},
		{"balance_slack: 1.5", "balance_slack"},
		{"balance_slack: -0.1", "balance_slack"},
		{"max_age: -1s", "max_age"},
		{"min_mbps: -1", "min_mbps"},
		{"nope: 1", "not found"},
	}
	for _, tc := range cases {
		c, err := plugin.ConfigFromYAML(tc.y)
		if err != nil {
			t.Fatal(err)
		}
		_, err = New(c, plugin.Env{})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: got %v", tc.y, err)
		}
	}
}

func TestCommitKeepsProviderUnderWithoutLossRegression(t *testing.T) {
	s := build(t, "")
	in := plugin.PlanInput{
		Now: t0,
		Providers: []plugin.PlanProvider{
			prov("a", "", 10, usage("a", 100, 180)),
			prov("b", "", 10, usage("b", 100, 10)),
		},
		Prefixes: []plugin.PlanPrefix{
			prefix(p1, "a", 50, path("a", 0), path("b", 0)),
			prefix(p2, "a", 40, path("a", 0), path("b", 0)),
			prefix(p3, "a", 20, path("a", 0), path("b", 0)),
		},
	}
	got := movesTo(s.Plan(in))
	if got[p1] != "b" || got[p2] != "b" {
		t.Fatalf("moves = %v", got)
	}
	if _, ok := got[p3]; ok {
		t.Fatalf("prefix that is not needed to get under commit was moved: %v", got)
	}
	// 180 - 50 - 40 = 90, which is under the 100 commit. b ends at 100.
	if relief := 50.0 + 40.0; relief < 80 {
		t.Fatal("did not cover the excess")
	}

	// The same volumes must not move onto a lossier path.
	in.Prefixes[0].Paths = []plugin.PlanPath{path("a", 0), path("b", 2)}
	in.Prefixes[1].Paths = []plugin.PlanPath{path("a", 0), path("b", 2)}
	in.Prefixes[2].Paths = []plugin.PlanPath{path("a", 0), path("b", 2)}
	if moves := s.Plan(in); len(moves) != 0 {
		t.Fatalf("loss regression was allowed: %+v", moves)
	}

	over := build(t, "loss_override: true")
	moves := over.Plan(in)
	if len(moves) == 0 {
		t.Fatal("loss_override did not allow the move")
	}
	for _, m := range moves {
		if m.Provider != "b" {
			t.Fatalf("move %+v", m)
		}
	}
}

func TestSeparatePercentileUsesOutbound(t *testing.T) {
	s := build(t, "")
	out := usage("a", 100, 0)
	out.Single = false
	out.UsageMbps = 0
	out.InMbps95 = 1
	out.OutMbps95 = 150
	out.Mode = plugin.PercentileSeparate
	idle := usage("b", 100, 10)
	in := plugin.PlanInput{
		Now: t0,
		Providers: []plugin.PlanProvider{
			prov("a", "", 10, out),
			prov("b", "", 10, idle),
		},
		Prefixes: []plugin.PlanPrefix{
			prefix(p1, "a", 60, path("a", 0), path("b", 0)),
		},
	}
	got := movesTo(s.Plan(in))
	if got[p1] != "b" {
		t.Fatalf("outbound 95th did not drive the move: %v", got)
	}
}

func TestNoMoveWithoutVolumeOrFreshUsage(t *testing.T) {
	s := build(t, "max_age: 15m")
	base := plugin.PlanInput{
		Now: t0,
		Providers: []plugin.PlanProvider{
			prov("a", "", 10, usage("a", 100, 180)),
			prov("b", "", 10, usage("b", 100, 10)),
		},
		Prefixes: []plugin.PlanPrefix{
			prefix(p1, "a", 60, path("a", 0), path("b", 0)),
		},
	}
	stale := base
	stale.Providers = append([]plugin.PlanProvider(nil), base.Providers...)
	ua := stale.Providers[0].Usage
	ua.Updated = t0.Add(-time.Hour)
	stale.Providers[0].Usage = ua
	if moves := s.Plan(stale); len(moves) != 0 {
		t.Fatalf("stale telemetry moved traffic: %+v", moves)
	}
	// Decide reads its clock before telemetry, so a row from this round is
	// stamped just after Now. That row is fresh. One far ahead is not.
	justRead := base
	justRead.Providers = append([]plugin.PlanProvider(nil), base.Providers...)
	for i := range justRead.Providers {
		justRead.Providers[i].Usage.Updated = t0.Add(time.Millisecond)
	}
	if got := movesTo(s.Plan(justRead)); got[p1] != "b" {
		t.Fatalf("telemetry read after the decision clock was ignored: %v", got)
	}
	future := justRead
	future.Providers = append([]plugin.PlanProvider(nil), justRead.Providers...)
	for i := range future.Providers {
		future.Providers[i].Usage.Updated = t0.Add(time.Hour)
	}
	if moves := s.Plan(future); len(moves) != 0 {
		t.Fatalf("telemetry from a clock an hour ahead moved traffic: %+v", moves)
	}
	novol := base
	novol.Prefixes = []plugin.PlanPrefix{prefix(p1, "a", 0, path("a", 0), path("b", 0))}
	if moves := s.Plan(novol); len(moves) != 0 {
		t.Fatalf("zero volume moved traffic: %+v", moves)
	}
	if moves := s.Plan(plugin.PlanInput{Now: t0, Prefixes: base.Prefixes}); len(moves) != 0 {
		t.Fatalf("missing telemetry moved traffic: %+v", moves)
	}
}

func TestCCDisableAndPrecedence(t *testing.T) {
	s := build(t, "")
	paths := []plugin.PlanPath{path("a", 0), path("b", 0), path("c", 0)}
	over := plugin.PlanInput{
		Now: t0,
		Providers: []plugin.PlanProvider{
			prov("a", "", 10, usage("a", 100, 150)),
			prov("b", "", 10, usage("b", 100, 100)),
			prov("c", "", 200, usage("c", 100, 10)),
		},
		Prefixes: []plugin.PlanPrefix{prefix(p1, "a", 40, paths...)},
	}
	if got := movesTo(s.Plan(over)); got[p1] != "c" {
		t.Fatalf("last resort was not used when the preferred provider is full: %v", got)
	}

	room := over
	room.Providers = append([]plugin.PlanProvider(nil), over.Providers...)
	ub := room.Providers[1].Usage
	ub.UsageMbps = 40
	room.Providers[1].Usage = ub
	if got := movesTo(s.Plan(room)); got[p1] != "b" {
		t.Fatalf("last resort was used while a preferred provider had room: %v", got)
	}

	disabled := room
	disabled.Providers = append([]plugin.PlanProvider(nil), room.Providers...)
	disabled.Providers[0].CCDisable = true
	if moves := s.Plan(disabled); len(moves) != 0 {
		t.Fatalf("moved off cc_disable: %+v", moves)
	}
	onlyCC := room
	onlyCC.Providers = append([]plugin.PlanProvider(nil), room.Providers...)
	onlyCC.Providers[1].CCDisable = true
	onlyCC.Providers[2].CCDisable = true
	if moves := s.Plan(onlyCC); len(moves) != 0 {
		t.Fatalf("moved onto cc_disable: %+v", moves)
	}
}

func TestGroupBalance(t *testing.T) {
	s := build(t, "balance: equal\nbalance_slack: 0.05")
	in := plugin.PlanInput{
		Now: t0,
		Providers: []plugin.PlanProvider{
			prov("a", "edge", 10, usage("a", 100, 90)),
			prov("b", "edge", 10, usage("b", 100, 10)),
			prov("c", "", 10, usage("c", 100, 5)),
		},
		Prefixes: []plugin.PlanPrefix{
			prefix(p1, "a", 30, path("a", 0), path("b", 0), path("c", 0)),
			prefix(p2, "a", 20, path("a", 0), path("b", 0), path("c", 0)),
		},
	}
	got := movesTo(s.Plan(in))
	if got[p1] != "b" {
		t.Fatalf("group balance moves = %v", got)
	}
	if _, ok := got[p2]; ok {
		t.Fatalf("balance moved a prefix that would swap which side is heavy: %v", got)
	}
	for _, dest := range got {
		if dest == "c" {
			t.Fatal("balance left the group")
		}
	}

	// Nobody is over commit, and balance is off: do not move.
	off := build(t, "balance: off")
	if moves := off.Plan(in); len(moves) != 0 {
		t.Fatalf("balance off moved inside the group: %+v", moves)
	}
}

func TestProportionalBalance(t *testing.T) {
	s := build(t, "balance: proportional\nbalance_slack: 0.05")
	// Neither provider is over its own commit. Shares follow the commits
	// (200 and 100): of 180 Mbps, a's target is 120 and b's is 60.
	in := plugin.PlanInput{
		Now: t0,
		Providers: []plugin.PlanProvider{
			prov("a", "edge", 10, usage("a", 200, 150)),
			prov("b", "edge", 10, usage("b", 100, 30)),
		},
		Prefixes: []plugin.PlanPrefix{
			prefix(p1, "a", 20, path("a", 0), path("b", 0)),
		},
	}
	got := movesTo(s.Plan(in))
	if got[p1] != "b" {
		t.Fatalf("proportional moves = %v", got)
	}
}

func TestRelievePrefersPrecedenceOverGroup(t *testing.T) {
	s := build(t, "")
	// b shares a's group but has a worse precedence than c. d is the last
	// resort, so b is not excluded by that rule. c must win.
	in := plugin.PlanInput{
		Now: t0,
		Providers: []plugin.PlanProvider{
			prov("a", "edge", 10, usage("a", 100, 160)),
			prov("b", "edge", 40, usage("b", 100, 10)),
			prov("c", "", 20, usage("c", 100, 10)),
			prov("d", "", 100, usage("d", 100, 10)),
		},
		Prefixes: []plugin.PlanPrefix{
			prefix(p1, "a", 50, path("a", 0), path("b", 0), path("c", 0), path("d", 0)),
		},
	}
	if got := movesTo(s.Plan(in)); got[p1] != "c" {
		t.Fatalf("same group outranked a better precedence: %v", got)
	}
}

func TestLockedPerformanceVolumeIsAlreadyLeaving(t *testing.T) {
	s := build(t, "")
	in := plugin.PlanInput{
		Now: t0,
		Providers: []plugin.PlanProvider{
			prov("a", "", 10, usage("a", 100, 150)),
			prov("b", "", 10, usage("b", 100, 10)),
		},
		Prefixes: []plugin.PlanPrefix{
			{Prefix: p1, Native: "a", Current: "b", VolumeMbps: 60, Locked: true, Paths: []plugin.PlanPath{path("a", 0), path("b", 0)}},
			prefix(p2, "a", 40, path("a", 0), path("b", 0)),
		},
	}
	if moves := s.Plan(in); len(moves) != 0 {
		t.Fatalf("commit moved traffic a performance steer is already taking: %+v", moves)
	}
}

func TestReversibleCommitIsKeptUntilTheFigureDrops(t *testing.T) {
	s := build(t, "")
	kept := plugin.PlanPrefix{
		Prefix: p1, Native: "a", Current: "b", VolumeMbps: 60, Reversible: true,
		Paths: []plugin.PlanPath{path("a", 0), path("b", 0)},
	}
	in := plugin.PlanInput{
		Now: t0,
		Providers: []plugin.PlanProvider{
			prov("a", "", 10, usage("a", 100, 90)),
			prov("b", "", 10, usage("b", 100, 100)),
		},
		Prefixes: []plugin.PlanPrefix{kept},
	}
	if got := movesTo(s.Plan(in)); got[p1] != "b" {
		t.Fatalf("in-place commit steer was dropped while native would go over: %v", got)
	}
	in.Providers[0].Usage.UsageMbps = 20
	in.Providers[1].Usage.UsageMbps = 80
	if moves := s.Plan(in); len(moves) != 0 {
		t.Fatalf("commit steer survived after the native provider could take it back: %+v", moves)
	}
}
