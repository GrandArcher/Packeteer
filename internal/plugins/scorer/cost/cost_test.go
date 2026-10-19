package cost

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var (
	p1 = netip.MustParsePrefix("198.51.100.0/24")
	p2 = netip.MustParsePrefix("203.0.113.0/24")
)

func build(t *testing.T, y string) *Scorer {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	s, err := plugin.Scorers.New(TypeName, c, plugin.Env{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return s.(*Scorer)
}

func prov(name string, cost float64) plugin.PlanProvider {
	return plugin.PlanProvider{Name: name, Up: true, Cost: cost, HasCost: true}
}

func path(name string, loss, rttMs float64) plugin.PlanPath {
	return plugin.PlanPath{Provider: name, LossPct: loss, RTT: time.Duration(rttMs * float64(time.Millisecond)), Usable: true}
}

func TestPlanCheapestInsideFloor(t *testing.T) {
	provs := []plugin.PlanProvider{prov("a", 10), prov("b", 5), prov("c", 2)}
	for _, tc := range []struct {
		name  string
		cfg   string
		provs []plugin.PlanProvider
		px    plugin.PlanPrefix
		want  string
	}{
		{name: "cheapest inside floor", px: plugin.PlanPrefix{Prefix: p1, Native: "a", Current: "a",
			Paths: []plugin.PlanPath{path("a", 0, 40), path("b", 0, 45), path("c", 0, 49)}}, want: "c"},
		{name: "cheapest outside rtt floor", px: plugin.PlanPrefix{Prefix: p1, Native: "a", Current: "a",
			Paths: []plugin.PlanPath{path("a", 0, 40), path("b", 0, 45), path("c", 0, 51)}}, want: "b"},
		{name: "floor measured from the best path, not native", px: plugin.PlanPrefix{Prefix: p1, Native: "a", Current: "a",
			Paths: []plugin.PlanPath{path("a", 0, 60), path("b", 0, 30), path("c", 0, 45)}}, want: "b"},
		{name: "loss outside floor", px: plugin.PlanPrefix{Prefix: p1, Native: "a", Current: "a",
			Paths: []plugin.PlanPath{path("a", 0, 40), path("b", 0.1, 40), path("c", 0.1, 40)}}},
		{name: "loss floor widened", cfg: "floor: {max_loss_pct: 0.5}", px: plugin.PlanPrefix{Prefix: p1, Native: "a", Current: "a",
			Paths: []plugin.PlanPath{path("a", 0, 40), path("b", 0.1, 40), path("c", 0.6, 40)}}, want: "b"},
		{name: "unusable path", px: plugin.PlanPrefix{Prefix: p1, Native: "a", Current: "a",
			Paths: []plugin.PlanPath{path("a", 0, 40), {Provider: "c", Usable: false}}}},
		{name: "locked performance steer", px: plugin.PlanPrefix{Prefix: p1, Native: "a", Current: "b", Locked: true,
			Paths: []plugin.PlanPath{path("a", 0, 40), path("c", 0, 40)}}},
		{name: "native cheapest", px: plugin.PlanPrefix{Prefix: p1, Native: "c", Current: "c",
			Paths: []plugin.PlanPath{path("a", 0, 40), path("c", 0, 40)}}},
		{name: "equal price keeps the active steer", provs: []plugin.PlanProvider{prov("a", 10), prov("b", 2), prov("c", 2)},
			px: plugin.PlanPrefix{Prefix: p1, Native: "a", Current: "c", Reversible: true,
				Paths: []plugin.PlanPath{path("a", 0, 40), path("b", 0, 40), path("c", 0, 40)}}, want: "c"},
		{name: "excluded provider sets no floor and is no destination",
			provs: []plugin.PlanProvider{prov("a", 10), prov("b", 5), {Name: "c", Up: true, Cost: 1, HasCost: true, Excluded: true}},
			px: plugin.PlanPrefix{Prefix: p1, Native: "a", Current: "a",
				Paths: []plugin.PlanPath{path("a", 0, 40), path("b", 0, 48), path("c", 0, 5)}}, want: "b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ps := provs
			if tc.provs != nil {
				ps = tc.provs
			}
			moves := build(t, tc.cfg).Plan(plugin.PlanInput{Providers: ps, Prefixes: []plugin.PlanPrefix{tc.px}})
			if tc.want == "" {
				if len(moves) != 0 {
					t.Fatalf("moves %+v", moves)
				}
				return
			}
			if len(moves) != 1 || moves[0].Provider != tc.want || moves[0].Cause != plugin.CauseCost {
				t.Fatalf("moves %+v, want %s", moves, tc.want)
			}
		})
	}
}

func TestPlanSavings(t *testing.T) {
	s := build(t, "")
	moves := s.Plan(plugin.PlanInput{
		Providers: []plugin.PlanProvider{prov("a", 10), prov("b", 4)},
		Prefixes: []plugin.PlanPrefix{
			{Prefix: p2, Native: "a", Current: "a", Paths: []plugin.PlanPath{path("a", 0, 40), path("b", 0, 40)}},
			{Prefix: p1, Native: "a", Current: "a", VolumeMbps: 50, Paths: []plugin.PlanPath{path("a", 0, 40), path("b", 0, 40)}},
		},
	})
	if len(moves) != 2 || moves[0].Prefix != p1 || moves[0].Savings != 300 || moves[1].Savings != 6 {
		t.Fatalf("moves %+v", moves)
	}
	if !strings.Contains(moves[0].Reason, "cost:") {
		t.Fatalf("reason %q", moves[0].Reason)
	}
}

func TestConfig(t *testing.T) {
	s := build(t, "")
	if l, r := s.Floor(); l != 0 || r != DefaultFloorRTT || s.CostFirst() {
		t.Fatalf("defaults: %v %v %v", l, r, s.CostFirst())
	}
	s = build(t, "precedence: cost\nfloor: {max_loss_pct: 1.5, max_rtt: 25ms}")
	if l, r := s.Floor(); l != 1.5 || r != 25*time.Millisecond || !s.CostFirst() {
		t.Fatalf("custom: %v %v %v", l, r, s.CostFirst())
	}
	if got := s.Score(plugin.PathStats{LossPct: 1, RTTAvg: 30 * time.Millisecond}); got != 130 {
		t.Fatalf("score %v", got)
	}
	var _ plugin.Planner = s
	var _ plugin.CostPolicy = s
	for y, want := range map[string]string{
		"precedence: cheapest":                            "precedence",
		"floor: {max_loss_pct: -1}":                       "max_loss_pct",
		"floor: {max_loss_pct: 101}":                      "max_loss_pct",
		"floor: {max_loss_pct: .nan}":                     "max_loss_pct",
		"floor: {max_rtt: -1ms}":                          "max_rtt",
		"floor: {max_rtt: 1h}":                            "max_rtt",
		"loss_weight: -1":                                 "negative",
		"bogus: 1":                                        "field bogus not found",
		"floor: {bogus: 1}":                               "field bogus not found",
		"loss_weight: 0\nrtt_weight: 0\njitter_weight: 0": "at least one weight",
	} {
		c, err := plugin.ConfigFromYAML(y)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := plugin.Scorers.New(TypeName, c, plugin.Env{}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v", y, err)
		}
	}
}

func portInput(capacity, commit float64, row plugin.Usage, have bool, vol float64) plugin.PlanInput {
	return plugin.PlanInput{
		Now: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		Providers: []plugin.PlanProvider{
			prov("transit", 10),
			{Name: "ix-a", Up: true, HasCost: true, Port: "ix"},
			{Name: "ix-b", Up: true, HasCost: true, Port: "ix"},
		},
		Ports: []plugin.PlanPort{{Name: "ix", CapacityMbps: capacity, CommitMbps: commit, Usage: row, HaveRow: have}},
		Prefixes: []plugin.PlanPrefix{
			{Prefix: p1, Native: "transit", Current: "transit", VolumeMbps: vol,
				Paths: []plugin.PlanPath{path("transit", 0, 40), path("ix-a", 0, 40), path("ix-b", 0, 40)}},
			{Prefix: p2, Native: "transit", Current: "transit", VolumeMbps: vol,
				Paths: []plugin.PlanPath{path("transit", 0, 40), path("ix-a", 0, 40), path("ix-b", 0, 40)}},
		},
	}
}

func portRow(p95 float64) plugin.Usage {
	return plugin.Usage{
		Provider: "ix", CommitMbps: 1, Samples: 10, Single: true, UsageMbps: p95,
		Updated: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
	}
}

func TestPortPeerCostsNothingUntilThePortIsFull(t *testing.T) {
	s := build(t, "")
	// Both prefixes fit: 100 of 1000 plus 2 x 100.
	moves := s.Plan(portInput(1000, 0, portRow(100), true, 100))
	if len(moves) != 2 {
		t.Fatalf("moves %+v, want both prefixes on the free port", moves)
	}
	for _, m := range moves {
		if m.Savings != 10*100 {
			t.Fatalf("savings %v, want the whole transit price (10 per Mbps x 100 Mbps)", m.Savings)
		}
	}
	// Only one fits in 150 Mbps of room, the second is held back.
	moves = s.Plan(portInput(1000, 0, portRow(850), true, 100))
	if len(moves) != 1 || moves[0].Prefix != p1 {
		t.Fatalf("moves %+v, want only the first prefix (room for one)", moves)
	}
	// A port commit binds before the capacity does.
	moves = s.Plan(portInput(1000, 250, portRow(100), true, 100))
	if len(moves) != 1 {
		t.Fatalf("moves %+v, want one move under a 250 Mbps commit", moves)
	}
}

func TestPortRefusesWithoutAFreshReadingOrAVolume(t *testing.T) {
	s := build(t, "")
	stale := portRow(10)
	stale.Updated = stale.Updated.Add(-time.Hour)
	for name, in := range map[string]plugin.PlanInput{
		"no row":         portInput(1000, 0, plugin.Usage{}, false, 100),
		"stale row":      portInput(1000, 0, stale, true, 100),
		"unknown volume": portInput(1000, 0, portRow(10), true, 0),
	} {
		if moves := s.Plan(in); len(moves) != 0 {
			t.Errorf("%s: moves %+v onto a port that cannot be checked", name, moves)
		}
	}
}

func TestPortBooksLockedAndActiveSteers(t *testing.T) {
	s := build(t, "")
	in := portInput(1000, 0, portRow(850), true, 100)
	// p2 is a performance steer onto the port: its 100 Mbps is not in the
	// row yet, so the port has 50 Mbps of room left and p1 must stay.
	in.Prefixes[1].Locked = true
	in.Prefixes[1].Current = "ix-b"
	if moves := s.Plan(in); len(moves) != 0 {
		t.Fatalf("moves %+v ignored the locked steer's volume", moves)
	}
	// An active cost steer is already in the row. Replanned from native it
	// frees its volume first, so it keeps its place.
	in = portInput(1000, 0, portRow(950), true, 100)
	in.Prefixes = in.Prefixes[:1]
	in.Prefixes[0].Current, in.Prefixes[0].Reversible = "ix-a", true
	moves := s.Plan(in)
	if len(moves) != 1 || moves[0].Provider != "ix-a" {
		t.Fatalf("moves %+v, want the active steer kept", moves)
	}
}

func TestPlanReasonIsASCII(t *testing.T) {
	moves := build(t, "").Plan(plugin.PlanInput{
		Providers: []plugin.PlanProvider{prov("a", 10), prov("b", 4)},
		Prefixes: []plugin.PlanPrefix{
			{Prefix: p1, Native: "a", Current: "a", Paths: []plugin.PlanPath{path("a", 0, 40), path("b", 0, 40)}},
		},
	})
	if len(moves) != 1 {
		t.Fatalf("moves %+v", moves)
	}
	if want := "cost: a 10->b 4 per Mbps inside floor"; moves[0].Reason != want {
		t.Fatalf("reason = %q, want %q", moves[0].Reason, want)
	}
}
