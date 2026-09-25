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
