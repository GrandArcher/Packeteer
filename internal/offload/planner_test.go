package offload

import (
	"fmt"
	"math"
	"math/rand"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weights"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func testCfg() PlannerConfig {
	return PlannerConfig{
		DisplaceMargin:   ptr(DefaultDisplaceMargin),
		HoldTime:         10 * time.Minute,
		MaxSwapsPerRound: 2,
		MaxShedPerRound:  DefaultMaxShedPerRound,
	}
}

func newPlanner(t *testing.T, p Profile, cfg PlannerConfig) *Planner {
	t.Helper()
	pl, err := NewPlanner(p, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return pl
}

func plan(t *testing.T, pl *Planner, in Input) Plan {
	t.Helper()
	got, err := pl.Plan(in)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// actions maps each decided prefix to its action; a swap also maps the
// displaced prefix to "out".
func actions(p Plan) map[string]string {
	m := map[string]string{}
	for _, d := range p.Decisions {
		m[d.Prefix.String()] = string(d.Action)
		if d.Action == Swap {
			m[d.Out.String()] = "out"
		}
	}
	return m
}

func count(p Plan, a Action) int {
	n := 0
	for _, d := range p.Decisions {
		if d.Action == a {
			n++
		}
	}
	return n
}

func installedFix(p string, gain float64, since time.Time) Candidate {
	return Candidate{Prefix: pfx(p), Cause: plugin.CausePerformance, Gain: gain, Since: since, Installed: true}
}

func wantFix(p string, gain float64) Candidate {
	return Candidate{Prefix: pfx(p), Cause: plugin.CausePerformance, Gain: gain, Since: t0}
}

var full = Result{HeadroomV4: 0, HeadroomV6: 0}

func TestMarginAndHoldTime(t *testing.T) {
	old := t0.Add(-time.Hour)
	cases := []struct {
		name  string
		gain  float64 // challenger
		since time.Time
		want  string
	}{
		{"above margin", 125.1, old, "swap"},
		{"exactly at margin", 125, old, "swap"},
		{"below margin", 124.9, old, "withhold"},
		{"equal weight", 100, old, "withhold"},
		{"inside hold time", 200, t0.Add(-9 * time.Minute), "withhold"},
		{"exactly hold time", 200, t0.Add(-10 * time.Minute), "swap"},
		{"installed time unknown", 200, time.Time{}, "withhold"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pl := newPlanner(t, NoneProfile(), testCfg())
			got := plan(t, pl, Input{
				Now:        t0,
				Candidates: []Candidate{installedFix("192.0.2.0/24", 100, c.since), wantFix("198.51.100.0/24", c.gain)},
				Budget:     full,
			})
			a := actions(got)
			if a["198.51.100.0/24"] != c.want {
				t.Fatalf("challenger %s, want %s: %+v", a["198.51.100.0/24"], c.want, got.Decisions)
			}
			if c.want == "swap" && a["192.0.2.0/24"] != "out" {
				t.Fatalf("victim not displaced: %+v", got.Decisions)
			}
			if c.want == "withhold" && a["192.0.2.0/24"] != "keep" {
				t.Fatalf("victim not kept: %+v", got.Decisions)
			}
		})
	}
}

func TestZeroWeightsDoNotSwap(t *testing.T) {
	pl := newPlanner(t, NoneProfile(), testCfg())
	got := plan(t, pl, Input{
		Now:        t0,
		Candidates: []Candidate{installedFix("192.0.2.0/24", 0, t0.Add(-time.Hour)), wantFix("198.51.100.0/24", 0)},
		Budget:     full,
	})
	if count(got, Swap) != 0 {
		t.Fatalf("swapped equal zero weights: %+v", got.Decisions)
	}
}

func TestSwapsAreCappedPerRound(t *testing.T) {
	cfg := testCfg()
	cfg.MaxSwapsPerRound = 2
	pl := newPlanner(t, NoneProfile(), cfg)
	old := t0.Add(-time.Hour)
	in := Input{Now: t0, Budget: full}
	for i := 0; i < 4; i++ {
		in.Candidates = append(in.Candidates,
			installedFix(fmt.Sprintf("192.0.2.%d/32", i), 10, old),
			wantFix(fmt.Sprintf("198.51.100.%d/32", i), 100))
	}
	got := plan(t, pl, in)
	if n := count(got, Swap); n != 2 {
		t.Fatalf("%d swaps, want 2: %+v", n, got.Decisions)
	}
	if n := count(got, Withhold); n != 2 {
		t.Fatalf("%d withheld, want 2", n)
	}
	// Each victim leaves once.
	outs := map[netip.Prefix]bool{}
	for _, d := range got.Decisions {
		if d.Action == Swap {
			if outs[d.Out] {
				t.Fatalf("%s displaced twice", d.Out)
			}
			outs[d.Out] = true
		}
	}
}

func TestSwapRateCapPerMinute(t *testing.T) {
	cases := []struct {
		name  string
		capPM int
		used  int
		want  int
	}{
		{"off", 0, 100, 2},
		{"room for one", 3, 2, 1},
		{"cap reached", 3, 3, 0},
		{"over cap", 3, 9, 0},
		{"round cap binds", 10, 0, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := testCfg()
			cfg.MaxSwapsPerMinute = c.capPM
			pl := newPlanner(t, NoneProfile(), cfg)
			old := t0.Add(-time.Hour)
			in := Input{Now: t0, Budget: full, SwapsLastMinute: c.used}
			for i := 0; i < 3; i++ {
				in.Candidates = append(in.Candidates,
					installedFix(fmt.Sprintf("192.0.2.%d/32", i), 10, old),
					wantFix(fmt.Sprintf("198.51.100.%d/32", i), 100))
			}
			if n := count(plan(t, pl, in), Swap); n != c.want {
				t.Fatalf("%d swaps, want %d", n, c.want)
			}
		})
	}
}

func TestSwapKeepsFamily(t *testing.T) {
	pl := newPlanner(t, NoneProfile(), testCfg())
	got := plan(t, pl, Input{
		Now: t0,
		Candidates: []Candidate{
			installedFix("192.0.2.0/24", 10, t0.Add(-time.Hour)),
			wantFix("2001:db8::/32", 100),
		},
		Budget: full,
	})
	if a := actions(got); a["2001:db8::/32"] != "withhold" || a["192.0.2.0/24"] != "keep" {
		t.Fatalf("an IPv6 fix displaced an IPv4 one: %+v", got.Decisions)
	}
}

func TestShedLowestFirstAndCapped(t *testing.T) {
	cfg := testCfg()
	cfg.MaxShedPerRound = 3
	pl := newPlanner(t, NoneProfile(), cfg)
	in := Input{Now: t0, Budget: Result{ShedOK: true}}
	for i := 1; i <= 6; i++ {
		in.Candidates = append(in.Candidates, installedFix(fmt.Sprintf("192.0.2.%d/32", i), float64(i), t0.Add(-time.Hour)))
	}
	got := plan(t, pl, in)
	a := actions(got)
	for i := 1; i <= 6; i++ {
		want := "keep"
		if i <= 3 {
			want = "shed"
		}
		if a[fmt.Sprintf("192.0.2.%d/32", i)] != want {
			t.Fatalf("192.0.2.%d/32 is %s, want %s: %+v", i, a[fmt.Sprintf("192.0.2.%d/32", i)], want, got.Decisions)
		}
	}
}

func TestNoShedWithoutPressure(t *testing.T) {
	pl := newPlanner(t, NoneProfile(), testCfg())
	got := plan(t, pl, Input{
		Now:        t0,
		Candidates: []Candidate{installedFix("192.0.2.0/24", 1, t0)},
		Budget:     Result{HeadroomV4: 10},
	})
	if count(got, Shed) != 0 || count(got, Keep) != 1 {
		t.Fatalf("%+v", got.Decisions)
	}
}

func TestMitigationIsNeverShedOrSwapped(t *testing.T) {
	cfg := testCfg()
	cfg.MaxShedPerRound = 100
	pl := newPlanner(t, NoneProfile(), cfg)
	in := Input{
		Now:        t0,
		Mitigation: []netip.Prefix{pfx("203.0.113.1/32"), pfx("203.0.113.2/32")},
		Candidates: []Candidate{
			installedFix("192.0.2.0/24", 1, t0.Add(-time.Hour)),
			wantFix("198.51.100.0/24", 1000),
		},
		Budget: Result{ShedOK: true},
	}
	got := plan(t, pl, in)
	a := actions(got)
	for _, m := range in.Mitigation {
		if a[m.String()] != "keep" {
			t.Fatalf("mitigation %s is %s", m, a[m.String()])
		}
	}
	if a["192.0.2.0/24"] != "shed" {
		t.Fatalf("improvement was not shed: %+v", got.Decisions)
	}
	if _, err := pl.Plan(Input{Now: t0, Mitigation: []netip.Prefix{pfx("203.0.113.1/32")},
		Candidates: []Candidate{installedFix("203.0.113.1/32", 1, t0)}}); err == nil {
		t.Fatal("a prefix in both lists was accepted")
	}
}

func TestFreezeAndSettlingInstallAndShedNothing(t *testing.T) {
	prof := NoneProfile()
	prof.Timing = Timing{InstallSeconds: 30, AgeOutSeconds: 120}
	cands := []Candidate{installedFix("192.0.2.0/24", 1, t0.Add(-time.Hour)), wantFix("198.51.100.0/24", 1000)}
	cases := []struct {
		name   string
		in     Input
		reason FreezeReason
	}{
		{"budget freeze", Input{Budget: Result{Freezes: []Freeze{{FreezeStale, FIBv4}}}}, FreezeStale},
		{"installing", Input{Budget: Result{HeadroomV4: 9, ShedOK: true}, LastInstall: t0.Add(-29 * time.Second)}, FreezeSettling},
		{"ageing out", Input{Budget: Result{HeadroomV4: 9, ShedOK: true}, LastShed: t0.Add(-119 * time.Second)}, FreezeSettling},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.in.Now, c.in.Candidates = t0, cands
			got := plan(t, newPlanner(t, prof, testCfg()), c.in)
			if len(got.Freezes) == 0 || got.Freezes[len(got.Freezes)-1].Reason != c.reason {
				t.Fatalf("freezes %+v, want %s", got.Freezes, c.reason)
			}
			a := actions(got)
			if a["192.0.2.0/24"] != "keep" || a["198.51.100.0/24"] != "withhold" {
				t.Fatalf("acted while frozen: %+v", got.Decisions)
			}
		})
	}
	t.Run("settled", func(t *testing.T) {
		got := plan(t, newPlanner(t, prof, testCfg()), Input{
			Now: t0, Candidates: cands, Budget: Result{HeadroomV4: 9},
			LastInstall: t0.Add(-30 * time.Second), LastShed: t0.Add(-120 * time.Second),
		})
		if len(got.Freezes) != 0 || actions(got)["198.51.100.0/24"] != "install" {
			t.Fatalf("%+v %+v", got.Freezes, got.Decisions)
		}
	})
}

func hostFix(p string, gain float64) Candidate {
	c := wantFix(p, gain)
	c.HostEntry = true
	return c
}

// A host entry draws on the host headroom, not the FIB's: with the FIB full
// it installs, and each install also uses up the room the other fixes share.
func TestHostEntriesDrawOnTheirOwnHeadroom(t *testing.T) {
	pl := newPlanner(t, NoneProfile(), testCfg())
	got := plan(t, pl, Input{
		Now: t0,
		Candidates: []Candidate{
			hostFix("192.0.2.1/32", 3), hostFix("192.0.2.2/32", 2), hostFix("192.0.2.3/32", 1),
			wantFix("198.51.100.0/24", 9),
		},
		Budget: Result{HeadroomV4: 0, HeadroomHost: 2},
	})
	want := map[string]string{
		"192.0.2.1/32": "install", "192.0.2.2/32": "install", "192.0.2.3/32": "withhold",
		"198.51.100.0/24": "withhold",
	}
	if !reflect.DeepEqual(actions(got), want) {
		t.Fatalf("%v", actions(got))
	}

	// Shared next-hop room: a host entry ahead of a route leaves one less for it.
	got = plan(t, pl, Input{
		Now:        t0,
		Candidates: []Candidate{hostFix("192.0.2.1/32", 3), wantFix("198.51.100.0/24", 1), wantFix("203.0.113.0/24", 2)},
		Budget:     Result{HeadroomV4: 5, HeadroomHost: 2},
	})
	want = map[string]string{"192.0.2.1/32": "install", "198.51.100.0/24": "withhold", "203.0.113.0/24": "install"}
	if !reflect.DeepEqual(actions(got), want) {
		t.Fatalf("%v", actions(got))
	}
}

// Under FIB pressure an installed host entry is not shed (it takes no FIB
// entry) while an installed route is, and a host entry is never a swap victim
// for a route: removing it frees no FIB entry.
func TestHostEntriesAreNotShedForFIBPressure(t *testing.T) {
	old := t0.Add(-time.Hour)
	host := installedFix("192.0.2.1/32", 1, old)
	host.HostEntry = true
	pl := newPlanner(t, NoneProfile(), testCfg())
	got := plan(t, pl, Input{
		Now:        t0,
		Candidates: []Candidate{host, installedFix("198.51.100.0/24", 2, old), hostFix("192.0.2.2/32", 100)},
		Budget:     Result{HeadroomV4: 0, HeadroomHost: 5, ShedOK: true},
	})
	want := map[string]string{"192.0.2.1/32": "keep", "198.51.100.0/24": "shed", "192.0.2.2/32": "install"}
	if !reflect.DeepEqual(actions(got), want) {
		t.Errorf("%v", actions(got))
	}

	// No room anywhere: the wanted route displaces the installed route, not
	// the lower-ranked installed host entry.
	got = plan(t, pl, Input{
		Now:        t0,
		Candidates: []Candidate{host, installedFix("198.51.100.0/24", 2, old), wantFix("203.0.113.0/24", 100)},
		Budget:     Result{HeadroomV4: 0, HeadroomHost: 1},
	})
	want = map[string]string{"192.0.2.1/32": "keep", "198.51.100.0/24": "out", "203.0.113.0/24": "swap"}
	if !reflect.DeepEqual(actions(got), want) {
		t.Errorf("%v", actions(got))
	}
}

func TestInstallByRankWithinHeadroom(t *testing.T) {
	pl := newPlanner(t, NoneProfile(), testCfg())
	got := plan(t, pl, Input{
		Now: t0,
		Candidates: []Candidate{
			wantFix("192.0.2.1/32", 1), wantFix("192.0.2.2/32", 3), wantFix("192.0.2.3/32", 2),
			wantFix("2001:db8::1/128", 9),
		},
		Budget: Result{HeadroomV4: 2, HeadroomV6: 0},
	})
	want := map[string]string{
		"192.0.2.1/32": "withhold", "192.0.2.2/32": "install", "192.0.2.3/32": "install",
		"2001:db8::1/128": "withhold",
	}
	if !reflect.DeepEqual(actions(got), want) {
		t.Fatalf("%v", actions(got))
	}
}

func TestSharedIPv6PoolCountsAgainstV4(t *testing.T) {
	cfg := testCfg()
	cfg.IPv6 = IPv6Pool{Shared: true, Weight: 2}
	pl := newPlanner(t, NoneProfile(), cfg)
	got := plan(t, pl, Input{
		Now: t0,
		Candidates: []Candidate{
			wantFix("2001:db8::1/128", 10), wantFix("2001:db8::2/128", 9), wantFix("192.0.2.1/32", 8),
		},
		Budget: Result{HeadroomV4: 3, HeadroomV6: 1},
	})
	want := map[string]string{"2001:db8::1/128": "install", "2001:db8::2/128": "withhold", "192.0.2.1/32": "install"}
	if !reflect.DeepEqual(actions(got), want) {
		t.Fatalf("%v", actions(got))
	}
}

func TestDefaultRouteIsNeverPlanned(t *testing.T) {
	pl := newPlanner(t, NoneProfile(), testCfg())
	got := plan(t, pl, Input{
		Now:        t0,
		Candidates: []Candidate{wantFix("0.0.0.0/0", 100), wantFix("::/0", 100), {Gain: 5}},
		Budget:     Result{HeadroomV4: 9, HeadroomV6: 9},
	})
	if count(got, Install) != 0 || count(got, Withhold) != 3 {
		t.Fatalf("%+v", got.Decisions)
	}
}

func TestDuplicatePrefixIsAnError(t *testing.T) {
	pl := newPlanner(t, NoneProfile(), testCfg())
	_, err := pl.Plan(Input{Now: t0, Candidates: []Candidate{wantFix("192.0.2.0/24", 1), wantFix("192.0.2.0/24", 2)}})
	if err == nil || !strings.Contains(err.Error(), "192.0.2.0/24") {
		t.Fatalf("err = %v", err)
	}
}

func TestEmphasisFollowsMiss(t *testing.T) {
	// A has the larger gain, B the larger volume; one slot.
	cands := []Candidate{
		{Prefix: pfx("192.0.2.0/24"), Cause: plugin.CausePerformance, Gain: 50, VolumeMbps: 1, Since: t0},
		{Prefix: pfx("198.51.100.0/24"), Cause: plugin.CausePerformance, Gain: 5, VolumeMbps: 900, Since: t0},
	}
	for _, c := range []struct {
		miss Miss
		want string
	}{{Drop, "192.0.2.0/24"}, {CPUPunt, "198.51.100.0/24"}} {
		t.Run(string(c.miss), func(t *testing.T) {
			prof := NoneProfile()
			prof.Miss = c.miss
			got := plan(t, newPlanner(t, prof, testCfg()), Input{Now: t0, Candidates: cands, Budget: Result{HeadroomV4: 1}})
			for p, a := range actions(got) {
				if (p == c.want) != (a == "install") {
					t.Fatalf("%s -> %s, want %s installed", p, a, c.want)
				}
			}
		})
	}
}

func TestWeigherDecidesTheOrder(t *testing.T) {
	vol := 1.0
	w, err := weights.New(&weights.Config{Volume: &vol})
	if err != nil {
		t.Fatal(err)
	}
	cfg := testCfg()
	cfg.Weigher = w
	// Gain 10 + 0 = 10 against gain 1 + 100 = 101.
	got := plan(t, newPlanner(t, NoneProfile(), cfg), Input{
		Now: t0,
		Candidates: []Candidate{
			{Prefix: pfx("192.0.2.0/24"), Cause: plugin.CausePerformance, Gain: 10},
			{Prefix: pfx("198.51.100.0/24"), Cause: plugin.CausePerformance, Gain: 1, VolumeMbps: 100},
		},
		Budget: Result{HeadroomV4: 1},
	})
	if a := actions(got); a["198.51.100.0/24"] != "install" || a["192.0.2.0/24"] != "withhold" {
		t.Fatalf("%v", a)
	}
}

func TestEqualWeightTieBreaks(t *testing.T) {
	cands := []Candidate{
		{Prefix: pfx("192.0.2.4/32"), Cause: plugin.CauseCost, Gain: 1, Since: t0},
		{Prefix: pfx("192.0.2.3/32"), Cause: plugin.CausePerformance, Gain: 1, VolumeMbps: 1, Since: t0},
		{Prefix: pfx("192.0.2.2/32"), Cause: plugin.CausePerformance, Gain: 1, VolumeMbps: 2, Since: t0},
		{Prefix: pfx("192.0.2.1/32"), Cause: plugin.CausePerformance, Gain: 1, VolumeMbps: 2, Since: t0.Add(time.Hour)},
		{Prefix: pfx("192.0.2.0/32"), Cause: plugin.CauseStatic, Gain: 1, VolumeMbps: 0, Since: t0},
		{Prefix: pfx("192.0.2.9/32"), Cause: plugin.CausePerformance, Gain: 1, VolumeMbps: 2, Since: t0},
	}
	pl := newPlanner(t, NoneProfile(), testCfg())
	// Rank: static, then performance by volume (2: older first, then prefix),
	// then volume 1, then cost.
	want := []string{"192.0.2.0/32", "192.0.2.2/32", "192.0.2.9/32", "192.0.2.1/32", "192.0.2.3/32", "192.0.2.4/32"}
	for n := 1; n <= len(want); n++ {
		got := plan(t, pl, Input{Now: t0, Candidates: cands, Budget: Result{HeadroomV4: uint64(n)}})
		for i, p := range want {
			if inst := actions(got)[p] == "install"; inst != (i < n) {
				t.Fatalf("headroom %d: %s installed = %v", n, p, inst)
			}
		}
	}
}

func TestPlanIsDeterministic(t *testing.T) {
	pl := newPlanner(t, NoneProfile(), testCfg())
	rng := rand.New(rand.NewSource(1))
	causes := []string{plugin.CauseStatic, plugin.CausePerformance, plugin.CauseCommit, plugin.CauseCost, ""}
	for round := 0; round < 200; round++ {
		var cands []Candidate
		for i := 0; i < 12; i++ {
			c := Candidate{
				Cause:      causes[rng.Intn(len(causes))],
				Gain:       float64(rng.Intn(3)),
				VolumeMbps: float64(rng.Intn(3)),
				Since:      t0.Add(-time.Duration(rng.Intn(3)) * time.Hour),
				Installed:  rng.Intn(2) == 0,
			}
			if rng.Intn(4) == 0 {
				c.Prefix = netip.PrefixFrom(netip.MustParseAddr("2001:db8::").Next(), 128)
				for j := 0; j < i; j++ {
					c.Prefix = netip.PrefixFrom(c.Prefix.Addr().Next(), 128)
				}
			} else {
				c.Prefix = netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), 32)
			}
			cands = append(cands, c)
		}
		in := Input{
			Now: t0, Candidates: cands, Mitigation: []netip.Prefix{pfx("203.0.113.9/32")},
			Budget: Result{HeadroomV4: uint64(rng.Intn(4)), HeadroomV6: uint64(rng.Intn(3)), ShedOK: rng.Intn(3) == 0},
		}
		want := plan(t, pl, in)
		for k := 0; k < 5; k++ {
			shuffled := in
			shuffled.Candidates = append([]Candidate(nil), cands...)
			rng.Shuffle(len(shuffled.Candidates), func(i, j int) {
				shuffled.Candidates[i], shuffled.Candidates[j] = shuffled.Candidates[j], shuffled.Candidates[i]
			})
			if got := plan(t, pl, shuffled); !reflect.DeepEqual(got, want) {
				t.Fatalf("round %d: order of input changed the plan\n%+v\n%+v", round, want.Decisions, got.Decisions)
			}
		}
		if n := count(want, Swap); n > testCfg().MaxSwapsPerRound {
			t.Fatalf("%d swaps over the cap", n)
		}
		if n := count(want, Shed); n > DefaultMaxShedPerRound {
			t.Fatalf("%d sheds over the cap", n)
		}
	}
}

func TestPlannerConfigValidation(t *testing.T) {
	bad := map[string]func(*PlannerConfig){
		"negative margin":   func(c *PlannerConfig) { c.DisplaceMargin = ptr(-0.1) },
		"NaN margin":        func(c *PlannerConfig) { c.DisplaceMargin = ptr(math.NaN()) },
		"negative hold":     func(c *PlannerConfig) { c.HoldTime = -1 },
		"no swaps":          func(c *PlannerConfig) { c.MaxSwapsPerRound = 0 },
		"negative rate cap": func(c *PlannerConfig) { c.MaxSwapsPerMinute = -1 },
		"negative sheds":    func(c *PlannerConfig) { c.MaxShedPerRound = -1 },
		"shared no weight":  func(c *PlannerConfig) { c.IPv6 = IPv6Pool{Shared: true} },
	}
	for name, f := range bad {
		cfg := testCfg()
		f(&cfg)
		if _, err := NewPlanner(NoneProfile(), cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	prof := NoneProfile()
	prof.Timing.InstallSeconds = -1
	if _, err := NewPlanner(prof, testCfg()); err == nil {
		t.Error("negative timing accepted")
	}
}

func ptr(v float64) *float64 { return &v }

func TestDefaultsApply(t *testing.T) {
	cfg := testCfg()
	cfg.DisplaceMargin, cfg.MaxShedPerRound = nil, 0
	pl := newPlanner(t, NoneProfile(), cfg)
	if *pl.cfg.DisplaceMargin != 0.25 || pl.cfg.MaxShedPerRound != 5 {
		t.Fatalf("margin %v, max shed %d", *pl.cfg.DisplaceMargin, pl.cfg.MaxShedPerRound)
	}
	// A zero margin given on purpose is kept: any strictly larger weight swaps.
	cfg.DisplaceMargin = ptr(0)
	got := plan(t, newPlanner(t, NoneProfile(), cfg), Input{
		Now:        t0,
		Candidates: []Candidate{installedFix("192.0.2.0/24", 100, t0.Add(-time.Hour)), wantFix("198.51.100.0/24", 101)},
		Budget:     full,
	})
	if count(got, Swap) != 1 {
		t.Fatalf("%+v", got.Decisions)
	}
}

func TestInstalledDefaultRouteIsNeverShedOrSwapped(t *testing.T) {
	pl := newPlanner(t, NoneProfile(), testCfg())
	got := plan(t, pl, Input{
		Now: t0,
		Candidates: []Candidate{
			installedFix("0.0.0.0/0", 0, t0.Add(-time.Hour)),
			installedFix("::/0", 0, t0.Add(-time.Hour)),
			wantFix("198.51.100.0/24", 1000), wantFix("2001:db8::/32", 1000),
		},
		Budget: Result{ShedOK: true},
	})
	a := actions(got)
	if a["0.0.0.0/0"] != "keep" || a["::/0"] != "keep" || count(got, Shed) != 0 || count(got, Swap) != 0 {
		t.Fatalf("%+v", got.Decisions)
	}
}

func TestShedOnlyTheFamilyUnderPressure(t *testing.T) {
	pl := newPlanner(t, NoneProfile(), testCfg())
	got := plan(t, pl, Input{
		Now: t0,
		Candidates: []Candidate{
			installedFix("192.0.2.0/24", 1, t0.Add(-time.Hour)),
			installedFix("2001:db8::/32", 1, t0.Add(-time.Hour)),
		},
		Budget: Result{HeadroomV4: 50, HeadroomV6: 0, ShedOK: true},
	})
	if a := actions(got); a["2001:db8::/32"] != "shed" || a["192.0.2.0/24"] != "keep" {
		t.Fatalf("%v", a)
	}
}

func TestVolumeEmphasisMarginUsesVolume(t *testing.T) {
	prof := NoneProfile()
	prof.Miss = CPUPunt
	old := t0.Add(-time.Hour)
	mk := func(p string, gain, vol float64, installed bool) Candidate {
		return Candidate{Prefix: pfx(p), Cause: plugin.CausePerformance, Gain: gain, VolumeMbps: vol, Since: old, Installed: installed}
	}
	cases := []struct {
		name string
		want string
		cand Candidate
	}{
		// Lowest installed fix is 100 Mbps with a huge gain. A challenger with
		// more gain but less volume must not displace it; more volume must.
		{"more gain, less volume", "withhold", mk("198.51.100.0/24", 9999, 50, false)},
		{"inside volume margin", "withhold", mk("198.51.100.0/24", 1, 124, false)},
		{"volume past margin", "swap", mk("198.51.100.0/24", 1, 130, false)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := plan(t, newPlanner(t, prof, testCfg()), Input{
				Now:        t0,
				Candidates: []Candidate{mk("192.0.2.0/24", 500, 100, true), mk("192.0.2.128/25", 1, 400, true), c.cand},
				Budget:     full,
			})
			if a := actions(got); a["198.51.100.0/24"] != c.want {
				t.Fatalf("%v", a)
			}
		})
	}
}

func TestGainOnlyOverridesVolumeEmphasis(t *testing.T) {
	prof := NoneProfile()
	prof.Miss = CPUPunt
	cfg := testCfg()
	cfg.GainOnly = true
	old := t0.Add(-time.Hour)
	mk := func(p string, gain, vol float64, installed bool) Candidate {
		return Candidate{Prefix: pfx(p), Cause: plugin.CausePerformance, Gain: gain, VolumeMbps: vol, Since: old, Installed: installed}
	}
	// With volume emphasis this challenger would lose (50 Mbps against 100);
	// by gain it leads the installed fix by far more than the margin.
	got := plan(t, newPlanner(t, prof, cfg), Input{
		Now:        t0,
		Candidates: []Candidate{mk("192.0.2.0/24", 1, 100, true), mk("198.51.100.0/24", 9999, 50, false)},
		Budget:     full,
	})
	if a := actions(got); a["198.51.100.0/24"] != "swap" {
		t.Fatalf("%v", a)
	}
}

func TestInstallsAreCappedPerRound(t *testing.T) {
	cfg := testCfg()
	cfg.MaxInstallsPerRound = 3
	var cands []Candidate
	for i := range 10 {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), 32)
		cands = append(cands, Candidate{Prefix: p, Cause: plugin.CausePerformance, Gain: float64(10 - i), Since: t0})
	}
	got := plan(t, newPlanner(t, NoneProfile(), cfg), Input{Now: t0, Candidates: cands, Budget: Result{HeadroomV4: 100}})
	if n := count(got, Install); n != 3 {
		t.Fatalf("%d installs, want the cap 3", n)
	}
	a := actions(got)
	if a["198.51.100.0/32"] != "install" || a["198.51.100.2/32"] != "install" || a["198.51.100.3/32"] != "withhold" {
		t.Errorf("the best three must install: %v", a)
	}
	cfg.MaxInstallsPerRound = -1
	if _, err := NewPlanner(NoneProfile(), cfg); err == nil {
		t.Error("a negative install cap was accepted")
	}
}
