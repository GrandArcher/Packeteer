package mikrotik

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/offload"
	"github.com/GrandArcher/Packeteer/internal/plugins/routercheck/routeros"
)

var dryNow = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

func wantFix(prefix string, mbps float64) offload.Wanted {
	return offload.Wanted{
		Candidate: offload.Candidate{Prefix: netip.MustParsePrefix(prefix), Cause: "performance", Gain: 10, VolumeMbps: mbps, Since: dryNow.Add(-time.Hour)},
		Provider:  "transit-b",
	}
}

func dryRun(t *testing.T, opts Options, l routeros.L3HW, wanted ...offload.Wanted) offload.RouterReport {
	t.Helper()
	e, err := NewEvaluator(opts, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	snap := Snapshot{L3HW: l, CPUPathBps: 2_000_000_000, CPUPathKnown: opts.VolumeSource != ""}
	return e.Evaluate(Input{Now: dryNow, Neighbor: "192.0.2.1", Snap: &snap, At: dryNow.Add(-30 * time.Second), Wanted: wanted,
		Volume: offload.VolumeReport{Source: opts.VolumeSource}})
}

func states(rep offload.RouterReport) map[string]offload.FixState {
	m := map[string]offload.FixState{}
	for _, f := range rep.Fixes {
		m[f.Prefix] = f.State
	}
	return m
}

func dimension(rep offload.RouterReport, d offload.Dimension) offload.DimensionReport {
	for _, r := range rep.Dimensions {
		if r.Dimension == d {
			return r
		}
	}
	return offload.DimensionReport{}
}

// A CCR2216 with room in every dimension fits: the fixes would be offloaded.
func TestDryRunFits(t *testing.T) {
	rep := dryRun(t, labOpts, healthy(), wantFix("198.51.100.0/24", 80), wantFix("203.0.113.0/24", 40))
	if rep.Verdict != offload.VerdictFits || rep.Level != "dry_run" || rep.VersionVerdict != "ok" || rep.Freezes == nil || len(rep.Freezes) != 0 {
		t.Fatalf("report = %+v", rep)
	}
	got := states(rep)
	if got["198.51.100.0/24"] != offload.FixOffload || got["203.0.113.0/24"] != offload.FixOffload {
		t.Errorf("fix states = %v", got)
	}
	if rep.Fixes[0].Prefix != "198.51.100.0/24" || rep.Fixes[0].VolumeMbps == nil || *rep.Fixes[0].VolumeMbps != 80 {
		t.Errorf("fixes = %+v", rep.Fixes)
	}
	lpm := dimension(rep, offload.FIBv4)
	// 100000 target, 60000 used, 20% reserve; the reading is 30 s old.
	if !lpm.Known || lpm.Cap != 100000 || lpm.Used != 60000 || lpm.Reserve != 20000 || lpm.Free != 20000 || lpm.ReadingAgeSeconds == nil || *lpm.ReadingAgeSeconds != 30 {
		t.Errorf("lpm = %+v", lpm)
	}
	if nh := dimension(rep, offload.NextHops); nh.Cap != 8192 || nh.Used != 93 || nh.Reserve != 820 || nh.Free != 7279 {
		t.Errorf("next hops = %+v", nh)
	}
	if cpu := dimension(rep, offload.CPU); !cpu.Known || cpu.Cap != 100_000_000_000 || cpu.Used != 2_000_000_000 {
		t.Errorf("cpu = %+v", cpu)
	}
	if rep.Default.Met == nil || !*rep.Default.Met || rep.Default.Policy != offload.OutOfHW {
		t.Errorf("default = %+v", rep.Default)
	}
	if rep.Counters == nil || rep.Counters.IPv4RoutesHW != 90000 || rep.Counters.IPv4RoutesCPU != 0 {
		t.Errorf("counters = %+v", rep.Counters)
	}
}

// The chip cut the table short (shortest hardware prefix /30): the report
// says so and blocks every fix.
func TestDryRunPartialOffloadDefaultOnCPU(t *testing.T) {
	l := healthy()
	l.Monitor = routeros.Monitor{State: "ok", IPv4RoutesTotal: 942338, IPv4RoutesHW: 37729, IPv4RoutesCPU: 904609, IPv4ShortestHWPrefix: 30, NexthopCap: 8192, NexthopUsage: 93}
	l.Advanced = &routeros.AdvancedMonitor{ErrorCode: "0", HasLPM: true, LPMCap: 27200, LPMUsage: 27200}
	rep := dryRun(t, labOpts, l, wantFix("198.51.100.0/24", 80))
	if rep.Verdict != offload.VerdictPartial {
		t.Fatalf("verdict = %q", rep.Verdict)
	}
	if !slices.Contains(rep.Freezes, offload.Freeze{Reason: offload.FreezePreCheck}) {
		t.Errorf("freezes = %+v", rep.Freezes)
	}
	if got := states(rep)["198.51.100.0/24"]; got != offload.FixBlocked {
		t.Errorf("fix state = %q, want blocked", got)
	}
	if rep.Default.Met == nil || !*rep.Default.Met {
		t.Errorf("the default stays out of hardware: %+v", rep.Default)
	}
	if rep.Counters.ShortestHWPrefix != 30 || rep.Counters.IPv4RoutesCPU != 904609 {
		t.Errorf("counters = %+v", rep.Counters)
	}
	if lpm := dimension(rep, offload.FIBv4); lpm.Cap != 27200 || lpm.Free != 0 {
		t.Errorf("lpm = %+v", lpm)
	}
}

func TestDryRunNexthopExhausted(t *testing.T) {
	l := healthy()
	l.Monitor.NexthopUsage = 8192
	rep := dryRun(t, labOpts, l, wantFix("198.51.100.0/24", 80))
	if rep.Verdict != offload.VerdictNexthopExhausted {
		t.Fatalf("verdict = %q", rep.Verdict)
	}
	if nh := dimension(rep, offload.NextHops); nh.Free != 0 || nh.Used != nh.Cap {
		t.Errorf("next hops = %+v", nh)
	}
	if got := states(rep)["198.51.100.0/24"]; got != offload.FixBlocked {
		t.Errorf("fix state = %q, want blocked", got)
	}
	var found bool
	for _, f := range rep.Findings {
		found = found || f.Code == CodeNexthopFull
	}
	if !found {
		t.Errorf("findings = %+v", rep.Findings)
	}
}

// The dry run plans what the planner plans: the same budget and planner
// configs, the same candidates, the same installs.
func TestDryRunMatchesThePlanner(t *testing.T) {
	l := healthy()
	l.Advanced.LPMUsage = 79990 // 10 entries of headroom
	var wanted []offload.Wanted
	var cands []offload.Candidate
	for i := range 20 {
		w := wantFix(fmt.Sprintf("198.51.100.%d/32", i), float64(100+i))
		wanted = append(wanted, w)
		cands = append(cands, w.Candidate)
	}
	rep := dryRun(t, labOpts, l, wanted...)

	b, err := offload.NewBudget(BudgetConfig(labOpts, time.Minute, true))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := Profile(labOpts, func() (Snapshot, bool) {
		return Snapshot{L3HW: l, CPUPathBps: 2_000_000_000, CPUPathKnown: true}, true
	})
	samples := offload.Collect(context.Background(), p.Reader, p.Dimensions, dryNow.Add(-30*time.Second))
	res := Gate(b.Evaluate(dryNow, offload.Identity{Profile: ID, Version: l.Version}, samples), Assess(l, labOpts))
	pl, err := offload.NewPlanner(p, PlannerConfig(labOpts, true))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := pl.Plan(offload.Input{Now: dryNow, Candidates: cands, Budget: res})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]offload.FixState{}
	installs := 0
	for _, d := range plan.Decisions {
		want[d.Prefix.String()] = offload.FixWithhold
		if d.Action == offload.Install {
			want[d.Prefix.String()] = offload.FixOffload
			installs++
		}
	}
	if installs != 10 {
		t.Fatalf("the planner installs %d, want the 10 of headroom", installs)
	}
	if got := states(rep); !equalStates(got, want) {
		t.Errorf("report states %v\nplanner states %v", got, want)
	}
	// The highest volumes win under a CPU punt.
	if got := states(rep)["198.51.100.19/32"]; got != offload.FixOffload {
		t.Errorf("busiest fix = %q", got)
	}
	if got := states(rep)["198.51.100.0/32"]; got != offload.FixWithhold {
		t.Errorf("quietest fix = %q", got)
	}
}

func equalStates(a, b map[string]offload.FixState) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestDryRunIPv6IsSoftwareWithIPv6HWOff(t *testing.T) {
	l := healthy()
	l.Settings.IPv6HW = false
	rep := dryRun(t, labOpts, l, wantFix("198.51.100.0/24", 80), wantFix("2001:db8:100::/48", 90))
	got := states(rep)
	if got["2001:db8:100::/48"] != offload.FixSoftware || got["198.51.100.0/24"] != offload.FixOffload {
		t.Errorf("states = %v", got)
	}
}

func TestDryRunWithoutAReadingIsUnavailable(t *testing.T) {
	e, err := NewEvaluator(labOpts, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rep := e.Evaluate(Input{Now: dryNow, Neighbor: "192.0.2.1", Err: "read /system/resource: connection refused", Wanted: []offload.Wanted{wantFix("198.51.100.0/24", 0)}})
	if rep.Verdict != offload.VerdictUnavailable || rep.Level != "refuse" || rep.ReadAt != nil || rep.Error == "" {
		t.Fatalf("report = %+v", rep)
	}
	if len(rep.Freezes) == 0 || rep.Freezes[0].Reason != offload.FreezeMissing {
		t.Errorf("freezes = %+v", rep.Freezes)
	}
	if f := rep.Fixes[0]; f.State != offload.FixBlocked || f.VolumeMbps != nil {
		t.Errorf("fix = %+v", f)
	}
}

func TestDryRunStaleReadingFreezes(t *testing.T) {
	e, _ := NewEvaluator(labOpts, time.Minute)
	snap := Snapshot{L3HW: healthy(), CPUPathKnown: true}
	rep := e.Evaluate(Input{Now: dryNow, Neighbor: "192.0.2.1", Snap: &snap, At: dryNow.Add(-10 * time.Minute), Wanted: []offload.Wanted{wantFix("198.51.100.0/24", 5)}})
	if rep.Verdict != offload.VerdictFrozen || !slices.Contains(rep.Freezes, offload.Freeze{Reason: offload.FreezeStale, Dimension: offload.FIBv4}) {
		t.Fatalf("verdict %q freezes %+v", rep.Verdict, rep.Freezes)
	}
	if lpm := dimension(rep, offload.FIBv4); lpm.Problem != offload.FreezeStale || *lpm.ReadingAgeSeconds != 600 {
		t.Errorf("lpm = %+v", lpm)
	}
	if got := states(rep)["198.51.100.0/24"]; got != offload.FixBlocked {
		t.Errorf("fix state = %q", got)
	}
}

func TestDryRunDefaultInHardwareIsNotMet(t *testing.T) {
	l := healthy()
	l.DefaultRoutes[0].HFlag = true
	rep := dryRun(t, labOpts, l, wantFix("198.51.100.0/24", 5))
	if rep.Default.Met == nil || *rep.Default.Met || rep.Default.Detail == "" || rep.Verdict != offload.VerdictFrozen {
		t.Fatalf("default %+v verdict %q", rep.Default, rep.Verdict)
	}
	l.DefaultRoutes = nil
	if rep := dryRun(t, labOpts, l); rep.Default.Met != nil || rep.Default.Detail == "" {
		t.Errorf("no default read: %+v", rep.Default)
	}
}

func TestDryRunVersionVerdicts(t *testing.T) {
	for version, want := range map[string]string{"7.24.2": "ok", "7.17.2": "warn", "7.5": "report_only", "7.2": "refused", "weird": "unknown"} {
		l := healthy()
		l.Version = version
		rep := dryRun(t, labOpts, l, wantFix("198.51.100.0/24", 5))
		if rep.VersionVerdict != want {
			t.Errorf("%s: verdict %q, want %q", version, rep.VersionVerdict, want)
		}
		if want == "refused" || want == "report_only" || want == "unknown" {
			if rep.Level == "dry_run" || states(rep)["198.51.100.0/24"] != offload.FixBlocked {
				t.Errorf("%s: level %q state %q", version, rep.Level, states(rep)["198.51.100.0/24"])
			}
		}
	}
}

// A router with no volume source ranks by gain and reports the Traffic-Flow
// blind spot; its CPU dimension is not budgeted.
func TestDryRunWithoutVolumeSource(t *testing.T) {
	opts := Options{Model: CCR2216}
	e, _ := NewEvaluator(opts, time.Minute)
	snap := Snapshot{L3HW: healthy()}
	vol := offload.BuildVolume("", nil, func(netip.Prefix) bool { return true })
	rep := e.Evaluate(Input{Now: dryNow, Neighbor: "192.0.2.1", Snap: &snap, At: dryNow, Wanted: []offload.Wanted{wantFix("198.51.100.0/24", 0)}, Volume: vol})
	if rep.Verdict != offload.VerdictFits || dimension(rep, offload.CPU).Dimension != "" {
		t.Fatalf("verdict %q, cpu %+v", rep.Verdict, dimension(rep, offload.CPU))
	}
	if len(rep.Volume.BlindSpots) != 1 || rep.Volume.BlindSpots[0].Code != offload.BlindTrafficFlow {
		t.Errorf("blind spots = %+v", rep.Volume.BlindSpots)
	}
}

// A profile that cannot be rebuilt for the router's ipv6-hw setting still
// returns a report the page can render: no null dimensions, fixes blocked.
func TestDryRunRebuildFailureKeepsTheReportWhole(t *testing.T) {
	e, err := NewEvaluator(labOpts, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	e.recheck = -time.Minute
	l := healthy()
	l.Settings.IPv6HW = !e.ipv6HW
	snap := Snapshot{L3HW: l}
	rep := e.Evaluate(Input{Now: dryNow, Neighbor: "192.0.2.1", Snap: &snap, At: dryNow, Wanted: []offload.Wanted{wantFix("198.51.100.0/24", 5)}})
	if rep.Error == "" || rep.Dimensions == nil {
		t.Fatalf("error %q dimensions %v", rep.Error, rep.Dimensions)
	}
	if got := states(rep)["198.51.100.0/24"]; got != offload.FixBlocked {
		t.Errorf("fix state = %q", got)
	}
}
