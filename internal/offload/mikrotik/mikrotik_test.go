package mikrotik

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/offload"
	"github.com/GrandArcher/Packeteer/internal/plugins/routercheck/routeros"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var labOpts = Options{Model: CCR2216, VolumeSource: "lab-sflow"}

// healthy is a CCR2216 on 7.24.2 that passes every check: one bridge, every
// port offloaded, a 802.3ad bond, VLANs on the bridge, both defaults
// suppressed, and no policy routing or firewall.
func healthy() routeros.L3HW {
	return routeros.L3HW{
		Version:    "7.24.2",
		Applicable: true,
		Monitor: routeros.Monitor{
			State: "ok", IPv4RoutesTotal: 90000, IPv4RoutesHW: 90000,
			NexthopCap: 8192, NexthopUsage: 93,
		},
		Advanced: &routeros.AdvancedMonitor{ErrorCode: "0", HasLPM: true, LPMCap: 200000, LPMUsage: 60000},
		Settings: routeros.Settings{IPv6HW: true},
		Ports: []routeros.Port{
			{Name: "switch1-cpu"},
			{Name: "sfp-sfpplus1", L3HW: true},
			{Name: "qsfp28-1-1", L3HW: true},
		},
		Bridges: []routeros.Iface{{Name: "bridge1", L3HW: true}},
		VLANs:   []routeros.Iface{{Name: "vlan100", L3HW: true, Parent: "bridge1"}},
		Bonds:   []routeros.Iface{{Name: "bond1", Mode: "802.3ad"}},
		DefaultRoutes: []routeros.DefaultRoute{
			{Family: "ipv4", Gateway: "192.0.2.1", Distance: 20, Protocol: "BGP", Active: true, SuppressHWOffload: true},
			{Family: "ipv6", Gateway: "2001:db8::1", Distance: 20, Protocol: "BGP", Active: true, SuppressHWOffload: true},
		},
	}
}

func codes(a Assessment) []string {
	var out []string
	for _, f := range a.Findings {
		out = append(out, f.Code)
	}
	slices.Sort(out)
	return out
}

func hasFreeze(a Assessment, r offload.FreezeReason) bool {
	for _, f := range a.Freezes {
		if f.Reason == r {
			return true
		}
	}
	return false
}

func TestHealthyRouterHasNoFindings(t *testing.T) {
	a := Assess(healthy(), labOpts)
	if len(a.Findings) != 0 || len(a.Freezes) != 0 || a.MaxRun != offload.DryRun {
		t.Fatalf("assessment = %+v", a)
	}
}

func TestEachPreCheckHasAFixture(t *testing.T) {
	fixtures := map[string]func(*routeros.L3HW){
		CheckVRF:          func(l *routeros.L3HW) { l.VRFs = 1 },
		CheckRoutingRules: func(l *routeros.L3HW) { l.RoutingRules = 1 },
		// A mark-routing rule is a mangle rule too and must raise only its own check.
		CheckMangleMarks:   func(l *routeros.L3HW) { l.MarkRoutingRules = 1; l.MangleRules = 1 },
		CheckForwardBypass: func(l *routeros.L3HW) { l.NATRules = 1 },
		CheckMultiBridge: func(l *routeros.L3HW) {
			l.Bridges = append(l.Bridges, routeros.Iface{Name: "bridge2", L3HW: true})
		},
		CheckVLANOnPort: func(l *routeros.L3HW) {
			l.VLANs = append(l.VLANs, routeros.Iface{Name: "vlan200", Parent: "bond1"})
		},
		CheckAsymmetric: func(l *routeros.L3HW) { l.Ports[2].L3HW = false },
		CheckBondMode:   func(l *routeros.L3HW) { l.Bonds[0].Mode = "active-backup" },
		CheckVRRP:       func(l *routeros.L3HW) { l.VRRPInterfaces = 1 },
		CheckL3HWDisabled: func(l *routeros.L3HW) {
			l.Advanced.ErrorCode = "13"
		},
	}
	for _, id := range preChecks {
		mutate, ok := fixtures[id]
		if !ok {
			t.Errorf("pre-check %q has no fixture", id)
			continue
		}
		t.Run(id, func(t *testing.T) {
			l := healthy()
			mutate(&l)
			a := Assess(l, labOpts)
			if got := codes(a); !reflect.DeepEqual(got, []string{id}) {
				t.Fatalf("findings = %v, want only %q", got, id)
			}
			if !hasFreeze(a, offload.FreezePreCheck) || a.Findings[0].Severity != Freeze || a.Findings[0].Detail == "" {
				t.Fatalf("assessment = %+v", a)
			}
			if a.MaxRun != offload.DryRun {
				t.Errorf("a pre-check lowered MaxRun to %s", a.MaxRun)
			}
		})
	}
	if len(fixtures) != len(preChecks) {
		t.Errorf("%d fixtures for %d pre-checks", len(fixtures), len(preChecks))
	}
}

func TestPreCheckVariants(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*routeros.L3HW)
		want   []string
	}{
		{"forward filter", func(l *routeros.L3HW) { l.ForwardFilterRules = 2 }, []string{CheckForwardBypass}},
		{"non-marking mangle", func(l *routeros.L3HW) { l.MangleRules = 1 }, []string{CheckForwardBypass}},
		{"vlan on a port", func(l *routeros.L3HW) { l.VLANs[0].Parent = "sfp-sfpplus1" }, []string{CheckVLANOnPort}},
		{"disabled vlan on a port is ignored", func(l *routeros.L3HW) {
			l.VLANs = append(l.VLANs, routeros.Iface{Name: "vlan9", Disabled: true, Parent: "sfp-sfpplus1"})
		}, nil},
		{"disabled second bridge is ignored", func(l *routeros.L3HW) {
			l.Bridges = append(l.Bridges, routeros.Iface{Name: "old", Disabled: true})
		}, nil},
		{"balance-xor bond is fine", func(l *routeros.L3HW) { l.Bonds[0].Mode = "balance-xor" }, nil},
		{"l3hw off on every port", func(l *routeros.L3HW) { l.Ports[1].L3HW, l.Ports[2].L3HW = false, false }, []string{CheckL3HWDisabled}},
		{"monitor not ok", func(l *routeros.L3HW) { l.Monitor.State = "disabled" }, []string{CheckL3HWDisabled}},
		{"empty error code", func(l *routeros.L3HW) { l.Advanced.ErrorCode = "" }, nil},
		{"no advanced monitor", func(l *routeros.L3HW) { l.Advanced = nil }, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := healthy()
			c.mutate(&l)
			if got := codes(Assess(l, labOpts)); !slices.Equal(got, c.want) {
				t.Fatalf("findings = %v, want %v", got, c.want)
			}
		})
	}
}

func TestDefaultInHardwareIsAnAlarmAndFreeze(t *testing.T) {
	l := healthy()
	l.DefaultRoutes[0].HFlag = true
	l.DefaultRoutes[0].SuppressHWOffload = false
	a := Assess(l, labOpts)
	if got := codes(a); !slices.Equal(got, []string{CodeDefaultInHW}) {
		t.Fatalf("findings = %v", got)
	}
	f := a.Findings[0]
	if f.Severity != Alarm || !strings.Contains(f.Detail, "suppress-hw-offload=yes") || !strings.Contains(f.Detail, "192.0.2.1") {
		t.Errorf("finding = %+v", f)
	}
	if !hasFreeze(a, offload.FreezeDefaultPolicy) {
		t.Errorf("freezes = %+v", a.Freezes)
	}
	res := Gate(offload.Result{Free: map[offload.Dimension]uint64{offload.FIBv4: 9}, HeadroomV4: 9, ShedOK: true}, a)
	if !res.Frozen() || res.HeadroomV4 != 0 || res.Free != nil || res.ShedOK {
		t.Errorf("gated result = %+v", res)
	}
}

func TestDefaultNotSuppressedFreezes(t *testing.T) {
	l := healthy()
	l.DefaultRoutes[1].SuppressHWOffload = false
	a := Assess(l, labOpts)
	if got := codes(a); !slices.Equal(got, []string{CodeDefaultEligible}) || !hasFreeze(a, offload.FreezeDefaultPolicy) {
		t.Fatalf("assessment = %+v", a)
	}
	if a.Findings[0].Severity != Freeze {
		t.Errorf("severity = %s", a.Findings[0].Severity)
	}
}

func TestVersionMapsToRefuseReportWarn(t *testing.T) {
	cases := []struct {
		version string
		maxRun  offload.RunLevel
		code    string
		freeze  bool
	}{
		{"6.49.10", offload.Refuse, CodeVersionRefused, true},
		{"7.1.5", offload.Refuse, CodeVersionRefused, true},
		{"7.2", offload.Refuse, CodeVersionRefused, true},
		{"7.2.3", offload.Refuse, CodeVersionRefused, true},
		{"7.3", offload.Report, CodeVersionReportOnly, true},
		{"7.9.2", offload.Report, CodeVersionReportOnly, true},
		{"7.10", offload.DryRun, "", false},
		{"7.15.3", offload.DryRun, "", false},
		{"7.16", offload.DryRun, CodeVersionWarn, false},
		{"7.16rc1", offload.DryRun, CodeVersionWarn, false},
		{"7.17.2", offload.DryRun, CodeVersionWarn, false},
		{"7.18.9", offload.DryRun, CodeVersionWarn, false},
		{"7.19", offload.DryRun, "", false},
		{"7.24.2", offload.DryRun, "", false},
		{"8.0", offload.DryRun, "", false},
		{"", offload.Report, CodeVersionUnknown, true},
		{"seven", offload.Report, CodeVersionUnknown, true},
	}
	for _, c := range cases {
		t.Run(c.version, func(t *testing.T) {
			l := healthy()
			l.Version = c.version
			a := Assess(l, labOpts)
			var want []string
			if c.code != "" {
				want = []string{c.code}
			}
			if got := codes(a); !slices.Equal(got, want) {
				t.Fatalf("findings = %v, want %v", got, want)
			}
			if a.MaxRun != c.maxRun || hasFreeze(a, offload.FreezeKnownBad) != c.freeze {
				t.Fatalf("maxRun %s freeze %v, want %s %v", a.MaxRun, hasFreeze(a, offload.FreezeKnownBad), c.maxRun, c.freeze)
			}
			if c.code == CodeVersionWarn && a.Findings[0].Severity != Warn {
				t.Errorf("a warn version froze: %+v", a)
			}
		})
	}
}

func TestParseVersion(t *testing.T) {
	for in, want := range map[string]version{
		"7.24.2": {7, 24, 2}, "7.16": {7, 16, 0}, "7.17beta4": {7, 17, 0}, "7.16rc1": {7, 16, 0},
		"7.18.1rc2": {7, 18, 1}, " 7.10 ": {7, 10, 0},
	} {
		if got, ok := parseVersion(in); !ok || got != want {
			t.Errorf("parseVersion(%q) = %v %v, want %v", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "7", "x.y", "7.x", "..", "99999999999999999999.1"} {
		if _, ok := parseVersion(in); ok {
			t.Errorf("parseVersion(%q) accepted", in)
		}
	}
}

func TestNotApplicableIsRefused(t *testing.T) {
	a := Assess(routeros.L3HW{Version: "7.24.2"}, labOpts)
	if a.MaxRun != offload.Refuse || !slices.Equal(codes(a), []string{CodeNotApplicable}) || len(a.Freezes) != 0 {
		t.Fatalf("assessment = %+v", a)
	}
}

func TestSHWPAndNexthopThresholds(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*routeros.L3HW)
		want   []string
		freeze *offload.Freeze
	}{
		{"shwp above zero", func(l *routeros.L3HW) { l.Monitor.IPv4ShortestHWPrefix = 30 }, []string{CodeSHWP}, &offload.Freeze{Reason: offload.FreezePreCheck}},
		{"nexthops below warn", func(l *routeros.L3HW) { l.Monitor.NexthopUsage = 7372 }, nil, nil},
		{"nexthops at warn", func(l *routeros.L3HW) { l.Monitor.NexthopUsage = 7373 }, []string{CodeNexthopWarn}, nil},
		{"nexthops full", func(l *routeros.L3HW) { l.Monitor.NexthopUsage = 8192 }, []string{CodeNexthopFull}, &offload.Freeze{Reason: offload.FreezePreCheck, Dimension: offload.NextHops}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := healthy()
			c.mutate(&l)
			a := Assess(l, labOpts)
			if got := codes(a); !slices.Equal(got, c.want) {
				t.Fatalf("findings = %v, want %v", got, c.want)
			}
			switch {
			case c.freeze == nil && len(a.Freezes) != 0:
				t.Errorf("unexpected freezes %+v", a.Freezes)
			case c.freeze != nil && !slices.Equal(a.Freezes, []offload.Freeze{*c.freeze}):
				t.Errorf("freezes = %+v, want %+v", a.Freezes, *c.freeze)
			}
		})
	}
}

func TestNoVolumeSourceWarnsAndFallsBackToGain(t *testing.T) {
	a := Assess(healthy(), Options{Model: CCR2216})
	if got := codes(a); !slices.Equal(got, []string{CodeNoVolumeSource}) || a.Findings[0].Severity != Warn || len(a.Freezes) != 0 {
		t.Fatalf("assessment = %+v", a)
	}
	if !PlannerConfig(Options{}, false).GainOnly || PlannerConfig(labOpts, false).GainOnly {
		t.Error("GainOnly must hold exactly when no volume source is named")
	}
}

func TestFreezesAreNotRepeated(t *testing.T) {
	l := healthy()
	l.VRFs, l.VRRPInterfaces, l.RoutingRules = 1, 1, 1
	a := Assess(l, labOpts)
	if len(a.Freezes) != 1 || len(a.Findings) != 3 {
		t.Fatalf("assessment = %+v", a)
	}
}

func TestProfile(t *testing.T) {
	p, err := Profile(labOpts, func() (Snapshot, bool) { return Snapshot{}, false })
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "mikrotik-l3hw-lpm" || p.MaxRun != offload.DryRun || p.Status != offload.Partial ||
		p.DefaultPolicy.Kind != offload.OutOfHW || p.Miss != offload.CPUPunt || !p.Flow.NeedsFlow {
		t.Fatalf("profile = %+v", p)
	}
	if _, err := offload.CheckRun(p, offload.DryRun); err != nil {
		t.Errorf("dry run refused: %v", err)
	}
	if _, err := offload.CheckRun(p, offload.Enforce); !errors.Is(err, offload.ErrRefused) {
		t.Errorf("enforce err = %v, want ErrRefused", err)
	}
	if p.Thresholds != (offload.Thresholds{Warn: 0.9, Full: 1}) {
		t.Errorf("thresholds = %+v", p.Thresholds)
	}
	if !slices.Equal(p.PreChecks, preChecks) {
		t.Errorf("pre-checks = %v", p.PreChecks)
	}
	if want := []string{"<= 7.2", "< 7.10", "7.16 - 7.18"}; len(p.KnownBad) != 3 || p.KnownBad[0].Version != want[0] || p.KnownBad[1].Version != want[1] || p.KnownBad[2].Version != want[2] {
		t.Errorf("known bad = %+v", p.KnownBad)
	}
	if p.Timing.InstallSeconds < 11 || p.Timing.AgeOutSeconds < 11 {
		t.Errorf("timing %+v is inside the 10 s route-index-delay", p.Timing)
	}
	reg := offload.NewRegistry()
	if err := reg.Register(p); err != nil {
		t.Fatalf("register: %v", err)
	}
	if got, err := reg.Get(ID); err != nil || got.ID != ID {
		t.Errorf("get = %+v %v", got, err)
	}
	if _, err := Profile(Options{Model: "ccr9999"}, nil); err == nil || !strings.Contains(err.Error(), "unknown model") {
		t.Errorf("unknown model err = %v", err)
	}
}

func snap(l routeros.L3HW, bps uint64) func() (Snapshot, bool) {
	return func() (Snapshot, bool) { return Snapshot{L3HW: l, CPUPathBps: bps, CPUPathKnown: true}, true }
}

func read(t *testing.T, opts Options, src func() (Snapshot, bool), d offload.Dimension) offload.Reading {
	t.Helper()
	p, err := Profile(opts, src)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Reader.Read(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestReaderDimensions(t *testing.T) {
	const gbit = 1_000_000_000
	known := func(used, total uint64) offload.Reading {
		return offload.Reading{Used: used, Total: total, Known: true}
	}
	if got := read(t, labOpts, snap(healthy(), 10*gbit), offload.FIBv4); got != known(60000, 100000) {
		t.Errorf("ccr2216 lpm = %+v: the 100K target is the total", got)
	}
	if got := read(t, Options{Model: CCR2116}, snap(healthy(), 0), offload.FIBv4); got != known(60000, 200000) {
		t.Errorf("ccr2116 lpm = %+v: no target", got)
	}
	over := healthy()
	over.Advanced.LPMUsage = 150000
	if got := read(t, labOpts, snap(over, 0), offload.FIBv4); got != known(100000, 100000) {
		t.Errorf("table above the target = %+v, want full", got)
	}
	insane := healthy()
	insane.Advanced.LPMUsage = 250000
	if got := read(t, labOpts, snap(insane, 0), offload.FIBv4); got != known(250000, 200000) {
		t.Errorf("used above the chip cap = %+v, must stay as read", got)
	}
	if got := read(t, labOpts, snap(healthy(), 0), offload.NextHops); got != known(93, 8192) {
		t.Errorf("next hops = %+v", got)
	}
	if got := read(t, labOpts, snap(healthy(), 30*gbit), offload.CPU); got != known(30*gbit, 100*gbit) {
		t.Errorf("ccr2216 cpu = %+v", got)
	}
	if got := read(t, Options{Model: CCR2116}, snap(healthy(), 0), offload.CPU); got != known(0, 40*gbit) {
		t.Errorf("ccr2116 cpu = %+v", got)
	}
}

func TestReaderUnknownIsNeverZero(t *testing.T) {
	noLPM := healthy()
	noLPM.Advanced = &routeros.AdvancedMonitor{}
	chr := healthy()
	chr.Applicable = false
	noNH := healthy()
	noNH.Monitor.NexthopCap = 0
	cases := []struct {
		name string
		opts Options
		src  func() (Snapshot, bool)
		dim  offload.Dimension
	}{
		{"no snapshot", labOpts, func() (Snapshot, bool) { return Snapshot{}, false }, offload.FIBv4},
		{"nil source", labOpts, nil, offload.FIBv4},
		{"not applicable", labOpts, snap(chr, 0), offload.NextHops},
		{"no lpm fields", labOpts, snap(noLPM, 0), offload.FIBv4},
		{"no advanced monitor", labOpts, snap(func() routeros.L3HW { l := healthy(); l.Advanced = nil; return l }(), 0), offload.FIBv4},
		{"no nexthop cap", labOpts, snap(noNH, 0), offload.NextHops},
		{"unknown model", Options{}, snap(healthy(), 5), offload.CPU},
		{"no cpu source", labOpts, func() (Snapshot, bool) { return Snapshot{L3HW: healthy()}, true }, offload.CPU},
		{"unlisted dimension", labOpts, snap(healthy(), 0), offload.FIBv6},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := read(t, c.opts, c.src, c.dim); got != (offload.Reading{}) {
				t.Fatalf("reading = %+v, want unknown", got)
			}
		})
	}
}

// budget runs the profile's reader and budget config the way the caller will.
func budget(t *testing.T, l routeros.L3HW, bps uint64, ipv6 bool, now time.Time) offload.Result {
	t.Helper()
	p, err := Profile(labOpts, snap(l, bps))
	if err != nil {
		t.Fatal(err)
	}
	b, err := offload.NewBudget(BudgetConfig(labOpts, time.Minute, ipv6))
	if err != nil {
		t.Fatal(err)
	}
	samples := offload.Collect(context.Background(), p.Reader, p.Dimensions, now)
	return b.Evaluate(now, offload.Identity{Profile: ID, Version: l.Version}, samples)
}

func TestBudgetFromTheProfile(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	const gbit = 1_000_000_000
	l := healthy()
	l.Advanced.LPMUsage = 78000

	res := budget(t, l, 10*gbit, true, now)
	if res.Frozen() {
		t.Fatalf("frozen: %+v", res.Freezes)
	}
	// LPM: 100000 target - 78000 used - 20000 reserve. Next hops: 8192 - 93 - 820
	// reserve. CPU: no per-route unit.
	if res.Free[offload.FIBv4] != 2000 || res.Free[offload.NextHops] != 7279 {
		t.Errorf("free = %v", res.Free)
	}
	if res.HeadroomV4 != 2000 || res.HeadroomV6 != 1000 {
		t.Errorf("headroom = %d v4, %d v6: the LPM pool limits both and v6 costs 2 entries", res.HeadroomV4, res.HeadroomV6)
	}

	if res := budget(t, l, 10*gbit, false, now); res.HeadroomV6 != 0 || res.HeadroomV4 == 0 {
		t.Errorf("ipv6-hw off: headroom = %d v4, %d v6", res.HeadroomV4, res.HeadroomV6)
	}

	// CPU path at 85 of 100 Gbit/s leaves less than the 20% reserve: no installs.
	if res := budget(t, l, 85*gbit, true, now); res.HeadroomV4 != 0 || res.HeadroomV6 != 0 || res.Frozen() {
		t.Errorf("cpu pressure: %+v", res)
	}

	full := healthy()
	full.Advanced.LPMUsage = 100000
	if res := budget(t, full, 0, true, now); res.HeadroomV4 != 0 || !res.ShedOK {
		t.Errorf("table at the target: %+v", res)
	}

	if res := budget(t, healthy(), 0, true, now); res.Frozen() {
		t.Fatalf("cpu path zero must be a reading, not a freeze: %+v", res.Freezes)
	}
	// A named source that has produced no CPU-path rate: the budget fails closed.
	noCPU, err := Profile(labOpts, func() (Snapshot, bool) { return Snapshot{L3HW: healthy()}, true })
	if err != nil {
		t.Fatal(err)
	}
	b, _ := offload.NewBudget(BudgetConfig(labOpts, time.Minute, true))
	res = b.Evaluate(now, offload.Identity{Profile: ID}, offload.Collect(context.Background(), noCPU.Reader, noCPU.Dimensions, now))
	if len(res.Freezes) != 1 || res.Freezes[0] != (offload.Freeze{Reason: offload.FreezeMissing, Dimension: offload.CPU}) {
		t.Errorf("no cpu-path rate: freezes = %+v", res.Freezes)
	}
}

func TestNoVolumeSourceBudgetsWithoutTheCPUPathAndPlansByGain(t *testing.T) {
	noSrc := Options{Model: CCR2216}
	p, err := Profile(noSrc, func() (Snapshot, bool) { return Snapshot{L3HW: healthy()}, true })
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(p.Dimensions, offload.CPU) {
		t.Fatalf("dimensions = %v", p.Dimensions)
	}
	cfg := BudgetConfig(noSrc, time.Minute, false)
	if slices.Contains(cfg.Dimensions, offload.CPU) || len(cfg.Reserve) != 2 {
		t.Fatalf("budget config = %+v", cfg)
	}
	b, err := offload.NewBudget(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	res := b.Evaluate(now, offload.Identity{Profile: ID}, offload.Collect(context.Background(), p.Reader, p.Dimensions, now))
	if res.Frozen() || res.HeadroomV4 == 0 {
		t.Fatalf("budget = %+v", res)
	}
	pl, err := offload.NewPlanner(p, PlannerConfig(noSrc, false))
	if err != nil {
		t.Fatal(err)
	}
	// By volume the first fix (1 Mbps) would not displace the installed one
	// (100 Mbps); by gain it leads by far more than the margin.
	old := now.Add(-time.Hour)
	res.HeadroomV4 = 0
	got, err := pl.Plan(offload.Input{Now: now, Budget: res, Candidates: []offload.Candidate{
		{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Cause: plugin.CausePerformance, Gain: 1, VolumeMbps: 100, Since: old, Installed: true},
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Cause: plugin.CausePerformance, Gain: 50, VolumeMbps: 1, Since: old},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := offload.Decision{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Action: offload.Swap, Out: netip.MustParsePrefix("192.0.2.0/24")}
	if len(got.Decisions) != 1 || got.Decisions[0].Prefix != want.Prefix || got.Decisions[0].Action != want.Action || got.Decisions[0].Out != want.Out {
		t.Fatalf("decisions = %+v", got.Decisions)
	}
}

func TestBudgetConfigMatchesProfileDimensions(t *testing.T) {
	p, err := Profile(labOpts, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, v6 := range []bool{false, true} {
		cfg := BudgetConfig(labOpts, time.Minute, v6)
		if !slices.Equal(cfg.Dimensions, p.Dimensions) {
			t.Errorf("budget dimensions %v differ from the profile's %v", cfg.Dimensions, p.Dimensions)
		}
		if cfg.IPv6 != PlannerConfig(labOpts, v6).IPv6 {
			t.Errorf("ipv6 pool differs between budget and planner for ipv6-hw=%v", v6)
		}
		if cfg.IPv6.Shared != v6 {
			t.Errorf("shared = %v for ipv6-hw=%v", cfg.IPv6.Shared, v6)
		}
	}
}

func TestPlannerStaysUnderTheReindexLimit(t *testing.T) {
	p, err := Profile(labOpts, nil)
	if err != nil {
		t.Fatal(err)
	}
	pl, err := offload.NewPlanner(p, PlannerConfig(labOpts, true))
	if err != nil {
		t.Fatal(err)
	}
	cfg := PlannerConfig(labOpts, true)
	if changes := cfg.MaxInstallsPerRound + 2*cfg.MaxSwapsPerRound + cfg.MaxShedPerRound; changes >= 128 {
		t.Errorf("a full round is %d changes, not under 128", changes)
	}

	// 40 installed fixes and 40 better challengers: swaps stop at the cap.
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	old := now.Add(-time.Hour)
	var cands []offload.Candidate
	for i := range 40 {
		inst := netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), 32)
		chal := netip.PrefixFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), 32)
		cands = append(cands,
			offload.Candidate{Prefix: inst, Cause: plugin.CausePerformance, Gain: 1, VolumeMbps: 1, Since: old, Installed: true},
			offload.Candidate{Prefix: chal, Cause: plugin.CausePerformance, Gain: 100, VolumeMbps: 100, Since: old})
	}
	plan, err := pl.Plan(offload.Input{Now: now, Candidates: cands, Budget: offload.Result{HeadroomV4: 0, ShedOK: false}})
	if err != nil {
		t.Fatal(err)
	}
	swaps := 0
	for _, d := range plan.Decisions {
		if d.Action == offload.Swap {
			swaps++
		}
	}
	if swaps != cfg.MaxSwapsPerRound {
		t.Errorf("%d swaps, want the cap %d", swaps, cfg.MaxSwapsPerRound)
	}
}

func TestInstallsStopAtTheCap(t *testing.T) {
	p, err := Profile(labOpts, nil)
	if err != nil {
		t.Fatal(err)
	}
	pl, err := offload.NewPlanner(p, PlannerConfig(labOpts, false))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	var cands []offload.Candidate
	for i := range 100 {
		pre := netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), 32)
		cands = append(cands, offload.Candidate{Prefix: pre, Cause: plugin.CausePerformance, Gain: 1, Since: now})
	}
	got, err := pl.Plan(offload.Input{Now: now, Candidates: cands, Budget: offload.Result{HeadroomV4: 2000}})
	if err != nil {
		t.Fatal(err)
	}
	installs := 0
	for _, d := range got.Decisions {
		if d.Action == offload.Install {
			installs++
		}
	}
	if installs != 64 {
		t.Errorf("%d installs with 2000 free entries, want the cap 64", installs)
	}
}

func TestDefaultsChanged(t *testing.T) {
	base := healthy()
	if DefaultsChanged(base, base) {
		t.Error("identical readings reported as changed")
	}
	reordered := healthy()
	reordered.DefaultRoutes[0], reordered.DefaultRoutes[1] = reordered.DefaultRoutes[1], reordered.DefaultRoutes[0]
	if DefaultsChanged(base, reordered) {
		t.Error("a reordered list reported as changed")
	}
	cases := map[string]func(*routeros.L3HW){
		"gateway":     func(l *routeros.L3HW) { l.DefaultRoutes[0].Gateway = "192.0.2.2" },
		"distance":    func(l *routeros.L3HW) { l.DefaultRoutes[0].Distance = 30 },
		"local pref":  func(l *routeros.L3HW) { l.DefaultRoutes[0].LocalPref = 300 },
		"active":      func(l *routeros.L3HW) { l.DefaultRoutes[0].Active = false },
		"suppression": func(l *routeros.L3HW) { l.DefaultRoutes[1].SuppressHWOffload = false },
		"removed":     func(l *routeros.L3HW) { l.DefaultRoutes = l.DefaultRoutes[:1] },
		"added": func(l *routeros.L3HW) {
			l.DefaultRoutes = append(l.DefaultRoutes, routeros.DefaultRoute{Family: "ipv4", Gateway: "192.0.2.9", Protocol: "Static route", SuppressHWOffload: true})
		},
	}
	for name, mutate := range cases {
		cur := healthy()
		mutate(&cur)
		if !DefaultsChanged(base, cur) {
			t.Errorf("%s change not detected", name)
		}
	}
}

func TestHostsAreReportedNotBudgeted(t *testing.T) {
	l := healthy()
	l.Monitor.IPv4Hosts = 87
	if a := Assess(l, labOpts); a.IPv4Hosts != 87 || len(a.Findings) != 0 {
		t.Errorf("assessment = %+v", a)
	}
}

func TestGatedBudgetPlansNothing(t *testing.T) {
	p, err := Profile(labOpts, nil)
	if err != nil {
		t.Fatal(err)
	}
	pl, err := offload.NewPlanner(p, PlannerConfig(labOpts, false))
	if err != nil {
		t.Fatal(err)
	}
	l := healthy()
	l.DefaultRoutes[0].HFlag = true
	roomy := offload.Result{Free: map[offload.Dimension]uint64{offload.FIBv4: 500}, HeadroomV4: 500, ShedOK: true}
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	in := offload.Input{
		Now: now,
		Candidates: []offload.Candidate{
			{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Cause: plugin.CausePerformance, Gain: 5, Since: now.Add(-time.Hour)},
			{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Cause: plugin.CausePerformance, Gain: 1, Since: now.Add(-time.Hour), Installed: true},
		},
	}

	in.Budget = roomy
	got, err := pl.Plan(in)
	if err != nil || len(got.Freezes) != 0 || got.Decisions[0].Action != offload.Install {
		t.Fatalf("ungated plan = %+v %v", got, err)
	}

	in.Budget = Gate(roomy, Assess(l, labOpts))
	got, err = pl.Plan(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Freezes) == 0 || got.Freezes[0].Reason != offload.FreezeDefaultPolicy {
		t.Fatalf("freezes = %+v", got.Freezes)
	}
	for _, d := range got.Decisions {
		if d.Action == offload.Install || d.Action == offload.Swap || d.Action == offload.Shed {
			t.Errorf("a frozen plan changed hardware: %+v", d)
		}
	}
}

func TestGateWithoutFreezesChangesNothing(t *testing.T) {
	res := offload.Result{Free: map[offload.Dimension]uint64{offload.FIBv4: 7}, HeadroomV4: 7}
	if got := Gate(res, Assessment{MaxRun: offload.DryRun}); !reflect.DeepEqual(got, res) {
		t.Errorf("gate changed an unfrozen result: %+v", got)
	}
	budgetFreeze := offload.Result{Freezes: []offload.Freeze{{Reason: offload.FreezeStale, Dimension: offload.CPU}}}
	got := Gate(budgetFreeze, Assessment{Freezes: []offload.Freeze{{Reason: offload.FreezePreCheck}}})
	if len(got.Freezes) != 2 || len(budgetFreeze.Freezes) != 1 {
		t.Errorf("gated = %+v, input = %+v", got.Freezes, budgetFreeze.Freezes)
	}
}
