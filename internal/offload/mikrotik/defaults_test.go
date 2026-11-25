package mikrotik

import (
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/offload"
	"github.com/GrandArcher/Packeteer/internal/plugins/routercheck/routeros"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// nextHops are the providers behind the lab defaults.
var nextHops = map[netip.Addr]string{
	netip.MustParseAddr("192.0.2.1"):   "transit-a",
	netip.MustParseAddr("2001:db8::1"): "transit-a",
	netip.MustParseAddr("192.0.2.2"):   "transit-b",
	netip.MustParseAddr("192.0.2.3"):   "transit-c",
}

// defaultsLab is a router with three providers on static defaults: transit-a
// (IPv4 and IPv6) is active, transit-b and transit-c are backups.
func defaultsLab() routeros.L3HW {
	l := healthy()
	l.DefaultRoutes = []routeros.DefaultRoute{
		{Family: "ipv4", Gateway: "192.0.2.1", Distance: 1, Protocol: "Static route", Active: true, SuppressHWOffload: true},
		{Family: "ipv6", Gateway: "2001:db8::1", Distance: 1, Protocol: "Static route", Active: true, SuppressHWOffload: true},
		{Family: "ipv4", Gateway: "192.0.2.2", Distance: 5, Protocol: "Static route", Inactive: true, SuppressHWOffload: true},
		{Family: "ipv4", Gateway: "192.0.2.3", Distance: 2, Protocol: "Static route", Inactive: true, SuppressHWOffload: true},
	}
	return l
}

// bgpLab has the same three providers on BGP defaults of one distance.
func bgpLab() routeros.L3HW {
	l := healthy()
	l.DefaultRoutes = []routeros.DefaultRoute{
		{Family: "ipv4", Gateway: "192.0.2.1", Distance: 20, Protocol: "BGP", LocalPref: 100, Active: true, SuppressHWOffload: true},
		{Family: "ipv4", Gateway: "192.0.2.2", Distance: 20, Protocol: "BGP", LocalPref: 100, Inactive: true, SuppressHWOffload: true},
		{Family: "ipv4", Gateway: "192.0.2.3", Distance: 20, Protocol: "BGP", LocalPref: 100, Inactive: true, SuppressHWOffload: true},
	}
	return l
}

func quality() []offload.ProviderQuality {
	return []offload.ProviderQuality{
		{Provider: "transit-a", Score: 42.5, LossPct: 1.25, RTTMs: 61.5},
		{Provider: "transit-b", Score: 12, LossPct: 0.1, RTTMs: 18},
		{Provider: "transit-c", Score: 20.25, LossPct: 0.5, RTTMs: 30},
	}
}

// poll is one evaluation of a fresh reading taken at at, with now a second later.
func poll(t *testing.T, e *Evaluator, at time.Time, l routeros.L3HW, wanted ...offload.Wanted) offload.RouterReport {
	t.Helper()
	snap := Snapshot{L3HW: l, CPUPathBps: 2_000_000_000, CPUPathKnown: true}
	return e.Evaluate(Input{Now: at.Add(time.Second), Neighbor: "192.0.2.254", Snap: &snap, At: at, Wanted: wanted,
		Volume: offload.VolumeReport{Source: labOpts.VolumeSource}, Quality: quality(), NextHops: nextHops})
}

func labEvaluator(t *testing.T) *Evaluator {
	t.Helper()
	e, err := NewEvaluator(labOpts, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func goldenFile(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/offload/mikrotik -update)", err)
	}
	if got != string(want) {
		t.Errorf("%s differs from the golden file; run go test ./internal/offload/mikrotik -update and review it\n--- got ---\n%s", name, got)
	}
}

func TestDefaultsSnippetGolden(t *testing.T) {
	rep := poll(t, labEvaluator(t), dryNow, defaultsLab())
	d := rep.Defaults
	if d == nil || d.Settling || d.Note != "" {
		t.Fatalf("defaults = %+v", d)
	}
	goldenFile(t, "defaults", d.Snippet)

	d = poll(t, labEvaluator(t), dryNow, bgpLab()).Defaults
	if d == nil || d.Settling || d.Note != "" {
		t.Fatalf("bgp defaults = %+v", d)
	}
	goldenFile(t, "defaults-bgp", d.Snippet)
}

// RouterOS compares distance across protocols before bgp-local-pref, so a
// ranking over static and BGP defaults, or over BGP defaults of different
// distances, cannot be carried out by a snippet: nothing is proposed, the
// routes carry no rank and no failover plan follows an order the router
// would not take.
func TestDefaultsUnorderableMixesProposeNothing(t *testing.T) {
	mixed := defaultsLab()
	mixed.DefaultRoutes[2] = routeros.DefaultRoute{Family: "ipv4", Gateway: "192.0.2.2", Distance: 20, Protocol: "BGP", LocalPref: 100, Inactive: true, SuppressHWOffload: true}
	distances := bgpLab()
	distances.DefaultRoutes[2].Distance = 200
	for name, tc := range map[string]struct {
		lab  routeros.L3HW
		note string
	}{
		"static and bgp": {mixed, "different protocols"},
		"bgp distances":  {distances, "different distances"},
	} {
		t.Run(name, func(t *testing.T) {
			rep := poll(t, labEvaluator(t), dryNow, tc.lab, wantFix("198.51.100.0/24", 80))
			d := rep.Defaults
			if d.Snippet != "" || !strings.Contains(d.Note, tc.note) || len(d.Failovers) != 0 {
				t.Fatalf("defaults = %+v", d)
			}
			for _, r := range d.Routes {
				if r.Proposed != 0 || r.Rank != 0 {
					t.Errorf("route %+v is proposed or ranked", r)
				}
			}
		})
	}
}

// The ranking follows the measured score, and each default gets the
// attribute its protocol uses: distance for a static route, local-pref for BGP.
func TestDefaultsRanksAndProposesPerProtocol(t *testing.T) {
	type want struct {
		attr          string
		rank          int
		current, prop int64
	}
	for name, tc := range map[string]struct {
		lab routeros.L3HW
		exp map[string]want
	}{
		"static": {defaultsLab(), map[string]want{
			"ipv4 192.0.2.1":   {"distance", 3, 1, 3},
			"ipv6 2001:db8::1": {"distance", 3, 1, 3},
			"ipv4 192.0.2.2":   {"distance", 1, 5, 1},
			"ipv4 192.0.2.3":   {"distance", 2, 2, 2},
		}},
		"bgp": {bgpLab(), map[string]want{
			"ipv4 192.0.2.1": {"bgp-local-pref", 3, 100, 180},
			"ipv4 192.0.2.2": {"bgp-local-pref", 1, 100, 200},
			"ipv4 192.0.2.3": {"bgp-local-pref", 2, 100, 190},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			d := poll(t, labEvaluator(t), dryNow, tc.lab).Defaults
			var order []string
			for _, p := range d.Providers {
				order = append(order, p.Provider)
			}
			if !slices.Equal(order, []string{"transit-b", "transit-c", "transit-a"}) {
				t.Fatalf("order = %v", order)
			}
			got := map[string]want{}
			for _, r := range d.Routes {
				got[r.Family+" "+r.Gateway] = want{r.Attribute, r.Rank, r.Current, r.Proposed}
			}
			for k, w := range tc.exp {
				if got[k] != w {
					t.Errorf("%s = %+v, want %+v", k, got[k], w)
				}
			}
			if !strings.Contains(d.Snippet, "Generated for review: nothing is applied") {
				t.Errorf("snippet lacks its header:\n%s", d.Snippet)
			}
		})
	}
}

// A provider that has no measurement, a gateway that is no provider's
// next_hop and a protocol with no proposal each leave a note and no guess.
func TestDefaultsProposeNothingWithoutEvidence(t *testing.T) {
	e := labEvaluator(t)
	snap := Snapshot{L3HW: defaultsLab()}
	in := Input{Now: dryNow, At: dryNow, Snap: &snap, NextHops: nextHops, Quality: quality()[:2]}
	d := e.Evaluate(in).Defaults
	if d.Snippet != "" || !strings.Contains(d.Note, "transit-c has no measurement") {
		t.Errorf("unmeasured provider: note %q snippet %q", d.Note, d.Snippet)
	}
	for _, r := range d.Routes {
		if r.Proposed != 0 {
			t.Errorf("proposal %+v without evidence", r)
		}
	}

	l := defaultsLab()
	l.DefaultRoutes = []routeros.DefaultRoute{
		{Family: "ipv4", Gateway: "203.0.113.77", Distance: 1, Protocol: "Static route", Active: true, SuppressHWOffload: true},
		{Family: "ipv4", Gateway: "192.0.2.2", Distance: 1, Protocol: "DHCP", Inactive: true, SuppressHWOffload: true},
	}
	snap = Snapshot{L3HW: l}
	in = Input{Now: dryNow, At: dryNow, Snap: &snap, NextHops: nextHops, Quality: quality()}
	d = labEvaluator(t).Evaluate(in).Defaults
	if d.Snippet != "" || d.Routes[0].Provider != "" || d.Routes[0].Note == "" || d.Routes[1].Attribute != "" || d.Routes[1].Note == "" {
		t.Errorf("defaults = %+v", d)
	}
}

// With no default that is a provider's, there is nothing to rank.
func TestDefaultsNoProviderBehindAnyDefault(t *testing.T) {
	snap := Snapshot{L3HW: defaultsLab()}
	d := labEvaluator(t).Evaluate(Input{Now: dryNow, At: dryNow, Snap: &snap}).Defaults
	if d.Snippet != "" || !strings.Contains(d.Note, "no default route has a provider") || len(d.Providers) != 0 {
		t.Errorf("defaults = %+v", d)
	}
}

// Ranking hysteresis and cooldown reach the report: a small lead does not
// reorder the defaults, a large one does only after the cooldown.
func TestDefaultsRankingHysteresisAndCooldown(t *testing.T) {
	e := labEvaluator(t)
	l := defaultsLab()
	first := func(d *offload.DefaultsReport) string { return d.Providers[0].Provider }
	run := func(at time.Time, a, b, c float64) *offload.DefaultsReport {
		snap := Snapshot{L3HW: l}
		q := []offload.ProviderQuality{{Provider: "transit-a", Score: a}, {Provider: "transit-b", Score: b}, {Provider: "transit-c", Score: c}}
		return e.Evaluate(Input{Now: at, At: at, Snap: &snap, Quality: q, NextHops: nextHops}).Defaults
	}
	if got := first(run(dryNow, 10, 12, 30)); got != "transit-a" {
		t.Fatalf("first = %s", got)
	}
	// transit-b is 8% ahead of transit-a's 10: inside the margin.
	if got := first(run(dryNow.Add(time.Minute), 10, 9.2, 30)); got != "transit-a" {
		t.Errorf("small lead: first = %s", got)
	}
	// 50% ahead: the order changes.
	if got := first(run(dryNow.Add(2*time.Minute), 10, 5, 30)); got != "transit-b" {
		t.Errorf("large lead: first = %s", got)
	}
	// transit-a swings far ahead at once: the cooldown holds the order.
	if got := first(run(dryNow.Add(3*time.Minute), 1, 5, 30)); got != "transit-b" {
		t.Errorf("inside the cooldown: first = %s", got)
	}
	if got := first(run(dryNow.Add(2*time.Minute+rankCooldown), 1, 5, 30)); got != "transit-a" {
		t.Errorf("after the cooldown: first = %s", got)
	}
}

// A change of the active default recomputes and freezes until a reading is
// taken after the settle time; the first readings do not freeze.
func TestActiveDefaultChangeFreezesUntilAFreshReading(t *testing.T) {
	e := labEvaluator(t)
	wanted := []offload.Wanted{wantFix("198.51.100.0/24", 80)}
	l := defaultsLab()

	rep := poll(t, e, dryNow, l, wanted...)
	if rep.Verdict != offload.VerdictFits || rep.Defaults.Settling || states(rep)["198.51.100.0/24"] != offload.FixOffload {
		t.Fatalf("before: %+v", rep)
	}
	if rep = poll(t, e, dryNow.Add(time.Minute), l, wanted...); rep.Defaults.Settling {
		t.Fatalf("an unchanged default settled: %+v", rep.Defaults)
	}

	// The active default moves from transit-a to transit-c.
	moved := defaultsLab()
	moved.DefaultRoutes = slices.Clone(moved.DefaultRoutes)
	for _, i := range []int{0, 1} {
		moved.DefaultRoutes[i].Active, moved.DefaultRoutes[i].Inactive = false, true
	}
	moved.DefaultRoutes[3].Active, moved.DefaultRoutes[3].Inactive = true, false
	changed := dryNow.Add(2 * time.Minute)
	rep = poll(t, e, changed, moved, wanted...)
	d := rep.Defaults
	if !d.Settling || d.SettlingSince == nil || !d.SettlingSince.Equal(changed) || d.Snippet != "" {
		t.Fatalf("after the change: %+v", d)
	}
	if rep.Verdict != offload.VerdictFrozen || !slices.Contains(rep.Freezes, offload.Freeze{Reason: offload.FreezeSettling}) {
		t.Errorf("verdict %q freezes %v", rep.Verdict, rep.Freezes)
	}
	if got := states(rep)["198.51.100.0/24"]; got != offload.FixBlocked {
		t.Errorf("fix state while settling = %s", got)
	}
	// The failover plans are recomputed for the new active default: transit-a
	// is a backup now and transit-c is not.
	var backups []string
	for _, f := range d.Failovers {
		backups = append(backups, f.Backup)
	}
	slices.Sort(backups)
	if !slices.Equal(backups, []string{"transit-a", "transit-b"}) {
		t.Errorf("failover backups = %v", backups)
	}
	// The fix steers to transit-b, which is lost for transit-a's failover: its
	// slot is freed in the plan for the settled router, though it is frozen now.
	for _, f := range d.Failovers {
		if f.Backup == "transit-a" && (f.Dropped != 1 || f.Freed != 1) {
			t.Errorf("transit-a failover while settling = %+v", f)
		}
	}
	// The same reading again, and a reading inside the settle time, stay frozen.
	if rep = poll(t, e, changed, moved, wanted...); !rep.Defaults.Settling {
		t.Error("the same reading unfroze")
	}
	if rep = poll(t, e, changed.Add(10*time.Second), moved, wanted...); !rep.Defaults.Settling {
		t.Error("a reading inside the settle time unfroze")
	}
	// A reading after the settle time ends it, and the plan runs again.
	rep = poll(t, e, changed.Add(time.Minute), moved, wanted...)
	if rep.Defaults.Settling || rep.Verdict != offload.VerdictFits || states(rep)["198.51.100.0/24"] != offload.FixOffload || rep.Defaults.Snippet == "" {
		t.Errorf("after a fresh reading: %+v", rep)
	}
}

// Only a change of the default routes settles: a changed table does not.
func TestOtherReadingChangesDoNotSettle(t *testing.T) {
	e := labEvaluator(t)
	poll(t, e, dryNow, defaultsLab())
	l := defaultsLab()
	l.Monitor.IPv4RoutesHW += 100
	if d := poll(t, e, dryNow.Add(time.Minute), l).Defaults; d.Settling {
		t.Errorf("defaults = %+v", d)
	}
}

// Each backup's plan drops the fixes that steer to a provider assumed lost,
// hands their slots back, and plans the rest again on the same budget.
func TestFailoverPlansPerBackup(t *testing.T) {
	e := labEvaluator(t)
	w := func(prefix, provider string) offload.Wanted {
		x := wantFix(prefix, 10)
		x.Provider = provider
		return x
	}
	rep := poll(t, e, dryNow, defaultsLab(),
		w("198.51.100.0/24", "transit-a"), w("203.0.113.0/24", "transit-b"), w("192.0.2.0/24", "transit-c"))
	if len(rep.Defaults.Failovers) != 2 {
		t.Fatalf("failovers = %+v", rep.Defaults.Failovers)
	}
	b, c := rep.Defaults.Failovers[0], rep.Defaults.Failovers[1]
	// transit-b is ranked first: only the active transit-a is lost.
	if b.Backup != "transit-b" || b.Rank != 1 || !slices.Equal(b.Lost, []string{"transit-a"}) || b.Dropped != 1 || b.Freed != 1 || b.Offload != 2 || b.Withhold != 0 || b.Blocked != 0 {
		t.Errorf("transit-b = %+v", b)
	}
	// transit-c is second: transit-b ahead of it is lost too.
	if c.Backup != "transit-c" || c.Rank != 2 || !slices.Equal(c.Lost, []string{"transit-a", "transit-b"}) || c.Dropped != 2 || c.Freed != 2 || c.Offload != 1 {
		t.Errorf("transit-c = %+v", c)
	}
	if b.SettleSeconds != 15 || c.SettleSeconds != 15 {
		t.Errorf("settle = %d, %d", b.SettleSeconds, c.SettleSeconds)
	}
}

// When the router cannot be planned on, the failover plans are not made up.
func TestNoFailoverPlansWithoutAPlan(t *testing.T) {
	l := defaultsLab()
	l.Version = "7.0"
	rep := poll(t, labEvaluator(t), dryNow, l, wantFix("198.51.100.0/24", 80))
	if rep.Defaults == nil || len(rep.Defaults.Failovers) != 0 {
		t.Errorf("defaults = %+v", rep.Defaults)
	}
}

// Backups stay on the CPU path: the snippet writes suppress-hw-offload on
// every default it names (on the route, or in the BGP filter rule), and never
// offers to clear it.
func TestSnippetKeepsEveryDefaultOnTheCPU(t *testing.T) {
	for name, tc := range map[string]struct {
		lab    routeros.L3HW
		cmds   int
		suffix string
	}{
		"static": {defaultsLab(), 4, " suppress-hw-offload=yes"},
		"bgp":    {bgpLab(), 3, "set suppress-hw-offload yes }\""},
	} {
		t.Run(name, func(t *testing.T) {
			d := poll(t, labEvaluator(t), dryNow, tc.lab).Defaults
			var cmds int
			for _, line := range strings.Split(d.Snippet, "\n") {
				if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" || strings.HasPrefix(line, "/routing filter rule add") {
					continue
				}
				cmds++
				if !strings.HasSuffix(line, tc.suffix) {
					t.Errorf("command without suppress-hw-offload: %s", line)
				}
			}
			if cmds != tc.cmds || strings.Contains(d.Snippet, "suppress-hw-offload=no") || strings.Contains(d.Snippet, "suppress-hw-offload no") {
				t.Errorf("%d commands:\n%s", cmds, d.Snippet)
			}
		})
	}
}

func TestChainNameIsSafe(t *testing.T) {
	if got := chainName("transit a/b;x"); got != "transit-a-b-x" {
		t.Errorf("chainName = %q", got)
	}
}
