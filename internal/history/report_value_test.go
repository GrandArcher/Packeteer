package history

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// valueSeed is hand-checkable. The range is 2026-09-01 to 2026-09-03 and
// now is 2026-09-02 06:00; d1 and d2 are the two days.
//
//	m0 transit-b, started before the range: not counted
//	m1 transit-b inject  d1 +1h..+3h   100 Mbps  loss 10 -> 0,  rtt 50 -> 30
//	m2 transit-b inject  d1 +2h..+12h  300 Mbps  loss 2 -> 1,   rtt 80 -> 60
//	m3 transit-b observe d2 +1h, open  200 Mbps  loss 20 -> 2,  rtt 70 -> 40
//	m4 transit-b (no mode) d2 +2h..+4h, no volume loss 4 -> 1,  rtt 100 -> 90
//	m5 transit-a observe d2 +3h, open: no measurement of either path
//	m6 transit-d inject  d2 +1h..+2h: no stored measurement of the chosen path
//
// transit-c was never chosen and must have no row.
func valueSeed() plugin.History {
	d1 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	d2 := d1.Add(24 * time.Hour)
	meas := func(r plugin.ImprovementRecord, bl, br, al, ar float64) plugin.ImprovementRecord {
		r.HasBefore, r.BeforeLoss, r.BeforeRTT = true, bl, br
		r.HasAfter, r.AfterLoss, r.AfterRTT = true, al, ar
		return r
	}
	m6 := plugin.ImprovementRecord{ID: "m6", Prefix: pfxC, Provider: "transit-d", Native: "transit-a", Mode: "inject",
		Start: d2.Add(time.Hour), End: d2.Add(2 * time.Hour), HasBefore: true, BeforeLoss: 1, BeforeRTT: 20}
	return plugin.History{Improvements: []plugin.ImprovementRecord{
		meas(plugin.ImprovementRecord{ID: "m0", Prefix: pfxA, Provider: "transit-b", Native: "transit-a", Mode: "inject", VolumeMbps: 50,
			Start: d1.Add(-2 * time.Hour), End: d1.Add(time.Hour)}, 50, 90, 0, 10),
		meas(plugin.ImprovementRecord{ID: "m1", Prefix: pfxA, Provider: "transit-b", Native: "transit-a", Mode: "inject", VolumeMbps: 100,
			Start: d1.Add(time.Hour), End: d1.Add(3 * time.Hour)}, 10, 50, 0, 30),
		meas(plugin.ImprovementRecord{ID: "m2", Prefix: pfxB, Provider: "transit-b", Native: "transit-a", Mode: "inject", VolumeMbps: 300, Cause: plugin.CauseCost,
			Start: d1.Add(2 * time.Hour), End: d1.Add(12 * time.Hour)}, 2, 80, 1, 60),
		meas(plugin.ImprovementRecord{ID: "m3", Prefix: pfxC, Provider: "transit-b", Native: "transit-a", Mode: "observe", VolumeMbps: 200,
			Start: d2.Add(time.Hour)}, 20, 70, 2, 40),
		meas(plugin.ImprovementRecord{ID: "m4", Prefix: pfxA, Provider: "transit-b", Native: "transit-a",
			Start: d2.Add(2 * time.Hour), End: d2.Add(4 * time.Hour)}, 4, 100, 1, 90),
		{ID: "m5", Prefix: pfxB, Provider: "transit-a", Native: "transit-b", Mode: "observe", Start: d2.Add(3 * time.Hour)},
		m6,
	}}
}

func buildValue(t *testing.T, mod ...func(*Query)) []ValueRow {
	t.Helper()
	q := Query{Name: ReportValue, From: from, To: to, Now: now}
	for _, m := range mod {
		m(&q)
	}
	rep, err := Build(valueSeed(), q)
	if err != nil {
		t.Fatal(err)
	}
	return rep.Rows.([]ValueRow)
}

func TestValueMatchesHandCalculation(t *testing.T) {
	// Announced transit-b: volume weights 100 and 300.
	//   loss before (100*10 + 300*2)/400 = 4, after (0 + 300*1)/400 = 0.75
	//   rtt before (100*50 + 300*80)/400 = 72.5, after (100*30 + 300*60)/400 = 52.5
	announced := ValueRow{Basis: BasisAnnounced, Improvements: 2, Measured: 2, SteeredHours: 12, Weighting: WeightFlow, VolumeMbps: 400,
		BeforeLossPct: ptr(4), AfterLossPct: ptr(0.75), LossAvoided: ptr(3.25), BeforeRTTMs: ptr(72.5), AfterRTTMs: ptr(52.5), RTTAvoidedMs: ptr(20)}
	// Estimated: m4 has no volume, so the mean is unweighted.
	//   loss before (20+4)/2 = 12, after (2+1)/2 = 1.5; rtt before 85, after 65
	// m3 is open for 5h to now, m4 lasted 2h and m5 3h.
	est := ValueRow{Basis: BasisEstimate, Improvements: 2, Measured: 2, SteeredHours: 7, Weighting: WeightEqual,
		BeforeLossPct: ptr(12), AfterLossPct: ptr(1.5), LossAvoided: ptr(10.5), BeforeRTTMs: ptr(85), AfterRTTMs: ptr(65), RTTAvoidedMs: ptr(20)}
	with := func(r ValueRow, scope, provider, day string, imps int, hours float64) ValueRow {
		r.Scope, r.Provider, r.Day, r.Improvements, r.SteeredHours = scope, provider, day, imps, hours
		return r
	}
	want := []ValueRow{
		// m5 and m6 add improvements and hours but no measurement.
		with(announced, ValueTotal, "", "", 3, 13),
		with(est, ValueTotal, "", "", 3, 10),
		{Scope: ValueProvider, Provider: "transit-a", Basis: BasisEstimate, Improvements: 1, SteeredHours: 3},
		with(announced, ValueProvider, "transit-b", "", 2, 12),
		with(est, ValueProvider, "transit-b", "", 2, 7),
		{Scope: ValueProvider, Provider: "transit-d", Basis: BasisAnnounced, Improvements: 1, SteeredHours: 1},
		with(announced, ValueDay, "", "2026-09-01", 2, 12),
		{Scope: ValueDay, Day: "2026-09-02", Basis: BasisAnnounced, Improvements: 1, SteeredHours: 1},
		with(est, ValueDay, "", "2026-09-02", 3, 10),
	}
	got := buildValue(t)
	if len(got) != len(want) {
		t.Fatalf("%d rows, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if g, ws := jsonOf(t, got[i]), jsonOf(t, w); g != ws {
			t.Errorf("row %d\n got %s\nwant %s", i, g, ws)
		}
	}
}

// Only inject records are announced; observe, suggest, and a record with no
// mode (made before the column existed) are estimates.
func TestValueLabelsEveryModeAsRecordedTraffic(t *testing.T) {
	for mode, want := range map[string]string{
		"inject": BasisAnnounced, "observe": BasisEstimate, "suggest": BasisEstimate, "": BasisEstimate,
	} {
		h := valueSeed()
		h.Improvements = []plugin.ImprovementRecord{{ID: "x", Prefix: pfxA, Provider: "transit-b", Native: "transit-a", Mode: mode,
			Start: from.Add(time.Hour), HasBefore: true, BeforeLoss: 3, HasAfter: true, AfterLoss: 1}}
		rep, err := Build(h, Query{Name: ReportValue, From: from, To: to, Now: now})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rep.Rows.([]ValueRow) {
			if r.Basis != want {
				t.Errorf("mode %q: %s row is %s, want %s", mode, r.Scope, r.Basis, want)
			}
		}
	}
}

// The recorder stores a path with no reply as loss 100 and RTT 0 (not as a
// missing figure), so neither a dead chosen path nor a dead native path may
// produce an RTT figure.
func TestValueDeadPathGivesNoRTTGain(t *testing.T) {
	move := func(id string, bl, br, al, ar float64) plugin.ImprovementRecord {
		return plugin.ImprovementRecord{ID: id, Prefix: pfxA, Provider: "transit-b", Native: "transit-a", Mode: "inject", Start: from.Add(time.Hour),
			HasBefore: true, BeforeLoss: bl, BeforeRTT: br, HasAfter: true, AfterLoss: al, AfterRTT: ar}
	}
	for name, r := range map[string]plugin.ImprovementRecord{
		"chosen path dead": move("a", 2, 40, 100, 0),
		"native path dead": move("b", 100, 0, 1, 30),
	} {
		h := plugin.History{Improvements: []plugin.ImprovementRecord{r}}
		rep, err := Build(h, Query{Name: ReportValue, From: from, To: to, Now: now})
		if err != nil {
			t.Fatal(err)
		}
		row := rep.Rows.([]ValueRow)[0]
		if row.Measured != 1 || row.RTTAvoidedMs != nil || row.BeforeRTTMs != nil || row.AfterRTTMs != nil {
			t.Errorf("%s: RTT figures from a path with no reply: %+v", name, row)
		}
	}
	// Loss still counts: a dead chosen path is 98 points worse, not a gain.
	h := plugin.History{Improvements: []plugin.ImprovementRecord{move("a", 2, 40, 100, 0)}}
	rep, err := Build(h, Query{Name: ReportValue, From: from, To: to, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if got := *rep.Rows.([]ValueRow)[0].LossAvoided; got != -98 {
		t.Errorf("loss avoided onto a dead path = %v, want -98", got)
	}
	// With a second move whose paths both answered, the RTT mean uses that
	// move alone.
	h = plugin.History{Improvements: []plugin.ImprovementRecord{move("a", 2, 40, 100, 0), move("c", 5, 90, 1, 50)}}
	rep, err = Build(h, Query{Name: ReportValue, From: from, To: to, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if got := *rep.Rows.([]ValueRow)[0].RTTAvoidedMs; got != 40 {
		t.Errorf("rtt avoided = %v, want 40 from the one move with two live paths", got)
	}
}

func TestValueCreditsOnlyTheChosenProvider(t *testing.T) {
	rows := buildValue(t, func(q *Query) { q.Provider = "transit-b" })
	for _, r := range rows {
		if r.Scope == ValueProvider && r.Provider != "transit-b" {
			t.Errorf("provider filter kept %s", r.Provider)
		}
		// m5 and m6 are not onto transit-b.
		if r.Scope == ValueTotal && r.Improvements != 2 {
			t.Errorf("total for transit-b: %+v", r)
		}
	}
	// transit-a is the native path of the other moves, so filtering by it
	// credits it with m5 alone.
	for _, r := range buildValue(t, func(q *Query) { q.Provider = "transit-a" }) {
		if r.Scope == ValueTotal && (r.Improvements != 1 || r.Measured != 0 || r.LossAvoided != nil) {
			t.Errorf("total for transit-a: %+v", r)
		}
	}
	for _, r := range buildValue(t) {
		if r.Provider == "transit-c" {
			t.Errorf("a provider that was never chosen has a row: %+v", r)
		}
	}
}

func TestValueUnmeasuredMovesShowNoGain(t *testing.T) {
	for _, r := range buildValue(t) {
		if r.Provider != "transit-d" && r.Provider != "transit-a" {
			continue
		}
		if r.Measured != 0 || r.LossAvoided != nil || r.RTTAvoidedMs != nil || r.BeforeLossPct != nil || r.Weighting != "" {
			t.Errorf("%s shows a gain it did not measure: %+v", r.Provider, r)
		}
	}
}

func TestValueNegativeWhenTheChosenPathIsWorse(t *testing.T) {
	h := valueSeed()
	h.Improvements = []plugin.ImprovementRecord{{ID: "w", Prefix: pfxA, Provider: "transit-b", Native: "transit-a", Mode: "inject", Cause: plugin.CauseCost,
		Start: from.Add(time.Hour), End: from.Add(2 * time.Hour), HasBefore: true, BeforeLoss: 1, BeforeRTT: 20, HasAfter: true, AfterLoss: 3, AfterRTT: 35}}
	rep, err := Build(h, Query{Name: ReportValue, From: from, To: to, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	r := rep.Rows.([]ValueRow)[0]
	if *r.LossAvoided != -2 || *r.RTTAvoidedMs != -15 {
		t.Errorf("worse path avoided %v loss, %v ms; want -2 and -15", *r.LossAvoided, *r.RTTAvoidedMs)
	}
}

func TestValueFiltersAndLimit(t *testing.T) {
	if rows := buildValue(t, func(q *Query) { q.Cause = plugin.CauseCost }); len(rows) != 3 || rows[0].Improvements != 1 || rows[0].LossAvoided == nil || *rows[0].LossAvoided != 1 {
		t.Errorf("cause=cost: %+v", rows)
	}
	// pfxC holds m3 (observe) and m6 (inject, never measured).
	rows := buildValue(t, func(q *Query) { q.Prefix = pfxC })
	if len(rows) < 2 || rows[0].Basis != BasisAnnounced || rows[0].Improvements != 1 || rows[1].Basis != BasisEstimate || rows[1].Improvements != 1 ||
		rows[0].Scope != ValueTotal || rows[1].Scope != ValueTotal {
		t.Errorf("prefix filter: %+v", rows)
	}
	if err := (Query{Name: ReportValue, Limit: 5}).Validate(); err == nil {
		t.Error("limit accepted on a report that is never cut")
	}
	if rows := buildValue(t, func(q *Query) { q.Provider = "transit-c" }); len(rows) != 0 {
		t.Errorf("a provider nothing chose has rows: %+v", rows)
	}
}

func jsonOf(t *testing.T, r ValueRow) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
