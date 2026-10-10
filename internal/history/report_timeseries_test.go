package history

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var pfxD = netip.MustParsePrefix("2001:db8::/32")

// tsBucket is a rollup of `measured` probes whose average loss and RTT are
// the given values.
func tsBucket(day time.Time, p netip.Prefix, provider string, measured int, loss, rtt float64) plugin.ProbeBucket {
	return plugin.ProbeBucket{Day: day, Prefix: p, Provider: provider, Probes: measured, Measured: measured,
		LossSum: loss * float64(measured), RTTSumMs: rtt * float64(measured)}
}

// tsSeed is two days with one prefix per bucket case:
//
//	A performance, 10%/100ms -> 0%/40ms on d1 (better 50), 2%/80ms -> 2%/79ms on d2
//	B performance, 0%/100ms -> 0%/75ms on d1 (better 20, not 50), 100ms -> 40ms on d2 (better 50)
//	C cost, 50ms -> 48ms on d1 (in all only)
//	D commit, chosen provider has no measurement (skipped)
func tsSeed() plugin.History {
	d1 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	d2 := d1.Add(24 * time.Hour)
	return plugin.History{
		Buckets: []plugin.ProbeBucket{
			tsBucket(d1, pfxA, "transit-a", 10, 10, 100), tsBucket(d1, pfxA, "transit-b", 10, 0, 40),
			tsBucket(d2, pfxA, "transit-a", 10, 2, 80), tsBucket(d2, pfxA, "transit-b", 10, 2, 79),
			tsBucket(d1, pfxB, "transit-a", 10, 0, 100), tsBucket(d1, pfxB, "transit-b", 10, 0, 75),
			tsBucket(d2, pfxB, "transit-a", 10, 0, 100), tsBucket(d2, pfxB, "transit-b", 10, 0, 40),
			tsBucket(d1, pfxC, "transit-a", 10, 0, 50), tsBucket(d1, pfxC, "transit-b", 10, 0, 48),
			tsBucket(d1, pfxD, "transit-a", 10, 5, 60),
			// A second write for the same day adds to the rollup.
			tsBucket(d1, pfxA, "transit-a", 0, 0, 0),
			// Outside the range: ignored.
			tsBucket(d1.Add(-24*time.Hour), pfxA, "transit-a", 99, 99, 999), tsBucket(d1.Add(-24*time.Hour), pfxA, "transit-b", 99, 0, 1),
		},
		Improvements: []plugin.ImprovementRecord{
			{ID: "a1", Prefix: pfxA, Provider: "transit-b", Native: "transit-a", Cause: plugin.CausePerformance,
				Start: d1.Add(1 * time.Hour), End: d1.Add(3 * time.Hour)},
			// Open: active on d2 up to Now.
			{ID: "a2", Prefix: pfxA, Provider: "transit-b", Native: "transit-a", Start: d2.Add(1 * time.Hour)},
			// Spans midnight, so it is on both days.
			{ID: "b1", Prefix: pfxB, Provider: "transit-b", Native: "transit-a", Cause: plugin.CausePerformance,
				Start: d1.Add(22 * time.Hour), End: d2.Add(2 * time.Hour)},
			{ID: "c1", Prefix: pfxC, Provider: "transit-b", Native: "transit-a", Cause: plugin.CauseCost,
				Start: d1.Add(2 * time.Hour), End: d1.Add(12 * time.Hour)},
			{ID: "d1", Prefix: pfxD, Provider: "transit-b", Native: "transit-a", Cause: plugin.CauseCommit,
				Start: d1.Add(2 * time.Hour), End: d1.Add(12 * time.Hour)},
			// No native provider recorded: nothing to compare with.
			{ID: "x1", Prefix: pfxA, Provider: "transit-b", Start: d1.Add(2 * time.Hour), End: d1.Add(3 * time.Hour)},
			// Ended before the range.
			{ID: "old", Prefix: pfxA, Provider: "transit-b", Native: "transit-a", Start: d1.Add(-48 * time.Hour), End: d1.Add(-47 * time.Hour)},
		},
	}
}

func buildTS(t *testing.T, h plugin.History, mod ...func(*Query)) Report {
	t.Helper()
	q := Query{Name: ReportTimeSeries, From: from, To: to, Now: now}
	for _, m := range mod {
		m(&q)
	}
	r, err := Build(h, q)
	if err != nil {
		t.Fatalf("Build(timeseries): %v", err)
	}
	return r
}

func TestTimeSeriesBuckets(t *testing.T) {
	rows := buildTS(t, tsSeed()).Rows.([]TimeSeriesRow)
	want := []TimeSeriesRow{
		// d1: A, B, C. D has no chosen-provider rollup.
		{Day: "2026-09-01", Bucket: BucketAll, Prefixes: 3, BeforeLossPct: round(100.0 / 30), AfterLossPct: 0, BeforeRTTMs: round(250.0 / 3), AfterRTTMs: round(163.0 / 3)},
		{Day: "2026-09-01", Bucket: BucketProblem, Prefixes: 2, BeforeLossPct: 5, AfterLossPct: 0, BeforeRTTMs: 100, AfterRTTMs: 57.5},
		{Day: "2026-09-01", Bucket: BucketBetter20, Prefixes: 2, BeforeLossPct: 5, AfterLossPct: 0, BeforeRTTMs: 100, AfterRTTMs: 57.5},
		{Day: "2026-09-01", Bucket: BucketBetter50, Prefixes: 1, BeforeLossPct: 10, AfterLossPct: 0, BeforeRTTMs: 100, AfterRTTMs: 40},
		// d2: A (open, 1%) and B (carried over midnight).
		{Day: "2026-09-02", Bucket: BucketAll, Prefixes: 2, BeforeLossPct: 1, AfterLossPct: 1, BeforeRTTMs: 90, AfterRTTMs: 59.5},
		{Day: "2026-09-02", Bucket: BucketProblem, Prefixes: 2, BeforeLossPct: 1, AfterLossPct: 1, BeforeRTTMs: 90, AfterRTTMs: 59.5},
		{Day: "2026-09-02", Bucket: BucketBetter20, Prefixes: 1, BeforeLossPct: 0, AfterLossPct: 0, BeforeRTTMs: 100, AfterRTTMs: 40},
		{Day: "2026-09-02", Bucket: BucketBetter50, Prefixes: 1, BeforeLossPct: 0, AfterLossPct: 0, BeforeRTTMs: 100, AfterRTTMs: 40},
	}
	if len(rows) != len(want) {
		t.Fatalf("got %d rows, want %d: %+v", len(rows), len(want), rows)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d\n got %+v\nwant %+v", i, rows[i], want[i])
		}
	}
}

// Each bucket has its own test input so a regression in one rule names it.
func TestTimeSeriesEachBucketAlone(t *testing.T) {
	d1 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name         string
		cause        string
		nl, cl       float64 // native and chosen loss
		nr, cr       float64 // native and chosen RTT
		wantInBucket map[string]bool
	}{
		{"performance move, no gain", plugin.CausePerformance, 0, 0, 50, 50, map[string]bool{BucketAll: true, BucketProblem: true}},
		{"cost move, 10% better", plugin.CauseCost, 0, 0, 100, 90, map[string]bool{BucketAll: true}},
		{"commit move, exactly 20% better rtt", plugin.CauseCommit, 0, 0, 100, 80, map[string]bool{BucketAll: true, BucketBetter20: true}},
		{"cost move, loss 50% better", plugin.CauseCost, 4, 2, 50, 50, map[string]bool{BucketAll: true, BucketBetter20: true, BucketBetter50: true}},
		{"performance move, worse", plugin.CausePerformance, 1, 5, 50, 70, map[string]bool{BucketAll: true, BucketProblem: true}},
		{"unset cause is performance", "", 0, 0, 100, 49, map[string]bool{BucketAll: true, BucketProblem: true, BucketBetter20: true, BucketBetter50: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := plugin.History{
				Buckets: []plugin.ProbeBucket{
					tsBucket(d1, pfxA, "transit-a", 5, c.nl, c.nr), tsBucket(d1, pfxA, "transit-b", 5, c.cl, c.cr),
				},
				Improvements: []plugin.ImprovementRecord{
					{ID: "1", Prefix: pfxA, Provider: "transit-b", Native: "transit-a", Cause: c.cause, Start: d1.Add(time.Hour), End: d1.Add(2 * time.Hour)},
				},
			}
			got := map[string]bool{}
			for _, r := range buildTS(t, h).Rows.([]TimeSeriesRow) {
				got[r.Bucket] = true
				if r.Prefixes != 1 || r.BeforeLossPct != c.nl || r.AfterLossPct != c.cl || r.BeforeRTTMs != c.nr || r.AfterRTTMs != c.cr {
					t.Errorf("%s row = %+v", r.Bucket, r)
				}
			}
			for _, b := range Buckets {
				if got[b] != c.wantInBucket[b] {
					t.Errorf("bucket %s present = %v, want %v", b, got[b], c.wantInBucket[b])
				}
			}
		})
	}
}

func TestTimeSeriesEmptyAndUnmeasured(t *testing.T) {
	for name, h := range map[string]plugin.History{
		"no history":                   {},
		"improvements without rollups": {Improvements: tsSeed().Improvements},
		"rollups without improvements": {Buckets: tsSeed().Buckets},
	} {
		rep := buildTS(t, h)
		rows, ok := rep.Rows.([]TimeSeriesRow)
		if !ok || rows == nil || len(rows) != 0 {
			t.Errorf("%s: rows = %#v, want an empty typed slice", name, rep.Rows)
		}
		b, err := json.Marshal(rep)
		if err != nil || !strings.Contains(string(b), `"rows":[]`) {
			t.Errorf("%s: json = %s (%v)", name, b, err)
		}
		var csv bytes.Buffer
		if err := rep.CSV(&csv); err != nil || strings.TrimSpace(csv.String()) != "day,bucket,prefixes,before_loss_pct,after_loss_pct,before_rtt_ms,after_rtt_ms" {
			t.Errorf("%s: csv = %q (%v)", name, csv.String(), err)
		}
	}
}

func TestTimeSeriesNotCutByLimitAndCSV(t *testing.T) {
	rep := buildTS(t, tsSeed(), func(q *Query) { q.Limit = 1 })
	if n := len(rep.Rows.([]TimeSeriesRow)); n != 8 {
		t.Fatalf("limit 1 gave %d rows, want all 8", n)
	}
	var buf bytes.Buffer
	if err := rep.CSV(&buf); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 9 || lines[0] != "day,bucket,prefixes,before_loss_pct,after_loss_pct,before_rtt_ms,after_rtt_ms" ||
		lines[2] != "2026-09-01,problem,2,5,0,100,57.5" {
		t.Fatalf("csv = %q", lines)
	}
}

// An improvement that is still open stops at Now: a query that ends before
// it started, or Now before the second day, shows no point for that day.
func TestTimeSeriesOpenImprovementStopsAtNow(t *testing.T) {
	rows := buildTS(t, tsSeed(), func(q *Query) { q.Now = from.Add(12 * time.Hour); q.To = from.Add(12 * time.Hour) }).Rows.([]TimeSeriesRow)
	for _, r := range rows {
		if r.Day != "2026-09-01" {
			t.Fatalf("row after Now: %+v", r)
		}
	}
	if len(rows) == 0 {
		t.Fatal("no rows for the first day")
	}
}

func TestTimeSeriesListedAndPure(t *testing.T) {
	if !Known(ReportTimeSeries) {
		t.Fatal("timeseries is not a known report")
	}
	a, b := buildTS(t, tsSeed()), buildTS(t, tsSeed())
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if !bytes.Equal(ja, jb) {
		t.Fatalf("not deterministic:\n%s\n%s", ja, jb)
	}
}
