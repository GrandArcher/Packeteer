package history

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// seed is a fixed two-day history on documentation prefixes and ASNs.
func seed() plugin.History {
	d1 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	d2 := d1.Add(24 * time.Hour)
	return plugin.History{
		Buckets: []plugin.ProbeBucket{
			{Day: d1, Prefix: pfxA, Provider: "transit-a", Probes: 10, Failed: 2, Measured: 8, LossSum: 80, RTTSumMs: 400, JitterSum: 16},
			{Day: d1, Prefix: pfxA, Provider: "transit-b", Probes: 10, Measured: 10, LossSum: 0, RTTSumMs: 300, JitterSum: 10},
			{Day: d2, Prefix: pfxB, Provider: "transit-a", Probes: 4, Measured: 4, LossSum: 4, RTTSumMs: 80, JitterSum: 4},
			{Day: d2, Prefix: pfxC, Provider: "transit-b", Probes: 6, Measured: 6, LossSum: 0, RTTSumMs: 60, JitterSum: 0},
			// Outside the range: ignored.
			{Day: d1.Add(-24 * time.Hour), Prefix: pfxA, Provider: "transit-a", Probes: 99, Measured: 99},
		},
		Improvements: []plugin.ImprovementRecord{
			{ID: "1", Prefix: pfxA, Provider: "transit-b", Native: "transit-a", Cause: plugin.CausePerformance,
				Start: d1.Add(1 * time.Hour), End: d1.Add(3 * time.Hour), EndReason: "ttl expired",
				HasBefore: true, BeforeLoss: 10, BeforeRTT: 50, HasAfter: true, AfterLoss: 0, AfterRTT: 30, OriginASN: 64500, Country: "NL"},
			{ID: "2", Prefix: pfxA, Provider: "transit-b", Native: "transit-a", Cause: "",
				Start: d2.Add(1 * time.Hour), HasBefore: true, BeforeLoss: 20, BeforeRTT: 70, HasAfter: true, AfterLoss: 2, AfterRTT: 40, OriginASN: 64500, Country: "NL"},
			{ID: "3", Prefix: pfxB, Provider: "transit-b", Native: "transit-a", Cause: plugin.CauseCost,
				Start: d2.Add(2 * time.Hour), End: d2.Add(12 * time.Hour), HasBefore: true, BeforeLoss: 1, BeforeRTT: 20, HasAfter: true, AfterLoss: 1, AfterRTT: 22,
				CostDelta: 2, VolumeMbps: 100, EstSavings: 200, OriginASN: 64501, Country: "DE"},
			{ID: "4", Prefix: pfxC, Provider: "transit-a", Native: "transit-b", Cause: plugin.CauseCommit,
				Start: d2.Add(4 * time.Hour), OriginASN: 64500},
			// Started before the range and ended inside: counts hours, not starts.
			{ID: "0", Prefix: pfxB, Provider: "transit-b", Native: "transit-a", Cause: plugin.CauseCost,
				Start: d1.Add(-2 * time.Hour), End: d1.Add(1 * time.Hour), CostDelta: 1, EstSavings: 73},
			// Ended before the range: ignored.
			{ID: "old", Prefix: pfxC, Provider: "transit-a", Start: d1.Add(-48 * time.Hour), End: d1.Add(-47 * time.Hour)},
		},
		Prefixes: []plugin.PrefixInfo{
			{Prefix: pfxA, OriginASN: 64500, Country: "NL", VolumeMbps: 5},
			{Prefix: pfxB, OriginASN: 64501, Country: "DE", VolumeMbps: 100},
			{Prefix: pfxC, OriginASN: 64500, VolumeMbps: 50},
		},
	}
}

var (
	from = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	to   = from.Add(48 * time.Hour)
	now  = from.Add(24*time.Hour + 6*time.Hour) // day 2, 06:00
)

func build(t *testing.T, name string, mod ...func(*Query)) Report {
	t.Helper()
	q := Query{Name: name, From: from, To: to, Now: now}
	for _, m := range mod {
		m(&q)
	}
	r, err := Build(seed(), q)
	if err != nil {
		t.Fatalf("Build(%s): %v", name, err)
	}
	return r
}

func TestSummary(t *testing.T) {
	rows := build(t, ReportSummary).Rows.([]SummaryRow)
	s := rows[0]
	want := SummaryRow{
		Improvements: 4, Performance: 2, Commit: 1, Cost: 1, Active: 3,
		// 1: 2h, 2: 5h (to now), 3: 4h (to now), 4: 2h, 0: 1h inside the range.
		SteeredHours:  14,
		BeforeLossPct: round((10 + 20 + 1) / 3.0), AfterLossPct: 1, BeforeRTTMs: round((50 + 70 + 20) / 3.0), AfterRTTMs: 30.667,
		Probes: 30, FailedProbes: 2, Prefixes: 3,
		// Active at now: 2 and 4 (no savings) and 3 (200).
		EstSavingsRate: 200,
		// 3: 200 × 4h / 730; 0: 73 × 1h / 730.
		EstSavingsAccrued: round(200*4.0/730 + 73*1.0/730),
	}
	if s != want {
		t.Fatalf("summary\n got %+v\nwant %+v", s, want)
	}
}

func TestImprovementsNewestFirst(t *testing.T) {
	rows := build(t, ReportImprovements).Rows.([]ImprovementRow)
	var ids []string
	for _, r := range rows {
		ids = append(ids, r.Prefix+"/"+r.Cause)
	}
	got := strings.Join(ids, ",")
	want := "203.0.113.0/24/commit,198.51.100.0/24/cost,192.0.2.0/24/performance,192.0.2.0/24/performance,198.51.100.0/24/cost"
	if got != want {
		t.Fatalf("order = %s", got)
	}
	if rows[0].BeforeLossPct != nil || !rows[0].End.IsZero() {
		t.Fatalf("commit row without measurements: %+v", rows[0])
	}
	if *rows[2].BeforeLossPct != 20 || *rows[2].AfterRTTMs != 40 || rows[2].Hours != 5 {
		t.Fatalf("row 2 = %+v", rows[2])
	}
	limited := build(t, ReportImprovements, func(q *Query) { q.Limit = 2 }).Rows.([]ImprovementRow)
	if len(limited) != 2 {
		t.Fatalf("limit: %d rows", len(limited))
	}
}

func TestCausesPerDay(t *testing.T) {
	rows := build(t, ReportCauses).Rows.([]CauseRow)
	want := []CauseRow{
		{Day: "2026-09-01", Performance: 1, Total: 1},
		{Day: "2026-09-02", Performance: 1, Commit: 1, Cost: 1, Total: 3},
	}
	if len(rows) != len(want) || rows[0] != want[0] || rows[1] != want[1] {
		t.Fatalf("causes = %+v", rows)
	}
}

func TestPerformanceBeforeAfter(t *testing.T) {
	rows := build(t, ReportPerformance).Rows.([]PerformanceRow)
	if len(rows) != 3 {
		t.Fatalf("rows = %+v", rows)
	}
	perf, cost, all := rows[0], rows[1], rows[2]
	if perf.Cause != "performance" || perf.Improvements != 2 || perf.BeforeLossPct != 15 || perf.AfterLossPct != 1 ||
		perf.LossReduced != 14 || perf.BeforeRTTMs != 60 || perf.AfterRTTMs != 35 || perf.RTTReducedMs != 25 {
		t.Fatalf("performance = %+v", perf)
	}
	if cost.Cause != "cost" || cost.Improvements != 1 || cost.RTTReducedMs != -2 {
		t.Fatalf("cost = %+v", cost)
	}
	if all.Cause != "all" || all.Improvements != 3 {
		t.Fatalf("all = %+v", all)
	}
}

func TestProviderEfficiency(t *testing.T) {
	rows := build(t, ReportProviders).Rows.([]ProviderRow)
	if len(rows) != 2 {
		t.Fatalf("rows = %+v", rows)
	}
	a, b := rows[0], rows[1]
	// transit-a: 14 probes, 2 failed; loss (80+4)/12 = 7; rtt 480/12 = 40.
	if a.Provider != "transit-a" || a.Probes != 14 || a.FailedPct != round(200.0/14) || a.AvgLossPct != 7 || a.AvgRTTMs != 40 ||
		a.AvgJitterMs != round(20.0/12) || a.ImprovementsTo != 1 || a.ImprovementsFrom != 3 || a.SteeredHours != 2 {
		t.Fatalf("transit-a = %+v", a)
	}
	// transit-b: 16 probes; onto it 1, 2, 3 (and 0's hour); off it 4.
	if b.Provider != "transit-b" || b.Probes != 16 || b.FailedPct != 0 || b.AvgLossPct != 0 || b.AvgRTTMs != 22.5 ||
		b.ImprovementsTo != 3 || b.ImprovementsFrom != 1 || b.SteeredHours != 12 {
		t.Fatalf("transit-b = %+v", b)
	}
}

func TestTopPrefixes(t *testing.T) {
	rows := build(t, ReportPrefixes).Rows.([]PrefixRow)
	if len(rows) != 3 || rows[0].Prefix != "192.0.2.0/24" || rows[0].Improvements != 2 || rows[0].OriginASN != 64500 || rows[0].Country != "NL" ||
		rows[0].AvgLossPct != round(80.0/18) {
		t.Fatalf("problems = %+v", rows)
	}
	// Equal improvement counts (1 each) break on loss: B has 1%, C 0%.
	if rows[1].Prefix != "198.51.100.0/24" || rows[2].Prefix != "203.0.113.0/24" {
		t.Fatalf("problems order = %+v", rows)
	}
	vol := build(t, ReportPrefixes, func(q *Query) { q.Sort = SortVolume; q.Limit = 1 }).Rows.([]PrefixRow)
	if len(vol) != 1 || vol[0].Prefix != "198.51.100.0/24" || vol[0].VolumeMbps != 100 {
		t.Fatalf("volume = %+v", vol)
	}
	loss := build(t, ReportPrefixes, func(q *Query) { q.Sort = SortLoss }).Rows.([]PrefixRow)
	if loss[0].Prefix != "192.0.2.0/24" || loss[2].Prefix != "203.0.113.0/24" {
		t.Fatalf("loss = %+v", loss)
	}
	if _, err := Build(seed(), Query{Name: ReportPrefixes, From: from, To: to, Sort: "bogus"}); err == nil {
		t.Fatal("bad sort accepted")
	}
}

func TestTopASNsAndCountries(t *testing.T) {
	asns := build(t, ReportASNs).Rows.([]GroupRow)
	if len(asns) != 2 || asns[0].Key != "64500" || asns[0].Prefixes != 2 || asns[0].Improvements != 3 || asns[0].VolumeMbps != 55 || asns[0].Probes != 26 {
		t.Fatalf("asns = %+v", asns)
	}
	if asns[1].Key != "64501" || asns[1].Improvements != 1 {
		t.Fatalf("asns[1] = %+v", asns[1])
	}
	cs := build(t, ReportCountries).Rows.([]GroupRow)
	// C has no country and is left out.
	if len(cs) != 2 || cs[0].Key != "NL" || cs[0].Improvements != 2 || cs[1].Key != "DE" {
		t.Fatalf("countries = %+v", cs)
	}
}

func TestProbesPerDay(t *testing.T) {
	rows := build(t, ReportProbes).Rows.([]ProbeDayRow)
	want := []ProbeDayRow{
		{Day: "2026-09-01", Probes: 20, Failed: 2, Prefixes: 1, AvgLossPct: round(80.0 / 18), AvgRTTMs: round(700.0 / 18)},
		{Day: "2026-09-02", Probes: 10, Prefixes: 2, AvgLossPct: 0.4, AvgRTTMs: 14},
	}
	if len(rows) != 2 || rows[0] != want[0] || rows[1] != want[1] {
		t.Fatalf("probes = %+v", rows)
	}
}

func TestSavings(t *testing.T) {
	rows := build(t, ReportSavings).Rows.([]SavingsRow)
	if len(rows) != 2 {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].Prefix != "198.51.100.0/24" || rows[0].EstSavings != 200 || rows[0].Hours != 4 || rows[0].Accrued != round(800.0/730) || rows[0].End.IsZero() {
		t.Fatalf("savings[0] = %+v", rows[0])
	}
	if rows[1].Hours != 1 || rows[1].Accrued != 0.1 {
		t.Fatalf("savings[1] = %+v", rows[1])
	}
}

func TestEmptyHistory(t *testing.T) {
	for _, r := range Reports {
		rep, err := Build(plugin.History{}, Query{Name: r.Name, From: from, To: to})
		if err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		b, _ := json.Marshal(rep)
		if strings.Contains(string(b), `"rows":null`) {
			t.Fatalf("%s: rows is null: %s", r.Name, b)
		}
		var buf bytes.Buffer
		if err := rep.CSV(&buf); err != nil || buf.Len() == 0 {
			t.Fatalf("%s: csv %q %v", r.Name, buf.String(), err)
		}
	}
	if _, err := Build(plugin.History{}, Query{Name: "nope", From: from, To: to}); err == nil {
		t.Fatal("unknown report accepted")
	}
}

func TestCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := build(t, ReportCauses).CSV(&buf); err != nil {
		t.Fatal(err)
	}
	want := "day,performance,commit,cost,total\n2026-09-01,1,0,0,1\n2026-09-02,1,1,1,3\n"
	if buf.String() != want {
		t.Fatalf("csv =\n%s", buf.String())
	}
	buf.Reset()
	if err := build(t, ReportImprovements, func(q *Query) { q.Limit = 1 }).CSV(&buf); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[1], "203.0.113.0/24,transit-a,transit-b,commit,") || !strings.Contains(lines[1], ",64500,") {
		t.Fatalf("improvements csv =\n%s", buf.String())
	}
}
