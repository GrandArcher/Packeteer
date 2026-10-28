package history

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var (
	scPfx1   = netip.MustParsePrefix("198.51.100.0/24")
	scPfx2   = netip.MustParsePrefix("203.0.113.0/24")
	scPfx3   = netip.MustParsePrefix("192.0.2.0/24")
	scNoASN  = netip.MustParsePrefix("2001:db8::/32")
	scDay1   = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	scDay2   = scDay1.Add(24 * time.Hour)
	scBefore = scDay1.Add(-24 * time.Hour)
)

// scorecardSeed has AS64500 on two prefixes (100 and 300 Mbps) measured by
// three providers, and AS64501 on one prefix with no known volume.
func scorecardSeed() plugin.History {
	bk := func(day time.Time, p netip.Prefix, provider string, measured, failed int, loss, rtt, jit float64) plugin.ProbeBucket {
		return plugin.ProbeBucket{Day: day, Prefix: p, Provider: provider, Probes: measured + failed, Measured: measured, Failed: failed,
			LossSum: loss * float64(measured), RTTSumMs: rtt * float64(measured), JitterSum: jit * float64(measured)}
	}
	return plugin.History{
		Buckets: []plugin.ProbeBucket{
			// transit-a: a bad day on the small prefix, and 40 ms on the big one.
			bk(scDay1, scPfx1, "transit-a", 10, 0, 0, 20, 1),
			bk(scDay2, scPfx1, "transit-a", 10, 0, 10, 30, 2),
			bk(scDay1, scPfx2, "transit-a", 10, 0, 0, 40, 3),
			bk(scDay2, scPfx2, "transit-a", 10, 0, 0, 40, 3),
			// transit-b: clean, 25 ms.
			bk(scDay1, scPfx1, "transit-b", 10, 0, 0, 25, 1),
			bk(scDay2, scPfx1, "transit-b", 10, 0, 0, 25, 1),
			bk(scDay1, scPfx2, "transit-b", 10, 0, 0, 25, 1),
			bk(scDay2, scPfx2, "transit-b", 10, 0, 0, 25, 1),
			// transit-c never answered.
			bk(scDay1, scPfx1, "transit-c", 0, 10, 0, 0, 0),
			// AS64501 has no volume: equal weights, and a tie.
			bk(scDay1, scPfx3, "transit-a", 10, 0, 0, 20, 1),
			bk(scDay1, scPfx3, "transit-b", 10, 0, 0, 20, 1),
			// No learned origin, and outside the range: both left out.
			bk(scDay1, scNoASN, "transit-a", 10, 0, 50, 90, 9),
			bk(scBefore, scPfx1, "transit-a", 10, 0, 90, 900, 90),
		},
		Prefixes: []plugin.PrefixInfo{
			{Prefix: scPfx1, OriginASN: 64500, VolumeMbps: 100},
			{Prefix: scPfx2, OriginASN: 64500, VolumeMbps: 300},
			{Prefix: scPfx3, OriginASN: 64501},
		},
	}
}

func scorecard(t *testing.T, mod ...func(*Query)) Report {
	t.Helper()
	q := Query{Name: ReportScorecard, From: scDay1, To: scDay1.Add(48 * time.Hour)}
	for _, m := range mod {
		m(&q)
	}
	r, err := Build(scorecardSeed(), q)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func fv(v float64) *float64 { return &v }

func eq(a, b *float64) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }

func TestScorecardPercentilesWeightedByVolume(t *testing.T) {
	rows := scorecard(t).Rows.([]ScorecardRow)
	if len(rows) != 5 {
		t.Fatalf("%d rows: %+v", len(rows), rows)
	}
	want := []ScorecardRow{
		{Provider: "transit-b", OriginASN: 64500, Rank: 1, Prefixes: 2, Probes: 40, VolumeMbps: 400, Weighting: WeightFlow,
			LossP50Pct: fv(0), LossP95Pct: fv(0), RTTP50Ms: fv(25), RTTP95Ms: fv(25), JitP50Ms: fv(1), JitP95Ms: fv(1)},
		// The RTT samples are 20 and 30 ms at 100 Mbps and 40 ms twice at
		// 300 Mbps: the weighted median is 40 ms where an unweighted one
		// is 30 ms. The one lossy day (10%) is the 95th percentile only.
		{Provider: "transit-a", OriginASN: 64500, Rank: 2, Prefixes: 2, Probes: 40, VolumeMbps: 400, Weighting: WeightFlow,
			LossP50Pct: fv(0), LossP95Pct: fv(10), RTTP50Ms: fv(40), RTTP95Ms: fv(40), JitP50Ms: fv(3), JitP95Ms: fv(3)},
		{Provider: "transit-c", OriginASN: 64500, Rank: 3, Prefixes: 1, Probes: 10, FailedPct: 100, VolumeMbps: 100, Weighting: WeightFlow,
			LossP50Pct: fv(100), LossP95Pct: fv(100)},
		// Tied on every ranked figure: the same rank.
		{Provider: "transit-a", OriginASN: 64501, Rank: 1, Prefixes: 1, Probes: 10, Weighting: WeightEqual,
			LossP50Pct: fv(0), LossP95Pct: fv(0), RTTP50Ms: fv(20), RTTP95Ms: fv(20), JitP50Ms: fv(1), JitP95Ms: fv(1)},
		{Provider: "transit-b", OriginASN: 64501, Rank: 1, Prefixes: 1, Probes: 10, Weighting: WeightEqual,
			LossP50Pct: fv(0), LossP95Pct: fv(0), RTTP50Ms: fv(20), RTTP95Ms: fv(20), JitP50Ms: fv(1), JitP95Ms: fv(1)},
	}
	for i, w := range want {
		g := rows[i]
		if g.Provider != w.Provider || g.OriginASN != w.OriginASN || g.Rank != w.Rank || g.Prefixes != w.Prefixes || g.Probes != w.Probes ||
			g.FailedPct != w.FailedPct || g.VolumeMbps != w.VolumeMbps || g.Weighting != w.Weighting ||
			!eq(g.LossP50Pct, w.LossP50Pct) || !eq(g.LossP95Pct, w.LossP95Pct) || !eq(g.RTTP50Ms, w.RTTP50Ms) ||
			!eq(g.RTTP95Ms, w.RTTP95Ms) || !eq(g.JitP50Ms, w.JitP50Ms) || !eq(g.JitP95Ms, w.JitP95Ms) {
			t.Errorf("row %d\n got %+v\nwant %+v", i, g, w)
		}
	}
}

func TestScorecardWeightedPercentile(t *testing.T) {
	s := []sample{{v: 10, w: 1}, {v: 20, w: 1}, {v: 30, w: 8}}
	for p, want := range map[float64]float64{10: 10, 20: 20, 50: 30, 95: 30} {
		if got := weightedPercentile(s, p); got == nil || *got != want {
			t.Errorf("p%v = %v, want %v", p, got, want)
		}
	}
	if weightedPercentile(nil, 50) != nil || weightedPercentile([]sample{{v: 5}}, 50) != nil {
		t.Error("no weight must give no percentile")
	}
}

func TestScorecardFiltersSortAndCut(t *testing.T) {
	only := scorecard(t, func(q *Query) { q.ASN = 64501 }).Rows.([]ScorecardRow)
	if len(only) != 2 || only[0].OriginASN != 64501 {
		t.Fatalf("asn filter = %+v", only)
	}
	// A prefix filter ranks the providers on that prefix alone.
	p2 := scorecard(t, func(q *Query) { q.Prefix = scPfx2 }).Rows.([]ScorecardRow)
	if len(p2) != 2 || p2[0].Provider != "transit-b" || p2[1].Provider != "transit-a" || *p2[1].LossP95Pct != 0 || p2[1].Rank != 2 {
		t.Fatalf("prefix filter = %+v", p2)
	}
	if err := (Query{Name: ReportScorecard, Provider: "transit-a"}).Validate(); err == nil {
		t.Fatal("a provider filter would rank a subset and must be refused")
	}
	// Sorting puts a row with no RTT last in either direction, and the
	// sort happens before the cut.
	for _, order := range []string{OrderAsc, OrderDesc} {
		rep := scorecard(t, func(q *Query) { q.Sort = "rtt_p50_ms"; q.Order = order })
		rows := rep.Rows.([]ScorecardRow)
		if rows[len(rows)-1].Provider != "transit-c" || rows[len(rows)-1].RTTP50Ms != nil {
			t.Fatalf("%s: row with no RTT is not last: %+v", order, rows)
		}
	}
	rep := scorecard(t, func(q *Query) { q.Sort = "loss_p95_pct"; q.Order = OrderDesc; q.Limit = 1 })
	cut := rep.Rows.([]ScorecardRow)
	if rep.Total != 5 || len(cut) != 1 || cut[0].Provider != "transit-c" {
		t.Fatalf("sorted and cut = %+v total %d", cut, rep.Total)
	}
}

func TestScorecardCSVLeavesAbsentFiguresEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := scorecard(t).CSV(&buf); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 6 || lines[0] != "provider,origin_asn,rank,prefixes,probes,failed_pct,volume_mbps,weighting,loss_p50_pct,loss_p95_pct,rtt_p50_ms,rtt_p95_ms,jitter_p50_ms,jitter_p95_ms" {
		t.Fatalf("csv = %q", buf.String())
	}
	if lines[1] != "transit-b,64500,1,2,40,0,400,flow,0,0,25,25,1,1" || lines[3] != "transit-c,64500,3,1,10,100,100,flow,100,100,,,," {
		t.Fatalf("csv rows = %q", lines)
	}
}
