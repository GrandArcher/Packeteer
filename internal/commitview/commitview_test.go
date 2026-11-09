package commitview

import (
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var day0 = time.Date(2030, 1, 10, 0, 0, 0, 0, time.UTC)

// samples returns one sample every 5 minutes from start whose outbound
// rate is 1, 2, 3 ... Mbps and inbound is half of it.
func samples(start, periodStart time.Time, n int) []plugin.UsageSample {
	out := make([]plugin.UsageSample, n)
	for i := range out {
		mbps := float64(i + 1)
		out[i] = plugin.UsageSample{Provider: "transit-a", Host: "edge", Interface: "ether1",
			PeriodStart: periodStart, PeriodEnd: periodStart.AddDate(0, 1, 0),
			At: start.Add(time.Duration(i) * 5 * time.Minute), InBps: mbps * 5e5, OutBps: mbps * 1e6}
	}
	return out
}

func TestSeriesKeepsBusiestSampleAndRunning95th(t *testing.T) {
	s := samples(day0, day0.AddDate(0, 0, -9), 20)
	pts := Series(plugin.PercentileSeparate, s, day0, 30*time.Minute)
	if len(pts) != 4 {
		t.Fatalf("points = %+v", pts)
	}
	// Six samples per 30 minutes: the first point is samples 1-6, busiest 6.
	if pts[0].Mbps != 6 || pts[0].P95Mbps != 6 || pts[0].At != s[5].At {
		t.Fatalf("first point = %+v", pts[0])
	}
	// Nearest rank: ceil(0.95*20) = 19, the 95th of the first twenty.
	last := pts[len(pts)-1]
	if last.Mbps != 20 || last.P95Mbps != 19 || last.NewPeriod {
		t.Fatalf("last point = %+v", last)
	}
}

func TestSeriesModes(t *testing.T) {
	s := samples(day0, day0.AddDate(0, 0, -9), 20)
	// Inbound is half of outbound, so the larger direction is outbound too.
	// Swap the last five samples so inbound is larger there.
	for i := 15; i < 20; i++ {
		s[i].InBps, s[i].OutBps = s[i].OutBps, s[i].InBps
	}
	sep := Series(plugin.PercentileSeparate, s, day0, 2*time.Hour)
	greater := Series(plugin.PercentileGreater, s, day0, 2*time.Hour)
	gsep := Series(plugin.PercentileGreaterSeparate, s, day0, 2*time.Hour)
	if len(sep) != 1 || len(greater) != 1 || len(gsep) != 1 {
		t.Fatalf("points %d %d %d", len(sep), len(greater), len(gsep))
	}
	// separate follows the outbound direction only: its busiest sample is
	// sample 15 (15 Mbps out), not the 20 Mbps that came in.
	if sep[0].Mbps != 15 {
		t.Fatalf("separate busiest = %v", sep[0].Mbps)
	}
	// greater takes max(in, out) per sample; the busiest is 20.
	if greater[0].Mbps != 20 || greater[0].P95Mbps != 19 {
		t.Fatalf("greater = %+v", greater[0])
	}
	// greater_separate is the larger of the two directions' own 95ths.
	if gsep[0].Mbps != 20 || gsep[0].P95Mbps <= 0 {
		t.Fatalf("greater_separate = %+v", gsep[0])
	}
	in95, _ := plugin.Percentile95([]float64{.5, 1, 1.5, 2, 2.5, 3, 3.5, 4, 4.5, 5, 5.5, 6, 6.5, 7, 7.5, 16, 17, 18, 19, 20})
	out95, _ := plugin.Percentile95([]float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 8, 8.5, 9, 9.5, 10})
	if want := max(in95, out95); gsep[0].P95Mbps != want {
		t.Fatalf("greater_separate 95th = %v, want %v", gsep[0].P95Mbps, want)
	}
}

func TestSeriesPeriodRollResetsThe95th(t *testing.T) {
	start := day0.Add(-50 * time.Minute)
	periodA := day0.AddDate(0, -1, 0)
	a := samples(start, periodA, 10)
	b := samples(day0, day0, 4)
	for i := range b {
		b[i].OutBps = 2e6
	}
	pts := Series(plugin.PercentileSeparate, append(a, b...), start, 30*time.Minute)
	var rolled []Point
	for _, p := range pts {
		if p.NewPeriod {
			rolled = append(rolled, p)
		}
	}
	// The first drawn point starts its period; so does the first of period B.
	if len(rolled) != 2 || !rolled[1].At.Equal(b[3].At) {
		t.Fatalf("points = %+v", pts)
	}
	if got := pts[len(pts)-1]; got.P95Mbps != 2 || got.Mbps != 2 {
		t.Fatalf("new period carried the old samples: %+v", got)
	}
}

func TestSeriesEarlierSamplesOnlyFeedThe95th(t *testing.T) {
	s := samples(day0.Add(-100*time.Minute), day0.AddDate(0, 0, -9), 40)
	from := day0
	pts := Series(plugin.PercentileSeparate, s, from, time.Hour)
	for _, p := range pts {
		if p.At.Before(from) {
			t.Fatalf("point before from: %+v", p)
		}
	}
	first := pts[0]
	if first.NewPeriod {
		t.Fatalf("the period began before the range: %+v", first)
	}
	// 20 samples precede from and 12 fall in its first hour, so the first
	// point ends at sample 32 (32 Mbps) and the 95th of those 32 samples is
	// rank ceil(0.95*32) = 31.
	if first.Mbps != 32 || first.P95Mbps != 31 {
		t.Fatalf("first = %+v", first)
	}
	if got := Series(plugin.PercentileSeparate, nil, from, time.Hour); len(got) != 0 {
		t.Fatalf("no samples gave %+v", got)
	}
}

func TestMovesGroupByDirectionPeerAndBucket(t *testing.T) {
	from := day0
	row := func(prefix, prov, native, cause, mode string, off time.Duration) history.ImprovementRow {
		return history.ImprovementRow{Prefix: prefix, Provider: prov, Native: native, Cause: cause, Mode: mode, Start: from.Add(off)}
	}
	rows := []history.ImprovementRow{
		row("192.0.2.0/24", "transit-b", "transit-a", "commit", "inject", time.Minute),
		row("198.51.100.0/24", "transit-b", "transit-a", "commit", "inject", 20*time.Minute),
		row("203.0.113.0/24", "transit-b", "transit-a", "commit", "inject", 3*time.Hour),
		row("192.0.2.0/24", "transit-c", "transit-a", "commit", "observe", time.Minute),
		row("198.51.100.0/24", "transit-a", "transit-c", "commit", "observe", time.Minute),
		row("198.51.100.0/24", "transit-b", "transit-a", "performance", "inject", time.Minute),
		row("198.51.100.0/24", "transit-b", "transit-c", "commit", "inject", time.Minute),
		row("198.51.100.0/24", "transit-b", "transit-a", "commit", "inject", -time.Minute),
		row("192.0.2.0/24", "transit-b", "transit-a", "commit", "inject", 2*time.Minute),
	}
	got := Moves(rows, "transit-a", from, time.Hour)
	want := []Move{
		{At: from.Add(time.Minute), Direction: "off", Peer: "transit-b", Prefixes: 2, Announced: true},
		{At: from.Add(time.Minute), Direction: "off", Peer: "transit-c", Prefixes: 1},
		{At: from.Add(time.Minute), Direction: "onto", Peer: "transit-c", Prefixes: 1},
		{At: from.Add(3 * time.Hour), Direction: "off", Peer: "transit-b", Prefixes: 1, Announced: true},
	}
	if len(got) != len(want) {
		t.Fatalf("moves = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("move %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if m := Moves(rows, "transit-z", from, time.Hour); len(m) != 0 {
		t.Fatalf("unrelated provider got %+v", m)
	}
}
