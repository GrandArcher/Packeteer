package main

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/commitview"
	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/internal/provseries"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// The seed gives the report a point per day in every bucket the smoke
// test looks for, and nothing outside documentation prefixes.
func TestSeedFillsEveryBucket(t *testing.T) {
	now := time.Date(2026, 10, 10, 13, 0, 0, 0, time.UTC)
	b := seed(now)
	h := historyFrom(b)
	rep, err := history.Build(h, history.Query{Name: history.ReportTimeSeries, From: now.Add(-7 * 24 * time.Hour), To: now, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, r := range rep.Rows.([]history.TimeSeriesRow) {
		got[r.Bucket]++
	}
	for _, name := range history.Buckets {
		if got[name] != days {
			t.Errorf("bucket %s has %d days, want %d", name, got[name], days)
		}
	}
}

func historyFrom(b plugin.HistoryBatch) plugin.History {
	return plugin.History{Buckets: b.Buckets, Improvements: b.Improvements, Prefixes: b.Prefixes}
}

// The probes-by-ASN smoke step (#203) reads two rows a day: AS64496 with
// two prefixes and 400 probes, AS64497 with one and 200.
func TestSeedGivesProbesByASN(t *testing.T) {
	now := time.Date(2026, 10, 10, 13, 0, 0, 0, time.UTC)
	rep, err := history.Build(historyFrom(seed(now)), history.Query{Name: history.ReportProbeASNs, From: now.Add(-30 * 24 * time.Hour), To: now.Add(time.Hour), Now: now, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	rows := rep.Rows.([]history.ProbeASNRow)
	if len(rows) != 2*days || rows[0].Day != "2026-10-10" || rows[0].OriginASN != 64496 || rows[0].Prefixes != 2 || rows[0].Probes != 400 ||
		rows[1].OriginASN != 64497 || rows[1].Prefixes != 1 || rows[1].Probes != 200 {
		t.Fatalf("probe_asns = %+v", rows)
	}
}

// The commit seed covers the longest range of the page with samples for
// both providers, ends lab-a over its commit, keeps lab-b under, and holds
// the commit moves the markers need, one of them announced.
func TestCommitSeed(t *testing.T) {
	now := time.Date(2026, 10, 10, 13, 2, 0, 0, time.UTC)
	samples, b := commitSeed(now)
	if want := (commitDays*24*12 + 1) * 2; len(samples) != want {
		t.Fatalf("%d samples, want %d", len(samples), want)
	}
	byProvider := map[string][]plugin.RateSample{}
	for _, s := range samples {
		if !s.PeriodStart.Equal(time.Date(s.At.Year(), s.At.Month(), 1, 0, 0, 0, 0, time.UTC)) || !s.At.Before(s.PeriodEnd) {
			t.Fatalf("sample %s has period %s - %s", s.At, s.PeriodStart, s.PeriodEnd)
		}
		if s.At.After(now) {
			t.Fatalf("sample from the future: %s", s.At)
		}
		if s.PeriodStart.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) {
			byProvider[s.Provider] = append(byProvider[s.Provider], plugin.RateSample{In: s.InBps, Out: s.OutBps})
		}
	}
	a, _ := plugin.Percentile95(rates(byProvider["lab-a"]))
	c, _ := plugin.Percentile95(rates(byProvider["lab-b"]))
	if a/1e6 <= 100 || c/1e6 >= 200 {
		t.Fatalf("open period 95th: lab-a %.1f Mbps (commit 100), lab-b %.1f Mbps (commit 200)", a/1e6, c/1e6)
	}
	announced := 0
	for _, r := range b.Improvements {
		if r.Cause != plugin.CauseCommit || r.Native != "lab-a" || r.Provider != "lab-b" {
			t.Fatalf("record = %+v", r)
		}
		if r.Mode == "inject" {
			announced++
		}
	}
	if len(b.Improvements) != 4 || announced != 1 {
		t.Fatalf("%d improvements, %d announced", len(b.Improvements), announced)
	}
}

// The smoke test runs at any UTC time: on the 1st just after midnight the
// open period holds only night samples and lab-a must still be over its
// commit, and the 30-day range must keep the two observe moves apart.
func TestCommitSeedAnyHour(t *testing.T) {
	for h := range 24 {
		now := time.Date(2026, 11, 1, h, 5, 0, 0, time.UTC)
		samples, b := commitSeed(now)
		var open []float64
		for _, s := range samples {
			if s.Provider == "lab-a" && s.PeriodStart.Equal(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) {
				open = append(open, s.OutBps)
			}
		}
		if p, ok := plugin.Percentile95(open); !ok || p/1e6 <= 100 {
			t.Fatalf("%s: open period 95th of lab-a %.1f Mbps from %d samples, want over 100", now, p/1e6, len(open))
		}
		rows := make([]history.ImprovementRow, 0, len(b.Improvements))
		for _, r := range b.Improvements {
			rows = append(rows, history.ImprovementRow{Prefix: r.Prefix.String(), Provider: r.Provider, Native: r.Native, Cause: r.Cause, Mode: r.Mode, Start: r.Start})
		}
		for days, want := range map[int][]int{1: {}, 7: {1, 2, 1}, 30: {1, 2, 1}} {
			from := now.Add(-time.Duration(days) * 24 * time.Hour)
			var got []int
			for _, m := range commitview.Moves(rows, "lab-b", from, commitview.Steps[days]) {
				if m.Direction != "onto" {
					t.Fatalf("%s: move %+v", now, m)
				}
				got = append(got, m.Prefixes)
			}
			if !slices.Equal(got, want) {
				t.Fatalf("%s, %d days: prefixes per move %v, want %v", now, days, got, want)
			}
		}
	}
}

func rates(in []plugin.RateSample) []float64 {
	out := make([]float64, len(in))
	for i, r := range in {
		out[i] = r.Out
	}
	return out
}

type sampleStore []plugin.ProviderSample

func (s *sampleStore) PutProviderSamples(context.Context, []plugin.ProviderSample) error { return nil }

func (s *sampleStore) ProviderSamples(_ context.Context, from, to time.Time) ([]plugin.ProviderSample, error) {
	var out []plugin.ProviderSample
	for _, sm := range *s {
		if !sm.Slot.Before(from) && sm.Slot.Before(to) {
			out = append(out, sm)
		}
	}
	return out, nil
}

// The provider seed fills the 24 hours up to the current slot for both
// providers, and the series the controller builds from it gives the 15-minute
// figures the smoke test asserts: lab-a 120 ms, 8% loss, 12 ms jitter and
// lab-b 40 ms, no loss, 4 ms jitter.
func TestProviderSeedGivesTheSmokeFigures(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 10, 13, 2, 0, 0, time.UTC)
	rows := providerSeed(now)
	if want := (24*12 + 1) * 2; len(rows) != want {
		t.Fatalf("%d samples, want %d", len(rows), want)
	}
	for _, r := range rows {
		if r.Slot.After(now) || !r.Slot.Equal(r.Slot.Truncate(5*time.Minute)) {
			t.Fatalf("sample slot %s is in the future or off the grid", r.Slot)
		}
	}
	series := provseries.New(func() time.Time { return now })
	store := sampleStore(rows)
	if err := series.Restore(ctx, &store); err != nil {
		t.Fatal(err)
	}
	want := map[string][3]float64{"lab-a": {120, 8, 12}, "lab-b": {40, 0, 4}}
	stats := series.Stats()
	if len(stats) != 2 {
		t.Fatalf("stats = %+v", stats)
	}
	for _, st := range stats {
		w := want[st.Provider]
		if got := st.Last15m; !got.HasRTT || got.RTTMs != w[0] || got.LossPct != w[1] || got.JitterMs != w[2] {
			t.Errorf("%s 15 min = %+v, want %v", st.Provider, got, w)
		}
		if st.Last24h.Slots != 288+1 || len(st.Points) < 24 {
			t.Errorf("%s 24 h = %+v with %d points", st.Provider, st.Last24h, len(st.Points))
		}
	}
}
