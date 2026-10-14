package main

import (
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/history"
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
	return plugin.History{Buckets: b.Buckets, Improvements: b.Improvements}
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

func rates(in []plugin.RateSample) []float64 {
	out := make([]float64, len(in))
	for i, r := range in {
		out[i] = r.Out
	}
	return out
}
