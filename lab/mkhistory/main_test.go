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
