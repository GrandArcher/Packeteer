package sqlite

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestUsageSamplePruneKeepsOpenPeriod(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, "path: "+filepath.Join(t.TempDir(), "p.db")+"\nretention: 48h")
	// cutoff = March 17 00:00 minus 48h = March 15 00:00.
	now := time.Date(2026, 3, 17, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)

	closed := plugin.UsageSample{
		Provider: "transit-a", Host: "edge", Interface: "ether1",
		PeriodStart: time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC),
		PeriodEnd:   time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC),
		At:          time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC),
		InBps:       5e6, OutBps: 1e6,
	}
	// Ended a day ago: still inside retention, kept for a report.
	recent := closed
	recent.PeriodStart = time.Date(2026, 2, 16, 0, 0, 0, 0, time.UTC)
	recent.PeriodEnd = time.Date(2026, 3, 16, 0, 0, 0, 0, time.UTC)
	recent.At = time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	recent.Interface = "ether2"
	// Open period ends in April. An old timestamp inside it must stay,
	// or a short retention would change the live 95th after a restart.
	open := plugin.UsageSample{
		Provider: "transit-a", Host: "edge", Interface: "ether1",
		PeriodStart: time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC),
		PeriodEnd:   time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC),
		At:          time.Date(2026, 3, 16, 1, 0, 0, 0, time.UTC),
		InBps:       2e6, OutBps: 2e6,
	}
	if err := s.PutUsageSamples(ctx, []plugin.UsageSample{closed, recent, open}); err != nil {
		t.Fatal(err)
	}
	if err := s.prune(ctx); err != nil {
		t.Fatal(err)
	}
	q := plugin.UsageSampleQuery{Provider: "transit-a", Host: "edge", Interface: "ether1", From: time.Unix(0, 0).UTC(), To: now.Add(60 * 24 * time.Hour)}
	rows, err := s.UsageSamples(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].InBps != 2e6 || !rows[0].At.Equal(open.At) {
		t.Fatalf("ether1 after prune = %+v", rows)
	}
	q.Interface = "ether2"
	rows, err = s.UsageSamples(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || !rows[0].PeriodEnd.Equal(recent.PeriodEnd) {
		t.Fatalf("recent closed period = %+v", rows)
	}
}

func TestUsageSampleTrimAndLimit(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, "path: "+filepath.Join(t.TempDir(), "p.db"))
	s.now = func() time.Time { return day }
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	var batch []plugin.UsageSample
	for i := 1; i <= 5; i++ {
		batch = append(batch, plugin.UsageSample{
			Provider: "transit-a", Host: "edge", Interface: "ether1",
			PeriodStart: start, PeriodEnd: end,
			At:    start.Add(time.Duration(i) * time.Hour),
			InBps: float64(i) * 1e6, OutBps: float64(i) * 1e6,
		})
	}
	if err := s.PutUsageSamples(ctx, batch); err != nil {
		t.Fatal(err)
	}
	// Keep the newest three: hours 3, 4, 5. Hour 3 is the oldest kept.
	if err := s.TrimUsageSamples(ctx, "transit-a", "edge", "ether1", start, end, start.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	rows, err := s.UsageSamples(ctx, plugin.UsageSampleQuery{
		Provider: "transit-a", Host: "edge", Interface: "ether1", From: start, To: end,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[0].InBps != 3e6 || rows[2].InBps != 5e6 {
		t.Fatalf("trimmed = %+v", rows)
	}
	limited, err := s.UsageSamples(ctx, plugin.UsageSampleQuery{
		Provider: "transit-a", Host: "edge", Interface: "ether1", From: start, To: end, Limit: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(limited) != 2 || limited[0].InBps != 4e6 || limited[1].InBps != 5e6 {
		t.Fatalf("limit = %+v", limited)
	}
	// A sample in another period is not trimmed by the open period.
	other := batch[0]
	other.At = start.Add(-24 * time.Hour)
	other.PeriodStart = start.AddDate(0, -1, 0)
	other.PeriodEnd = start
	if err := s.PutUsageSamples(ctx, []plugin.UsageSample{other}); err != nil {
		t.Fatal(err)
	}
	if err := s.TrimUsageSamples(ctx, "transit-a", "edge", "ether1", start, end, start.Add(4*time.Hour)); err != nil {
		t.Fatal(err)
	}
	prev, err := s.UsageSamples(ctx, plugin.UsageSampleQuery{
		Provider: "transit-a", Host: "edge", Interface: "ether1",
		From: other.PeriodStart, To: other.PeriodEnd,
	})
	if err != nil || len(prev) != 1 {
		t.Fatalf("closed period trimmed: %+v %v", prev, err)
	}
}

func TestUsageSampleRejects(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, "path: "+filepath.Join(t.TempDir(), "p.db"))
	if _, err := s.UsageSamples(ctx, plugin.UsageSampleQuery{Provider: "transit-a"}); err == nil || !strings.Contains(err.Error(), "not started") {
		t.Fatalf("before start: %v", err)
	}
	s.now = func() time.Time { return day }
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	if err := s.PutUsageSamples(ctx, []plugin.UsageSample{{Provider: "transit-a"}}); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("invalid sample: %v", err)
	}
	if _, err := s.UsageSamples(ctx, plugin.UsageSampleQuery{}); err == nil || !strings.Contains(err.Error(), "provider") {
		t.Fatalf("empty provider: %v", err)
	}
	if _, err := s.UsageSamples(ctx, plugin.UsageSampleQuery{Provider: "transit-a", Limit: -1}); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("limit: %v", err)
	}
}
