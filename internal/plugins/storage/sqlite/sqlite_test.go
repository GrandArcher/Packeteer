package sqlite

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func newStore(t *testing.T, yaml string) *Store {
	t.Helper()
	c, err := plugin.ConfigFromYAML(yaml)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(c, plugin.Env{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestRegistered(t *testing.T) {
	if !plugin.Storages.Has(TypeName) {
		t.Fatal("sqlite storage not registered")
	}
}

func TestConfig(t *testing.T) {
	s := newStore(t, "")
	if s.Path() != DefaultPath || s.retention != DefaultRetention {
		t.Fatalf("defaults: %s %s", s.Path(), s.retention)
	}
	for _, bad := range []string{
		"path: relative.db",
		"retention: 1h",
		"retention: 100000h",
		"nope: 1",
	} {
		c, _ := plugin.ConfigFromYAML(bad)
		if _, err := New(c, plugin.Env{}); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

var (
	day  = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	pfxA = netip.MustParsePrefix("192.0.2.0/24")
	pfxB = netip.MustParsePrefix("198.51.100.0/24")
)

// TestSurvivesRestart writes, closes, and opens a second store on the same
// file: the path a mounted /var/lib/packeteer volume keeps across a
// container restart.
func TestSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sub", "packeteer.db")
	cfg := "path: " + path
	s := newStore(t, cfg)
	s.now = func() time.Time { return day.Add(48 * time.Hour) }
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	open := plugin.ImprovementRecord{
		ID: "a", Prefix: pfxA, Provider: "transit-b", Native: "transit-a", Cause: plugin.CausePerformance,
		Reason: "loss", Mode: "observe", Start: day.Add(time.Hour), HasBefore: true, BeforeLoss: 10, BeforeRTT: 40,
		HasAfter: true, AfterLoss: 0, AfterRTT: 30, OriginASN: 64500, Country: "NL", CostDelta: 1.5, EstSavings: 15, VolumeMbps: 10,
	}
	err := s.Write(ctx, plugin.HistoryBatch{
		Buckets: []plugin.ProbeBucket{
			{Day: day, Prefix: pfxA, Provider: "transit-a", Probes: 2, Measured: 2, LossSum: 20, RTTSumMs: 80, JitterSum: 2},
			{Day: day, Prefix: pfxB, Provider: "transit-a", Probes: 1, Failed: 1},
		},
		Improvements: []plugin.ImprovementRecord{open},
		Prefixes:     []plugin.PrefixInfo{{Prefix: pfxA, OriginASN: 64500, Country: "NL", VolumeMbps: 10, Updated: day}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Buckets add; improvements replace by ID.
	closed := open
	closed.End, closed.EndReason = day.Add(2*time.Hour), "ttl expired"
	err = s.Write(ctx, plugin.HistoryBatch{
		Buckets:      []plugin.ProbeBucket{{Day: day, Prefix: pfxA, Provider: "transit-a", Probes: 1, Measured: 1, LossSum: 5, RTTSumMs: 30, JitterSum: 1}},
		Improvements: []plugin.ImprovementRecord{closed, {ID: "b", Prefix: pfxB, Provider: "transit-a", Native: "transit-b", Start: day.Add(3 * time.Hour)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Stop(ctx); err != nil {
		t.Fatal(err)
	}

	s2 := newStore(t, cfg)
	s2.now = s.now
	if err := s2.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s2.Stop(ctx)
	h, err := s2.Read(ctx, plugin.HistoryQuery{From: day, To: day.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Buckets) != 2 {
		t.Fatalf("buckets = %+v", h.Buckets)
	}
	got := h.Buckets[0]
	if got.Prefix != pfxA || got.Probes != 3 || got.Measured != 3 || got.LossSum != 25 || got.RTTSumMs != 110 || got.JitterSum != 3 || !got.Day.Equal(day) {
		t.Fatalf("merged bucket = %+v", got)
	}
	if len(h.Improvements) != 2 {
		t.Fatalf("improvements = %+v", h.Improvements)
	}
	if r := h.Improvements[0]; r.ID != "a" || !r.End.Equal(closed.End) || r.EndReason != "ttl expired" || !r.HasBefore || r.BeforeLoss != 10 ||
		r.AfterRTT != 30 || r.OriginASN != 64500 || r.Country != "NL" || r.EstSavings != 15 || r.Prefix != pfxA {
		t.Fatalf("improvement a = %+v", r)
	}
	if len(h.Prefixes) != 1 || h.Prefixes[0].OriginASN != 64500 || h.Prefixes[0].VolumeMbps != 10 {
		t.Fatalf("prefixes = %+v", h.Prefixes)
	}
	openOnly, err := s2.Read(ctx, plugin.HistoryQuery{OpenOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(openOnly.Improvements) != 1 || openOnly.Improvements[0].ID != "b" || len(openOnly.Buckets) != 0 {
		t.Fatalf("open only = %+v", openOnly)
	}
	// Outside the range: nothing.
	later, err := s2.Read(ctx, plugin.HistoryQuery{From: day.Add(48 * time.Hour), To: day.Add(72 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(later.Buckets) != 0 || len(later.Improvements) != 1 { // b is still open
		t.Fatalf("later = %+v", later)
	}
}

func TestPrune(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, "path: "+filepath.Join(t.TempDir(), "p.db")+"\nretention: 48h")
	now := day.Add(10 * 24 * time.Hour)
	s.now = func() time.Time { return now }
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	err := s.Write(ctx, plugin.HistoryBatch{
		Buckets: []plugin.ProbeBucket{
			{Day: day, Prefix: pfxA, Provider: "transit-a", Probes: 1},
			{Day: now.Truncate(24 * time.Hour), Prefix: pfxA, Provider: "transit-a", Probes: 1},
		},
		Improvements: []plugin.ImprovementRecord{
			{ID: "old", Prefix: pfxA, Start: day, End: day.Add(time.Hour)},
			{ID: "open", Prefix: pfxB, Start: day},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.prune(ctx); err != nil {
		t.Fatal(err)
	}
	h, err := s.Read(ctx, plugin.HistoryQuery{From: time.Unix(0, 0), To: now.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Buckets) != 1 || len(h.Improvements) != 1 || h.Improvements[0].ID != "open" {
		t.Fatalf("after prune: %+v", h)
	}
}

func TestNotStarted(t *testing.T) {
	s := newStore(t, "")
	if err := s.Write(context.Background(), plugin.HistoryBatch{}); err == nil || !strings.Contains(err.Error(), "not started") {
		t.Fatalf("Write before Start: %v", err)
	}
	if err := s.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestReadIncludesWholeFirstDay(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, "path: "+filepath.Join(t.TempDir(), "d.db"))
	s.now = func() time.Time { return day }
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	if err := s.Write(ctx, plugin.HistoryBatch{Buckets: []plugin.ProbeBucket{{Day: day, Prefix: pfxA, Provider: "transit-a", Probes: 1}}}); err != nil {
		t.Fatal(err)
	}
	h, err := s.Read(ctx, plugin.HistoryQuery{From: day.Add(13 * time.Hour), To: day.Add(20 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Buckets) != 1 {
		t.Fatalf("mid-day range dropped the day's rollup: %+v", h.Buckets)
	}
}
