package history

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/storage/sqlite"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var (
	pfxA = netip.MustParsePrefix("192.0.2.0/24")
	pfxB = netip.MustParsePrefix("198.51.100.0/24")
	pfxC = netip.MustParsePrefix("203.0.113.0/24")
)

// memStore is an in-memory plugin.Storage with an injectable write error.
type memStore struct {
	plugin.Base
	mu     sync.Mutex
	fail   error
	writes int
	h      plugin.History
}

func (m *memStore) Write(_ context.Context, b plugin.HistoryBatch) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	m.writes++
	for _, k := range b.Buckets {
		merged := false
		for i := range m.h.Buckets {
			c := &m.h.Buckets[i]
			if c.Day.Equal(k.Day) && c.Prefix == k.Prefix && c.Provider == k.Provider {
				c.Probes += k.Probes
				c.Failed += k.Failed
				c.Measured += k.Measured
				c.LossSum += k.LossSum
				c.RTTSumMs += k.RTTSumMs
				c.JitterSum += k.JitterSum
				merged = true
			}
		}
		if !merged {
			m.h.Buckets = append(m.h.Buckets, k)
		}
	}
	for _, r := range b.Improvements {
		i := slices.IndexFunc(m.h.Improvements, func(x plugin.ImprovementRecord) bool { return x.ID == r.ID })
		if i >= 0 {
			m.h.Improvements[i] = r
		} else {
			m.h.Improvements = append(m.h.Improvements, r)
		}
	}
	for _, p := range b.Prefixes {
		i := slices.IndexFunc(m.h.Prefixes, func(x plugin.PrefixInfo) bool { return x.Prefix == p.Prefix })
		if i >= 0 {
			m.h.Prefixes[i] = p
		} else {
			m.h.Prefixes = append(m.h.Prefixes, p)
		}
	}
	return nil
}

func (m *memStore) Read(_ context.Context, q plugin.HistoryQuery) (plugin.History, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out plugin.History
	for _, r := range m.h.Improvements {
		if q.OpenOnly {
			if r.End.IsZero() {
				out.Improvements = append(out.Improvements, r)
			}
			continue
		}
		if r.Start.Before(q.To) && (r.End.IsZero() || !r.End.Before(q.From)) {
			out.Improvements = append(out.Improvements, r)
		}
	}
	if q.OpenOnly {
		return out, nil
	}
	for _, b := range m.h.Buckets {
		if !b.Day.Before(q.From.UTC().Truncate(24*time.Hour)) && b.Day.Before(q.To) {
			out.Buckets = append(out.Buckets, b)
		}
	}
	out.Prefixes = slices.Clone(m.h.Prefixes)
	return out, nil
}

var t0 = time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

func result(p netip.Prefix, provider string, loss float64, rtt time.Duration, at time.Time) probe.Result {
	return probe.Result{Provider: provider, Prefix: p, Stats: probe.Stats{Sent: 10, Received: 10, LossPct: loss, RTTAvg: rtt, Jitter: time.Millisecond}, Time: at}
}

func newRecorder(store plugin.Storage, clock *time.Time) *Recorder {
	return New(Options{
		Store: store, Mode: "observe", FlushEvery: time.Hour,
		Now: func() time.Time { return *clock },
		Describe: func(p netip.Prefix) (uint32, string) {
			if p == pfxA {
				return 64500, "NL"
			}
			return 0, ""
		},
		Volumes: func(context.Context) map[netip.Prefix]float64 { return map[netip.Prefix]float64{pfxA: 12.5} },
	})
}

func TestRecorderLifecycle(t *testing.T) {
	ctx := context.Background()
	clock := t0
	store := &memStore{}
	// A record the previous process left open.
	_ = store.Write(ctx, plugin.HistoryBatch{Improvements: []plugin.ImprovementRecord{{ID: "stale", Prefix: pfxB, Start: t0.Add(-48 * time.Hour)}}})
	rec := newRecorder(store, &clock)
	if err := rec.Start(ctx); err != nil {
		t.Fatal(err)
	}
	h, _ := store.Read(ctx, plugin.HistoryQuery{OpenOnly: true})
	if len(h.Improvements) != 0 {
		t.Fatalf("stale record still open: %+v", h.Improvements)
	}

	results := []probe.Result{
		result(pfxA, "transit-a", 20, 50*time.Millisecond, t0),
		result(pfxA, "transit-b", 0, 30*time.Millisecond, t0),
	}
	for _, r := range results {
		rec.Probe(r)
	}
	rec.Probe(probe.Result{Provider: "transit-a", Prefix: pfxA, Err: "source down", Time: t0})

	imp := policy.Improvement{Prefix: pfxA, Provider: "transit-b", Native: "transit-a", Reason: "loss 20% -> 0%"}
	rec.Decision(t0, []policy.Change{{Action: policy.ActionImprove, New: imp}}, results)

	// Unflushed rows are already in reports.
	rep, err := rec.Report(ctx, Query{Name: ReportSummary, From: t0.Truncate(24 * time.Hour), To: t0.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	s := rep.Rows.([]SummaryRow)[0]
	if s.Improvements != 1 || s.Active != 1 || s.Probes != 3 || s.FailedProbes != 1 || s.BeforeLossPct != 20 || s.AfterRTTMs != 30 {
		t.Fatalf("summary before flush = %+v", s)
	}

	// A failed write keeps the rows.
	store.fail = errors.New("disk full")
	if err := rec.Flush(ctx); err == nil {
		t.Fatal("flush error not returned")
	}
	store.fail = nil
	if err := rec.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if len(store.h.Buckets) != 2 || store.h.Buckets[0].Probes+store.h.Buckets[1].Probes != 3 {
		t.Fatalf("buckets after requeue = %+v", store.h.Buckets)
	}
	if len(store.h.Prefixes) != 1 || store.h.Prefixes[0].OriginASN != 64500 || store.h.Prefixes[0].VolumeMbps != 12.5 {
		t.Fatalf("prefixes = %+v", store.h.Prefixes)
	}

	// Switch ends one record and starts another; retire ends it.
	clock = t0.Add(10 * time.Minute)
	sw := imp
	sw.Provider = "transit-c"
	rec.Decision(clock, []policy.Change{{Action: policy.ActionSwitch, Old: imp, New: sw}}, results)
	clock = t0.Add(20 * time.Minute)
	old := sw
	old.Reason = "ttl expired"
	rec.Decision(clock, []policy.Change{{Action: policy.ActionRetire, Old: old}}, results)
	// And a second improvement that is still open at shutdown.
	rec.Decision(clock, []policy.Change{{Action: policy.ActionImprove, New: policy.Improvement{Prefix: pfxC, Provider: "transit-a", Native: "transit-b", Cause: plugin.CauseCommit}}}, nil)
	clock = t0.Add(30 * time.Minute)
	if err := rec.Close(ctx); err != nil {
		t.Fatal(err)
	}

	byPrefix := map[string][]plugin.ImprovementRecord{}
	for _, r := range store.h.Improvements {
		byPrefix[r.Prefix.String()+"/"+r.Provider] = append(byPrefix[r.Prefix.String()+"/"+r.Provider], r)
	}
	first := byPrefix["192.0.2.0/24/transit-b"]
	if len(first) != 1 || first[0].EndReason != "switched to transit-c" || !first[0].End.Equal(t0.Add(10*time.Minute)) ||
		first[0].Cause != plugin.CausePerformance || first[0].Mode != "observe" || first[0].OriginASN != 64500 || first[0].Country != "NL" {
		t.Fatalf("first = %+v", first)
	}
	second := byPrefix["192.0.2.0/24/transit-c"]
	if len(second) != 1 || second[0].EndReason != "ttl expired" || second[0].HasAfter {
		t.Fatalf("second = %+v", second)
	}
	third := byPrefix["203.0.113.0/24/transit-a"]
	if len(third) != 1 || third[0].EndReason != EndShutdown || !third[0].End.Equal(t0.Add(30*time.Minute)) || third[0].HasBefore {
		t.Fatalf("third = %+v", third)
	}
}

// TestRecorderSurvivesRestart runs the recorder on the sqlite plugin, stops
// both, and reads the reports from a fresh process on the same file: what a
// mounted /var/lib/packeteer gives across a container restart.
func TestRecorderSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	cfg, err := plugin.ConfigFromYAML("path: " + filepath.Join(t.TempDir(), "packeteer.db"))
	if err != nil {
		t.Fatal(err)
	}
	open := func() *sqlite.Store {
		s, err := sqlite.New(cfg, plugin.Env{})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Start(ctx); err != nil {
			t.Fatal(err)
		}
		return s
	}
	clock := t0
	store := open()
	rec := newRecorder(store, &clock)
	if err := rec.Start(ctx); err != nil {
		t.Fatal(err)
	}
	results := []probe.Result{
		result(pfxA, "transit-a", 10, 40*time.Millisecond, t0),
		result(pfxA, "transit-b", 0, 20*time.Millisecond, t0),
	}
	for _, r := range results {
		rec.Probe(r)
	}
	rec.Decision(t0, []policy.Change{{Action: policy.ActionImprove, New: policy.Improvement{Prefix: pfxA, Provider: "transit-b", Native: "transit-a"}}}, results)
	clock = t0.Add(time.Hour)
	if err := rec.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Stop(ctx); err != nil {
		t.Fatal(err)
	}

	store = open()
	defer store.Stop(ctx)
	rec = newRecorder(store, &clock)
	if err := rec.Start(ctx); err != nil {
		t.Fatal(err)
	}
	q := Query{From: t0.Truncate(24 * time.Hour), To: t0.Add(24 * time.Hour)}
	q.Name = ReportImprovements
	rep, err := rec.Report(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	rows := rep.Rows.([]ImprovementRow)
	if len(rows) != 1 || rows[0].Prefix != "192.0.2.0/24" || rows[0].EndReason != EndShutdown || rows[0].Hours != 1 ||
		*rows[0].BeforeLossPct != 10 || *rows[0].AfterRTTMs != 20 {
		t.Fatalf("after restart = %+v", rows)
	}
	q.Name = ReportProviders
	rep, err = rec.Report(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	prov := rep.Rows.([]ProviderRow)
	if len(prov) != 2 || prov[0].Probes != 1 || prov[0].AvgLossPct != 10 || prov[1].ImprovementsTo != 1 {
		t.Fatalf("providers after restart = %+v", prov)
	}
	if err := rec.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
