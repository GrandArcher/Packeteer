package history

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/storage/sqlite"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/provseries"
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
		s, err := newSQLite(cfg)
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

func TestRecorderMitigations(t *testing.T) {
	ctx := context.Background()
	cfg, err := plugin.ConfigFromYAML("path: " + filepath.Join(t.TempDir(), "packeteer.db"))
	if err != nil {
		t.Fatal(err)
	}
	open := func() *sqlite.Store {
		s, err := newSQLite(cfg)
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
	fs := plugin.MitigationRecord{ID: "fs", Prefix: pfxB, Action: plugin.MitigationFlowSpecDrop, Match: "proto=17", Routes: 1,
		Mode: "inject", Created: t0, Expires: t0.Add(2 * time.Hour)}
	rec.Mitigation(fs)
	fs.Announced = t0.Add(time.Minute)
	rec.Mitigation(fs)
	bh := plugin.MitigationRecord{ID: "bh", Prefix: pfxC, Action: plugin.MitigationBlackhole, Routes: 1, Mode: "inject",
		Created: t0, Expires: t0.Add(time.Hour), Announced: t0, End: t0.Add(30 * time.Minute), EndReason: "removed"}
	rec.Mitigation(bh)
	rec.Mitigation(plugin.MitigationRecord{ID: "bad"})

	// Unflushed rows are in the report already.
	clock = t0.Add(time.Hour + time.Minute)
	q := Query{Name: ReportMitigations, From: t0.Truncate(24 * time.Hour), To: t0.Add(24 * time.Hour)}
	rep, err := rec.Report(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	rows := rep.Rows.([]MitigationRow)
	if len(rows) != 2 || rows[0].ID != "bh" || rows[0].Hours != 0.5 || rows[1].ID != "fs" || rows[1].Hours != 1 || !rows[1].End.IsZero() {
		t.Fatalf("mitigations before close = %+v", rows)
	}
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
	rep, err = rec.Report(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	rows = rep.Rows.([]MitigationRow)
	if len(rows) != 2 || rows[1].ID != "fs" || rows[1].EndReason != EndShutdown || !rows[1].End.Equal(clock) || rows[1].Match != "proto=17" {
		t.Fatalf("mitigations after restart = %+v", rows)
	}
	var csv strings.Builder
	if err := rep.CSV(&csv); err != nil || !strings.HasPrefix(csv.String(), "id,prefix,action,") || strings.Count(csv.String(), "\n") != 3 {
		t.Fatalf("csv = %q %v", csv.String(), err)
	}
	if err := rec.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

// Anomalies (#33) are stored from detection to clearing, with the rule and
// mitigation, and an anomaly left open is closed on Close and survives a
// restart as history.
func TestRecorderAnomalies(t *testing.T) {
	ctx := context.Background()
	cfg, err := plugin.ConfigFromYAML("path: " + filepath.Join(t.TempDir(), "packeteer.db"))
	if err != nil {
		t.Fatal(err)
	}
	open := func() *sqlite.Store {
		s, err := newSQLite(cfg)
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
	udp := plugin.AnomalyRecord{ID: "a1", Prefix: pfxB, Protocol: "udp", PeakMbps: 120, BaselineMbps: 4, Reason: "flood", Start: t0}
	rec.Anomaly(udp)
	udp.Rule, udp.Mitigation, udp.Action = "udp-flood", "m1", plugin.MitigationFlowSpecDrop
	rec.Anomaly(udp)
	tcp := plugin.AnomalyRecord{ID: "a2", Prefix: pfxC, Protocol: "tcp", PeakMbps: 50, Reason: "burst", Start: t0.Add(time.Minute),
		End: t0.Add(11 * time.Minute), EndReason: "traffic is back within its baseline"}
	rec.Anomaly(tcp)
	rec.Anomaly(plugin.AnomalyRecord{ID: "bad"})
	clock = t0.Add(time.Hour)
	q := Query{Name: ReportAnomalies, From: t0.Truncate(24 * time.Hour), To: t0.Add(24 * time.Hour)}
	rep, err := rec.Report(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	rows := rep.Rows.([]AnomalyRow)
	if len(rows) != 2 || rows[0].ID != "a2" || rows[0].Minutes != 10 || rows[1].ID != "a1" || rows[1].Rule != "udp-flood" ||
		rows[1].Mitigation != "m1" || rows[1].Minutes != 60 || !rows[1].End.IsZero() {
		t.Fatalf("anomalies before close = %+v", rows)
	}
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
	rep, err = rec.Report(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	rows = rep.Rows.([]AnomalyRow)
	if len(rows) != 2 || rows[1].EndReason != EndAnomalyShutdown || !rows[1].End.Equal(clock) || rows[1].Action != plugin.MitigationFlowSpecDrop {
		t.Fatalf("anomalies after restart = %+v", rows)
	}
	var csv strings.Builder
	if err := rep.CSV(&csv); err != nil || !strings.HasPrefix(csv.String(), "id,prefix,protocol,") || strings.Count(csv.String(), "\n") != 3 {
		t.Fatalf("csv = %q %v", csv.String(), err)
	}
	if err := rec.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRecorderReportsEachStoreWrite(t *testing.T) {
	clock := t0
	store := &memStore{}
	var results []error
	r := New(Options{Store: store, Mode: "observe", FlushEvery: time.Hour, Now: func() time.Time { return clock },
		OnWrite: func(err error) { results = append(results, err) }})
	if err := r.Flush(context.Background()); err != nil || len(results) != 0 {
		t.Fatalf("an empty flush wrote or reported: err=%v results=%v", err, results)
	}
	r.Probe(result(pfxA, "lab-a", 0, 5*time.Millisecond, clock))
	store.fail = errors.New("disk is read-only")
	if err := r.Flush(context.Background()); err == nil {
		t.Fatal("flush with a failing store returned nil")
	}
	store.fail = nil
	if err := r.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0] == nil || results[0].Error() != "disk is read-only" || results[1] != nil {
		t.Fatalf("OnWrite results = %v, want the failure then success", results)
	}
}

// An improvement is stored with the volume the decision saw, and Report
// names the configured exchange peers (#148).
func TestRecorderExchangeReport(t *testing.T) {
	ctx := context.Background()
	clock := t0
	store := &memStore{}
	rec := New(Options{Store: store, Mode: "observe", FlushEvery: time.Hour, Now: func() time.Time { return clock },
		Exchanges: map[string]string{"ix-peer-a": "ix-lab", "ix-peer-b": "ix-lab"}})
	rec.Decision(t0, []policy.Change{{Action: policy.ActionImprove, New: policy.Improvement{Prefix: pfxA, Provider: "ix-peer-a", Native: "transit-a", VolumeMbps: 30}}}, nil)
	rec.Decision(t0, []policy.Change{{Action: policy.ActionImprove, New: policy.Improvement{Prefix: pfxB, Provider: "transit-b", Native: "transit-a", VolumeMbps: 99}}}, nil)
	clock = t0.Add(time.Hour)
	if err := rec.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if i := slices.IndexFunc(store.h.Improvements, func(r plugin.ImprovementRecord) bool { return r.Provider == "ix-peer-a" }); i < 0 || store.h.Improvements[i].VolumeMbps != 30 {
		t.Fatalf("stored improvements = %+v", store.h.Improvements)
	}
	rep, err := rec.Report(ctx, Query{Name: ReportExchanges, From: t0.Truncate(24 * time.Hour), To: t0.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	rows := rep.Rows.([]ExchangeRow)
	if len(rows) != 2 || rows[0].Peer != "ix-peer-a" || rows[0].Exchange != "ix-lab" || rows[0].VolumeMbps != 30 || rows[0].Active != 1 ||
		rows[1].Peer != "ix-peer-b" || rows[1].Improvements != 0 {
		t.Fatalf("rows = %+v", rows)
	}
}

// TestRecorderKeepsProviderSeriesAcrossRestart feeds the provider series,
// closes the recorder, and reads the series back in a fresh one on the same
// sqlite file. A store without provider samples is left alone.
func TestRecorderKeepsProviderSeriesAcrossRestart(t *testing.T) {
	ctx := context.Background()
	cfg, err := plugin.ConfigFromYAML("path: " + filepath.Join(t.TempDir(), "packeteer.db"))
	if err != nil {
		t.Fatal(err)
	}
	open := func() *sqlite.Store {
		s, err := newSQLite(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Start(ctx); err != nil {
			t.Fatal(err)
		}
		return s
	}
	run := func(series *provseries.Series) {
		store := open()
		defer store.Stop(ctx)
		rec := New(Options{Store: store, Series: series, Now: func() time.Time { return t0 }})
		if err := rec.Start(ctx); err != nil {
			t.Fatal(err)
		}
		series.Add(result(pfxA, "transit-a", 10, 40*time.Millisecond, t0))
		if err := rec.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}
	first := provseries.New(func() time.Time { return t0 })
	run(first)
	second := provseries.New(func() time.Time { return t0 })
	run(second)
	stats := second.Stats()
	if len(stats) != 1 || stats[0].Provider != "transit-a" || stats[0].Last24h.Slots != 1 || stats[0].Last24h.RTTMs != 40 {
		t.Fatalf("restored stats = %+v", stats)
	}
	// Two runs each added one probe to the same slot; the second held the first's.
	check := open()
	defer check.Stop(ctx)
	if got, err := check.ProviderSamples(ctx, t0.Add(-time.Hour), t0.Add(time.Hour)); err != nil || len(got) != 1 || got[0].Probes != 2 {
		t.Fatalf("slot after two runs = %+v, %v", got, err)
	}

	mem := &memStore{}
	rec := New(Options{Store: mem, Series: first, Now: func() time.Time { return t0 }})
	if err := rec.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(ctx); err != nil {
		t.Fatalf("a store without provider samples broke Close: %v", err)
	}
}

// #200: every learned path's validity is recorded per provider and origin,
// not only the chosen path. A state or source change starts a new record;
// an unchanged one extends Last. Unflushed records show in the prefix
// history, and the records survive the store.
func TestRecorderRPKIRoutes(t *testing.T) {
	ctx := context.Background()
	cfg, err := plugin.ConfigFromYAML("path: " + filepath.Join(t.TempDir(), "packeteer.db"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := newSQLite(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer store.Stop(ctx)
	clock := t0
	rec := newRecorder(store, &clock)
	if err := rec.Start(ctx); err != nil {
		t.Fatal(err)
	}
	fetched := t0.Add(-time.Minute)
	valid := plugin.RPKIAnswer{State: plugin.RPKIValid, Source: "routinator", Updated: fetched}
	invalid := plugin.RPKIAnswer{State: plugin.RPKIInvalid, Source: "routinator", Updated: fetched}
	round := []RPKIRoute{
		{Prefix: pfxA, Provider: "transit-a", Origin: 64496, Answer: valid},
		{Prefix: pfxA, Provider: "transit-b", Origin: 64511, Answer: invalid},
		{Prefix: pfxA, Provider: "transit-b", Origin: 64496, Answer: valid},
		{Prefix: pfxB, Provider: "transit-a", Origin: 64497, Answer: valid},
	}
	rec.RPKI(t0, round)
	rec.RPKI(t0.Add(time.Minute), round)
	round[0].Answer = plugin.RPKIAnswer{State: plugin.RPKIUnknown}
	rec.RPKI(t0.Add(2*time.Minute), round)

	want := []RPKIRow{
		{Provider: "transit-a", Origin: 64496, State: plugin.RPKIUnknown, First: t0.Add(2 * time.Minute), Last: t0.Add(2 * time.Minute)},
		{Provider: "transit-a", Origin: 64496, State: plugin.RPKIValid, Source: "routinator", First: t0, Last: t0.Add(time.Minute)},
		{Provider: "transit-b", Origin: 64496, State: plugin.RPKIValid, Source: "routinator", First: t0, Last: t0.Add(2 * time.Minute)},
		{Provider: "transit-b", Origin: 64511, State: plugin.RPKIInvalid, Source: "routinator", First: t0, Last: t0.Add(2 * time.Minute)},
	}
	q := Query{From: t0.Add(-time.Hour), To: t0.Add(time.Hour)}
	for _, stage := range []string{"before flush", "after flush"} {
		h, err := rec.Prefix(ctx, pfxA, q)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(h.RPKI, want) {
			t.Fatalf("%s: rpki = %+v, want %+v", stage, h.RPKI, want)
		}
		if err := rec.Flush(ctx); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := store.Read(ctx, plugin.HistoryQuery{From: q.From, To: q.To})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.RPKIRoutes) != 5 {
		t.Fatalf("stored = %+v, want 5 records", stored.RPKIRoutes)
	}
	if err := rec.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

// A path missing from one round continues its span; one gone longer than
// rpkiGap starts a new span when it returns (#200).
func TestRecorderRPKIMissedRound(t *testing.T) {
	ctx := context.Background()
	cfg, err := plugin.ConfigFromYAML("path: " + filepath.Join(t.TempDir(), "packeteer.db"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := newSQLite(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer store.Stop(ctx)
	clock := t0
	rec := newRecorder(store, &clock)
	if err := rec.Start(ctx); err != nil {
		t.Fatal(err)
	}
	valid := plugin.RPKIAnswer{State: plugin.RPKIValid, Source: "routinator"}
	a := RPKIRoute{Prefix: pfxA, Provider: "transit-a", Origin: 64496, Answer: valid}
	b := RPKIRoute{Prefix: pfxB, Provider: "transit-a", Origin: 64497, Answer: valid}
	rec.RPKI(t0, []RPKIRoute{a, b})
	rec.RPKI(t0.Add(time.Minute), []RPKIRoute{b})
	rec.RPKI(t0.Add(2*time.Minute), []RPKIRoute{a, b})
	rec.RPKI(t0.Add(10*time.Minute), []RPKIRoute{b})
	rec.RPKI(t0.Add(20*time.Minute), []RPKIRoute{a, b})

	h, err := rec.Prefix(ctx, pfxA, Query{From: t0.Add(-time.Hour), To: t0.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	want := []RPKIRow{
		{Provider: "transit-a", Origin: 64496, State: plugin.RPKIValid, Source: "routinator", First: t0.Add(20 * time.Minute), Last: t0.Add(20 * time.Minute)},
		{Provider: "transit-a", Origin: 64496, State: plugin.RPKIValid, Source: "routinator", First: t0, Last: t0.Add(2 * time.Minute)},
	}
	if !slices.Equal(h.RPKI, want) {
		t.Fatalf("rpki = %+v, want %+v", h.RPKI, want)
	}
}

// A change carries the gate list of the decision that made it, and the
// record keeps it as JSON for the prefix page (#201).
func TestRecorderStoresExplain(t *testing.T) {
	ctx := context.Background()
	clock := t0
	store := &memStore{}
	rec := newRecorder(store, &clock)
	imp := policy.Improvement{Prefix: pfxA, Provider: "transit-b", Native: "transit-a", Reason: "rtt"}
	ex := &policy.Explain{Outcome: policy.OutcomeMoved, Reason: "rtt", Gates: []policy.Gate{{Name: policy.GateThresholds, Status: policy.GatePass, Value: "40 ms"}}}
	rec.Decision(t0, []policy.Change{{Action: policy.ActionImprove, New: imp, Explain: ex}}, nil)
	other := policy.Improvement{Prefix: pfxC, Provider: "transit-b", Native: "transit-a"}
	rec.Decision(t0, []policy.Change{{Action: policy.ActionImprove, New: other}}, nil)
	if err := rec.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	got := map[netip.Prefix]string{}
	for _, r := range store.h.Improvements {
		got[r.Prefix] = r.Explain
	}
	want := `{"outcome":"moved","reason":"rtt","gates":[{"gate":"thresholds","status":"pass","value":"40 ms"}],"samples":null}`
	if got[pfxA] != want || got[pfxC] != "" {
		t.Fatalf("stored explains = %q", got)
	}
}

// newSQLite opens the sqlite plugin with its retention prune on the test's
// fixed clock, so rows written at t0 survive a restart whatever the real
// date is (#444).
func newSQLite(cfg plugin.Config) (*sqlite.Store, error) {
	s, err := sqlite.New(cfg, plugin.Env{})
	if err == nil {
		s.SetClock(func() time.Time { return t0.Add(24 * time.Hour) })
	}
	return s, err
}
