package main

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/export"
	"github.com/GrandArcher/Packeteer/internal/notify"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type exportSink struct {
	plugin.Base
	streams []string
	mu      sync.Mutex
	got     []plugin.ExportRecord
}

func (s *exportSink) Streams() []string { return s.streams }
func (s *exportSink) Export(_ context.Context, b []plugin.ExportRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, b...)
	return nil
}

func (s *exportSink) drain(t *testing.T, d *export.Dispatcher) []plugin.ExportRecord {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.Close(ctx); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]plugin.ExportRecord(nil), s.got...)
}

func newExportSink(streams ...string) (*exportSink, *export.Dispatcher) {
	s := &exportSink{streams: streams}
	return s, export.New([]export.Target{{Name: "pipeline", Exporter: s}}, export.Options{})
}

func TestExportDecisionsRecordsEachChange(t *testing.T) {
	s, d := newExportSink(plugin.StreamDecisions)
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	p := netip.MustParsePrefix("192.0.2.0/24")
	first := policy.Improvement{Prefix: p, Provider: "transit-b", Native: "transit-a", Since: t0, Cause: plugin.CausePerformance, Reason: "lower loss"}
	second := policy.Improvement{Prefix: p, Provider: "transit-c", Native: "transit-a", Since: t0.Add(time.Minute), Cause: plugin.CausePerformance}
	now := t0.Add(5 * time.Minute)
	exportDecisions(d, now, "observe", []policy.Change{
		{Action: policy.ActionImprove, New: first},
		{Action: policy.ActionSwitch, Old: first, New: second},
		{Action: policy.ActionRetire, Old: second},
	})
	got := s.drain(t, d)
	if len(got) != 3 {
		t.Fatalf("records = %d", len(got))
	}
	add, sw, ret := got[0].Decision, got[1].Decision, got[2].Decision
	if add.Action != "improve" || add.ID != first.ID() || add.Provider != "transit-b" || add.Native != "transit-a" ||
		add.Mode != "observe" || add.Cause != plugin.CausePerformance || add.Reason != "lower loss" || !add.Time.Equal(now) || !add.Since.Equal(t0) {
		t.Fatalf("improve = %+v", add)
	}
	if sw.Action != "switch" || sw.ID != second.ID() || sw.Previous != "transit-b" || sw.PreviousID != first.ID() || sw.Provider != "transit-c" {
		t.Fatalf("switch = %+v", sw)
	}
	if ret.Action != "retire" || ret.ID != second.ID() || ret.Provider != "transit-c" || !ret.Since.Equal(second.Since) {
		t.Fatalf("retire must carry the ID and start of the improvement it ends: %+v", ret)
	}
}

func TestExportDecisionsIdleWithoutAnExporter(t *testing.T) {
	_, d := newExportSink(plugin.StreamEvents)
	exportDecisions(d, time.Now(), "observe", []policy.Change{{Action: policy.ActionImprove, New: policy.Improvement{Prefix: netip.MustParsePrefix("192.0.2.0/24")}}})
	exportDecisions(nil, time.Now(), "observe", nil)
	if n := d.Stats()[0].Sent + d.Stats()[0].Dropped; n != 0 {
		t.Fatalf("an events-only exporter got %d decision records", n)
	}
	_ = d.Close(context.Background())
}

func TestEventTeeKeepsTheRecorderAndExports(t *testing.T) {
	s, d := newExportSink(plugin.StreamEvents)
	var kept []plugin.Event
	disp := notify.New(nil, notify.Options{Recorder: eventTee{recorderFunc(func(e plugin.Event) { kept = append(kept, e) }), d}})
	disp.Emit(plugin.NewEvent(plugin.EventImprovementAdded, time.Unix(1790000000, 0), "m", map[string]string{"improvement_id": "00000000000000ab"}))
	got := s.drain(t, d)
	if len(kept) != 1 || len(got) != 1 {
		t.Fatalf("recorder %d, exporter %d", len(kept), len(got))
	}
	if e := got[0].Event; e.Kind != plugin.EventImprovementAdded || e.Fields["improvement_id"] != "00000000000000ab" || e.Severity == "" {
		t.Fatalf("exported event = %+v (the dispatcher fills the severity before the recorder)", e)
	}
}

type recorderFunc func(plugin.Event)

func (f recorderFunc) Record(e plugin.Event) { f(e) }

type tapSource struct {
	plugin.Base
	tap func(plugin.FlowObservation)
}

func (*tapSource) Targets(context.Context) ([]plugin.Target, error) { return nil, nil }
func (s *tapSource) SetFlowTap(fn func(plugin.FlowObservation))     { s.tap = fn }

func TestFlowTapTagsProviderAndImprovement(t *testing.T) {
	s, d := newExportSink(plugin.StreamFlows)
	src := &tapSource{}
	set := &pluginhost.Set{Sources: []pluginhost.Instance[plugin.TargetSource]{{Name: "flow", Plugin: src}}}
	tags := &exportTags{}
	native := func(a netip.Addr) string {
		if a == netip.MustParseAddr("198.51.100.5") {
			return "transit-a"
		}
		return ""
	}
	wireFlowExport(set, d, native, tags)
	if src.tap == nil {
		t.Fatal("the tap was not installed")
	}
	steered := netip.MustParsePrefix("192.0.2.0/24")
	imp := policy.Improvement{Prefix: steered, Provider: "transit-b", Native: "transit-a", Since: time.Unix(1790000000, 0)}
	at := time.Unix(1790000100, 0)
	obs := func(dst string, p netip.Prefix) plugin.FlowObservation {
		return plugin.FlowObservation{At: at, Src: netip.MustParseAddr("203.0.113.9"), Dst: netip.MustParseAddr(dst), Proto: 6, Bytes: 100, Prefix: p}
	}
	src.tap(obs("192.0.2.7", steered)) // before any decision round: native
	on := func(netip.Prefix) (string, bool) { return "transit-b", true }
	tags.set("inject", []policy.Improvement{imp}, on)
	src.tap(obs("192.0.2.7", steered))
	src.tap(obs("198.51.100.5", netip.MustParsePrefix("198.51.100.0/24")))
	tags.set("observe", []policy.Improvement{imp}, on)
	src.tap(obs("192.0.2.7", steered))
	tags.set("inject", nil, on)
	src.tap(obs("192.0.2.7", steered))
	tags.set("inject", []policy.Improvement{imp}, func(netip.Prefix) (string, bool) { return "", false })
	src.tap(obs("192.0.2.7", steered))
	tags.set("inject", []policy.Improvement{imp}, func(netip.Prefix) (string, bool) { return "transit-c", true })
	src.tap(obs("192.0.2.7", steered))

	got := s.drain(t, d)
	if len(got) != 7 {
		t.Fatalf("records = %d", len(got))
	}
	f := func(i int) plugin.FlowRecord { return *got[i].Flow }
	if f(0).Provider != "" || f(0).ImprovementID != "" {
		t.Fatalf("before a decision round: %+v", f(0))
	}
	if r := f(1); r.Provider != "transit-b" || r.ImprovementID != imp.ID() || r.Prefix != "192.0.2.0/24" || r.Bytes != 100 || r.Proto != 6 || !r.Time.Equal(at) {
		t.Fatalf("steered flow = %+v", r)
	}
	if r := f(2); r.Provider != "transit-a" || r.ImprovementID != "" {
		t.Fatalf("native flow must carry the RIB's provider and no improvement ID: %+v", r)
	}
	if r := f(3); r.ImprovementID != "" || r.Provider != "" {
		t.Fatalf("a recommendation in observe must not tag the flow as moved: %+v", r)
	}
	if r := f(4); r.ImprovementID != "" || r.Provider != "" {
		t.Fatalf("a retired improvement must stop tagging: %+v", r)
	}
	if r := f(5); r.ImprovementID != "" || r.Provider != "" {
		t.Fatalf("an improvement the announcer did not install must not tag the flow: %+v", r)
	}
	if r := f(6); r.ImprovementID != "" || r.Provider != "" {
		t.Fatalf("a route still on the wire for another provider must not tag the flow: %+v", r)
	}
}

func TestFlowTapStaysOffWithoutAFlowExporter(t *testing.T) {
	_, d := newExportSink(plugin.StreamEvents, plugin.StreamDecisions)
	src := &tapSource{}
	set := &pluginhost.Set{Sources: []pluginhost.Instance[plugin.TargetSource]{{Name: "flow", Plugin: src}}}
	wireFlowExport(set, d, nil, &exportTags{})
	wireFlowExport(set, nil, nil, &exportTags{})
	wireFlowExport(nil, d, nil, &exportTags{})
	if src.tap != nil {
		t.Fatal("the per-record tap must not run unless an exporter takes flows")
	}
	_ = d.Close(context.Background())
}

func TestExportStats(t *testing.T) {
	if exportStats(export.New(nil, export.Options{})) != nil {
		t.Fatal("no exporters must leave /metrics without packeteer_export_*")
	}
	_, d := newExportSink(plugin.StreamEvents)
	defer d.Close(context.Background())
	if fn := exportStats(d); fn == nil || len(fn()) != 1 {
		t.Fatal("a configured exporter must report")
	}
}
