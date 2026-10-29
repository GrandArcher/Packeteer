package export

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fake struct {
	plugin.Base
	streams []string
	mu      sync.Mutex
	got     []plugin.ExportRecord
	batches []int
	err     error
	block   chan struct{}
}

func (f *fake) Streams() []string { return f.streams }

func (f *fake) Export(ctx context.Context, b []plugin.ExportRecord) error {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, b...)
	f.batches = append(f.batches, len(b))
	return f.err
}

func (f *fake) records() []plugin.ExportRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]plugin.ExportRecord(nil), f.got...)
}

func closeIn(t *testing.T, d *Dispatcher) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRoutesRecordsByStream(t *testing.T) {
	all := &fake{streams: []string{plugin.StreamEvents, plugin.StreamDecisions, plugin.StreamFlows}}
	dec := &fake{streams: []string{plugin.StreamDecisions}}
	d := New([]Target{{"all", all}, {"dec", dec}}, Options{})
	if !d.Wants(plugin.StreamFlows) || !d.Wants(plugin.StreamDecisions) || d.Wants("nope") {
		t.Fatal("Wants must follow the exporters' streams")
	}
	d.Event(plugin.Event{Kind: "improvement.added"})
	d.Decision(plugin.DecisionRecord{ID: "abc", Prefix: "192.0.2.0/24"})
	d.Flow(plugin.FlowRecord{Prefix: "192.0.2.0/24", Bytes: 9})
	closeIn(t, d)

	if n := len(all.records()); n != 3 {
		t.Fatalf("exporter with all streams got %d records", n)
	}
	got := dec.records()
	if len(got) != 1 || got[0].Stream != plugin.StreamDecisions || got[0].Decision.ID != "abc" {
		t.Fatalf("decision-only exporter got %+v", got)
	}
	stats := map[string]Stat{}
	for _, s := range d.Stats() {
		stats[s.Exporter+"/"+s.Stream] = s
	}
	if len(stats) != 4 || stats["all/flows"].Sent != 1 || stats["dec/decisions"].Sent != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if _, ok := stats["dec/events"]; ok {
		t.Fatal("a stream the exporter does not take must not be reported")
	}
}

func TestFailureIsCountedPerRecord(t *testing.T) {
	f := &fake{streams: []string{plugin.StreamEvents}, err: errors.New("sink down")}
	d := New([]Target{{"k", f}}, Options{})
	d.Event(plugin.Event{Kind: "a"})
	d.Event(plugin.Event{Kind: "b"})
	closeIn(t, d)
	s := d.Stats()[0]
	if s.Failed != 2 || s.Sent != 0 {
		t.Fatalf("stat = %+v", s)
	}
}

func TestFullQueueDropsWithoutBlocking(t *testing.T) {
	f := &fake{streams: []string{plugin.StreamFlows}, block: make(chan struct{})}
	d := New([]Target{{"slow", f}}, Options{Queue: 2, Timeout: time.Minute})
	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			d.Flow(plugin.FlowRecord{Bytes: uint64(i)})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a stuck sink blocked the producer")
	}
	if got := d.Stats()[0].Dropped; got < 40 {
		t.Fatalf("dropped = %d, want most of 50 with a queue of 2", got)
	}
	close(f.block)
	closeIn(t, d)
}

func TestCloseCancelsStuckDeliveryAndDropsLateRecords(t *testing.T) {
	f := &fake{streams: []string{plugin.StreamEvents}, block: make(chan struct{})}
	d := New([]Target{{"slow", f}}, Options{Timeout: time.Minute})
	d.Event(plugin.Event{Kind: "a"})
	time.Sleep(20 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := d.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close = %v, want deadline exceeded", err)
	}
	d.Event(plugin.Event{Kind: "late"})
	if s := d.Stats()[0]; s.Dropped != 1 || s.Failed != 1 {
		t.Fatalf("stat = %+v (cancelled delivery fails, late record drops)", s)
	}
}

func TestBatchesQueuedRecords(t *testing.T) {
	f := &fake{streams: []string{plugin.StreamFlows}, block: make(chan struct{})}
	d := New([]Target{{"b", f}}, Options{Queue: 100, Timeout: time.Minute})
	for i := 0; i < 10; i++ {
		d.Flow(plugin.FlowRecord{Bytes: uint64(i)})
	}
	time.Sleep(20 * time.Millisecond)
	close(f.block)
	closeIn(t, d)
	total := 0
	for _, n := range f.batches {
		total += n
	}
	if total != 10 || len(f.batches) > 3 {
		t.Fatalf("batches = %v, want 10 records in a few calls", f.batches)
	}
}

func TestNilAndEmptyAreInert(t *testing.T) {
	var d *Dispatcher
	d.Event(plugin.Event{})
	d.Flow(plugin.FlowRecord{})
	if d.Wants(plugin.StreamEvents) || d.Stats() != nil || d.Close(context.Background()) != nil {
		t.Fatal("nil dispatcher must do nothing")
	}
	e := New(nil, Options{})
	e.Decision(plugin.DecisionRecord{})
	if e.Wants(plugin.StreamDecisions) || len(e.Stats()) != 0 {
		t.Fatal("no exporters means no streams wanted")
	}
	closeIn(t, e)
}

func TestJSON(t *testing.T) {
	key, body, err := JSON(plugin.ExportRecord{Stream: plugin.StreamEvents, Event: &plugin.Event{Kind: "bgp.session_down", Message: "m"}})
	if err != nil || key != "bgp.session_down" || !strings.Contains(string(body), `"kind":"bgp.session_down"`) {
		t.Fatalf("event: %q %s %v", key, body, err)
	}
	key, body, err = JSON(plugin.ExportRecord{Stream: plugin.StreamDecisions, Decision: &plugin.DecisionRecord{ID: "ab12", Prefix: "192.0.2.0/24", Provider: "transit-b"}})
	if err != nil || key != "192.0.2.0/24" || !strings.Contains(string(body), `"id":"ab12"`) || !strings.Contains(string(body), `"provider":"transit-b"`) {
		t.Fatalf("decision: %q %s %v", key, body, err)
	}
	key, body, err = JSON(plugin.ExportRecord{Stream: plugin.StreamFlows, Flow: &plugin.FlowRecord{Prefix: "198.51.100.0/24", ImprovementID: "ff"}})
	if err != nil || key != "198.51.100.0/24" || !strings.Contains(string(body), `"improvement_id":"ff"`) {
		t.Fatalf("flow: %q %s %v", key, body, err)
	}
	if _, _, err := JSON(plugin.ExportRecord{}); err == nil {
		t.Fatal("empty record must fail")
	}
}
