package eventlog

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var t0 = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func ev(kind string, sev plugin.Severity, i int) plugin.Event {
	return plugin.Event{Time: t0.Add(time.Duration(i) * time.Second), Kind: kind, Severity: sev, Message: fmt.Sprintf("event %d", i)}
}

// syncBuf is a log sink that is safe for the writer goroutine.
type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func capture() (*slog.Logger, *syncBuf) {
	buf := &syncBuf{}
	return slog.New(slog.NewTextHandler(buf, nil)), buf
}

func messages(t *testing.T, l *Log, q plugin.EventQuery) []string {
	t.Helper()
	got, err := l.Query(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range got {
		out = append(out, e.Message)
	}
	return out
}

func TestMemoryLogIsCappedAndNewestFirst(t *testing.T) {
	l := New(nil, nil)
	if l.Stored() {
		t.Fatal("a log without a store says it is stored")
	}
	for i := 0; i < MemoryCap+5; i++ {
		l.Record(ev(plugin.EventImprovementAdded, plugin.SeverityInfo, i))
	}
	got := messages(t, l, plugin.EventQuery{})
	if len(got) != MemoryCap {
		t.Fatalf("kept %d events, want %d", len(got), MemoryCap)
	}
	if got[0] != fmt.Sprintf("event %d", MemoryCap+4) || got[MemoryCap-1] != "event 5" {
		t.Errorf("order: first %q last %q", got[0], got[MemoryCap-1])
	}
}

func TestMemoryLogFiltersAndSkipsAudit(t *testing.T) {
	l := New(nil, nil)
	l.Record(ev(plugin.EventControllerStarted, plugin.SeverityInfo, 0))
	l.Record(ev(plugin.EventAudit, plugin.SeverityInfo, 1))
	l.Record(ev(plugin.EventCommitExceeded, plugin.SeverityWarning, 2))
	l.Record(ev(plugin.EventProviderDown, plugin.SeverityCritical, 3))
	if got := messages(t, l, plugin.EventQuery{}); fmt.Sprint(got) != "[event 3 event 2 event 0]" {
		t.Errorf("all: %v (the audit event must not be kept)", got)
	}
	if got := messages(t, l, plugin.EventQuery{MinSeverity: plugin.SeverityWarning, Limit: 1}); fmt.Sprint(got) != "[event 3]" {
		t.Errorf("warning+ limit 1: %v", got)
	}
	if got := messages(t, l, plugin.EventQuery{From: t0.Add(time.Second), To: t0.Add(3 * time.Second)}); fmt.Sprint(got) != "[event 2]" {
		t.Errorf("range: %v", got)
	}
}

// fakeStore is an EventStore whose writes can be held and failed.
type fakeStore struct {
	mu      sync.Mutex
	rows    []plugin.Event
	gate    chan struct{} // writes wait for it to close, when set
	failing bool
}

func (f *fakeStore) AppendEvent(_ context.Context, e plugin.Event) error {
	if f.gate != nil {
		<-f.gate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failing {
		return errors.New("disk full")
	}
	f.rows = append(f.rows, e)
	return nil
}

func (f *fakeStore) Events(_ context.Context, q plugin.EventQuery) ([]plugin.Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []plugin.Event
	for i := len(f.rows) - 1; i >= 0; i-- {
		if q.Match(f.rows[i]) {
			out = append(out, f.rows[i])
		}
	}
	return out, nil
}

func TestStoredLogWritesAndFlushesOnClose(t *testing.T) {
	st := &fakeStore{}
	l := New(st, nil)
	if !l.Stored() {
		t.Fatal("a log with a store says it is not stored")
	}
	l.Record(ev(plugin.EventControllerStarted, plugin.SeverityInfo, 0))
	l.Record(ev(plugin.EventAudit, plugin.SeverityInfo, 1))
	l.Record(ev(plugin.EventProviderDown, plugin.SeverityCritical, 2))
	if err := l.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := messages(t, l, plugin.EventQuery{}); fmt.Sprint(got) != "[event 2 event 0]" {
		t.Errorf("stored events: %v", got)
	}
	l.Record(ev(plugin.EventProviderUp, plugin.SeverityInfo, 3)) // after Close: ignored, no panic
	if err := l.Close(context.Background()); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if got := messages(t, l, plugin.EventQuery{}); len(got) != 2 {
		t.Errorf("an event recorded after Close was stored: %v", got)
	}
}

// A store that stalls must not block Record: the queue fills, the extra
// events are dropped and logged, and the caller returns at once.
func TestStoredLogNeverBlocksTheCaller(t *testing.T) {
	st := &fakeStore{gate: make(chan struct{})}
	lg, out := capture()
	l := New(st, lg)
	done := make(chan struct{})
	go func() {
		for i := 0; i < QueueCap+50; i++ {
			l.Record(ev(plugin.EventImprovementAdded, plugin.SeverityInfo, i))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Record blocked on a stalled store")
	}
	if !strings.Contains(out.String(), "event log queue full") {
		t.Errorf("a full queue was not logged: %q", out.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := l.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Close with a stalled store = %v, want the context's deadline", err)
	}
	close(st.gate)
}

func TestStoredLogLogsFailedWrites(t *testing.T) {
	st := &fakeStore{failing: true}
	lg, out := capture()
	l := New(st, lg)
	l.Record(ev(plugin.EventProviderDown, plugin.SeverityCritical, 0))
	if err := l.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "event store write failed") || !strings.Contains(out.String(), "disk full") {
		t.Errorf("a failed write was not logged: %q", out.String())
	}
}
