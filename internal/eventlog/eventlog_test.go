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
	l := New(nil, nil, nil)
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
	l := New(nil, nil, nil)
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
	l := New(st, nil, nil)
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
	l := New(st, lg, nil)
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
	l := New(st, lg, nil)
	l.Record(ev(plugin.EventProviderDown, plugin.SeverityCritical, 0))
	if err := l.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "event store write failed") || !strings.Contains(out.String(), "disk full") {
		t.Errorf("a failed write was not logged: %q", out.String())
	}
}

func TestOnWriteSeesStoreFailureAndRecovery(t *testing.T) {
	st := &fakeStore{failing: true}
	results := make(chan error, 4)
	l := New(st, nil, func(err error) { results <- err })
	l.Record(ev(plugin.EventControllerStarted, plugin.SeverityInfo, 0))
	first := <-results
	if first == nil || first.Error() != "disk full" {
		t.Fatalf("first write result = %v, want disk full", first)
	}
	st.mu.Lock()
	st.failing = false
	st.mu.Unlock()
	l.Record(ev(plugin.EventProviderDown, plugin.SeverityCritical, 1))
	if second := <-results; second != nil {
		t.Fatalf("second write result = %v, want success", second)
	}
	if err := l.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func provider(kind string, sev plugin.Severity, i int, name string) plugin.Event {
	e := ev(kind, sev, i)
	e.Fields = map[string]string{"provider": name}
	return e
}

// An acknowledgement covers the open incident's problem events, not an
// earlier incident of the same alert, and ends when the alert resolves.
func TestAcknowledgeOpenAlertUntilResolved(t *testing.T) {
	ctx := context.Background()
	l := New(nil, nil, nil)
	first := provider(plugin.EventProviderDown, plugin.SeverityCritical, 0, "transit-a")
	key := first.DedupKey()
	l.Record(first)
	l.Record(provider(plugin.EventProviderUp, plugin.SeverityInfo, 1, "transit-a"))
	if _, err := l.Acknowledge(ctx, key, "noc1", "", t0.Add(2*time.Second)); !errors.Is(err, ErrResolved) {
		t.Fatalf("ack of a resolved alert: %v", err)
	}
	again := provider(plugin.EventProviderDown, plugin.SeverityCritical, 3, "transit-a")
	l.Record(again)
	l.Record(provider(plugin.EventProviderDown, plugin.SeverityCritical, 4, "transit-b"))

	a, err := l.Acknowledge(ctx, key, "noc1", "ticket 7", t0.Add(5*time.Second))
	if err != nil || a.By != "noc1" || a.Note != "ticket 7" || a.Key != key || !a.At.Equal(t0.Add(5*time.Second)) {
		t.Fatalf("ack %+v %v", a, err)
	}
	if got, ok := l.AckOf(again); !ok || got.By != "noc1" {
		t.Errorf("open incident not covered: %+v %v", got, ok)
	}
	if _, ok := l.AckOf(first); ok {
		t.Error("an earlier incident of the alert is covered")
	}
	if _, ok := l.AckOf(provider(plugin.EventProviderDown, plugin.SeverityCritical, 4, "transit-b")); ok {
		t.Error("another provider's alert is covered")
	}
	repeat := provider(plugin.EventProviderDown, plugin.SeverityCritical, 6, "transit-a")
	l.Record(repeat)
	if _, ok := l.AckOf(repeat); !ok {
		t.Error("a repeat of the open alert is not covered")
	}

	l.Record(provider(plugin.EventProviderUp, plugin.SeverityInfo, 7, "transit-a"))
	if _, ok := l.AckOf(repeat); ok {
		t.Error("acknowledgement kept after the alert resolved")
	}
}

func TestAcknowledgeNeedsAWarningOrCriticalAlert(t *testing.T) {
	ctx := context.Background()
	l := New(nil, nil, nil)
	info := ev(plugin.EventImprovementAdded, plugin.SeverityInfo, 0)
	info.Fields = map[string]string{"prefix": "198.51.100.0/24"}
	l.Record(info)
	for _, key := range []string{info.DedupKey(), "packeteer/provider/provider=transit-z"} {
		if _, err := l.Acknowledge(ctx, key, "noc1", "", t0); !errors.Is(err, ErrNoAlert) {
			t.Errorf("%s: %v", key, err)
		}
	}
	if _, ok := l.AckOf(info); ok {
		t.Error("a refused key was recorded")
	}
}

func TestAcknowledgementsAreBounded(t *testing.T) {
	ctx := context.Background()
	l := New(nil, nil, nil)
	for i := range MemoryCap + 1 {
		l.Record(provider(plugin.EventProviderDown, plugin.SeverityCritical, i, fmt.Sprint("p", i)))
	}
	// p0 fell out of the ring. Ack p1..pN, then one more alert: the
	// oldest acknowledgement (p1) is dropped.
	for i := 1; i <= MemoryCap; i++ {
		key := provider(plugin.EventProviderDown, plugin.SeverityCritical, i, fmt.Sprint("p", i)).DedupKey()
		if _, err := l.Acknowledge(ctx, key, "noc1", "", t0.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatalf("ack %d: %v", i, err)
		}
	}
	extra := provider(plugin.EventProviderDown, plugin.SeverityCritical, MemoryCap+1, "extra")
	l.Record(extra)
	if _, err := l.Acknowledge(ctx, extra.DedupKey(), "noc1", "", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	n := len(l.acks)
	_, oldest := l.acks[provider(plugin.EventProviderDown, plugin.SeverityCritical, 1, "p1").DedupKey()]
	l.mu.Unlock()
	if n != MemoryCap || oldest {
		t.Errorf("acks = %d, oldest kept %v", n, oldest)
	}
}
