// Package eventlog keeps recent controller events for the Events page
// (#173). Without a storage plugin that keeps events it holds the newest
// MemoryCap events since start. With one, events are also written to it
// by a worker with a bounded queue, so a slow disk never delays the
// caller. Operators may acknowledge an open alert (#558); nothing else
// changes it. It never announces a route and never changes a decision.
package eventlog

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Bounds.
const (
	// MemoryCap is how many events the in-memory log keeps.
	MemoryCap = 1000
	// QueueCap is how many events wait for the store before new ones are
	// dropped (and logged).
	QueueCap = 256
	// writeTimeout bounds one store write.
	writeTimeout = 5 * time.Second
)

// Log records events and answers queries.
type Log struct {
	store   plugin.EventStore
	log     *slog.Logger
	onWrite func(error)
	started time.Time

	mu     sync.Mutex
	closed bool
	ring   []plugin.Event // newest last, at most MemoryCap; used without a store
	q      chan plugin.Event
	done   chan struct{}
	acks   map[string]Ack // by Event.DedupKey, at most MemoryCap
}

// Ack is an operator's acknowledgement of an open alert: a note that
// someone has it in hand. Notifications are unchanged. It ends when an
// event resolves the alert, and it is kept in memory only.
type Ack struct {
	Key  string    `json:"key"`
	By   string    `json:"by"`
	At   time.Time `json:"at"`
	Note string    `json:"note,omitempty"`
	// since is the newest resolving event of the key before the
	// acknowledged one: events of an earlier incident are not covered.
	since time.Time
}

var warnRank, _ = plugin.SeverityRank(plugin.SeverityWarning)

// Acknowledge errors.
var (
	ErrNoAlert  = errors.New("no warning or critical alert with that key among the newest events")
	ErrResolved = errors.New("that alert is already resolved")
)

// New returns a log. store may be nil. With a store it starts the writer;
// Close stops it. onWrite, when set, is told the result of each store
// write.
func New(store plugin.EventStore, log *slog.Logger, onWrite func(error)) *Log {
	if log == nil {
		log = slog.Default()
	}
	l := &Log{store: store, log: log, onWrite: onWrite, started: time.Now()}
	if store != nil {
		l.q = make(chan plugin.Event, QueueCap)
		l.done = make(chan struct{})
		go l.write()
	}
	return l
}

// Stored reports whether events are kept across a restart.
func (l *Log) Stored() bool { return l.store != nil }

// Started is when the log began; without a store it is how far back the
// page can look.
func (l *Log) Started() time.Time { return l.started }

// Record keeps e. Audit records are not kept here: the audit log holds
// them, and a burst of sign-ins would push real events out. Record never
// blocks.
func (l *Log) Record(e plugin.Event) {
	if e.Kind == plugin.EventAudit {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	if e.Resolves() {
		delete(l.acks, e.DedupKey())
	}
	if l.store == nil {
		if len(l.ring) == MemoryCap {
			copy(l.ring, l.ring[1:])
			l.ring = l.ring[:MemoryCap-1]
		}
		l.ring = append(l.ring, e)
		return
	}
	select {
	case l.q <- e:
	default:
		l.log.Warn("event log queue full; event not stored", "kind", e.Kind)
	}
}

func (l *Log) write() {
	defer close(l.done)
	for e := range l.q {
		ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
		err := l.store.AppendEvent(ctx, e)
		if l.onWrite != nil {
			l.onWrite(err)
		}
		if err != nil {
			l.log.Error("event store write failed", "kind", e.Kind, "err", err)
		}
		cancel()
	}
}

// Query returns matching events, newest first.
func (l *Log) Query(ctx context.Context, q plugin.EventQuery) ([]plugin.Event, error) {
	if l.store != nil {
		return l.store.Events(ctx, q)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []plugin.Event
	for i := len(l.ring) - 1; i >= 0; i-- {
		e := l.ring[i]
		if !q.Match(e) {
			continue
		}
		out = append(out, e)
		if q.Limit > 0 && len(out) == q.Limit {
			break
		}
	}
	return out, nil
}

// Open returns the open alerts matching q, newest first: the newest event
// of each alert key (Event.DedupKey) when it is a problem event, not one
// that resolves its group. An alert whose newest event resolved it is
// left out, however many problem events came before. Only the newest
// MemoryCap events are read, so q.Limit applies to the alerts, not to the
// events scanned. q.Text and the time range apply to that newest event.
func (l *Log) Open(ctx context.Context, q plugin.EventQuery) ([]plugin.Event, error) {
	evs, err := l.Query(ctx, plugin.EventQuery{Limit: MemoryCap})
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []plugin.Event
	for _, e := range evs {
		key := e.DedupKey()
		if seen[key] {
			continue
		}
		seen[key] = true
		if e.Resolves() || !q.Match(e) {
			continue
		}
		out = append(out, e)
		if q.Limit > 0 && len(out) == q.Limit {
			break
		}
	}
	return out, nil
}

// Acknowledge records that by has seen the open alert key (an
// Event.DedupKey). The newest event with that key among the newest
// MemoryCap events must be a warning or critical event that does not
// resolve its group. Acknowledging again replaces the note. Past
// MemoryCap acknowledgements the oldest is dropped.
func (l *Log) Acknowledge(ctx context.Context, key, by, note string, now time.Time) (Ack, error) {
	evs, err := l.Query(ctx, plugin.EventQuery{Limit: MemoryCap})
	if err != nil {
		return Ack{}, err
	}
	a := Ack{Key: key, By: by, At: now.UTC(), Note: note}
	found := false
	for _, e := range evs {
		if e.DedupKey() != key {
			continue
		}
		if found {
			if e.Resolves() {
				a.since = e.Time
				break
			}
			continue
		}
		if e.Resolves() {
			return Ack{}, ErrResolved
		}
		if r, _ := plugin.SeverityRank(e.Severity); r < warnRank {
			return Ack{}, ErrNoAlert
		}
		found = true
	}
	if !found {
		return Ack{}, ErrNoAlert
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.acks == nil {
		l.acks = map[string]Ack{}
	}
	if _, ok := l.acks[key]; !ok && len(l.acks) >= MemoryCap {
		oldest := ""
		for k, v := range l.acks {
			if oldest == "" || v.At.Before(l.acks[oldest].At) {
				oldest = k
			}
		}
		delete(l.acks, oldest)
	}
	l.acks[key] = a
	return a, nil
}

// AckOf is the acknowledgement covering e: e is a problem event of an
// acknowledged alert, from the acknowledged incident.
func (l *Log) AckOf(e plugin.Event) (Ack, bool) {
	if e.Resolves() {
		return Ack{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok := l.acks[e.DedupKey()]
	if !ok || !e.Time.After(a.since) {
		return Ack{}, false
	}
	return a, true
}

// Close stops taking events and writes what is queued until ctx expires.
func (l *Log) Close(ctx context.Context) error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	if l.q != nil {
		close(l.q)
	}
	l.mu.Unlock()
	if l.done == nil {
		return nil
	}
	select {
	case <-l.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
