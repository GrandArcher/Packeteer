// Package eventlog keeps recent controller events for the Events page
// (#173). Without a storage plugin that keeps events it holds the newest
// MemoryCap events since start. With one, events are also written to it
// by a worker with a bounded queue, so a slow disk never delays the
// caller. It is read-only for operators: it never announces a route and
// never changes a decision.
package eventlog

import (
	"context"
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
	started time.Time

	mu     sync.Mutex
	closed bool
	ring   []plugin.Event // newest last, at most MemoryCap; used without a store
	q      chan plugin.Event
	done   chan struct{}
}

// New returns a log. store may be nil. With a store it starts the writer;
// Close stops it.
func New(store plugin.EventStore, log *slog.Logger) *Log {
	if log == nil {
		log = slog.Default()
	}
	l := &Log{store: store, log: log, started: time.Now()}
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
		if err := l.store.AppendEvent(ctx, e); err != nil {
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
