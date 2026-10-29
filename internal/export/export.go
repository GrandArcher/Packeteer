// Package export fans events, decisions, and tagged flow records out to the
// configured exporters (#207).
//
// Every call is non-blocking. Each exporter has its own bounded queue and
// worker, so a slow or dead sink drops its own records (counted) and never
// delays probing, decisions, withdrawals, or the notifiers. Exporters
// only read; nothing here announces.
package export

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Defaults.
const (
	DefaultQueue   = 4096
	DefaultTimeout = 10 * time.Second
	// MaxBatch bounds the records handed to one Export call.
	MaxBatch = 256
)

// Streams in the order Stats reports them.
var streams = []string{plugin.StreamEvents, plugin.StreamDecisions, plugin.StreamFlows}

func streamIndex(s string) int {
	for i, n := range streams {
		if n == s {
			return i
		}
	}
	return -1
}

// Target is one configured exporter.
type Target struct {
	Name     string
	Exporter plugin.Exporter
}

// Options tune the dispatcher. Zero values use the defaults.
type Options struct {
	Queue   int
	Timeout time.Duration
	Logger  *slog.Logger
}

// Stat counts one exporter's records on one stream.
type Stat struct {
	Exporter string
	Stream   string
	Sent     uint64
	Failed   uint64
	// Dropped is records a full queue turned away.
	Dropped uint64
}

type counts struct{ sent, failed, dropped atomic.Uint64 }

type worker struct {
	name string
	x    plugin.Exporter
	// takes[i] is true when the exporter takes streams[i].
	takes [3]bool
	q     chan plugin.ExportRecord
	n     [3]counts
}

// Dispatcher delivers records asynchronously.
type Dispatcher struct {
	workers []*worker
	timeout time.Duration
	log     *slog.Logger

	mu     sync.RWMutex
	closed bool
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

// New starts one worker per target. No targets yields a dispatcher whose
// calls do nothing.
func New(targets []Target, o Options) *Dispatcher {
	if o.Queue <= 0 {
		o.Queue = DefaultQueue
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &Dispatcher{timeout: o.Timeout, log: o.Logger, ctx: ctx, cancel: cancel}
	for _, t := range targets {
		if t.Exporter == nil {
			continue
		}
		w := &worker{name: t.Name, x: t.Exporter, q: make(chan plugin.ExportRecord, o.Queue)}
		for _, s := range t.Exporter.Streams() {
			if i := streamIndex(s); i >= 0 {
				w.takes[i] = true
			}
		}
		d.workers = append(d.workers, w)
		d.wg.Add(1)
		go d.run(w)
	}
	return d
}

// Wants reports whether any exporter takes stream. A producer that is
// costly (the flow tap) checks it once and stays off otherwise.
func (d *Dispatcher) Wants(stream string) bool {
	if d == nil {
		return false
	}
	i := streamIndex(stream)
	if i < 0 {
		return false
	}
	for _, w := range d.workers {
		if w.takes[i] {
			return true
		}
	}
	return false
}

// Event queues an event for the exporters that take events.
func (d *Dispatcher) Event(e plugin.Event) {
	d.send(plugin.ExportRecord{Stream: plugin.StreamEvents, Event: &e})
}

// Decision queues one decision change.
func (d *Dispatcher) Decision(r plugin.DecisionRecord) {
	d.send(plugin.ExportRecord{Stream: plugin.StreamDecisions, Decision: &r})
}

// Flow queues one tagged flow record.
func (d *Dispatcher) Flow(r plugin.FlowRecord) {
	d.send(plugin.ExportRecord{Stream: plugin.StreamFlows, Flow: &r})
}

func (d *Dispatcher) send(r plugin.ExportRecord) {
	if d == nil || len(d.workers) == 0 {
		return
	}
	i := streamIndex(r.Stream)
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, w := range d.workers {
		if i < 0 || !w.takes[i] {
			continue
		}
		if d.closed {
			w.n[i].dropped.Add(1)
			continue
		}
		select {
		case w.q <- r:
		default:
			w.n[i].dropped.Add(1)
		}
	}
}

func (d *Dispatcher) run(w *worker) {
	defer d.wg.Done()
	batch := make([]plugin.ExportRecord, 0, MaxBatch)
	for r := range w.q {
		batch = append(batch[:0], r)
	fill:
		for len(batch) < MaxBatch {
			select {
			case r, ok := <-w.q:
				if !ok {
					break fill
				}
				batch = append(batch, r)
			default:
				break fill
			}
		}
		d.deliver(w, batch)
	}
}

func (d *Dispatcher) deliver(w *worker, batch []plugin.ExportRecord) {
	ctx, cancel := context.WithTimeout(d.ctx, d.timeout)
	defer cancel()
	err := w.x.Export(ctx, batch)
	if err != nil {
		d.log.Warn("export", "exporter", w.name, "records", len(batch), "err", err)
	}
	for _, r := range batch {
		c := &w.n[streamIndex(r.Stream)]
		if err != nil {
			c.failed.Add(1)
		} else {
			c.sent.Add(1)
		}
	}
}

// Stats reports the counters for every exporter and the streams it takes.
func (d *Dispatcher) Stats() []Stat {
	if d == nil {
		return nil
	}
	var out []Stat
	for _, w := range d.workers {
		for i, s := range streams {
			if !w.takes[i] {
				continue
			}
			out = append(out, Stat{Exporter: w.name, Stream: s,
				Sent: w.n[i].sent.Load(), Failed: w.n[i].failed.Load(), Dropped: w.n[i].dropped.Load()})
		}
	}
	return out
}

// Close stops accepting records and delivers what is queued until ctx
// expires. A delivery still running then is cancelled.
func (d *Dispatcher) Close(ctx context.Context) error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	for _, w := range d.workers {
		close(w.q)
	}
	d.mu.Unlock()
	done := make(chan struct{})
	go func() { d.wg.Wait(); close(done) }()
	select {
	case <-done:
		d.cancel()
		return nil
	case <-ctx.Done():
		d.cancel()
		<-done
		return ctx.Err()
	}
}

// JSON renders a record as the JSON body Kafka and NATS carry, with the
// key that keeps one prefix (or one event kind) in order on a partition.
func JSON(r plugin.ExportRecord) (key string, body []byte, err error) {
	switch {
	case r.Event != nil:
		key = r.Event.Kind
		body, err = json.Marshal(r.Event)
	case r.Decision != nil:
		key = r.Decision.Prefix
		body, err = json.Marshal(r.Decision)
	case r.Flow != nil:
		key = r.Flow.Prefix
		body, err = json.Marshal(r.Flow)
	default:
		err = errors.New("empty export record")
	}
	return key, body, err
}
