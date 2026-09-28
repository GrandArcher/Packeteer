// Package notify fans controller events out to the configured notifiers.
//
// Emit never blocks the caller. Each notifier has its own bounded queue and
// worker, so a slow SMTP relay cannot delay a webhook, and neither can
// delay probing, decisions, or withdrawals. Filters and rate limits come
// from the notifier's plugin.EventGate. Notifiers never announce routes.
package notify

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Defaults.
const (
	DefaultQueue   = 256
	DefaultTimeout = 10 * time.Second
)

// Target is one configured notifier.
type Target struct {
	Name     string
	Notifier plugin.Notifier
}

// Options tune the dispatcher. Zero values use the defaults.
type Options struct {
	Queue   int
	Timeout time.Duration
	Logger  *slog.Logger
	Now     func() time.Time
}

// Stats counts deliveries across all notifiers.
type Stats struct {
	Delivered  uint64 `json:"delivered"`
	Failed     uint64 `json:"failed"`
	Filtered   uint64 `json:"filtered"`
	RateLimits uint64 `json:"rate_limited"`
	Dropped    uint64 `json:"dropped"` // queue full or dispatcher closed
}

type worker struct {
	name string
	n    plugin.Notifier
	gate *plugin.EventGate
	q    chan plugin.Event
}

// Dispatcher delivers events asynchronously.
type Dispatcher struct {
	workers []*worker
	timeout time.Duration
	log     *slog.Logger
	now     func() time.Time

	mu     sync.RWMutex
	closed bool
	wg     sync.WaitGroup
	cancel context.CancelFunc
	ctx    context.Context

	delivered, failed, filtered, limited, dropped atomic.Uint64
}

// New starts one worker per target. A nil or empty target list yields a
// dispatcher whose Emit is a no-op.
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
	if o.Now == nil {
		o.Now = time.Now
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &Dispatcher{timeout: o.Timeout, log: o.Logger, now: o.Now, ctx: ctx, cancel: cancel}
	for _, t := range targets {
		if t.Notifier == nil {
			continue
		}
		w := &worker{name: t.Name, n: t.Notifier, q: make(chan plugin.Event, o.Queue)}
		if g, ok := t.Notifier.(plugin.Gated); ok {
			w.gate = g.EventGate()
		}
		d.workers = append(d.workers, w)
		d.wg.Add(1)
		go d.run(w)
	}
	return d
}

// Enabled reports whether any notifier is configured.
func (d *Dispatcher) Enabled() bool { return d != nil && len(d.workers) > 0 }

// Emit queues e for every notifier. It fills Time and Severity from the
// catalog when they are empty. A full queue drops the event for that
// notifier and counts it; the caller is never blocked.
func (d *Dispatcher) Emit(e plugin.Event) {
	if !d.Enabled() {
		return
	}
	if e.Time.IsZero() {
		e.Time = d.now()
	}
	if e.Severity == "" {
		if s, ok := plugin.LookupEvent(e.Kind); ok {
			e.Severity = s.Severity
		} else {
			e.Severity = plugin.SeverityInfo
		}
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		d.dropped.Add(uint64(len(d.workers)))
		return
	}
	for _, w := range d.workers {
		select {
		case w.q <- e:
		default:
			d.dropped.Add(1)
			d.log.Warn("notify queue full; event dropped", "notifier", w.name, "kind", e.Kind)
		}
	}
}

func (d *Dispatcher) run(w *worker) {
	defer d.wg.Done()
	for e := range w.q {
		d.deliver(w, e)
	}
}

func (d *Dispatcher) deliver(w *worker, e plugin.Event) {
	if !w.gate.Match(e) {
		d.filtered.Add(1)
		return
	}
	ok, suppressed := w.gate.Allow(e, d.now())
	if !ok {
		d.limited.Add(1)
		d.log.Debug("notify rate limited", "notifier", w.name, "kind", e.Kind)
		return
	}
	e = e.WithSuppressed(suppressed)
	ctx, cancel := context.WithTimeout(d.ctx, d.timeout)
	defer cancel()
	if err := w.n.Notify(ctx, e); err != nil {
		d.failed.Add(1)
		d.log.Warn("notify", "notifier", w.name, "kind", e.Kind, "err", err)
		return
	}
	d.delivered.Add(1)
}

// Close stops accepting events and delivers what is queued until ctx
// expires. Deliveries still running then are cancelled.
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
		// Cancel in-flight deliveries; the rest of the queue fails fast.
		d.cancel()
		return ctx.Err()
	}
}

// Stats returns delivery counters.
func (d *Dispatcher) Stats() Stats {
	if d == nil {
		return Stats{}
	}
	return Stats{
		Delivered: d.delivered.Load(), Failed: d.failed.Load(), Filtered: d.filtered.Load(),
		RateLimits: d.limited.Load(), Dropped: d.dropped.Load(),
	}
}
