// Package history records what the controller measured and decided into a
// storage plugin, and builds reports from it.
//
// The recorder keeps daily probe rollups and improvement records in memory
// and flushes them on a timer, so a slow or failing disk never delays a
// probe, a decision, or a withdraw. It never announces routes. Report
// aggregation (report.go) is pure and runs on whatever the store returns.
package history

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// DefaultFlushEvery is how often pending rows are written.
const DefaultFlushEvery = time.Minute

// maxPending caps unflushed bucket keys while the store keeps failing, so
// a dead disk cannot grow memory without bound. Extra probes are dropped
// from history (never from decisions).
const maxPending = 200000

// End reasons written by the recorder itself.
const (
	EndRestart  = "controller restarted (routes withdrawn)"
	EndShutdown = "controller stopped (routes withdrawn)"
)

// Options configure a Recorder.
type Options struct {
	Store      plugin.Storage
	Mode       string
	Logger     *slog.Logger
	FlushEvery time.Duration
	// Describe returns the origin ASN and country for a prefix. Either
	// may be zero. Nil records neither.
	Describe func(netip.Prefix) (asn uint32, country string)
	// Volumes returns observed per-prefix rates in Mbps. Nil records none.
	Volumes func(ctx context.Context) map[netip.Prefix]float64
	Now     func() time.Time
}

type bucketKey struct {
	day      int64
	prefix   netip.Prefix
	provider string
}

// Recorder buffers history and writes it to a storage plugin.
type Recorder struct {
	opt Options
	log *slog.Logger

	mu       sync.Mutex
	buckets  map[bucketKey]*plugin.ProbeBucket
	dirty    map[string]plugin.ImprovementRecord
	open     map[netip.Prefix]plugin.ImprovementRecord
	prefixes map[netip.Prefix]bool
	seq      uint64
	dropped  int

	flushMu sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
}

// New returns a recorder. It does not touch the store until Start.
func New(opt Options) *Recorder {
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	if opt.FlushEvery <= 0 {
		opt.FlushEvery = DefaultFlushEvery
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	return &Recorder{
		opt: opt, log: opt.Logger,
		buckets:  map[bucketKey]*plugin.ProbeBucket{},
		dirty:    map[string]plugin.ImprovementRecord{},
		open:     map[netip.Prefix]plugin.ImprovementRecord{},
		prefixes: map[netip.Prefix]bool{},
	}
}

// Start ends improvement records a previous process left open (that
// process withdrew its routes, or lost its session, when it stopped) and
// starts the flush loop. The store must already be started.
func (r *Recorder) Start(ctx context.Context) error {
	h, err := r.opt.Store.Read(ctx, plugin.HistoryQuery{OpenOnly: true})
	if err != nil {
		return fmt.Errorf("history: read open improvements: %w", err)
	}
	if len(h.Improvements) > 0 {
		now := r.opt.Now().UTC()
		for i := range h.Improvements {
			h.Improvements[i].End = now
			h.Improvements[i].EndReason = EndRestart
		}
		if err := r.opt.Store.Write(ctx, plugin.HistoryBatch{Improvements: h.Improvements}); err != nil {
			return fmt.Errorf("history: close open improvements: %w", err)
		}
		r.log.Info("history: closed improvements left open by the previous run", "count", len(h.Improvements))
	}
	loopCtx, cancel := context.WithCancel(context.Background())
	r.cancel, r.done = cancel, make(chan struct{})
	go r.loop(loopCtx)
	return nil
}

func (r *Recorder) loop(ctx context.Context) {
	defer close(r.done)
	t := time.NewTicker(r.opt.FlushEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			if err := r.Flush(fctx); err != nil && !errors.Is(err, context.Canceled) {
				r.log.Warn("history flush", "err", err)
			}
			cancel()
		}
	}
}

// Close ends the open improvement records (the caller has withdrawn the
// routes), flushes, and stops the loop. The store is stopped by the host.
func (r *Recorder) Close(ctx context.Context) error {
	if r.cancel != nil {
		r.cancel()
		<-r.done
		r.cancel = nil
	}
	now := r.opt.Now().UTC()
	r.mu.Lock()
	for p, rec := range r.open {
		rec.End, rec.EndReason = now, EndShutdown
		r.dirty[rec.ID] = rec
		delete(r.open, p)
	}
	r.mu.Unlock()
	return r.Flush(ctx)
}

// Probe adds one result to today's rollup. Safe for concurrent use.
func (r *Recorder) Probe(res probe.Result) {
	if !res.Prefix.IsValid() || res.Provider == "" {
		return
	}
	t := res.Time
	if t.IsZero() {
		t = r.opt.Now()
	}
	day := t.UTC().Truncate(24 * time.Hour)
	k := bucketKey{day: day.Unix(), prefix: res.Prefix, provider: res.Provider}
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.buckets[k]
	if b == nil {
		if len(r.buckets) >= maxPending {
			r.dropped++
			return
		}
		b = &plugin.ProbeBucket{Day: day, Prefix: res.Prefix, Provider: res.Provider}
		r.buckets[k] = b
	}
	b.Probes++
	if !res.OK() {
		b.Failed++
	} else {
		b.Measured++
		b.LossSum += res.Stats.LossPct
		b.RTTSumMs += ms(res.Stats.RTTAvg)
		b.JitterSum += ms(res.Stats.Jitter)
	}
	r.prefixes[res.Prefix] = true
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// Decision records the improvement changes of one evaluation. results are
// the measurements the evaluation used; they give the before (native) and
// after (chosen provider) numbers.
func (r *Recorder) Decision(now time.Time, changes []policy.Change, results []probe.Result) {
	if len(changes) == 0 {
		return
	}
	type key struct {
		p netip.Prefix
		n string
	}
	latest := map[key]probe.Result{}
	for _, res := range results {
		k := key{res.Prefix, res.Provider}
		if old, ok := latest[k]; !ok || res.Time.After(old.Time) {
			latest[k] = res
		}
	}
	measure := func(p netip.Prefix, provider string) (bool, float64, float64) {
		res, ok := latest[key{p, provider}]
		if !ok || !res.OK() {
			return false, 0, 0
		}
		return true, res.Stats.LossPct, ms(res.Stats.RTTAvg)
	}
	now = now.UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	end := func(p netip.Prefix, reason string) {
		rec, ok := r.open[p]
		if !ok {
			return
		}
		rec.End, rec.EndReason = now, reason
		r.dirty[rec.ID] = rec
		delete(r.open, p)
	}
	for _, c := range changes {
		switch c.Action {
		case policy.ActionImprove, policy.ActionSwitch:
			imp := c.New
			if c.Action == policy.ActionSwitch {
				end(imp.Prefix, "switched to "+imp.Provider)
			} else {
				end(imp.Prefix, "replaced")
			}
			r.seq++
			rec := plugin.ImprovementRecord{
				ID:     fmt.Sprintf("%s@%d.%d", imp.Prefix, now.UnixNano(), r.seq),
				Prefix: imp.Prefix, Provider: imp.Provider, Native: imp.Native, Cause: imp.Cause, Reason: imp.Reason,
				Mode: r.opt.Mode, Start: now, CostDelta: imp.CostDelta, EstSavings: imp.EstSavings,
			}
			if rec.Cause == "" {
				rec.Cause = plugin.CausePerformance
			}
			rec.HasBefore, rec.BeforeLoss, rec.BeforeRTT = measure(imp.Prefix, imp.Native)
			rec.HasAfter, rec.AfterLoss, rec.AfterRTT = measure(imp.Prefix, imp.Provider)
			if r.opt.Describe != nil {
				rec.OriginASN, rec.Country = r.opt.Describe(imp.Prefix)
			}
			r.open[imp.Prefix] = rec
			r.dirty[rec.ID] = rec
			r.prefixes[imp.Prefix] = true
		case policy.ActionRetire:
			end(c.Old.Prefix, c.Old.Reason)
		}
	}
}

// take swaps out the pending batch.
func (r *Recorder) take() (plugin.HistoryBatch, []netip.Prefix) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var b plugin.HistoryBatch
	for _, k := range r.buckets {
		b.Buckets = append(b.Buckets, *k)
	}
	for _, rec := range r.dirty {
		b.Improvements = append(b.Improvements, rec)
	}
	var ps []netip.Prefix
	for p := range r.prefixes {
		ps = append(ps, p)
	}
	r.buckets = map[bucketKey]*plugin.ProbeBucket{}
	r.dirty = map[string]plugin.ImprovementRecord{}
	r.prefixes = map[netip.Prefix]bool{}
	if r.dropped > 0 {
		r.log.Warn("history: dropped probe rollups while the store was failing", "count", r.dropped)
		r.dropped = 0
	}
	return b, ps
}

// requeue puts a failed batch back. Buckets add; a newer record for the
// same improvement wins.
func (r *Recorder) requeue(b plugin.HistoryBatch, ps []netip.Prefix) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, k := range b.Buckets {
		key := bucketKey{day: k.Day.Unix(), prefix: k.Prefix, provider: k.Provider}
		cur := r.buckets[key]
		if cur == nil {
			if len(r.buckets) >= maxPending {
				r.dropped += k.Probes
				continue
			}
			c := k
			r.buckets[key] = &c
			continue
		}
		cur.Probes += k.Probes
		cur.Failed += k.Failed
		cur.Measured += k.Measured
		cur.LossSum += k.LossSum
		cur.RTTSumMs += k.RTTSumMs
		cur.JitterSum += k.JitterSum
	}
	for _, rec := range b.Improvements {
		if _, newer := r.dirty[rec.ID]; !newer {
			r.dirty[rec.ID] = rec
		}
	}
	for _, p := range ps {
		r.prefixes[p] = true
	}
}

// Flush writes pending rows. On error they are kept for the next flush.
func (r *Recorder) Flush(ctx context.Context) error {
	r.flushMu.Lock()
	defer r.flushMu.Unlock()
	b, ps := r.take()
	if len(ps) > 0 && (r.opt.Describe != nil || r.opt.Volumes != nil) {
		var vols map[netip.Prefix]float64
		if r.opt.Volumes != nil {
			vols = r.opt.Volumes(ctx)
		}
		now := r.opt.Now().UTC()
		for _, p := range ps {
			info := plugin.PrefixInfo{Prefix: p, VolumeMbps: vols[p], Updated: now}
			if r.opt.Describe != nil {
				info.OriginASN, info.Country = r.opt.Describe(p)
			}
			b.Prefixes = append(b.Prefixes, info)
		}
	}
	if len(b.Buckets) == 0 && len(b.Improvements) == 0 && len(b.Prefixes) == 0 {
		return nil
	}
	if err := r.opt.Store.Write(ctx, b); err != nil {
		r.requeue(b, ps)
		return err
	}
	return nil
}

// History reads the store for [from, to) and merges rows not yet flushed,
// so a report includes the last minute.
func (r *Recorder) History(ctx context.Context, from, to time.Time) (plugin.History, error) {
	// A flush in progress has taken rows out of memory but not written
	// them yet; wait for it so they are not missing from this read.
	r.flushMu.Lock()
	defer r.flushMu.Unlock()
	h, err := r.opt.Store.Read(ctx, plugin.HistoryQuery{From: from, To: to})
	if err != nil {
		return h, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := map[bucketKey]int{}
	for i, b := range h.Buckets {
		idx[bucketKey{day: b.Day.Unix(), prefix: b.Prefix, provider: b.Provider}] = i
	}
	for k, b := range r.buckets {
		if b.Day.Before(from.UTC().Truncate(24*time.Hour)) || !b.Day.Before(to) {
			continue
		}
		if i, ok := idx[k]; ok {
			cur := &h.Buckets[i]
			cur.Probes += b.Probes
			cur.Failed += b.Failed
			cur.Measured += b.Measured
			cur.LossSum += b.LossSum
			cur.RTTSumMs += b.RTTSumMs
			cur.JitterSum += b.JitterSum
			continue
		}
		h.Buckets = append(h.Buckets, *b)
	}
	byID := map[string]int{}
	for i, rec := range h.Improvements {
		byID[rec.ID] = i
	}
	for id, rec := range r.dirty {
		if i, ok := byID[id]; ok {
			h.Improvements[i] = rec
		} else {
			h.Improvements = append(h.Improvements, rec)
		}
	}
	return h, nil
}

// Report builds one report for [from, to).
func (r *Recorder) Report(ctx context.Context, q Query) (Report, error) {
	if !Known(q.Name) {
		return Report{}, fmt.Errorf("unknown report %q", q.Name)
	}
	h, err := r.History(ctx, q.From, q.To)
	if err != nil {
		return Report{}, err
	}
	if q.Now.IsZero() {
		q.Now = r.opt.Now()
	}
	return Build(h, q)
}
