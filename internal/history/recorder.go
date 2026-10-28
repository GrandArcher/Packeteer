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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/provseries"
	"github.com/GrandArcher/Packeteer/internal/replay"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// DefaultFlushEvery is how often pending rows are written.
const DefaultFlushEvery = time.Minute

// maxPending caps unflushed bucket keys while the store keeps failing, so
// a dead disk cannot grow memory without bound. Extra probes are dropped
// from history (never from decisions).
const maxPending = 200000

// maxPendingRounds caps unflushed decision rounds (#204) while the store
// keeps failing. Each is the whole round's input, so the cap is small.
const maxPendingRounds = 600

// End reasons written by the recorder itself.
const (
	EndRestart  = "controller restarted (routes withdrawn)"
	EndShutdown = "controller stopped (routes withdrawn)"
	// Anomalies are not routes: they end because detection stopped.
	EndAnomalyRestart  = "controller restarted (detection state is in memory only)"
	EndAnomalyShutdown = "controller stopped"
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
	// Exchanges maps each exchange peer (a provider name) to its exchange
	// for the exchanges report. Nil when no exchange is configured.
	Exchanges map[string]string
	Now       func() time.Time
	// Series, when set, is the per-provider five-minute series. The recorder
	// restores it on Start and flushes it with the rest, when the store
	// keeps provider samples. The controller feeds it, not the recorder.
	Series *provseries.Series
	// OnWrite, when set, is told the result of each store write the
	// flush attempts. The System page shows it as the storage state.
	OnWrite func(error)
	// RoundEvery is the least time between two kept decision rounds.
	// Evaluations also run on every RIB change, so without it the rate of
	// rounds follows route churn. Zero keeps every round.
	RoundEvery time.Duration
}

type rpkiKey struct {
	prefix   netip.Prefix
	provider string
	origin   uint32
}

// rpkiRowKey is the stored row: one path's record from its first round.
type rpkiRowKey struct {
	rpkiKey
	first int64
}

// RPKIRoute is one learned path's origin-validation answer in a decision
// round (#200): a provider's path toward a probed prefix, by origin AS.
type RPKIRoute struct {
	Prefix   netip.Prefix
	Provider string
	Origin   uint32
	Answer   plugin.RPKIAnswer
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

	mu      sync.Mutex
	buckets map[bucketKey]*plugin.ProbeBucket
	dirty   map[string]plugin.ImprovementRecord
	open    map[netip.Prefix]plugin.ImprovementRecord
	// mits are mitigation records not yet flushed; openMits the rules
	// still held, closed on Close.
	mits     map[string]plugin.MitigationRecord
	openMits map[string]plugin.MitigationRecord
	// anoms are anomaly records not yet flushed; openAnoms the anomalies
	// still open, closed on Close (#33).
	anoms     map[string]plugin.AnomalyRecord
	openAnoms map[string]plugin.AnomalyRecord
	prefixes  map[netip.Prefix]bool
	// rpkiOpen is the current record of each learned path's validity;
	// rpkiDirty holds the records not yet flushed (#200).
	rpkiOpen    map[rpkiKey]plugin.RPKIRouteRecord
	rpkiDirty   map[rpkiRowKey]plugin.RPKIRouteRecord
	seq         uint64
	dropped     int
	rpkiDropped int
	// rounds are encoded decision rounds not yet flushed (#204).
	rounds        []plugin.RoundRecord
	roundsDropped int
	lastRound     time.Time

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
		mits:     map[string]plugin.MitigationRecord{},
		openMits: map[string]plugin.MitigationRecord{},

		anoms:     map[string]plugin.AnomalyRecord{},
		openAnoms: map[string]plugin.AnomalyRecord{},
		rpkiOpen:  map[rpkiKey]plugin.RPKIRouteRecord{},
		rpkiDirty: map[rpkiRowKey]plugin.RPKIRouteRecord{},
	}
}

// Start ends improvement and mitigation records a previous process left
// open (that process withdrew its routes, or lost its session, when it
// stopped; mitigation rules live in memory only) and starts the flush
// loop. The store must already be started.
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
	if len(h.Mitigations) > 0 {
		now := r.opt.Now().UTC()
		for i := range h.Mitigations {
			h.Mitigations[i].End = now
			h.Mitigations[i].EndReason = EndRestart
		}
		if err := r.opt.Store.Write(ctx, plugin.HistoryBatch{Mitigations: h.Mitigations}); err != nil {
			return fmt.Errorf("history: close open mitigations: %w", err)
		}
		r.log.Info("history: closed mitigation rules left open by the previous run", "count", len(h.Mitigations))
	}
	if len(h.Anomalies) > 0 {
		now := r.opt.Now().UTC()
		for i := range h.Anomalies {
			h.Anomalies[i].End = now
			h.Anomalies[i].EndReason = EndAnomalyRestart
		}
		if err := r.opt.Store.Write(ctx, plugin.HistoryBatch{Anomalies: h.Anomalies}); err != nil {
			return fmt.Errorf("history: close open anomalies: %w", err)
		}
		r.log.Info("history: closed anomalies left open by the previous run", "count", len(h.Anomalies))
	}
	if store, ok := r.providerStore(); ok {
		if err := r.opt.Series.Restore(ctx, store); err != nil {
			r.log.Warn("history: read provider samples", "err", err)
		}
	}
	loopCtx, cancel := context.WithCancel(context.Background())
	r.cancel, r.done = cancel, make(chan struct{})
	go r.loop(loopCtx)
	return nil
}

// providerStore is the store's provider-sample side, when there is a series
// to keep and the store has one.
func (r *Recorder) providerStore() (plugin.ProviderSampleStore, bool) {
	if r.opt.Series == nil {
		return nil, false
	}
	store, ok := r.opt.Store.(plugin.ProviderSampleStore)
	return store, ok
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

// Close ends the open improvement and mitigation records (the caller has
// withdrawn the routes), flushes, and stops the loop. The store is stopped by the host.
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
	for id, m := range r.openMits {
		m.End, m.EndReason = now, EndShutdown
		r.mits[id] = m
		delete(r.openMits, id)
	}
	for id, a := range r.openAnoms {
		a.End, a.EndReason = now, EndAnomalyShutdown
		r.anoms[id] = a
		delete(r.openAnoms, id)
	}
	r.mu.Unlock()
	return r.Flush(ctx)
}

// KeepsRounds reports whether the store keeps decision rounds for replay
// (#204).
func (r *Recorder) KeepsRounds() bool {
	rs, ok := r.opt.Store.(plugin.RoundStore)
	return ok && rs.RoundRetention() > 0
}

// Round queues the input of the decision made at now for replay. It does
// nothing unless the store keeps rounds. Safe for concurrent use.
func (r *Recorder) Round(now time.Time, in policy.Input) {
	if !r.KeepsRounds() {
		return
	}
	r.mu.Lock()
	tooSoon := !r.lastRound.IsZero() && now.Sub(r.lastRound) < r.opt.RoundEvery
	r.mu.Unlock()
	if tooSoon {
		return
	}
	data, err := replay.Encode(now, in)
	if err != nil {
		r.log.Warn("history: encode decision round", "err", err)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastRound = now
	if len(r.rounds) >= maxPendingRounds {
		r.roundsDropped++
		return
	}
	r.rounds = append(r.rounds, plugin.RoundRecord{At: now, Input: data})
}

// flushRounds writes the queued decision rounds. On error they are kept
// for the next flush, up to the cap.
func (r *Recorder) flushRounds(ctx context.Context) error {
	r.mu.Lock()
	rounds, dropped := r.rounds, r.roundsDropped
	r.rounds, r.roundsDropped = nil, 0
	r.mu.Unlock()
	if dropped > 0 {
		r.log.Warn("history: dropped decision rounds while the store was failing", "count", dropped)
	}
	if len(rounds) == 0 {
		return nil
	}
	rs, ok := r.opt.Store.(plugin.RoundStore)
	if !ok {
		return nil
	}
	if err := rs.PutRounds(ctx, rounds); err != nil {
		r.mu.Lock()
		room := maxPendingRounds - len(r.rounds)
		if room > len(rounds) {
			room = len(rounds)
		}
		r.roundsDropped += len(rounds) - room
		r.rounds = append(rounds[len(rounds)-room:], r.rounds...)
		r.mu.Unlock()
		return err
	}
	return nil
}

// Mitigation records the latest state of a threat mitigation rule. A
// record with an End closes the rule; one without is held until Close.
// Safe for concurrent use.
func (r *Recorder) Mitigation(m plugin.MitigationRecord) {
	if m.ID == "" || !m.Prefix.IsValid() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if m.End.IsZero() {
		r.openMits[m.ID] = m
	} else {
		delete(r.openMits, m.ID)
	}
	r.mits[m.ID] = m
}

// Anomaly records the latest state of a traffic anomaly (#33). A record
// with an End closes it; one without is held until Close. Safe for
// concurrent use.
func (r *Recorder) Anomaly(a plugin.AnomalyRecord) {
	if a.ID == "" || !a.Prefix.IsValid() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if a.End.IsZero() {
		r.openAnoms[a.ID] = a
	} else {
		delete(r.openAnoms, a.ID)
	}
	r.anoms[a.ID] = a
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

// rpkiGap is how long a path may be missing from the rounds before its
// span ends. A shorter gap (a prefix skipped for one round) continues the
// span instead of splitting it.
const rpkiGap = 5 * time.Minute

// RPKI records the origin-validation state of every learned path of the
// probed prefixes in one decision round (#200). A path whose state or
// answering source changed starts a new record; one no longer learned
// keeps its last record. Safe for concurrent use.
func (r *Recorder) RPKI(now time.Time, routes []RPKIRoute) {
	now = now.UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := make(map[rpkiKey]bool, len(routes))
	for _, rt := range routes {
		k := rpkiKey{prefix: rt.Prefix, provider: rt.Provider, origin: rt.Origin}
		seen[k] = true
		rec, ok := r.rpkiOpen[k]
		if !ok || rec.State != rt.Answer.State || rec.Source != rt.Answer.Source {
			rec = plugin.RPKIRouteRecord{Prefix: rt.Prefix, Provider: rt.Provider, Origin: rt.Origin,
				State: rt.Answer.State, Source: rt.Answer.Source, First: now}
		}
		rec.Last = now
		r.rpkiOpen[k] = rec
		rk := rpkiRow(rec)
		if _, pending := r.rpkiDirty[rk]; !pending && len(r.rpkiDirty) >= maxPending {
			r.rpkiDropped++
			continue
		}
		r.rpkiDirty[rk] = rec
	}
	for k, rec := range r.rpkiOpen {
		if !seen[k] && now.Sub(rec.Last) > rpkiGap {
			delete(r.rpkiOpen, k)
		}
	}
}

func rpkiRow(rec plugin.RPKIRouteRecord) rpkiRowKey {
	return rpkiRowKey{rpkiKey: rpkiKey{prefix: rec.Prefix, provider: rec.Provider, origin: rec.Origin}, first: rec.First.UnixMilli()}
}

// Decision records the improvement changes of one evaluation. results are
// the measurements the evaluation used; they give the before (native) and
// after (chosen provider) numbers.
// SetMode records the mode new improvement rows use. A reload that
// changes mode calls it. Open rows keep the mode they started with.
func (r *Recorder) SetMode(mode string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.opt.Mode = mode
	r.mu.Unlock()
}

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
				Mode: r.opt.Mode, Start: now, CostDelta: imp.CostDelta, EstSavings: imp.EstSavings, VolumeMbps: imp.VolumeMbps,
			}
			if rec.Cause == "" {
				rec.Cause = plugin.CausePerformance
			}
			if c.Explain != nil {
				if b, err := json.Marshal(c.Explain); err == nil {
					rec.Explain = string(b)
				}
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
	for _, m := range r.mits {
		b.Mitigations = append(b.Mitigations, m)
	}
	for _, a := range r.anoms {
		b.Anomalies = append(b.Anomalies, a)
	}
	for _, rec := range r.rpkiDirty {
		b.RPKIRoutes = append(b.RPKIRoutes, rec)
	}
	var ps []netip.Prefix
	for p := range r.prefixes {
		ps = append(ps, p)
	}
	r.buckets = map[bucketKey]*plugin.ProbeBucket{}
	r.dirty = map[string]plugin.ImprovementRecord{}
	r.mits = map[string]plugin.MitigationRecord{}
	r.anoms = map[string]plugin.AnomalyRecord{}
	r.rpkiDirty = map[rpkiRowKey]plugin.RPKIRouteRecord{}
	r.prefixes = map[netip.Prefix]bool{}
	if r.dropped > 0 {
		r.log.Warn("history: dropped probe rollups while the store was failing", "count", r.dropped)
		r.dropped = 0
	}
	if r.rpkiDropped > 0 {
		r.log.Warn("history: dropped RPKI route records over the pending cap", "count", r.rpkiDropped)
		r.rpkiDropped = 0
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
	for _, m := range b.Mitigations {
		if _, newer := r.mits[m.ID]; !newer {
			r.mits[m.ID] = m
		}
	}
	for _, a := range b.Anomalies {
		if _, newer := r.anoms[a.ID]; !newer {
			r.anoms[a.ID] = a
		}
	}
	for _, rec := range b.RPKIRoutes {
		k := rpkiRow(rec)
		if _, newer := r.rpkiDirty[k]; !newer && len(r.rpkiDirty) < maxPending {
			r.rpkiDirty[k] = rec
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
	if store, ok := r.providerStore(); ok {
		if err := r.opt.Series.Flush(ctx, store); err != nil {
			r.log.Warn("history: write provider samples", "err", err)
		}
	}
	roundsErr := r.flushRounds(ctx)
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
	if len(b.Buckets) == 0 && len(b.Improvements) == 0 && len(b.Prefixes) == 0 && len(b.Mitigations) == 0 && len(b.Anomalies) == 0 && len(b.RPKIRoutes) == 0 {
		return roundsErr
	}
	err := r.opt.Store.Write(ctx, b)
	if r.opt.OnWrite != nil {
		r.opt.OnWrite(err)
	}
	if err != nil {
		r.requeue(b, ps)
		return errors.Join(err, roundsErr)
	}
	return roundsErr
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
	mitByID := map[string]int{}
	for i, m := range h.Mitigations {
		mitByID[m.ID] = i
	}
	for id, m := range r.mits {
		if !m.Created.Before(to) || (!m.End.IsZero() && m.End.Before(from)) {
			if _, ok := mitByID[id]; !ok {
				continue
			}
		}
		if i, ok := mitByID[id]; ok {
			h.Mitigations[i] = m
		} else {
			h.Mitigations = append(h.Mitigations, m)
		}
	}
	anomByID := map[string]int{}
	for i, a := range h.Anomalies {
		anomByID[a.ID] = i
	}
	for id, a := range r.anoms {
		i, stored := anomByID[id]
		if !stored && (!a.Start.Before(to) || (!a.End.IsZero() && a.End.Before(from))) {
			continue
		}
		if stored {
			h.Anomalies[i] = a
		} else {
			h.Anomalies = append(h.Anomalies, a)
		}
	}
	rpkiIdx := map[rpkiRowKey]int{}
	for i, rec := range h.RPKIRoutes {
		rpkiIdx[rpkiRow(rec)] = i
	}
	for k, rec := range r.rpkiDirty {
		if i, ok := rpkiIdx[k]; ok {
			h.RPKIRoutes[i] = rec
		} else if rec.First.Before(to) && !rec.Last.Before(from) {
			h.RPKIRoutes = append(h.RPKIRoutes, rec)
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
	q.Exchanges = r.opt.Exchanges
	return Build(h, q)
}

// Prefix builds the stored history of one prefix for [q.From, q.To).
func (r *Recorder) Prefix(ctx context.Context, p netip.Prefix, q Query) (PrefixHistory, error) {
	h, err := r.History(ctx, q.From, q.To)
	if err != nil {
		return PrefixHistory{}, err
	}
	if q.Now.IsZero() {
		q.Now = r.opt.Now()
	}
	return BuildPrefix(h, p, q), nil
}

// Search finds the stored improvements and probe rollups that match q.
func (r *Recorder) Search(ctx context.Context, q SearchQuery) (SearchResult, error) {
	h, err := r.History(ctx, q.From, q.To)
	if err != nil {
		return SearchResult{}, err
	}
	return Search(h, q), nil
}
