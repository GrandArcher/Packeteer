package probe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Provider is a transit whose path is measured from Source.
type Provider struct {
	Name   string
	Source netip.Addr
}

// NamedProber is one entry of the ordered prober chain.
type NamedProber struct {
	Name   string
	Prober plugin.Prober
}

// NamedSource is one configured target source.
type NamedSource struct {
	Name   string
	Source plugin.TargetSource
}

// Limiter bounds the global packet rate. *rate.Limiter satisfies it.
type Limiter interface {
	WaitN(ctx context.Context, n int) error
}

// Options tune the engine.
type Options struct {
	Interval             time.Duration // time between rounds
	Timeout              time.Duration // per-packet timeout
	Packets              int           // packets per probe run
	Workers              int           // concurrent probe runs
	PerTargetConcurrency int           // concurrent runs toward one target host
	Limiter              Limiter       // nil: unlimited
	Logger               *slog.Logger
	Now                  func() time.Time
	// Sleep waits between rounds. Nil uses a timer. Tests set it so Run's
	// scheduler can be stepped without waiting on the wall clock.
	Sleep    func(context.Context, time.Duration) error
	OnResult func(Result) // called for every result (optional)
	OnRound  func()       // called after each completed round (optional)
	// RoundTimeout bounds one round, including target collection. Zero
	// derives a bound from the interval and the per-probe deadline. A round
	// that exceeds it keeps the previous results: a prober or target source
	// that ignores cancellation must not pin stale improvements forever.
	RoundTimeout time.Duration
	// RetryLossPct, when greater than zero, re-probes a path with
	// RetryPackets before the result is stored if loss is at least this
	// percent. Zero disables retry. The retry sample replaces the first.
	RetryLossPct float64
	RetryPackets int
}

// Result is the latest measurement of one provider toward one prefix.
type Result struct {
	Provider string       `json:"provider"`
	Prefix   netip.Prefix `json:"prefix"`
	Target   netip.Addr   `json:"target"`
	Prober   string       `json:"prober,omitempty"` // prober that produced Stats
	Stats    Stats        `json:"stats"`
	Err      string       `json:"error,omitempty"` // set when no measurement was possible
	Time     time.Time    `json:"time"`
}

// OK reports whether the result holds a measurement.
func (r Result) OK() bool { return r.Err == "" }

// ProviderStatus is the probe-source health of one provider.
type ProviderStatus struct {
	Name   string     `json:"name"`
	Source netip.Addr `json:"source"`
	Up     bool       `json:"up"`
	Reason string     `json:"reason,omitempty"`
	Since  time.Time  `json:"since"`
}

type key struct {
	provider string
	prefix   netip.Prefix
}

type job struct {
	provider Provider
	target   plugin.Target
}

// Engine runs probe rounds and stores the latest results.
type Engine struct {
	providers []Provider
	probers   []NamedProber
	sources   []NamedSource
	opt       Options
	log       *slog.Logger

	mu      sync.RWMutex
	results map[key]Result
	status  map[string]ProviderStatus
	// cadence is the probe interval per prefix from the last complete
	// target list. Positive target intervals override Options.Interval.
	cadence map[netip.Prefix]time.Duration
	// srcCache holds the last target list for sources that are not on a
	// shorter cadence than Options.Interval. A VIP wake does not start
	// those sources again.
	srcCache map[string]sourceSnap

	semMu sync.Mutex
	sems  map[netip.Addr]chan struct{}

	// stateMu guards probeBusy and srcBusy. A timed-out round leaves its
	// probes (or a target source that ignores cancellation) running, and
	// further rounds are skipped until that work returns, so a stuck
	// prober cannot pile up goroutines.
	stateMu   sync.Mutex
	probeBusy bool
	srcBusy   map[string]bool
}

// errSourceBusy is returned when a target source's previous call has not
// returned. The round is treated as incomplete and previous results stay.
var errSourceBusy = errors.New("previous call still running")

// sourceSnap is one source's last target list. fast is true when any
// target asked for a shorter interval than the engine, and that source
// is read on every wake.
type sourceSnap struct {
	at      time.Time
	targets []plugin.Target
	err     error
	fast    bool
}

// New validates inputs and returns an engine.
func New(providers []Provider, probers []NamedProber, sources []NamedSource, opt Options) (*Engine, error) {
	if len(providers) == 0 {
		return nil, errors.New("probe: no providers")
	}
	if len(probers) == 0 {
		return nil, errors.New("probe: no probers")
	}
	if opt.Packets < 1 || opt.Timeout <= 0 || opt.Interval <= 0 {
		return nil, errors.New("probe: packets, timeout and interval must be positive")
	}
	if opt.RetryLossPct < 0 || opt.RetryLossPct > 100 {
		return nil, errors.New("probe: retry loss percent must be between 0 and 100")
	}
	if opt.RetryLossPct > 0 && opt.RetryPackets < 1 {
		return nil, errors.New("probe: retry packets must be positive when retry is enabled")
	}
	if opt.Workers < 1 {
		opt.Workers = 1
	}
	if opt.PerTargetConcurrency < 1 {
		opt.PerTargetConcurrency = 1
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	e := &Engine{providers: providers, probers: probers, sources: sources, opt: opt, log: opt.Logger,
		results: map[key]Result{}, status: map[string]ProviderStatus{}, sems: map[netip.Addr]chan struct{}{}}
	now := opt.Now()
	for _, p := range providers {
		e.status[p.Name] = ProviderStatus{Name: p.Name, Source: p.Source, Up: true, Since: now}
	}
	return e, nil
}

// Run probes immediately and then whenever a prefix is due. A target
// with a positive Interval (the vip source) is measured on that cadence.
// Other targets use Options.Interval. Results for prefixes that are not
// due are left in place. Sources that do not carry a shorter interval are
// re-read on Options.Interval, not on every wake. A completed round,
// including one that only probed the shorter cadence, still calls OnRound.
// The global rate limit applies to every probe, including the shorter
// cadence and any retry. It returns ctx.Err().
func (e *Engine) Run(ctx context.Context) error {
	last := map[netip.Prefix]time.Time{}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		probed, done := e.runRound(ctx, func(t plugin.Target) bool {
			return e.targetDue(t, last)
		}, true)
		if err := ctx.Err(); err != nil {
			return err
		}
		if done {
			stamp := e.opt.Now()
			e.mu.RLock()
			cad := e.cadence
			e.mu.RUnlock()
			for p := range probed {
				last[p] = stamp
			}
			for p := range last {
				if _, ok := cad[p]; !ok {
					delete(last, p)
				}
			}
		}
		wait := e.opt.Interval
		if done {
			wait = e.wakeAfter(e.opt.Now(), last)
		}
		if wait < 0 {
			wait = 0
		}
		if err := e.sleep(ctx, wait); err != nil {
			return err
		}
	}
}

func (e *Engine) sleep(ctx context.Context, d time.Duration) error {
	if e.opt.Sleep != nil {
		return e.opt.Sleep(ctx, d)
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// targetDue reports whether prefix t should be probed now.
func (e *Engine) targetDue(t plugin.Target, last map[netip.Prefix]time.Time) bool {
	every := e.opt.Interval
	if t.Interval > 0 {
		every = t.Interval
	}
	prev, ok := last[t.Prefix]
	if !ok {
		return true
	}
	return !e.opt.Now().Before(prev.Add(every))
}

// wakeAfter is how long to sleep before the next prefix is due.
func (e *Engine) wakeAfter(now time.Time, last map[netip.Prefix]time.Time) time.Duration {
	e.mu.RLock()
	cad := e.cadence
	e.mu.RUnlock()
	if len(cad) == 0 {
		return e.opt.Interval
	}
	var next time.Time
	for p, every := range cad {
		if every <= 0 {
			every = e.opt.Interval
		}
		when := now
		if prev, ok := last[p]; ok {
			when = prev.Add(every)
		}
		if next.IsZero() || when.Before(next) {
			next = when
		}
	}
	if next.IsZero() {
		return e.opt.Interval
	}
	wait := next.Sub(now)
	if wait < 0 {
		return 0
	}
	return wait
}

// roundBudget is the overall deadline for one round. An explicit
// RoundTimeout wins; otherwise the bound is long enough for a probe to
// use its own deadline and for about three intervals of target collection,
// which matches how old a measurement may be before it is stale.
func (e *Engine) roundBudget() time.Duration {
	if e.opt.RoundTimeout > 0 {
		return e.opt.RoundTimeout
	}
	pkts := e.opt.Packets
	if e.opt.RetryLossPct > 0 {
		pkts += e.opt.RetryPackets
	}
	per := time.Duration(pkts)*e.opt.Timeout + time.Second
	d := 3*e.opt.Interval + per
	if d < per+time.Second {
		d = per + time.Second
	}
	return d
}

// Targets collects and de-duplicates targets from every source. A failing
// source is logged and skipped so the others keep working. The context's
// deadline is an overall timeout: a source that ignores cancellation does
// not block the caller past it.
func (e *Engine) Targets(ctx context.Context) []plugin.Target {
	ts, _ := e.gatherTargets(ctx)
	return ts
}

// gatherTargets reports incomplete when a source missed the deadline or is
// still stuck from an earlier call. Callers must not replace stored results
// in that case.
func (e *Engine) gatherTargets(ctx context.Context) ([]plugin.Target, bool) {
	seen := map[netip.Prefix]int{}
	var out []plugin.Target
	incomplete := false
	for _, s := range e.sources {
		if ctx.Err() != nil {
			incomplete = true
			break
		}
		ts, err, called := e.targetsFrom(ctx, s)
		if err != nil {
			if called {
				e.log.Warn("target source failed", "source", s.Name, "err", err)
			}
			if errors.Is(err, errSourceBusy) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				incomplete = true
				break
			}
			continue
		}
		for _, t := range ts {
			t.Prefix = t.Prefix.Masked()
			if !t.Prefix.IsValid() {
				continue
			}
			if !t.Host.IsValid() {
				t.Host = DefaultHost(t.Prefix)
			}
			// The first source keeps the host. A later source can only
			// shorten the interval. A stored interval of zero means the
			// engine interval, so a longer VIP interval does not slow a
			// prefix that static or flow already listed.
			if i, ok := seen[t.Prefix]; ok {
				e.shortenInterval(&out[i], t.Interval)
				continue
			}
			seen[t.Prefix] = len(out)
			out = append(out, t)
		}
	}
	return out, incomplete
}

// shortenInterval sets dst.Interval when next is a strictly shorter
// cadence. Zero on either side means Options.Interval.
func (e *Engine) shortenInterval(dst *plugin.Target, next time.Duration) {
	want := next
	if want <= 0 {
		want = e.opt.Interval
	}
	cur := dst.Interval
	if cur <= 0 {
		cur = e.opt.Interval
	}
	if want >= cur {
		return
	}
	if next > 0 {
		dst.Interval = next
		return
	}
	dst.Interval = 0
}

// targetsFrom returns a cached target list for sources that are not on a
// shorter cadence. called is false when the cache was used. A deadline or
// a stuck source is not cached.
func (e *Engine) targetsFrom(ctx context.Context, s NamedSource) (ts []plugin.Target, err error, called bool) {
	if c, ok := e.loadSource(s.Name); ok {
		return c.targets, c.err, false
	}
	ts, err = e.oneSource(ctx, s)
	called = true
	if err != nil && (errors.Is(err, errSourceBusy) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)) {
		return nil, err, true
	}
	e.storeSource(s.Name, ts, err)
	return ts, err, true
}

func (e *Engine) loadSource(name string) (sourceSnap, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	c, ok := e.srcCache[name]
	if !ok || c.fast {
		return sourceSnap{}, false
	}
	if !e.opt.Now().Before(c.at.Add(e.opt.Interval)) {
		return sourceSnap{}, false
	}
	c.targets = cloneTargets(c.targets)
	return c, true
}

func (e *Engine) storeSource(name string, ts []plugin.Target, err error) {
	fast := false
	for _, t := range ts {
		if t.Interval > 0 && t.Interval < e.opt.Interval {
			fast = true
			break
		}
	}
	e.mu.Lock()
	if e.srcCache == nil {
		e.srcCache = map[string]sourceSnap{}
	}
	e.srcCache[name] = sourceSnap{at: e.opt.Now(), targets: cloneTargets(ts), err: err, fast: fast}
	e.mu.Unlock()
}

func cloneTargets(in []plugin.Target) []plugin.Target {
	if len(in) == 0 {
		return nil
	}
	out := make([]plugin.Target, len(in))
	copy(out, in)
	return out
}

func (e *Engine) oneSource(ctx context.Context, s NamedSource) ([]plugin.Target, error) {
	e.stateMu.Lock()
	if e.srcBusy == nil {
		e.srcBusy = map[string]bool{}
	}
	if e.srcBusy[s.Name] {
		e.stateMu.Unlock()
		return nil, errSourceBusy
	}
	e.srcBusy[s.Name] = true
	e.stateMu.Unlock()

	type result struct {
		ts  []plugin.Target
		err error
	}
	ch := make(chan result, 1)
	go func() {
		ts, err := s.Source.Targets(ctx)
		ch <- result{ts, err}
	}()
	select {
	case r := <-ch:
		e.clearSource(s.Name)
		return r.ts, r.err
	case <-ctx.Done():
		go func() {
			<-ch
			e.clearSource(s.Name)
		}()
		return nil, ctx.Err()
	}
}

func (e *Engine) clearSource(name string) {
	e.stateMu.Lock()
	delete(e.srcBusy, name)
	e.stateMu.Unlock()
}

func (e *Engine) setProbeBusy(busy bool) {
	e.stateMu.Lock()
	e.probeBusy = busy
	e.stateMu.Unlock()
}

func (e *Engine) probesBusy() bool {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	return e.probeBusy
}

// RunOnce performs one probe round over all providers and targets.
// The round has an overall deadline. If it expires, or a target source
// does not return, previous results are kept and OnRound is not called.
// RunOnce ignores per-target intervals and measures every target.
func (e *Engine) RunOnce(ctx context.Context) {
	_, _ = e.runRound(ctx, nil, false)
}

// runRound probes targets. allow, when non-nil, selects which gathered
// targets are probed; the others keep their stored results (merge).
// probed is the set of prefixes this call attempted. done is false when
// the round was skipped or abandoned, in which case stored results and
// the caller's schedule must stay as they were.
func (e *Engine) runRound(ctx context.Context, allow func(plugin.Target) bool, merge bool) (probed map[netip.Prefix]struct{}, done bool) {
	if e.probesBusy() {
		e.log.Debug("previous probe round still running; skipping")
		return nil, false
	}
	roundCtx, cancel := context.WithTimeout(ctx, e.roundBudget())
	defer cancel()

	targets, incomplete := e.gatherTargets(roundCtx)
	if incomplete || roundCtx.Err() != nil {
		if ctx.Err() == nil {
			e.log.Warn("probe round timed out listing targets; keeping previous results")
		}
		return nil, false
	}
	e.noteCadence(targets)
	keep := map[netip.Prefix]bool{}
	var jobs []job
	for _, t := range targets {
		keep[t.Prefix] = true
		if allow != nil && !allow(t) {
			continue
		}
		if probed == nil {
			probed = map[netip.Prefix]struct{}{}
		}
		probed[t.Prefix] = struct{}{}
		for _, p := range e.providers {
			if p.Source.Is4() != t.Host.Is4() {
				continue // provider cannot reach this address family
			}
			jobs = append(jobs, job{provider: p, target: t})
		}
	}
	// Targets exist but none are due. Keep stored results and let the
	// scheduler sleep. A prefix that left every source is still dropped,
	// which is the completed round CONFIG.md describes.
	if allow != nil && len(probed) == 0 && len(targets) > 0 {
		if e.droppedAny(keep) {
			e.commit(nil, nil, nil, keep, true)
			if e.opt.OnRound != nil {
				e.opt.OnRound()
			}
		}
		return probed, true
	}

	ch := make(chan job)
	type outcome struct {
		res        Result
		sourceDown bool
	}
	outs := make(chan outcome, len(jobs))
	var wg sync.WaitGroup
	for i := 0; i < e.opt.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				if roundCtx.Err() != nil {
					return
				}
				r, down := e.probe(roundCtx, j)
				select {
				case outs <- outcome{r, down}:
				case <-roundCtx.Done():
					return
				}
			}
		}()
	}
feed:
	for _, j := range jobs {
		select {
		case ch <- j:
		case <-roundCtx.Done():
			break feed
		}
	}
	close(ch)

	finished := make(chan struct{})
	go func() {
		wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-roundCtx.Done():
		e.leaveProbes(finished)
		if ctx.Err() == nil {
			e.log.Warn("probe round timed out; keeping previous results")
		}
		return nil, false
	}
	if roundCtx.Err() != nil {
		// Workers exited because the deadline fired. Do not commit a partial round.
		if ctx.Err() == nil {
			e.log.Warn("probe round timed out; keeping previous results")
		}
		return nil, false
	}
	close(outs)

	down := map[string]string{}
	ran := map[string]bool{}
	fresh := map[key]Result{}
	for o := range outs {
		ran[o.res.Provider] = true
		if o.sourceDown {
			down[o.res.Provider] = o.res.Err
		}
		fresh[key{o.res.Provider, o.res.Prefix}] = o.res
		if e.opt.OnResult != nil {
			e.opt.OnResult(o.res)
		}
	}

	e.commit(fresh, ran, down, keep, merge)
	if e.opt.OnRound != nil {
		e.opt.OnRound()
	}
	return probed, true
}

// droppedAny reports whether a stored result belongs to a prefix that is
// no longer in the target list.
func (e *Engine) droppedAny(keep map[netip.Prefix]bool) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for k := range e.results {
		if !keep[k.prefix] {
			return true
		}
	}
	return false
}

func (e *Engine) noteCadence(targets []plugin.Target) {
	m := make(map[netip.Prefix]time.Duration, len(targets))
	for _, t := range targets {
		every := e.opt.Interval
		if t.Interval > 0 {
			every = t.Interval
		}
		m[t.Prefix] = every
	}
	e.mu.Lock()
	e.cadence = m
	e.mu.Unlock()
}

// leaveProbes records that workers from a timed-out round may still be
// inside a prober that ignores cancellation. The next round waits until
// they return instead of starting another.
func (e *Engine) leaveProbes(finished <-chan struct{}) {
	select {
	case <-finished:
		return
	default:
	}
	e.setProbeBusy(true)
	go func() {
		<-finished
		e.setProbeBusy(false)
	}()
}

func (e *Engine) commit(fresh map[key]Result, ran map[string]bool, down map[string]string, keep map[netip.Prefix]bool, merge bool) {
	now := e.opt.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	if !merge {
		e.results = fresh
	} else {
		if e.results == nil {
			e.results = map[key]Result{}
		}
		for k, r := range fresh {
			e.results[k] = r
		}
		for k := range e.results {
			if !keep[k.prefix] {
				delete(e.results, k)
			}
		}
	}
	for _, p := range e.providers {
		if !ran[p.Name] {
			continue
		}
		st := e.status[p.Name]
		reason, isDown := down[p.Name]
		if st.Up == !isDown {
			continue
		}
		st.Up, st.Reason, st.Since = !isDown, reason, now
		if isDown {
			e.log.Error("probe source down; provider excluded (fail closed)", "provider", p.Name, "source", p.Source, "reason", reason)
		} else {
			e.log.Info("probe source recovered", "provider", p.Name, "source", p.Source)
		}
		e.status[p.Name] = st
	}
}

func (e *Engine) sem(a netip.Addr) chan struct{} {
	e.semMu.Lock()
	defer e.semMu.Unlock()
	s, ok := e.sems[a]
	if !ok {
		s = make(chan struct{}, e.opt.PerTargetConcurrency)
		e.sems[a] = s
	}
	return s
}

// probe runs the prober chain for one job. Chain semantics: try probers in
// order; move on when a prober errors or gets no replies; stop immediately
// (fail closed) if the source address is unusable.
func (e *Engine) probe(ctx context.Context, j job) (Result, bool) {
	res := Result{Provider: j.provider.Name, Prefix: j.target.Prefix, Target: j.target.Host}
	sem := e.sem(j.target.Host)
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		res.Err, res.Time = ctx.Err().Error(), e.opt.Now()
		return res, false
	}
	defer func() { <-sem }()

	req := plugin.ProbeRequest{Provider: j.provider.Name, Source: j.provider.Source,
		Target: j.target.Host, Count: e.opt.Packets, Timeout: e.opt.Timeout}
	var errs []error
	var fallback *Result
	var fallbackProber plugin.Prober
	for _, p := range e.probers {
		if e.opt.Limiter != nil {
			if err := e.opt.Limiter.WaitN(ctx, e.opt.Packets); err != nil {
				errs = append(errs, fmt.Errorf("rate limit: %w", err))
				break
			}
		}
		pctx, cancel := context.WithTimeout(ctx, time.Duration(e.opt.Packets)*e.opt.Timeout+time.Second)
		raw, err := p.Prober.Probe(pctx, req)
		cancel()
		if err != nil {
			if errors.Is(err, plugin.ErrSourceUnavailable) {
				res.Err, res.Time = fmt.Sprintf("%s: %v", p.Name, err), e.opt.Now()
				return res, true
			}
			errs = append(errs, fmt.Errorf("%s: %w", p.Name, err))
			continue
		}
		r := res
		r.Prober, r.Stats, r.Time = p.Name, Compute(raw), e.opt.Now()
		if r.Stats.Received > 0 {
			return e.retryLoss(ctx, r, p.Prober, j.provider.Source)
		}
		if fallback == nil {
			cp := r
			fallback = &cp // full loss: remember, but try the next prober
			fallbackProber = p.Prober
		}
	}
	if fallback != nil {
		return e.retryLoss(ctx, *fallback, fallbackProber, j.provider.Source)
	}
	res.Err, res.Time = errors.Join(errs...).Error(), e.opt.Now()
	return res, false
}

// retryLoss re-measures a high-loss result with more packets before it
// is stored. The retry sample replaces the first. A rate-limit or probe
// error keeps the first sample; a dead source still fails closed.
func (e *Engine) retryLoss(ctx context.Context, res Result, prober plugin.Prober, source netip.Addr) (Result, bool) {
	if e.opt.RetryLossPct <= 0 || !res.OK() || res.Stats.LossPct < e.opt.RetryLossPct || prober == nil {
		return res, false
	}
	count := e.opt.RetryPackets
	if e.opt.Limiter != nil {
		if err := e.opt.Limiter.WaitN(ctx, count); err != nil {
			e.log.Debug("retry skipped", "provider", res.Provider, "prefix", res.Prefix, "err", err)
			return res, false
		}
	}
	pctx, cancel := context.WithTimeout(ctx, time.Duration(count)*e.opt.Timeout+time.Second)
	defer cancel()
	raw, err := prober.Probe(pctx, plugin.ProbeRequest{
		Provider: res.Provider, Source: source, Target: res.Target, Count: count, Timeout: e.opt.Timeout,
	})
	if err != nil {
		if errors.Is(err, plugin.ErrSourceUnavailable) {
			res.Err = fmt.Sprintf("%s: %v", res.Prober, err)
			res.Time = e.opt.Now()
			res.Stats = Stats{}
			return res, true
		}
		e.log.Debug("retry failed; keeping first sample", "provider", res.Provider, "prefix", res.Prefix, "err", err)
		return res, false
	}
	e.log.Debug("retry probe", "provider", res.Provider, "prefix", res.Prefix, "loss_pct", res.Stats.LossPct, "packets", count)
	res.Stats = Compute(raw)
	res.Time = e.opt.Now()
	return res, false
}

// Results returns the latest results sorted by prefix, then provider.
func (e *Engine) Results() []Result {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Result, 0, len(e.results))
	for _, r := range e.results {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].Prefix.Addr().Compare(out[j].Prefix.Addr()); c != 0 {
			return c < 0
		}
		if out[i].Prefix.Bits() != out[j].Prefix.Bits() {
			return out[i].Prefix.Bits() < out[j].Prefix.Bits()
		}
		return out[i].Provider < out[j].Provider
	})
	return out
}

// Providers returns probe-source status per provider, in config order.
func (e *Engine) Providers() []ProviderStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]ProviderStatus, 0, len(e.providers))
	for _, p := range e.providers {
		out = append(out, e.status[p.Name])
	}
	return out
}
