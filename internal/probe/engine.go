package probe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Provider is a transit whose path is measured from Source.
type Provider struct {
	Name   string
	Source netip.Addr
	// NextHop is the provider's far-side gateway, the hop just past the
	// edge toward this provider. Zero means it is not known. It is a probe
	// target only: it is not a new provider and nothing is announced to it.
	NextHop netip.Addr
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
	// that exceeds it stores prefixes whose probes all finished and leaves
	// the rest as they were: a prober or target source that ignores
	// cancellation must not refresh a prefix it did not finish, and must
	// not discard prefixes that did finish.
	RoundTimeout time.Duration
	// RetryLossPct, when greater than zero, re-probes a path with
	// RetryPackets before the result is stored if loss is at least this
	// percent. Zero disables loss retry. The retry sample replaces the
	// first. Dispersion over the limit escalates the same way when
	// RetryPackets is positive.
	RetryLossPct float64
	RetryPackets int
	// MinReplies is how many replies a host needs before it can define
	// the score. Zero uses 1, so any reply counts. Fewer replies are
	// left out the way a silent host is.
	MinReplies int
	// Dispersion is the maximum RTT spread (max reply minus min reply)
	// for a host that defines the score. Zero disables the check. A
	// wider spread is left out the way a silent host is, and the prefix
	// is probed again with RetryPackets.
	Dispersion time.Duration
	// ProberRecheckRounds is how often a host is probed from the first
	// prober again. Probe 1, N+1, 2N+1, ... start at the chain head. The
	// others start at the prober that last got a reply from that host
	// and move only forward. Zero uses DefaultProberRecheckRounds.
	// One means every probe starts at the chain head.
	ProberRecheckRounds int
	// ProberMemory caps how many hosts keep a remembered prober. Zero
	// uses DefaultProberMemory. Hosts that leave the target set are
	// dropped. Past the cap, the least recently probed hosts are dropped.
	ProberMemory int
	// ExchangeLANs are peering LANs (#145). A prefix inside one, or a
	// pinned host on one, is not probed. A provider next hop on a LAN
	// stays the far-side gateway probe. Nil leaves every target alone.
	ExchangeLANs []netip.Prefix
	// Indirect, when set, traces a prefix whose in-prefix addresses are
	// all silent from each provider's source and scores that provider at
	// its own highest stable hop (#123). Nil disables it.
	Indirect *Indirect
}

// Result is the latest measurement of one provider toward one prefix.
type Result struct {
	Provider string       `json:"provider"`
	Prefix   netip.Prefix `json:"prefix"`
	Target   netip.Addr   `json:"target"`
	// Targets is every address probed for this provider and prefix, in
	// the order they were tried. Target is the one that defined the score.
	Targets []netip.Addr `json:"targets,omitempty"`
	Prober  string       `json:"prober,omitempty"` // prober that produced Stats
	Stats   Stats        `json:"stats"`
	Err     string       `json:"error,omitempty"` // set when no measurement was possible
	Time    time.Time    `json:"time"`
	// Subranges, when the target carried two or more (#121), are the
	// per-sub-range measurements. Stats is then their traffic-weighted
	// aggregate. Measurement only.
	Subranges []SubrangeResult `json:"subranges,omitempty"`
	// Indirect is true when every address inside the prefix was silent
	// and Target is this provider's highest stable traceroute hop toward
	// it (#123). Measurement only.
	Indirect bool `json:"indirect,omitempty"`
	// Hops is the stable traceroute hop addresses, in TTL order, from this
	// provider's indirect trace (#124). Empty when no trace is cached.
	// Outage detection maps them to origin ASNs. Measurement only.
	Hops []netip.Addr `json:"hops,omitempty"`
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
	hosts    []netip.Addr
	subs     []plugin.Subrange
}

// Engine runs probe rounds and stores the latest results.
type Engine struct {
	providers []Provider
	probers   []NamedProber
	sources   []NamedSource
	opt       Options
	// sched overrides interval, timeout, packets, and loss-retry timing
	// after a reload (#128). Nil keeps Options, which tests mutate directly.
	sched atomic.Pointer[Timing]
	log   *slog.Logger

	mu      sync.RWMutex
	results map[key]Result
	status  map[string]ProviderStatus
	// cadence is the probe interval per prefix from the last complete
	// target list. Positive target intervals override Options.Interval.
	cadence map[netip.Prefix]time.Duration
	// memory is the last host and interval a configured source submitted
	// for a prefix. retained is the decision state's active improvements
	// (#116): those prefixes stay in the probe set after every configured
	// source drops them. Both are guarded by mu.
	memory   map[netip.Prefix]plugin.Target
	retained map[netip.Prefix]struct{}
	// urgent is the decision state's half-confirmed prefixes (#117).
	// They are probed after a quarter of their interval instead of
	// waiting out the whole interval. A source that sets Target.Urgent
	// still probes on this round. The global rate limit still applies.
	// An empty set clears the mark. Guarded by mu.
	urgent map[netip.Prefix]struct{}
	// probedAt is when Run last probed the prefix. SetUrgent uses it so
	// a confirm streak does not wake the scheduler before the quarter-
	// interval gap. Guarded by mu.
	probedAt map[netip.Prefix]time.Time
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

	// wake is a one-slot signal. OnRound calls Wake when a detector has
	// new prefixes so sleep returns without waiting out the interval.
	wake chan struct{}

	// prefixCommits counts prefixes whose results were stored, once per
	// prefix per round that stored at least one of that prefix's results.
	// The load test turns this into active prefixes measured per hour (#125).
	prefixCommits atomic.Uint64

	// proberMem remembers which prober got a reply from a host. proberPlan
	// is the chain start chosen for the current round (one per host, shared
	// by providers and by a loss retry). proberNote is the latest chain
	// index that got a reply this round. All three are guarded by mu.
	proberMem  map[netip.Addr]proberSlot
	proberPlan map[netip.Addr]int
	proberNote map[netip.Addr]int
	memTick    uint64

	// indMu guards the indirect hop cache and trace queue (#123).
	// indWake starts a background pass.
	indMu     sync.Mutex
	indCache  map[key]indirectHop
	indQueued map[key]indirectReq
	indOrder  []key
	indWake   chan struct{}
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
	if opt.MinReplies == 0 {
		opt.MinReplies = 1
	}
	if opt.MinReplies < 1 || opt.MinReplies > 1000 {
		return nil, fmt.Errorf("probe: min replies %d must be between 1 and 1000", opt.MinReplies)
	}
	if opt.Dispersion < 0 {
		return nil, errors.New("probe: dispersion must not be negative")
	}
	if opt.ProberRecheckRounds == 0 {
		opt.ProberRecheckRounds = DefaultProberRecheckRounds
	}
	if opt.ProberRecheckRounds < 1 || opt.ProberRecheckRounds > MaxProberRecheckRounds {
		return nil, fmt.Errorf("probe: prober recheck rounds %d must be between 1 and %d", opt.ProberRecheckRounds, MaxProberRecheckRounds)
	}
	if opt.ProberMemory == 0 {
		opt.ProberMemory = DefaultProberMemory
	}
	if opt.ProberMemory < 1 || opt.ProberMemory > MaxProberMemory {
		return nil, fmt.Errorf("probe: prober memory %d must be between 1 and %d", opt.ProberMemory, MaxProberMemory)
	}
	if err := validIndirect(opt.Indirect); err != nil {
		return nil, err
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
	if len(opt.ExchangeLANs) > 0 {
		opt.ExchangeLANs = append([]netip.Prefix(nil), opt.ExchangeLANs...)
	}
	e := &Engine{providers: providers, probers: probers, sources: sources, opt: opt, log: opt.Logger,
		results: map[key]Result{}, status: map[string]ProviderStatus{}, sems: map[netip.Addr]chan struct{}{},
		wake: make(chan struct{}, 1), indCache: map[key]indirectHop{}, indQueued: map[key]indirectReq{},
		indWake: make(chan struct{}, 1)}
	now := opt.Now()
	for _, p := range providers {
		e.status[p.Name] = ProviderStatus{Name: p.Name, Source: p.Source, Up: true, Since: now}
	}
	return e, nil
}

// Timing is the probe timing a reload can change while the engine runs.
// Workers, the rate limit, dispersion, and indirect tracing stay on Options
// and still need a restart.
type Timing struct {
	Interval     time.Duration
	Timeout      time.Duration
	Packets      int
	RetryLossPct float64
	RetryPackets int
	RoundTimeout time.Duration
}

// SetTiming replaces the timing the next round uses and wakes Run.
func (e *Engine) SetTiming(t Timing) {
	if e == nil {
		return
	}
	e.sched.Store(&t)
	e.Wake()
}

// TimingNow is the timing the engine probes with.
func (e *Engine) TimingNow() Timing {
	if e == nil {
		return Timing{}
	}
	return e.live()
}

func (e *Engine) live() Timing {
	if p := e.sched.Load(); p != nil {
		return *p
	}
	return Timing{
		Interval: e.opt.Interval, Timeout: e.opt.Timeout, Packets: e.opt.Packets,
		RetryLossPct: e.opt.RetryLossPct, RetryPackets: e.opt.RetryPackets,
		RoundTimeout: e.opt.RoundTimeout,
	}
}

func (e *Engine) interval() time.Duration     { return e.live().Interval }
func (e *Engine) timeout() time.Duration      { return e.live().Timeout }
func (e *Engine) packets() int                { return e.live().Packets }
func (e *Engine) retryLoss() float64          { return e.live().RetryLossPct }
func (e *Engine) retryPackets() int           { return e.live().RetryPackets }
func (e *Engine) roundTimeout() time.Duration { return e.live().RoundTimeout }

// SetSources replaces the target sources. Removed names drop their target
// cache. Unchanged sources keep the engine's last list until the cache
// expires. Caller starts and stops the plugins.
func (e *Engine) SetSources(sources []NamedSource) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sources = append([]NamedSource(nil), sources...)
	if len(e.srcCache) == 0 {
		return
	}
	keep := map[string]bool{}
	for _, s := range sources {
		keep[s.Name] = true
	}
	for name := range e.srcCache {
		if !keep[name] {
			delete(e.srcCache, name)
		}
	}
}

func (e *Engine) sourceList() []NamedSource {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]NamedSource, len(e.sources))
	copy(out, e.sources)
	return out
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
	if e.indirectEnabled() {
		ictx, cancel := context.WithCancel(ctx)
		defer cancel()
		go e.runIndirect(ictx)
	}
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
			e.mu.Lock()
			for p := range last {
				if _, ok := cad[p]; !ok {
					delete(last, p)
					delete(e.probedAt, p)
				}
			}
			e.mu.Unlock()
		}
		wait := e.interval()
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

// Wake asks Run to start the next round without waiting out the interval.
// The outage source calls it from OnRound when a new incident re-queues
// prefixes. One pending wake is enough; extra calls are dropped.
func (e *Engine) Wake() {
	if e == nil || e.wake == nil {
		return
	}
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

func (e *Engine) consumeWake() bool {
	if e == nil || e.wake == nil {
		return false
	}
	select {
	case <-e.wake:
		return true
	default:
		return false
	}
}

func (e *Engine) sleep(ctx context.Context, d time.Duration) error {
	if e.consumeWake() {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
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
	case <-e.wake:
		return nil
	}
}

// targetDue reports whether prefix t should be probed now. Urgent from a
// source is a one-shot and is due immediately; the interval still applies
// on the following rounds. Urgent from SetUrgent (a confirm streak) waits
// a quarter of the prefix interval so consecutive rounds are not the same
// instant.
func (e *Engine) targetDue(t plugin.Target, last map[netip.Prefix]time.Time) bool {
	every := e.interval()
	if t.Interval > 0 {
		every = t.Interval
	}
	if t.Urgent && !e.decisionUrgent(t.Prefix) {
		return true
	}
	if t.Urgent && e.decisionUrgent(t.Prefix) {
		every = confirmProbeGap(every)
	}
	prev, ok := last[t.Prefix]
	if !ok {
		return true
	}
	return !e.opt.Now().Before(prev.Add(every))
}

// confirmProbeGap is the minimum time between probes of a prefix a
// half-confirmed performance move asked to measure early. It is a quarter
// of that prefix's interval.
func confirmProbeGap(every time.Duration) time.Duration {
	if every <= 0 {
		return 0
	}
	g := every / 4
	if g <= 0 {
		return every
	}
	return g
}

// wakeAfter is how long to sleep before the next prefix is due. A
// confirm-urgent prefix is due after a quarter of its interval.
func (e *Engine) wakeAfter(now time.Time, last map[netip.Prefix]time.Time) time.Duration {
	e.mu.RLock()
	cad := e.cadence
	urgent := e.urgent
	e.mu.RUnlock()
	if len(cad) == 0 {
		return e.interval()
	}
	var next time.Time
	for p, every := range cad {
		if every <= 0 {
			every = e.interval()
		}
		when := now
		if prev, ok := last[p]; ok {
			when = prev.Add(every)
		}
		if _, ok := urgent[p]; ok {
			gapWhen := now
			if prev, ok := last[p]; ok {
				gapWhen = prev.Add(confirmProbeGap(every))
			}
			if gapWhen.Before(when) {
				when = gapWhen
			}
		}
		if next.IsZero() || when.Before(next) {
			next = when
		}
	}
	if next.IsZero() {
		return e.interval()
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
	if e.roundTimeout() > 0 {
		return e.roundTimeout()
	}
	pkts := e.packets() + e.retryExtra()
	per := time.Duration(pkts)*e.timeout() + time.Second
	d := 3*e.interval() + per
	if d < per+time.Second {
		d = per + time.Second
	}
	return d
}

// retryExtra is how many packets a second probe may add. Loss retry and
// dispersion escalation both use RetryPackets, and both count toward the
// same staleness window: 3*interval + (packets + retryPackets)*timeout.
// The round deadline adds one more second on top of that product.
func (e *Engine) retryExtra() int {
	if e.retryPackets() < 1 {
		return 0
	}
	if e.retryLoss() > 0 || e.opt.Dispersion > 0 {
		return e.retryPackets()
	}
	return 0
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
	for _, s := range e.sourceList() {
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
			// A named host is a pin, unless the source marked it as a
			// candidate (a flow destination). An empty host stays the
			// representative address for scheduling, and the probe round
			// spreads it. Candidates are probed first and are not the
			// only addresses.
			t = normalizeTarget(t)
			// The first explicit host stays. A later pin replaces a
			// default or a candidate. A later candidate replaces only a
			// default. A later source can shorten the interval. A stored
			// interval of zero means the engine interval, so a longer VIP
			// interval does not slow a prefix that static or flow already
			// listed.
			if i, ok := seen[t.Prefix]; ok {
				e.shortenInterval(&out[i], t.Interval)
				if t.Urgent {
					out[i].Urgent = true
				}
				if t.Pinned && !out[i].Pinned {
					out[i].Host = t.Host
					out[i].Hosts = nil
					out[i].Subranges = nil
					out[i].Pinned = true
					out[i].Candidate = false
				} else if !out[i].Pinned && !out[i].Candidate && t.Candidate {
					out[i].Host = t.Host
					out[i].Hosts = append([]netip.Addr(nil), t.Hosts...)
					out[i].Candidate = true
				}
				// Sub-ranges come from the first source that named
				// them, unless a pin now owns the prefix.
				if !out[i].Pinned && len(out[i].Subranges) == 0 && len(t.Subranges) > 0 {
					out[i].Subranges = append([]plugin.Subrange(nil), t.Subranges...)
				}
				continue
			}
			seen[t.Prefix] = len(out)
			out = append(out, t)
		}
	}
	// A timed-out source leaves a partial list. Do not treat that as the
	// prefixes that still exist, and do not drop a remembered host.
	if !incomplete {
		e.keepImproved(&out)
		e.applyUrgent(&out)
		e.dropExchangeLANs(&out)
	}
	return out, incomplete
}

// dropExchangeLANs removes prefixes and pinned hosts that sit on a peering
// LAN after keepImproved, so a retained improvement cannot bring one back.
func (e *Engine) dropExchangeLANs(out *[]plugin.Target) {
	if out == nil || len(e.opt.ExchangeLANs) == 0 || len(*out) == 0 {
		return
	}
	before := *out
	next := exchange.FilterNormalized(e.opt.ExchangeLANs, before)
	if sameTargetSlice(before, next) {
		return
	}
	if len(next) < len(before) {
		e.log.Info("dropped probe targets inside an exchange LAN", "before", len(before), "after", len(next))
	}
	*out = next
}

func sameTargetSlice(a, b []plugin.Target) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	return &a[0] == &b[0]
}

// SetUrgent replaces the prefixes a half-confirmed performance move wants
// measured before the full probe interval elapses (#117). An empty list
// clears the set. A non-empty list wakes Run only when one of those
// prefixes is already due: a quarter of its interval since it was last
// probed. Waking sooner would probe the same sample back to back. Safe
// for concurrent use with probing. Every probe, urgent or not, still
// waits on Options.Limiter (probe.rate_limit_pps).
func (e *Engine) SetUrgent(prefixes []netip.Prefix) {
	if e == nil {
		return
	}
	next := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, p := range prefixes {
		p = p.Masked()
		if !p.IsValid() {
			continue
		}
		next[p] = struct{}{}
	}
	e.mu.Lock()
	e.urgent = next
	due := e.urgentDueLocked(next)
	e.mu.Unlock()
	if due {
		e.Wake()
	}
}

// urgentDueLocked reports whether any prefix in next may be probed now.
// The caller holds e.mu.
func (e *Engine) urgentDueLocked(next map[netip.Prefix]struct{}) bool {
	if len(next) == 0 {
		return false
	}
	now := e.opt.Now()
	for p := range next {
		prev, ok := e.probedAt[p]
		if !ok || !now.Before(prev.Add(confirmProbeGap(e.prefixIntervalLocked(p)))) {
			return true
		}
	}
	return false
}

// prefixIntervalLocked is the prefix's probe interval. The caller holds e.mu.
func (e *Engine) prefixIntervalLocked(p netip.Prefix) time.Duration {
	if e.cadence != nil {
		if every, ok := e.cadence[p]; ok && every > 0 {
			return every
		}
	}
	return e.interval()
}

// decisionUrgent reports whether p was marked by SetUrgent.
func (e *Engine) decisionUrgent(p netip.Prefix) bool {
	if e == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.urgent[p]
	return ok
}

// rememberProbes stamps prefixes this round actually probed, before
// OnRound, so SetUrgent can see that the quarter-interval gap has not
// elapsed yet.
func (e *Engine) rememberProbes(probed map[netip.Prefix]struct{}) {
	if e == nil || len(probed) == 0 {
		return
	}
	now := e.opt.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.probedAt == nil {
		e.probedAt = map[netip.Prefix]time.Time{}
	}
	for p := range probed {
		e.probedAt[p] = now
	}
}

// applyUrgent sets Urgent on targets the decision state is confirming.
// It does not add a prefix a source did not list: confirmation only
// re-measures a prefix already being probed.
func (e *Engine) applyUrgent(out *[]plugin.Target) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.urgent) == 0 || out == nil {
		return
	}
	for i := range *out {
		if _, ok := e.urgent[(*out)[i].Prefix]; ok {
			(*out)[i].Urgent = true
		}
	}
}

// shortenInterval sets dst.Interval when next is a strictly shorter
// cadence. Zero on either side means Options.Interval.
func (e *Engine) shortenInterval(dst *plugin.Target, next time.Duration) {
	want := next
	if want <= 0 {
		want = e.interval()
	}
	cur := dst.Interval
	if cur <= 0 {
		cur = e.interval()
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

// freshTargetSource is a target source whose list changes because of a
// probe round or a RIB read and must not be cached for Options.Interval.
// The outage source is fresh. static, flow, traceroute, and vip are not:
// vip is re-read when it carries a shorter interval, which the cache
// already treats as fast.
type freshTargetSource interface {
	Fresh() bool
}

func sourceFresh(s plugin.TargetSource) bool {
	f, ok := s.(freshTargetSource)
	return ok && f.Fresh()
}

// targetsFrom returns a cached target list for sources that are not on a
// shorter cadence and are not fresh. called is false when the cache was
// used. A deadline or a stuck source is not cached.
func (e *Engine) targetsFrom(ctx context.Context, s NamedSource) (ts []plugin.Target, err error, called bool) {
	if !sourceFresh(s.Source) {
		if c, ok := e.loadSource(s.Name); ok {
			return c.targets, c.err, false
		}
	}
	ts, err = e.oneSource(ctx, s)
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
	if !e.opt.Now().Before(c.at.Add(e.interval())) {
		return sourceSnap{}, false
	}
	c.targets = cloneTargets(c.targets)
	return c, true
}

func (e *Engine) storeSource(name string, ts []plugin.Target, err error) {
	fast := false
	for _, t := range ts {
		if t.Interval > 0 && t.Interval < e.interval() {
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
// The round has an overall deadline. A complete round stores every result
// together. If the deadline expires first, only prefixes whose provider
// probes all finished are stored, each prefix whole, and unfinished
// prefixes keep their previous results. If a target source does not
// return, nothing changes. OnRound is not called unless a prefix was stored.
// RunOnce ignores per-target intervals and measures every target.
func (e *Engine) RunOnce(ctx context.Context) {
	_, _ = e.runRound(ctx, nil, false)
}

// runRound probes targets. allow, when non-nil, selects which gathered
// targets are probed; the others keep their stored results (merge).
// probed is the set of prefixes this call stored (all attempted when the
// round completed). done is false when the round was skipped, shut down,
// or finished nothing, in which case stored results and the caller's
// schedule stay as they were.
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
	e.beginProberRound(targets)
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
			pin, candidates := targetProbeAddrs(t)
			hosts := omitLANHosts(ProbeHosts(t.Prefix, pin, candidates, p.NextHop, p.Source), p.NextHop, e.opt.ExchangeLANs)
			if len(hosts) == 0 {
				continue
			}
			jobs = append(jobs, job{provider: p, target: t, hosts: hosts, subs: jobSubranges(t, e.opt.ExchangeLANs)})
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

	// Urgent and shorter intervals first, so a round that runs out of time
	// still measures the priority tier, VIP prefixes, and confirm-urgent
	// prefixes before a longer tail (#118, #125).
	sortJobs(jobs, e.opt.Interval)

	ch := make(chan job)
	type outcome struct {
		res        Result
		sourceDown bool
	}
	// Buffered so a worker that finished before the deadline never blocks
	// on the send, including after the collector has stopped reading.
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
				r, srcDown := e.probe(roundCtx, j)
				if e.indirectEnabled() {
					if hops := e.traceHops(key{j.provider.Name, j.target.Prefix}); len(hops) > 0 {
						r.Hops = hops
					}
				}
				// A probe that the deadline cancelled must not refresh the
				// stored result. Staleness stays on the previous time.
				if roundCtx.Err() != nil {
					return
				}
				outs <- outcome{r, srcDown}
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
		close(outs)
	}()

	// Results are buffered until the round ends. A prefix is stored only
	// when every provider job for it finished, and all of its results go
	// in under one lock. The policy dates a round by the newest result for
	// a prefix, so a half-stored prefix would count one measurement round
	// twice toward confirm_rounds.
	want := map[netip.Prefix]int{}
	for _, j := range jobs {
		want[j.target.Prefix]++
	}
	fresh := map[key]Result{}
	got := map[netip.Prefix]int{}
	downBy := map[key]string{}
	received := 0
	collecting := true
	for collecting {
		select {
		case o, ok := <-outs:
			if !ok {
				collecting = false
				break
			}
			received++
			got[o.res.Prefix]++
			fresh[key{o.res.Provider, o.res.Prefix}] = o.res
			if o.sourceDown {
				downBy[key{o.res.Provider, o.res.Prefix}] = o.res.Err
			}
		case <-roundCtx.Done():
			collecting = false
		}
	}
	// Workers that finished before the deadline have already sent. A
	// round whose every job reported is complete even if the deadline
	// fired while the collector was choosing between the two channels.
	for drain := true; drain; {
		select {
		case o, ok := <-outs:
			if !ok {
				drain = false
				break
			}
			received++
			got[o.res.Prefix]++
			fresh[key{o.res.Provider, o.res.Prefix}] = o.res
			if o.sourceDown {
				downBy[key{o.res.Provider, o.res.Prefix}] = o.res.Err
			}
		default:
			drain = false
		}
	}
	if ctx.Err() != nil {
		// Shutdown: nothing was stored, so results stay as they were.
		e.leaveProbes(finished, nil)
		return nil, false
	}

	if received == len(jobs) {
		down := map[string]string{}
		ran := map[string]bool{}
		for k, r := range fresh {
			ran[r.Provider] = true
			if reason, isDown := downBy[k]; isDown {
				down[r.Provider] = reason
			}
		}
		e.finishProberRound()
		e.commit(fresh, ran, down, keep, merge)
		e.emitResults(fresh)
		e.rememberProbes(probed)
		e.addPrefixCommits(len(got))
		if e.opt.OnRound != nil {
			e.opt.OnRound()
		}
		return probed, true
	}

	// The deadline passed with jobs outstanding. Store prefixes whose
	// jobs all finished; leave the others, and their schedule, alone.
	committed := map[netip.Prefix]struct{}{}
	for pfx, n := range got {
		if n == want[pfx] {
			committed[pfx] = struct{}{}
		}
	}
	if len(committed) == 0 {
		e.leaveProbes(finished, nil)
		e.log.Warn("probe round timed out; keeping previous results")
		return nil, false
	}
	e.log.Warn("probe round timed out; kept finished prefix results", "finished", len(committed), "prefixes", len(want))
	stored := make(map[key]Result, len(fresh))
	ran := map[string]bool{}
	down := map[string]string{}
	for k, r := range fresh {
		if _, ok := committed[r.Prefix]; !ok {
			continue
		}
		stored[k] = r
		ran[r.Provider] = true
		if reason, isDown := downBy[k]; isDown {
			down[r.Provider] = reason
		}
	}
	e.pruneIndirect(keep)
	e.storeResults(stored, keep, ran, down)
	e.emitResults(stored)
	e.rememberProbes(committed)
	e.addPrefixCommits(len(committed))
	if e.opt.OnRound != nil {
		e.opt.OnRound()
	}
	// Probes still inside a prober that ignores cancellation must
	// finish before the next round plans prober memory.
	e.leaveProbes(finished, e.finishProberRound)
	return committed, true
}

// emitResults hands stored results to OnResult.
func (e *Engine) emitResults(rs map[key]Result) {
	if e.opt.OnResult == nil {
		return
	}
	for _, r := range rs {
		e.opt.OnResult(r)
	}
}

// sortJobs orders work so a round that cannot finish everything still
// probes the prefixes that are due soonest and the priority tier first.
// Urgent (a confirm streak, or a source that marked the target) is first,
// then a shorter interval than the engine (VIP), then the engine interval
// (flow top_n and ordinary targets), then a longer interval (flow tail).
func sortJobs(jobs []job, base time.Duration) {
	// Stable so prefixes in the same tier keep the order the sources
	// returned. Prober memory evicts the least recently probed host, and
	// that order is the target list when every interval is the same.
	sort.SliceStable(jobs, func(i, j int) bool {
		ti, ei := jobRank(jobs[i].target, base)
		tj, ej := jobRank(jobs[j].target, base)
		if ti != tj {
			return ti < tj
		}
		return ei < ej
	})
}

// jobRank is the probe order of one target. Lower is sooner.
func jobRank(t plugin.Target, base time.Duration) (tier int, every time.Duration) {
	every = base
	if t.Interval > 0 {
		every = t.Interval
	}
	switch {
	case t.Urgent:
		return 0, every
	case every < base:
		return 1, every
	case every > base:
		return 3, every
	default:
		return 2, every
	}
}

// storeResults merges the results of prefixes whose probes all finished,
// under one lock, and drops prefixes that left every source. It never
// drops a prefix the round did not finish: that one stays as it was.
func (e *Engine) storeResults(rs map[key]Result, keep map[netip.Prefix]bool, ran map[string]bool, down map[string]string) {
	now := e.opt.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.results == nil {
		e.results = map[key]Result{}
	}
	for k, r := range rs {
		e.results[k] = r
	}
	for k := range e.results {
		if !keep[k.prefix] {
			delete(e.results, k)
		}
	}
	e.applyStatusLocked(ran, down, now)
}

func (e *Engine) addPrefixCommits(n int) {
	if n > 0 {
		e.prefixCommits.Add(uint64(n))
	}
}

// PrefixCommits is how many prefixes have had a result stored since the
// engine was created, counted once per prefix per round.
func (e *Engine) PrefixCommits() uint64 {
	if e == nil {
		return 0
	}
	return e.prefixCommits.Load()
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
		every := e.interval()
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
// they return instead of starting another. after runs once they have
// returned, before the next round is allowed to start. Nil after is fine.
func (e *Engine) leaveProbes(finished <-chan struct{}, after func()) {
	done := func() {
		if after != nil {
			after()
		}
	}
	select {
	case <-finished:
		done()
		return
	default:
	}
	e.setProbeBusy(true)
	go func() {
		<-finished
		done()
		e.setProbeBusy(false)
	}()
}

func (e *Engine) commit(fresh map[key]Result, ran map[string]bool, down map[string]string, keep map[netip.Prefix]bool, merge bool) {
	e.pruneIndirect(keep)
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
	e.applyStatusLocked(ran, down, now)
}

// applyStatusLocked updates probe-source health from a round's results.
// The caller holds e.mu. A provider that did not finish a probe is left
// as it was. One source-unavailable result fails that provider closed.
func (e *Engine) applyStatusLocked(ran map[string]bool, down map[string]string, now time.Time) {
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

// probe measures every host for one provider and prefix and stores one
// result. A pinned host is probed alone. Flow candidates are probed
// first, then the automatic in-prefix hosts when fewer than three were
// named, and a usable far-side gateway, at most four. A host that does
// not qualify (too few replies, or an RTT spread over the limit) is
// left out of the score when another in-prefix host does, the same way
// a silent host is. The far-side gateway counts only when no in-prefix
// host qualified. Traceroute hop times are not used. A dead probe
// source fails closed. Every packet waits on the global rate limit
// inside probeOne, including a dispersion or loss retry.
//
// A target with sub-ranges (#121) is measured per sub-range instead, and
// the prefix result is their traffic-weighted aggregate. When none of
// them could be measured, the prefix hosts are probed as above.
func (e *Engine) probe(ctx context.Context, j job) (Result, bool) {
	if len(j.subs) > 0 {
		if res, down, ok := e.probeSubranges(ctx, j); ok {
			return res, down
		}
	}
	hosts := j.hosts
	if len(hosts) == 0 && j.target.Host.IsValid() {
		hosts = []netip.Addr{j.target.Host}
	}
	gw := netip.Addr{}
	if !j.target.Pinned {
		gw = j.provider.NextHop
	}
	copied := append([]netip.Addr(nil), hosts...)
	var samples []hostSample
	var errs []error
	for _, h := range hosts {
		one, down := e.probeOne(ctx, j.provider, j.target.Prefix, h, e.packets())
		one.Targets = copied
		if down || ctx.Err() != nil {
			return one, down
		}
		if one.Err != "" {
			errs = append(errs, errors.New(one.Err))
			continue
		}
		samples = append(samples, hostSample{addr: h, res: one, gateway: gw.IsValid() && h == gw})
	}
	if res, down, ok := e.probeIndirect(ctx, j, hosts, samples); ok {
		return res, down
	}
	if len(samples) == 0 {
		res := Result{Provider: j.provider.Name, Prefix: j.target.Prefix, Targets: copied, Time: e.opt.Now()}
		if len(hosts) > 0 {
			res.Target = hosts[0]
		}
		if len(errs) == 0 {
			res.Err = "no probe target"
		} else {
			res.Err = errors.Join(errs...).Error()
		}
		return res, false
	}
	res := combineHosts(j.provider.Name, j.target.Prefix, copied, samples, e.hostQualifies)
	lossRetry := e.retryLoss() > 0 && res.Stats.LossPct >= e.retryLoss()
	dispRetry := e.spreadOver(samples)
	if e.retryPackets() < 1 || (!lossRetry && !dispRetry) {
		return res, false
	}
	// Re-probe the hosts that define the score, and any host whose
	// spread is over the limit, so a small sample escalates to the
	// full one. The retry sample replaces the first.
	used := map[netip.Addr]bool{}
	for _, s := range scoreSamples(samples, e.hostQualifies) {
		used[s.addr] = true
	}
	if dispRetry {
		for _, s := range samples {
			if e.inconsistent(s.res.Stats) {
				used[s.addr] = true
			}
		}
	}
	var again []hostSample
	for _, s := range samples {
		if !used[s.addr] {
			continue
		}
		one, down := e.probeOne(ctx, j.provider, j.target.Prefix, s.addr, e.retryPackets())
		one.Targets = copied
		if down || ctx.Err() != nil {
			return one, down
		}
		if one.Err != "" {
			e.log.Debug("retry failed; keeping first sample", "provider", res.Provider, "prefix", res.Prefix, "err", one.Err)
			return res, false
		}
		again = append(again, hostSample{addr: s.addr, res: one, gateway: s.gateway})
	}
	reason := "loss"
	switch {
	case lossRetry && dispRetry:
		reason = "loss+dispersion"
	case dispRetry:
		reason = "dispersion"
	}
	e.log.Debug("retry probe", "provider", res.Provider, "prefix", res.Prefix, "loss_pct", res.Stats.LossPct, "packets", e.retryPackets(), "reason", reason)
	return combineHosts(j.provider.Name, j.target.Prefix, copied, again, e.hostQualifies), false
}

// hostQualifies reports whether one address may define the prefix score.
// The default (one reply, dispersion off) is the historical "any reply
// counts" rule. A single reply has a spread of zero.
func (e *Engine) hostQualifies(st Stats) bool {
	min := e.opt.MinReplies
	if min < 1 {
		min = 1
	}
	if st.Received < min {
		return false
	}
	if e.opt.Dispersion <= 0 || st.Received < 2 {
		return true
	}
	return st.RTTMax-st.RTTMin <= e.opt.Dispersion
}

// inconsistent reports whether the sample has enough replies to judge
// an RTT spread and that spread is over the limit. Too few replies are
// unqualified but do not escalate; dispersion does.
func (e *Engine) inconsistent(st Stats) bool {
	if e.opt.Dispersion <= 0 || st.Received < 2 {
		return false
	}
	return st.RTTMax-st.RTTMin > e.opt.Dispersion
}

// spreadOver reports whether any measured host should escalate the
// prefix to the full probe.
func (e *Engine) spreadOver(samples []hostSample) bool {
	if e.opt.Dispersion <= 0 {
		return false
	}
	for _, s := range samples {
		if e.inconsistent(s.res.Stats) {
			return true
		}
	}
	return false
}

// hostSample is one address's measurement inside a prefix.
type hostSample struct {
	addr    netip.Addr
	res     Result
	gateway bool
}

// probeOne runs the prober chain for one address. Chain semantics: try
// probers in order; move on when a prober errors or gets no replies; stop
// immediately (fail closed) if the source address is unusable. After a
// host has answered, later rounds start at that prober and move only
// forward. Every prober_recheck_rounds measurement starts at the first
// prober again. Each prober that runs waits on the global rate limit.
func (e *Engine) probeOne(ctx context.Context, p Provider, prefix netip.Prefix, host netip.Addr, count int) (Result, bool) {
	res := Result{Provider: p.Name, Prefix: prefix, Target: host}
	if count < 1 {
		res.Err, res.Time = "no packets", e.opt.Now()
		return res, false
	}
	sem := e.sem(host)
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		res.Err, res.Time = ctx.Err().Error(), e.opt.Now()
		return res, false
	}
	defer func() { <-sem }()

	req := plugin.ProbeRequest{Provider: p.Name, Source: p.Source,
		Target: host, Count: count, Timeout: e.timeout()}
	var errs []error
	var fallback *Result
	start := e.proberStart(host)
	for i := start; i < len(e.probers); i++ {
		pr := e.probers[i]
		if e.opt.Limiter != nil {
			if err := e.opt.Limiter.WaitN(ctx, count); err != nil {
				errs = append(errs, fmt.Errorf("rate limit: %w", err))
				break
			}
		}
		pctx, cancel := context.WithTimeout(ctx, time.Duration(count)*e.timeout()+time.Second)
		raw, err := pr.Prober.Probe(pctx, req)
		cancel()
		if err != nil {
			if errors.Is(err, plugin.ErrSourceUnavailable) {
				res.Err, res.Time = fmt.Sprintf("%s: %v", pr.Name, err), e.opt.Now()
				return res, true
			}
			errs = append(errs, fmt.Errorf("%s: %w", pr.Name, err))
			continue
		}
		r := res
		r.Prober, r.Stats, r.Time = pr.Name, Compute(raw), e.opt.Now()
		if r.Stats.Received > 0 {
			e.noteProber(host, i)
			return r, false
		}
		if fallback == nil {
			cp := r
			fallback = &cp // full loss: remember, but try the next prober
		}
	}
	if fallback != nil {
		return *fallback, false
	}
	res.Err, res.Time = errors.Join(errs...).Error(), e.opt.Now()
	return res, false
}

// scoreSamples picks the hosts that define the prefix. Qualified
// addresses inside the prefix win, so one silent or unqualified host
// does not. qualify nil means any reply counts. The far-side gateway
// is the sample only when none of those qualified. When nothing
// qualified, every measured host counts so the loss is still reported.
func scoreSamples(samples []hostSample, qualify func(Stats) bool) []hostSample {
	if qualify == nil {
		qualify = func(st Stats) bool { return st.Received > 0 }
	}
	var inPrefix, answered, measured []hostSample
	for _, s := range samples {
		if !s.res.OK() {
			continue
		}
		measured = append(measured, s)
		if !qualify(s.res.Stats) {
			continue
		}
		answered = append(answered, s)
		if !s.gateway {
			inPrefix = append(inPrefix, s)
		}
	}
	if len(inPrefix) > 0 {
		return inPrefix
	}
	if len(answered) > 0 {
		return answered
	}
	return measured
}

// combineHosts builds one result from the hosts that define the score.
// Loss and RTT come from those hosts only. Target is the first of them
// that answered, otherwise the first probed address.
func combineHosts(provider string, prefix netip.Prefix, hosts []netip.Addr, samples []hostSample, qualify func(Stats) bool) Result {
	used := scoreSamples(samples, qualify)
	res := Result{Provider: provider, Prefix: prefix, Targets: hosts, Time: samples[0].res.Time}
	if len(hosts) > 0 {
		res.Target = hosts[0]
	}
	if len(used) == 0 {
		res.Err = "no probe target"
		return res
	}
	res.Prober = used[0].res.Prober
	res.Time = used[len(used)-1].res.Time
	parts := make([]Stats, len(used))
	answered := false
	for i, s := range used {
		parts[i] = s.res.Stats
		if !answered && s.res.Stats.Received > 0 {
			res.Target = s.addr
			answered = true
		}
	}
	res.Stats = combineStats(parts)
	return res
}

// combineStats pools per-host statistics. RTT is the reply-weighted mean.
// Jitter is the reply-gap-weighted mean of the per-host jitters.
func combineStats(parts []Stats) Stats {
	var s Stats
	var rttSum time.Duration
	var jitSum time.Duration
	jitWeight := 0
	seenRTT := false
	for _, p := range parts {
		s.Sent += p.Sent
		s.Received += p.Received
		if p.Received == 0 {
			continue
		}
		rttSum += p.RTTAvg * time.Duration(p.Received)
		if !seenRTT || p.RTTMin < s.RTTMin {
			s.RTTMin = p.RTTMin
		}
		if p.RTTMax > s.RTTMax {
			s.RTTMax = p.RTTMax
		}
		seenRTT = true
		if p.Received > 1 {
			jitSum += p.Jitter * time.Duration(p.Received-1)
			jitWeight += p.Received - 1
		}
	}
	if s.Sent > 0 {
		lost := s.Sent - s.Received
		if lost < 0 {
			lost = 0
		}
		s.LossPct = 100 * float64(lost) / float64(s.Sent)
	}
	if s.Received > 0 {
		s.RTTAvg = rttSum / time.Duration(s.Received)
	}
	if jitWeight > 0 {
		s.Jitter = jitSum / time.Duration(jitWeight)
	}
	return s
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
