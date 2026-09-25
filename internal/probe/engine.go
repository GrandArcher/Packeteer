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
	OnResult             func(Result) // called for every result (optional)
	OnRound              func()       // called after each completed round (optional)
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

	semMu sync.Mutex
	sems  map[netip.Addr]chan struct{}
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

// Run performs a round immediately and then every Interval until ctx is
// cancelled. It returns ctx.Err().
func (e *Engine) Run(ctx context.Context) error {
	t := time.NewTicker(e.opt.Interval)
	defer t.Stop()
	for {
		e.RunOnce(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Targets collects and de-duplicates targets from every source. A failing
// source is logged and skipped so the others keep working.
func (e *Engine) Targets(ctx context.Context) []plugin.Target {
	seen := map[netip.Prefix]bool{}
	var out []plugin.Target
	for _, s := range e.sources {
		ts, err := s.Source.Targets(ctx)
		if err != nil {
			e.log.Warn("target source failed", "source", s.Name, "err", err)
			continue
		}
		for _, t := range ts {
			t.Prefix = t.Prefix.Masked()
			if !t.Prefix.IsValid() || seen[t.Prefix] {
				continue
			}
			if !t.Host.IsValid() {
				t.Host = DefaultHost(t.Prefix)
			}
			seen[t.Prefix] = true
			out = append(out, t)
		}
	}
	return out
}

// RunOnce performs one probe round over all providers and targets.
func (e *Engine) RunOnce(ctx context.Context) {
	targets := e.Targets(ctx)
	var jobs []job
	for _, t := range targets {
		for _, p := range e.providers {
			if p.Source.Is4() != t.Host.Is4() {
				continue // provider cannot reach this address family
			}
			jobs = append(jobs, job{provider: p, target: t})
		}
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
				r, down := e.probe(ctx, j)
				outs <- outcome{r, down}
			}
		}()
	}
feed:
	for _, j := range jobs {
		select {
		case ch <- j:
		case <-ctx.Done():
			break feed
		}
	}
	close(ch)
	wg.Wait()
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
	if ctx.Err() != nil {
		return // incomplete round: keep previous state
	}

	e.commit(fresh, ran, down)
	if e.opt.OnRound != nil {
		e.opt.OnRound()
	}
}

func (e *Engine) commit(fresh map[key]Result, ran map[string]bool, down map[string]string) {
	now := e.opt.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.results = fresh
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
			return r, false
		}
		if fallback == nil {
			fallback = &r // full loss: remember, but try the next prober
		}
	}
	if fallback != nil {
		return *fallback, false
	}
	res.Err, res.Time = errors.Join(errs...).Error(), e.opt.Now()
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
