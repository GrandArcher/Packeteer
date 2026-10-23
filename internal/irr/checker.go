package irr

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Cache defaults and bounds (irr.refresh, irr.staleness).
const (
	DefaultRefresh   = 6 * time.Hour
	DefaultStaleness = 24 * time.Hour
	MinRefresh       = time.Minute
	MaxStaleness     = 30 * 24 * time.Hour
	// retryAfter is how soon a lookup that a source failed is asked
	// again, so a server that is down is not queried every round.
	retryAfter = time.Minute
	// queueLen bounds the lookups waiting for the worker. A full queue
	// drops the request; the next Lookup asks again.
	queueLen = 4096
	// maxKeys bounds each cache (prefixes, as-sets, AS numbers).
	maxKeys = 100_000
)

// Source is one irr.sources entry.
type Source struct {
	Name string
	Type string
	IRR  plugin.IRR
}

// Options are the cache timers and the per-provider as-sets.
type Options struct {
	// Refresh is how old a cached answer may get before it is looked up
	// again in the background; it is served meanwhile.
	Refresh time.Duration
	// Staleness is how long an answer is used after its data time. Older
	// answers are unknown.
	Staleness time.Duration
	// ASSets maps a provider name to the as-set its paths' origins are
	// checked against (irr.as_sets).
	ASSets map[string]string
}

// Status is one source's health: the data time of its last answer and
// the error of its last lookup.
type Status struct {
	Source  string
	Type    string
	Up      bool
	Updated time.Time
	Error   string
}

// answer is one source's last good answer to one lookup.
type answer[T any] struct {
	val T
	at  time.Time // data time; zero until the source answered
	// unsupported: the source does not serve this lookup.
	unsupported bool
}

// entry is one lookup across every source, in source order.
type entry[T any] struct {
	per  []answer[T]
	next time.Time // when the background lookup runs again
}

type jobKind uint8

const (
	jobRoutes jobKind = iota
	jobSet
	jobName
)

type job struct {
	kind   jobKind
	prefix netip.Prefix
	set    string
	asn    uint32
}

// Checker answers per-path IRR lookups from its cache. A miss, or an
// answer older than Refresh, queues a background lookup that asks every
// source; Lookup never waits on the network. It is safe for concurrent
// use.
type Checker struct {
	sources []Source
	opt     Options
	now     func() time.Time
	queue   chan job

	mu      sync.Mutex
	routes  map[netip.Prefix]*entry[[]plugin.IRRRoute]
	sets    map[string]*entry[[]uint32]
	names   map[uint32]*entry[string]
	pending map[job]bool
	status  []Status
}

// NewChecker wraps the sources in order. With no sources every lookup is
// unknown and Enabled is false.
func NewChecker(sources []Source, opt Options) *Checker {
	c := &Checker{
		sources: sources, opt: opt, now: time.Now,
		queue:   make(chan job, queueLen),
		routes:  map[netip.Prefix]*entry[[]plugin.IRRRoute]{},
		sets:    map[string]*entry[[]uint32]{},
		names:   map[uint32]*entry[string]{},
		pending: map[job]bool{},
	}
	for _, s := range sources {
		c.status = append(c.status, Status{Source: s.Name, Type: s.Type})
	}
	return c
}

// Enabled reports whether any source is configured.
func (c *Checker) Enabled() bool { return c != nil && len(c.sources) > 0 }

// Run looks up queued keys until ctx ends. Start it once.
func (c *Checker) Run(ctx context.Context) {
	if !c.Enabled() {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-c.queue:
			c.fetch(ctx, j)
		}
	}
}

// Statuses is every source's health, in order.
func (c *Checker) Statuses() []Status {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.status)
}

// Lookup is the IRR view of a path with origin through provider for
// prefix. Without fresh data it is unknown and a lookup is queued.
func (c *Checker) Lookup(prefix netip.Prefix, origin uint32, provider string) plugin.IRRAnswer {
	a := plugin.IRRAnswer{State: plugin.IRRUnknown}
	if !c.Enabled() || !prefix.IsValid() {
		return a
	}
	prefix = prefix.Masked()
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	re := c.routes[prefix]
	c.wantLocked(job{kind: jobRoutes, prefix: prefix}, re != nil && now.Before(re.next))
	if re != nil {
		c.routeStateLocked(&a, re, origin, now)
	}
	if set := c.opt.ASSets[provider]; set != "" {
		a.ASSet, a.ASSetState = set, plugin.IRRUnknown
		se := c.sets[set]
		c.wantLocked(job{kind: jobSet, set: set}, se != nil && now.Before(se.next))
		if se != nil {
			a.ASSetState = c.setStateLocked(se, origin, now)
		}
	}
	ne := c.names[origin]
	c.wantLocked(job{kind: jobName, asn: origin}, ne != nil && now.Before(ne.next))
	if ne != nil {
		for _, r := range ne.per {
			if c.freshLocked(r.at, now) && r.val != "" {
				a.OriginName = r.val
				break
			}
		}
	}
	return a
}

// routeStateLocked is registered when any source has a fresh object with
// the origin (the first such source is named), not registered when every
// source that serves routes answered freshly without one, and unknown
// otherwise.
func (c *Checker) routeStateLocked(a *plugin.IRRAnswer, e *entry[[]plugin.IRRRoute], origin uint32, now time.Time) {
	missing, answered := false, false
	var oldest time.Time
	firstSource := ""
	for i, r := range e.per {
		if r.unsupported {
			continue
		}
		if !c.freshLocked(r.at, now) {
			missing = true
			continue
		}
		if !answered {
			firstSource = c.sources[i].Name
		}
		answered = true
		if oldest.IsZero() || r.at.Before(oldest) {
			oldest = r.at
		}
		for _, rt := range r.val {
			if !slices.Contains(a.Origins, rt.Origin) {
				a.Origins = append(a.Origins, rt.Origin)
			}
			if rt.Origin == origin && a.State != plugin.IRRRegistered {
				a.State, a.Source, a.Database, a.Updated = plugin.IRRRegistered, c.sources[i].Name, rt.Database, r.at
			}
		}
	}
	slices.Sort(a.Origins)
	if a.State == plugin.IRRRegistered || missing || !answered {
		return
	}
	a.State, a.Source, a.Updated = plugin.IRRNotRegistered, firstSource, oldest
}

// setStateLocked follows routeStateLocked for as-set membership.
func (c *Checker) setStateLocked(e *entry[[]uint32], origin uint32, now time.Time) plugin.IRRState {
	missing, answered := false, false
	for _, r := range e.per {
		if r.unsupported {
			continue
		}
		if !c.freshLocked(r.at, now) {
			missing = true
			continue
		}
		answered = true
		if slices.Contains(r.val, origin) {
			return plugin.IRRRegistered
		}
	}
	if missing || !answered {
		return plugin.IRRUnknown
	}
	return plugin.IRRNotRegistered
}

func (c *Checker) freshLocked(at, now time.Time) bool {
	return !at.IsZero() && now.Sub(at) <= c.opt.Staleness
}

// wantLocked queues j unless its answer is current or it is queued
// already. A full queue drops it.
func (c *Checker) wantLocked(j job, current bool) {
	if current || c.pending[j] {
		return
	}
	select {
	case c.queue <- j:
		c.pending[j] = true
	default:
	}
}

// fetch runs one queued lookup.
func (c *Checker) fetch(ctx context.Context, j job) {
	switch j.kind {
	case jobRoutes:
		fetchInto(ctx, c, c.routes, j.prefix, j, func(s plugin.IRR) ([]plugin.IRRRoute, time.Time, error) { return s.Routes(ctx, j.prefix) })
	case jobSet:
		fetchInto(ctx, c, c.sets, j.set, j, func(s plugin.IRR) ([]uint32, time.Time, error) { return s.ASSetMembers(ctx, j.set) })
	case jobName:
		fetchInto(ctx, c, c.names, j.asn, j, func(s plugin.IRR) (string, time.Time, error) { return s.ASName(ctx, j.asn) })
	}
}

// fetchInto asks every source for one key and stores the answers. A source
// that fails keeps its last answer, which ages out at Staleness, and the
// key is asked again after retryAfter. A new key in a full cache first
// evicts the entries that are due for a lookup, then arbitrary ones.
func fetchInto[K comparable, T any](ctx context.Context, c *Checker, m map[K]*entry[T], k K, j job, ask func(plugin.IRR) (T, time.Time, error)) {
	type result struct {
		val T
		at  time.Time
		err error
	}
	results := make([]result, len(c.sources))
	for i, s := range c.sources {
		results[i].val, results[i].at, results[i].err = ask(s.IRR)
	}
	if ctx.Err() != nil {
		return
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.pending, j)
	e, ok := m[k]
	if !ok {
		if len(m) >= maxKeys {
			for old, v := range m {
				if v.next.Before(now) {
					delete(m, old)
				}
			}
			for old := range m {
				if len(m) < maxKeys {
					break
				}
				delete(m, old)
			}
		}
		e = &entry[T]{per: make([]answer[T], len(c.sources))}
		m[k] = e
	}
	e.next = now.Add(c.opt.Refresh)
	for i, r := range results {
		st := &c.status[i]
		switch {
		case errors.Is(r.err, plugin.ErrIRRUnsupported):
			e.per[i] = answer[T]{unsupported: true}
		case r.err != nil:
			st.Up, st.Error = false, r.err.Error()
			e.next = now.Add(min(retryAfter, c.opt.Refresh))
		default:
			e.per[i] = answer[T]{val: r.val, at: r.at}
			st.Up, st.Error = true, ""
			if r.at.After(st.Updated) {
				st.Updated = r.at
			}
		}
	}
}
