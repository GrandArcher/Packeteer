// Package nonbgp is the flow-driven mode for a site with two internet
// links whose router has no BGP (#300). The Table tracks the destinations
// flow records show as synthetic prefixes, and the Steer controller turns
// the decision engine's improvements into static routes on the router.
// Nothing in this package speaks BGP, but a router that redistributes
// static routes exports them (docs/nonbgp.md).
package nonbgp

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Prefix floors: a synthetic prefix is never more specific than the
// smallest block that is routable on the Internet.
const (
	FloorV4 = 24
	FloorV6 = 48
)

const (
	// lookupRetry is how long a block waits after a failed covering
	// lookup. A block with no answer stays at its floor.
	lookupRetry = time.Minute
	// lookupWake is how often the lookup worker looks for blocks due.
	lookupWake = 5 * time.Second
	// probeSpan is how many bits wider than the floor a known announced
	// prefix is searched for a new block.
	probeSpan = 16
)

// Options configure a Table.
type Options struct {
	// WidenBits is how far a synthetic prefix may widen past the floor.
	// 0 never widens.
	WidenBits int
	// Idle is how long a block with no flow is kept.
	Idle time.Duration
	// MaxBlocks caps the tracked blocks.
	MaxBlocks int
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Log receives lookup failures; nil is slog.Default.
	Log *slog.Logger
}

// Route is one synthetic prefix: the smallest prefix that holds active
// blocks inside one announced prefix, within WidenBits of the floor, with at
// least as many active blocks as idle ones.
type Route struct {
	Prefix netip.Prefix `json:"prefix"`
	// Upper is the announced prefix that bounds Prefix, and Origin its
	// origin AS (0 when unknown). Upper is invalid when no lookup answered;
	// the route then stays at its floor.
	Upper    netip.Prefix `json:"upper,omitzero"`
	Origin   uint32       `json:"origin,omitempty"`
	Blocks   int          `json:"blocks"`
	LastSeen time.Time    `json:"last_seen"`
}

// Stats is the table's size and lookup health.
type Stats struct {
	Blocks  int
	Pending int
	// Dropped counts destinations not tracked because the block cap was
	// reached.
	Dropped uint64
	// LookupErrors counts failed covering lookups; LastError is the latest.
	LookupErrors uint64
	LastError    string
}

type block struct {
	// last is the latest flow, unix nanoseconds. It is stored under the
	// read lock; every other field is guarded by the table's lock.
	last atomic.Int64
	// upper and origin are the announced prefix of the block. settled is
	// set once a lookup answered, even with no bound (the announced prefix
	// is more specific than the block), so it is not asked again.
	upper   netip.Prefix
	origin  uint32
	settled bool
	retryAt time.Time
	syn     netip.Prefix
}

// Table tracks destinations as synthetic prefixes. Lookup is safe to call
// from the flow source's workers.
type Table struct {
	opt Options
	cov plugin.Covering
	log *slog.Logger

	mu      sync.RWMutex
	blocks  map[netip.Prefix]*block
	routes  map[netip.Prefix]Route
	known   map[netip.Prefix]uint32
	lastErr string

	dropped atomic.Uint64
	errs    atomic.Uint64
	wake    chan struct{}
}

// NewTable returns an empty table. cov may be nil: no prefix then widens.
func NewTable(opt Options, cov plugin.Covering) *Table {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	log := opt.Log
	if log == nil {
		log = slog.Default()
	}
	return &Table{opt: opt, cov: cov, log: log,
		blocks: map[netip.Prefix]*block{}, routes: map[netip.Prefix]Route{}, known: map[netip.Prefix]uint32{},
		wake: make(chan struct{}, 1)}
}

func floorBits(a netip.Addr) int {
	if a.Is4() {
		return FloorV4
	}
	return FloorV6
}

// Floor is the block that holds addr, the unit the table tracks.
func Floor(addr netip.Addr) netip.Prefix {
	p, _ := addr.Unmap().Prefix(floorBits(addr.Unmap()))
	return p
}

// Lookup returns the synthetic prefix that holds addr and records the flow.
// The first flow to an unseen block creates it at its floor. It reports
// false for an address that cannot be tracked, or when the block cap is
// reached. It is the flow source's prefix lookup.
func (t *Table) Lookup(addr netip.Addr) (netip.Prefix, bool) {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return netip.Prefix{}, false
	}
	blk := Floor(addr)
	now := t.opt.Now().UnixNano()
	t.mu.RLock()
	b, ok := t.blocks[blk]
	if ok {
		b.last.Store(now)
		syn := b.syn
		t.mu.RUnlock()
		return syn, true
	}
	t.mu.RUnlock()

	t.mu.Lock()
	defer t.mu.Unlock()
	if b, ok = t.blocks[blk]; ok {
		b.last.Store(now)
		return b.syn, true
	}
	if len(t.blocks) >= t.opt.MaxBlocks {
		t.dropped.Add(1)
		return netip.Prefix{}, false
	}
	b = &block{syn: blk}
	b.last.Store(now)
	t.blocks[blk] = b
	select {
	case t.wake <- struct{}{}:
	default:
	}
	return blk, true
}

// Refresh ages out idle blocks, applies the announced prefixes already
// learned, and recomputes the synthetic prefixes: a prefix widens when
// active blocks sit elsewhere inside the same announced prefix, and
// narrows back as they age out.
func (t *Table) Refresh() {
	now := t.opt.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	cut := now.Add(-t.opt.Idle).UnixNano()
	for blk, b := range t.blocks {
		if b.last.Load() < cut {
			delete(t.blocks, blk)
		}
	}
	for blk, b := range t.blocks {
		if !b.upper.IsValid() {
			b.upper, b.origin = t.knownCover(blk)
		}
	}
	t.recomputeLocked()
}

// knownCover is the most specific known announced prefix that holds blk.
func (t *Table) knownCover(blk netip.Prefix) (netip.Prefix, uint32) {
	for bits := blk.Bits(); bits >= blk.Bits()-probeSpan && bits > 0; bits-- {
		p, _ := blk.Addr().Prefix(bits)
		if origin, ok := t.known[p]; ok {
			return p, origin
		}
	}
	return netip.Prefix{}, 0
}

// group is the blocks that make one synthetic prefix, and the most specific
// announced prefix any of them sits in.
type group struct {
	blocks []netip.Prefix
	upper  netip.Prefix
	origin uint32
	syn    netip.Prefix
}

func (g *group) take(upper netip.Prefix, origin uint32) {
	if upper.IsValid() && (!g.upper.IsValid() || upper.Bits() > g.upper.Bits()) {
		g.upper, g.origin = upper, origin
	}
}

func (t *Table) recomputeLocked() {
	groups := map[netip.Prefix]*group{}
	for blk, b := range t.blocks {
		limit := blk.Bits()
		if b.upper.IsValid() && t.opt.WidenBits > 0 {
			limit = max(b.upper.Bits(), blk.Bits()-t.opt.WidenBits)
		}
		key, _ := blk.Addr().Prefix(limit)
		g := groups[key]
		if g == nil {
			g = &group{}
			groups[key] = g
		}
		g.blocks = append(g.blocks, blk)
		g.take(b.upper, b.origin)
	}
	ordered := make([]*group, 0, len(groups))
	for _, g := range groups {
		for _, part := range dense(g.blocks) {
			ordered = append(ordered, &group{blocks: part, upper: g.upper, origin: g.origin, syn: commonPrefix(part)})
		}
	}
	// Blocks under different announced prefixes group apart, so one group's
	// prefix can hold another's. Widest first, a nested group joins the
	// group that holds it: two overlapping static routes are never made.
	slices.SortFunc(ordered, func(a, b *group) int {
		return cmp.Or(cmp.Compare(a.syn.Bits(), b.syn.Bits()), cmp.Compare(b.upper.Bits(), a.upper.Bits()), a.syn.Addr().Compare(b.syn.Addr()))
	})
	merged := map[netip.Prefix]*group{}
	for _, g := range ordered {
		var outer *group
		for bits := g.syn.Bits(); bits >= 0 && outer == nil; bits-- {
			p, _ := g.syn.Addr().Prefix(bits)
			outer = merged[p]
		}
		if outer == nil {
			merged[g.syn] = g
			continue
		}
		// The outer group's announced prefix holds the merged prefix; the
		// inner one may be narrower than it.
		outer.blocks = append(outer.blocks, g.blocks...)
	}
	routes := make(map[netip.Prefix]Route, len(merged))
	for syn, g := range merged {
		r := Route{Prefix: syn, Upper: g.upper, Origin: g.origin, Blocks: len(g.blocks)}
		for _, blk := range g.blocks {
			b := t.blocks[blk]
			b.syn = syn
			if at := time.Unix(0, b.last.Load()); at.After(r.LastSeen) {
				r.LastSeen = at
			}
		}
		routes[syn] = r
	}
	t.routes = routes
}

// dense splits blocks so that the smallest prefix holding each part has at
// least as many blocks with flow as without. A route then never moves more
// unmeasured address space than measured: the probes measured targets in
// the active blocks only.
func dense(blocks []netip.Prefix) [][]netip.Prefix {
	p := commonPrefix(blocks)
	if 2*len(blocks) >= 1<<(blocks[0].Bits()-p.Bits()) {
		return [][]netip.Prefix{blocks}
	}
	low, _ := p.Addr().Prefix(p.Bits() + 1)
	var a, b []netip.Prefix
	for _, blk := range blocks {
		if low.Contains(blk.Addr()) {
			a = append(a, blk)
		} else {
			b = append(b, blk)
		}
	}
	return append(dense(a), dense(b)...)
}

// commonPrefix is the smallest prefix that holds every block.
func commonPrefix(blocks []netip.Prefix) netip.Prefix {
	p := blocks[0]
	for _, b := range blocks[1:] {
		for !p.Contains(b.Addr()) {
			p, _ = p.Addr().Prefix(p.Bits() - 1)
		}
	}
	return p
}

// Routes lists the synthetic prefixes, in prefix order.
func (t *Table) Routes() []Route {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Route, 0, len(t.routes))
	for _, p := range netpfx.SortedKeys(t.routes) {
		out = append(out, t.routes[p])
	}
	return out
}

// Has reports whether p is a current synthetic prefix.
func (t *Table) Has(p netip.Prefix) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.routes[p.Masked()]
	return ok
}

// Fill gives Decide what a RIB would: every synthetic prefix with a
// result is exited through native, the provider of the default route.
func (t *Table) Fill(in *policy.Input, native string) {
	in.RIBEnabled, in.RIBReady = true, true
	if in.Native == nil {
		in.Native = map[netip.Prefix]string{}
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, r := range in.Results {
		if _, ok := t.routes[r.Prefix]; ok {
			in.Native[r.Prefix] = native
		}
	}
}

// Stats reports the table's size and lookup health.
func (t *Table) Stats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	st := Stats{Blocks: len(t.blocks), Dropped: t.dropped.Load(), LookupErrors: t.errs.Load(), LastError: t.lastErr}
	now := t.opt.Now()
	for _, b := range t.blocks {
		if t.dueLocked(b, now) {
			st.Pending++
		}
	}
	return st
}

func (t *Table) dueLocked(b *block, now time.Time) bool {
	return t.cov != nil && !b.upper.IsValid() && !b.settled && !now.Before(b.retryAt)
}

// Run looks up the announced prefix of each block that has none, one at a
// time (the covering plugin rate-limits itself), until ctx ends. Without a
// covering plugin it returns at once.
func (t *Table) Run(ctx context.Context) {
	if t.cov == nil {
		return
	}
	tick := time.NewTicker(lookupWake)
	defer tick.Stop()
	for {
		for t.lookupOne(ctx) {
		}
		select {
		case <-ctx.Done():
			return
		case <-t.wake:
		case <-tick.C:
		}
	}
}

// lookupOne asks for one due block and reports whether it asked.
func (t *Table) lookupOne(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	now := t.opt.Now()
	t.mu.RLock()
	var pick netip.Prefix
	for blk, b := range t.blocks {
		if t.dueLocked(b, now) && (!pick.IsValid() || netpfx.Less(blk, pick)) {
			pick = blk
		}
	}
	t.mu.RUnlock()
	if !pick.IsValid() {
		return false
	}
	ans, err := t.ask(ctx, pick)
	t.mu.Lock()
	defer t.mu.Unlock()
	b, ok := t.blocks[pick]
	if err != nil {
		if ctx.Err() != nil {
			return false
		}
		t.errs.Add(1)
		t.lastErr = err.Error()
		if ok {
			b.retryAt = now.Add(lookupRetry)
		}
		t.log.Warn("non-BGP: covering prefix lookup failed", "block", pick, "err", err)
		return true
	}
	if ans.Prefix.IsValid() {
		t.known[ans.Prefix] = ans.Origin
	}
	if ok {
		b.upper, b.origin, b.settled = ans.Prefix, ans.Origin, true
	}
	return true
}

// ask validates the answer: it must hold the block, be of its family, and
// not be a default route. An announced prefix more specific than the block
// bounds nothing, so the answer is the zero value: the block stays at its
// floor and is not asked again.
func (t *Table) ask(ctx context.Context, blk netip.Prefix) (plugin.Announced, error) {
	a, err := t.cov.Covering(ctx, blk.Addr())
	if err != nil {
		return plugin.Announced{}, err
	}
	u := a.Prefix.Masked()
	switch {
	case !u.IsValid() || u.Bits() == 0 || u.Addr().Is4() != blk.Addr().Is4():
		return plugin.Announced{}, fmt.Errorf("covering answered %s for %s", u, blk)
	case u.Bits() > blk.Bits():
		return plugin.Announced{}, nil
	case !u.Contains(blk.Addr()):
		return plugin.Announced{}, errors.New("covering answered " + u.String() + ", which does not hold " + blk.String())
	}
	return plugin.Announced{Prefix: u, Origin: a.Origin}, nil
}
