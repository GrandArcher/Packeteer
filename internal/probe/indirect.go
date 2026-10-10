package probe

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Tracer finds the highest stable hop toward dst from src. wait runs
// before every packet it sends. ok is false when no hop was stable. The
// traceroute package's Tracer satisfies it.
type Tracer interface {
	Trace(ctx context.Context, src, dst netip.Addr, wait func(context.Context) error) (hop netip.Addr, ok bool, err error)
}

// pathTracer is a Tracer that also returns the stable hop addresses in
// TTL order. Indirect probing keeps them so outage detection can map hops
// to ASNs (#124). A tracer that does not implement it contributes no hop path.
type pathTracer interface {
	TracePath(ctx context.Context, src, dst netip.Addr, wait func(context.Context) error) (hops []netip.Addr, best netip.Addr, ok bool, err error)
}

// Indirect enables per-provider indirect probing (#123). When every
// address probed inside a prefix is silent for a provider, the prefix is
// traced in the background from that provider's source, and the highest
// stable hop becomes that provider's indirect host. Measurement only.
type Indirect struct {
	Tracer Tracer
	// Budget is the wall clock for one background pass across every
	// queued trace. Each trace gets an equal share, at least MinShare.
	// Traces the pass did not reach stay queued for the next pass.
	Budget   time.Duration
	MinShare time.Duration
	// CacheTTL is how long a discovered hop (or a trace that found none)
	// is reused before the prefix is traced again.
	CacheTTL time.Duration
	// MaxQueue caps the traces waiting for a pass. Zero means 1024.
	MaxQueue int
}

const defaultIndirectQueue = 1024

// indirectHop is the cached outcome of one trace. ok is false when the
// trace found no usable hop; the prefix is not traced again until the
// entry ages out. hops is the stable hop addresses in TTL order, kept
// even when the best hop is not usable, so outage detection can map them.
type indirectHop struct {
	hop  netip.Addr
	hops []netip.Addr
	ok   bool
	at   time.Time
}

// indirectReq is one queued trace.
type indirectReq struct {
	key      key
	provider Provider
	dst      netip.Addr
}

func validIndirect(in *Indirect) error {
	if in == nil {
		return nil
	}
	if in.Tracer == nil {
		return errors.New("probe: indirect needs a tracer")
	}
	if in.Budget <= 0 || in.CacheTTL <= 0 || in.MinShare < 0 || in.MaxQueue < 0 {
		return errors.New("probe: indirect budget and cache ttl must be positive")
	}
	return nil
}

// indirectEnabled reports whether silent prefixes are traced.
func (e *Engine) indirectEnabled() bool { return e.opt.Indirect != nil }

// inPrefixSilent reports whether at least one probed address sits inside
// the prefix and none of those got a reply. dst is the first of them, the
// destination a trace walks toward. A pin outside the prefix (a
// traceroute hop) is not an in-prefix address.
func inPrefixSilent(prefix netip.Prefix, hosts []netip.Addr, samples []hostSample) (dst netip.Addr, silent bool) {
	replied := map[netip.Addr]bool{}
	for _, s := range samples {
		if s.res.OK() && s.res.Stats.Received > 0 {
			replied[s.addr] = true
		}
	}
	for _, h := range hosts {
		if !prefix.Contains(h) {
			continue
		}
		if replied[h] {
			return netip.Addr{}, false
		}
		if !dst.IsValid() {
			dst = h
		}
	}
	return dst, dst.IsValid()
}

// probeIndirect runs after the prefix hosts of one job were probed. When
// an in-prefix address answered, the cached hop for this provider and
// prefix is dropped. When all of them were silent, a fresh cached hop is
// probed and, when it qualifies, defines the score and marks it indirect.
// Without a cached hop the trace is queued for the background pass. ok
// is false when the normal result stands. Every packet waits on the
// global rate limit inside probeOne.
func (e *Engine) probeIndirect(ctx context.Context, j job, hosts []netip.Addr, samples []hostSample) (res Result, down, ok bool) {
	if !e.indirectEnabled() {
		return Result{}, false, false
	}
	k := key{j.provider.Name, j.target.Prefix}
	dst, silent := inPrefixSilent(j.target.Prefix, hosts, samples)
	if !silent {
		e.forgetIndirect(k)
		return Result{}, false, false
	}
	hop, found := e.cachedIndirect(k)
	if !found {
		e.queueIndirect(indirectReq{key: k, provider: j.provider, dst: dst})
		return Result{}, false, false
	}
	if !hop.IsValid() {
		return Result{}, false, false // traced recently, no usable hop
	}
	one, dn := e.probeOne(ctx, j.provider, j.target.Prefix, hop, e.packets())
	if dn || ctx.Err() != nil {
		one.Targets = append(append([]netip.Addr(nil), hosts...), hop)
		return one, dn, true
	}
	if !one.OK() || one.Stats.Received == 0 {
		// The hop stopped answering. Trace again rather than score a
		// router that rate-limits as 100% loss.
		e.forgetIndirect(k)
		return Result{}, false, false
	}
	if !e.hostQualifies(one.Stats) {
		return Result{}, false, false
	}
	one.Targets = append(append([]netip.Addr(nil), hosts...), hop)
	one.Indirect = true
	return one, false, true
}

// loadIndirect returns the cached trace for k. found is false when there
// is no entry or it aged out. The hops slice aliases the cache; callers
// that keep it must copy.
func (e *Engine) loadIndirect(k key) (indirectHop, bool) {
	now := e.opt.Now()
	e.indMu.Lock()
	defer e.indMu.Unlock()
	h, ok := e.indCache[k]
	if !ok {
		return indirectHop{}, false
	}
	if e.opt.Indirect == nil || !now.Before(h.at.Add(e.opt.Indirect.CacheTTL)) {
		delete(e.indCache, k)
		return indirectHop{}, false
	}
	return h, true
}

// cachedIndirect returns the cached hop for k. found is false when there
// is no entry or it aged out. A found entry with an invalid hop means the
// last trace found none.
func (e *Engine) cachedIndirect(k key) (netip.Addr, bool) {
	h, ok := e.loadIndirect(k)
	if !ok {
		return netip.Addr{}, false
	}
	if !h.ok {
		return netip.Addr{}, true
	}
	return h.hop, true
}

// traceHops returns a copy of the cached stable hop addresses for k.
// Nil when no trace is cached or it listed no hop.
func (e *Engine) traceHops(k key) []netip.Addr {
	h, ok := e.loadIndirect(k)
	if !ok || len(h.hops) == 0 {
		return nil
	}
	return append([]netip.Addr(nil), h.hops...)
}

func (e *Engine) forgetIndirect(k key) {
	e.indMu.Lock()
	defer e.indMu.Unlock()
	delete(e.indCache, k)
	delete(e.indQueued, k)
}

// queueIndirect adds a trace for the next background pass. A key that is
// already queued keeps its place. Past MaxQueue new traces are dropped
// and asked for again on a later round.
func (e *Engine) queueIndirect(r indirectReq) {
	limit := e.opt.Indirect.MaxQueue
	if limit <= 0 {
		limit = defaultIndirectQueue
	}
	e.indMu.Lock()
	if e.indQueued == nil {
		e.indQueued = map[key]indirectReq{}
	}
	if _, ok := e.indQueued[r.key]; ok || len(e.indQueued) >= limit {
		e.indMu.Unlock()
		return
	}
	e.indQueued[r.key] = r
	e.indOrder = append(e.indOrder, r.key)
	e.indMu.Unlock()
	select {
	case e.indWake <- struct{}{}:
	default:
	}
}

// pendingIndirect is the queue in arrival order. Keys that were dropped
// since they were queued, or queued again after a drop, are compacted
// out so each key appears once.
func (e *Engine) pendingIndirect() []indirectReq {
	e.indMu.Lock()
	defer e.indMu.Unlock()
	order := e.indOrder[:0]
	seen := make(map[key]bool, len(e.indQueued))
	var out []indirectReq
	for _, k := range e.indOrder {
		r, ok := e.indQueued[k]
		if !ok || seen[k] {
			continue
		}
		seen[k] = true
		order = append(order, k)
		out = append(out, r)
	}
	e.indOrder = order
	return out
}

// pruneIndirect drops cached hops and queued traces for prefixes that
// left the target list. keep comes from a completed round.
func (e *Engine) pruneIndirect(keep map[netip.Prefix]bool) {
	if !e.indirectEnabled() {
		return
	}
	e.indMu.Lock()
	defer e.indMu.Unlock()
	for k := range e.indCache {
		if !keep[k.prefix] {
			delete(e.indCache, k)
		}
	}
	for k := range e.indQueued {
		if !keep[k.prefix] {
			delete(e.indQueued, k)
		}
	}
}

// indirectHosts is every cached hop, so prober memory keeps them.
func (e *Engine) indirectHosts() []netip.Addr {
	if !e.indirectEnabled() {
		return nil
	}
	e.indMu.Lock()
	defer e.indMu.Unlock()
	var out []netip.Addr
	for _, h := range e.indCache {
		if h.ok {
			out = append(out, h.hop)
		}
	}
	return out
}

// usableIndirect rejects a hop that is not a separate responder on this
// provider's path: the silent destination itself, the probe source, the
// other address family, or an address on an exchange peering LAN.
func (e *Engine) usableIndirect(hop, dst netip.Addr, p Provider) bool {
	if !hop.IsValid() || hop.Is4() != dst.Is4() {
		return false
	}
	hop = hop.Unmap()
	if hop == dst.Unmap() || (p.Source.IsValid() && hop == p.Source.Unmap()) {
		return false
	}
	if hop.IsUnspecified() || hop.IsLoopback() || hop.IsMulticast() || hop.IsLinkLocalUnicast() {
		return false
	}
	return !exchange.ContainsAddr(e.opt.ExchangeLANs, hop)
}

// runIndirect traces queued prefixes until ctx ends. A pass starts when
// a trace is queued and passes are at least Options.Interval apart, so
// tracing never runs back to back.
func (e *Engine) runIndirect(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.indWake:
		}
		e.IndirectPass(ctx)
		t := time.NewTimer(e.interval())
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// IndirectPass runs one background pass over the queued traces under
// Indirect.Budget and returns how many traces finished. Each trace runs
// from its provider's source address and every packet waits on the
// global rate limit. Traces the budget did not reach stay queued. Run
// calls it in the background; tests call it directly.
func (e *Engine) IndirectPass(ctx context.Context) int {
	if !e.indirectEnabled() {
		return 0
	}
	reqs := e.pendingIndirect()
	if len(reqs) == 0 {
		return 0
	}
	in := e.opt.Indirect
	bctx, cancel := context.WithTimeout(ctx, in.Budget)
	defer cancel()
	share := in.Budget / time.Duration(len(reqs))
	if share < in.MinShare {
		share = in.MinShare
	}
	var wait func(context.Context) error
	if e.opt.Limiter != nil {
		wait = func(c context.Context) error { return e.opt.Limiter.WaitN(c, 1) }
	}
	done := 0
	for _, r := range reqs {
		if bctx.Err() != nil {
			break
		}
		tctx, tcancel := context.WithTimeout(bctx, share)
		var hops []netip.Addr
		var hop netip.Addr
		var ok bool
		var err error
		if pt, is := in.Tracer.(pathTracer); is {
			hops, hop, ok, err = pt.TracePath(tctx, r.provider.Source, r.dst, wait)
		} else {
			hop, ok, err = in.Tracer.Trace(tctx, r.provider.Source, r.dst, wait)
		}
		tcancel()
		if err != nil {
			if errors.Is(err, plugin.ErrSourceUnavailable) {
				// The probe source is gone; the normal probe fails
				// closed. Ask again once the prefix is silent again.
				e.forgetIndirect(r.key)
				e.log.Warn("indirect trace: probe source unavailable", "provider", r.provider.Name, "source", r.provider.Source, "err", err)
				continue
			}
			// Nothing collected before the share ran out: retry later.
			continue
		}
		if ok && !e.usableIndirect(hop, r.dst, r.provider) {
			ok = false
		}
		entry := indirectHop{ok: ok, at: e.opt.Now()}
		if ok {
			entry.hop = hop.Unmap()
		}
		if len(hops) > 0 {
			entry.hops = append([]netip.Addr(nil), hops...)
		}
		e.indMu.Lock()
		if _, still := e.indQueued[r.key]; still {
			e.indCache[r.key] = entry
			delete(e.indQueued, r.key)
		}
		e.indMu.Unlock()
		done++
		e.log.Debug("indirect trace", "provider", r.provider.Name, "prefix", r.key.prefix, "dest", r.dst, "hop", entry.hop, "found", ok)
	}
	return done
}
