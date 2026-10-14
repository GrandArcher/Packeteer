package probe

import (
	"context"
	"net/netip"
	"sync"
)

// HopTarget is an exchange peer's next hop, probed from the peer's own
// source address (#149).
type HopTarget struct {
	Provider string
	Source   netip.Addr
	NextHop  netip.Addr
}

// HopResult is one next-hop measurement. Err is set when no measurement
// was possible (no prober could run, or the source address is unusable);
// a next hop that simply does not answer is a result with full loss.
type HopResult struct {
	Provider string
	Stats    Stats
	Err      string
}

// ProbeHops measures every target once, Workers at a time, with the same
// prober chain, packet count, timeout, and rate limit as a probe round. It
// stores nothing in the engine and changes no provider status: a next hop
// is a health signal, not a path score. Results are in target order. A
// cancelled context leaves the unfinished targets with Err set.
func (e *Engine) ProbeHops(ctx context.Context, targets []HopTarget) []HopResult {
	out := make([]HopResult, len(targets))
	idx := make(chan int)
	var wg sync.WaitGroup
	for range min(e.opt.Workers, len(targets)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idx {
				out[i] = e.probeHop(ctx, targets[i])
			}
		}()
	}
	for i := range targets {
		idx <- i
	}
	close(idx)
	wg.Wait()
	return out
}

func (e *Engine) probeHop(ctx context.Context, t HopTarget) HopResult {
	nh := t.NextHop.Unmap()
	res := Result{Provider: t.Provider, Prefix: netip.PrefixFrom(nh, nh.BitLen()), Target: nh}
	if ctx.Err() != nil {
		return HopResult{Provider: t.Provider, Err: ctx.Err().Error()}
	}
	sem := e.sem(nh)
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return HopResult{Provider: t.Provider, Err: ctx.Err().Error()}
	}
	defer func() { <-sem }()
	r, _ := e.runChain(ctx, res, Provider{Name: t.Provider, Source: t.Source}, e.packets(), 0, nil)
	return HopResult{Provider: t.Provider, Stats: r.Stats, Err: r.Err}
}
