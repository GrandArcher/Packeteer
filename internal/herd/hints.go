package herd

import (
	"cmp"
	"context"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// maxHints bounds the hints kept between refreshes. It equals the highest
// max_targets the herd_hints source accepts.
const maxHints = 1024

// Hint is a route in this node's RIB view that other members see degraded
// now (#672): Vantages counts them once per ASN, the way the world view
// counts (verified members only when an identity source is configured).
// A hint only adds a probe target; it is never a reason to steer.
type Hint struct {
	Prefix   netip.Prefix `json:"prefix"`
	Vantages int          `json:"vantages"`
}

// Hints returns the hints of the last refresh. It never blocks, so the
// probe engine may call it.
func (h *Herd) Hints() []Hint {
	if p := h.hints.Load(); p != nil {
		return *p
	}
	return nil
}

// runHints refreshes the hints every pull interval on herd's own
// goroutine, so the probe loop never reads the herd store.
func (h *Herd) runHints(ctx context.Context) {
	h.pull.guard.run(ctx, "hints", func(ctx context.Context) {
		t := time.NewTicker(h.o.Cfg.Limits.PullInterval)
		defer t.Stop()
		for {
			h.refreshHints(ctx)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	})
}

// refreshHints stores the hints of the current world view.
func (h *Herd) refreshHints(ctx context.Context) {
	out := []Hint{}
	defer func() { h.hints.Store(&out) }()
	if !h.o.RIB.Ready() {
		return
	}
	ev, err := h.board().Events(ctx, "")
	if err != nil {
		h.o.Log.Warn("herd hints", "err", err)
		return
	}
	out = hintsFrom(ev, h.o.RIB)
}

// hintsFrom maps world view events to local routes: a route target to the
// exact prefix when it is in the RIB view, an origin target to the routes
// in the view that this origin announces. Only other members' rows that
// count and see loss are counted; default routes and never-shared space
// are left out. Most vantages first, at most maxHints.
func hintsFrom(ev Events, view RIB) []Hint {
	out := []Hint{}
	prefixes, origins := map[netip.Prefix]int{}, map[uint32]int{}
	for _, e := range ev.Events {
		bad := map[uint32]bool{}
		for _, v := range e.Vantages {
			if !v.Local && v.Counted && v.Degraded {
				bad[v.ASN] = true
			}
		}
		if len(bad) == 0 {
			continue
		}
		switch e.Kind {
		case kindPrefix:
			if p, err := netip.ParsePrefix(e.Value); err == nil {
				prefixes[p] = len(bad)
			}
		case kindOrigin:
			if a, err := strconv.ParseUint(e.Value, 10, 32); err == nil {
				origins[uint32(a)] = len(bad)
			}
		}
	}
	for p, n := range prefixes {
		if _, ok := view.Exact(p); ok && Shareable(p) {
			out = append(out, Hint{Prefix: p, Vantages: n})
		}
	}
	if len(origins) > 0 {
		for _, rt := range view.Routes() {
			n := 0
			if len(rt.ASPath) > 0 {
				n = origins[rt.ASPath[len(rt.ASPath)-1]]
			}
			if _, dup := prefixes[rt.Prefix]; n > 0 && !dup && Shareable(rt.Prefix) {
				prefixes[rt.Prefix] = n
				out = append(out, Hint{Prefix: rt.Prefix, Vantages: n})
			}
		}
	}
	slices.SortFunc(out, func(a, b Hint) int {
		if c := cmp.Compare(b.Vantages, a.Vantages); c != 0 {
			return c
		}
		return cmp.Compare(a.Prefix.String(), b.Prefix.String())
	})
	return out[:min(len(out), maxHints)]
}

// crowd counts the other verified ASNs this node pulled records from for
// exactly prefix, inside its retention: the count the crowd threshold
// compares with crowd_k. Without an identity source nobody counts. A count
// is kept for one pull interval, the soonest it could change, so a peer
// that asks for many routes costs at most one count per route per
// interval.
func (h *Herd) crowd(prefix netip.Prefix) int {
	if h.pull == nil || h.ids == nil {
		return 0
	}
	now := h.o.Now()
	h.crowdMu.Lock()
	defer h.crowdMu.Unlock()
	if c, ok := h.crowdAt[prefix]; ok && now.Sub(c.at) < h.o.Cfg.Limits.PullInterval {
		return c.n
	}
	if len(h.crowdAt) >= maxCrowd {
		clear(h.crowdAt)
	}
	floor := now.Add(-time.Duration(h.o.Cfg.RetentionDays) * 24 * time.Hour)
	n := crowdCount(context.Background(), h.o.Store, h.peers(), h.o.ASN, prefix, floor)
	h.crowdAt[prefix] = crowdEntry{n: n, at: now}
	return n
}

// maxCrowd bounds the cached crowd counts.
const maxCrowd = 4096

type crowdEntry struct {
	n  int
	at time.Time
}

// crowdCount counts the distinct ASNs other than self among the verified
// peers that have a record for exactly prefix since floor.
func crowdCount(ctx context.Context, st plugin.HerdStore, peers []PeerStatus, self uint32, prefix netip.Prefix, floor time.Time) int {
	asns := map[uint32]bool{}
	for _, p := range peers {
		if !p.Verified || p.ASN == self || asns[p.ASN] {
			continue
		}
		rows, err := st.HerdRecords(ctx, plugin.HerdQuery{Member: p.KeyID, Prefix: prefix, Match: MatchExact, From: floor, Limit: 1})
		if err == nil && len(rows) > 0 {
			asns[p.ASN] = true
		}
	}
	return len(asns)
}
