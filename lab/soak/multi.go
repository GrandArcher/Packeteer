package main

import (
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"net/netip"
	"sync"
	"time"
)

// Withdraw-latency check (#383). Every withdrawEvery one IPv4 prefix that
// Packeteer has injected on every fast session for at least minInjected is
// withdrawn on every session. Packeteer must take its route back: the
// time from that withdraw to Packeteer's withdraw on each session is the
// update latency through the RIB view, Decide, and the announcer. Churn
// walks only the IPv6 entries, so it never touches the checked prefix.
const (
	withdrawEvery = 10 * time.Second
	// minInjected is past policy.NativePathConfirm (5s): a prefix that
	// leaves the RIB sooner after it was injected is kept, because the
	// router may have stopped sending it for our own route.
	minInjected = 15 * time.Second
	// withdrawWait is how long a fast session may keep the route.
	withdrawWait = time.Minute
	// reconnectWait is how long Packeteer may take to come back after a
	// flap. GoBGP waits out its idle hold time before it reconnects.
	reconnectWait = 2 * time.Minute
)

// latencies is what the withdraw check measured, in ms. Fast sessions
// read at once; the slow one reads at slow_peer_bps.
type latencies struct {
	mu       sync.Mutex
	checks   int
	fast     []float64
	slow     []float64
	slowLate int // the slow session still held the route after withdrawWait
}

func (l *latencies) add(slow bool, ms float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if slow {
		l.slow = append(l.slow, ms)
	} else {
		l.fast = append(l.fast, ms)
	}
}

// slowID is the index of the slow session, or -1.
func slowID(p Profile) int {
	if p.SlowPeerBPS > 0 {
		return p.sessions() - 1
	}
	return -1
}

// withdrawCheck runs the withdraw-latency check until ctx ends.
func withdrawCheck(ctx context.Context, f *fleet, tbl table, slow int, lat *latencies, fail func(string, ...any)) {
	rng := rand.New(rand.NewPCG(383, 383))
	t := time.NewTicker(withdrawEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		i, ok := pickInjected(f, tbl, slow, rng, time.Now())
		if !ok {
			continue
		}
		timeWithdraw(f, tbl.prefix(i), i, slow, withdrawWait, lat, fail)
	}
}

// pickInjected is an IPv4 entry every established fast session has held
// for minInjected, chosen at random. With no fast session up the slow one
// counts.
func pickInjected(f *fleet, tbl table, slow int, rng *rand.Rand, now time.Time) (int, bool) {
	var held []map[netip.Prefix]time.Time
	for _, r := range f.routers {
		if r.established() && r.id != slow {
			held = append(held, r.out.snapshot())
		}
	}
	if len(held) == 0 && slow >= 0 && f.routers[slow].established() {
		held = append(held, f.routers[slow].out.snapshot())
	}
	if len(held) == 0 {
		return 0, false
	}
	var cands []int
	for p, at := range held[0] {
		i, ok := tbl.index(p)
		if !ok || i >= v4Count || now.Sub(at) < minInjected || f.adv.withdrawn(i) {
			continue
		}
		all := true
		for _, h := range held[1:] {
			if t, ok := h[p]; !ok || now.Sub(t) < minInjected {
				all = false
				break
			}
		}
		if all {
			cands = append(cands, i)
		}
	}
	if len(cands) == 0 {
		return 0, false
	}
	return cands[rng.IntN(len(cands))], true
}

// timeWithdraw withdraws entry i on every session, waits up to wait for
// Packeteer's withdraw on each session that held it, and announces i
// again.
func timeWithdraw(f *fleet, p netip.Prefix, i, slow int, wait time.Duration, lat *latencies, fail func(string, ...any)) {
	var holders []*router
	for _, r := range f.routers {
		if _, ok := r.out.since(p); ok && r.established() {
			holders = append(holders, r)
		}
	}
	t0 := time.Now()
	f.withdraw(i, i+1)
	defer f.announce(i, i+1)
	lat.mu.Lock()
	lat.checks++
	lat.mu.Unlock()
	for _, r := range holders {
		gone := waitFor(context.Background(), wait, func() bool {
			_, held := r.out.since(p)
			return !held || !r.established()
		})
		at := r.out.withdrawnAt(p)
		switch {
		case gone && at.After(t0):
			lat.add(r.id == slow, float64(at.Sub(t0).Microseconds())/1000)
		case gone:
			// The session ended first and took its routes with it, or
			// Packeteer had retired the route before the check began.
		case r.id == slow:
			lat.mu.Lock()
			lat.slowLate++
			lat.mu.Unlock()
		default:
			fail("session %d still had Packeteer's route for %s %s after the prefix left every session", r.id, p, wait)
		}
	}
}

// flapStats is what the flapper did.
type flapStats struct {
	mu        sync.Mutex
	flaps     int
	reconnect float64 // longest flap to established, seconds
}

// flapper closes one session every p.FlapEvery, taking turns and never the
// slow one, and waits for Packeteer to come back. The router sends the
// whole table again on the new session.
func flapper(ctx context.Context, f *fleet, every time.Duration, slow int, st *flapStats, fail func(string, ...any)) {
	var turn []*router
	for _, r := range f.routers {
		if r.id != slow {
			turn = append(turn, r)
		}
	}
	if every <= 0 || len(turn) == 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for k := 0; ; k++ {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		r := turn[k%len(turn)]
		t0 := time.Now()
		if !r.flap() {
			continue
		}
		log.Printf("flap: closed session %d", r.id)
		back := waitFor(context.Background(), reconnectWait, r.established)
		secs := time.Since(t0).Seconds()
		st.mu.Lock()
		st.flaps++
		st.reconnect = max(st.reconnect, secs)
		st.mu.Unlock()
		if !back {
			fail("session %d did not come back %s after a flap", r.id, reconnectWait)
			return
		}
		log.Printf("flap: session %d back after %.1fs", r.id, secs)
	}
}

// sameRoutes waits until every established fast session holds the same
// Packeteer routes and returns the count, or an error naming two sessions
// that still differ.
func sameRoutes(ctx context.Context, f *fleet, slow int, timeout time.Duration) (int, error) {
	var a, b map[netip.Prefix]time.Time
	var ia, ib int
	ok := waitFor(ctx, timeout, func() bool {
		a = nil
		for _, r := range f.routers {
			if r.id == slow || !r.established() {
				continue
			}
			got := r.out.snapshot()
			if a == nil {
				a, ia = got, r.id
				continue
			}
			if !sameKeys(a, got) {
				b, ib = got, r.id
				return false
			}
		}
		return true
	})
	if !ok {
		return 0, fmt.Errorf("session %d holds %d Packeteer routes and session %d holds %d", ia, len(a), ib, len(b))
	}
	return len(a), nil
}

func sameKeys(a, b map[netip.Prefix]time.Time) bool {
	if len(a) != len(b) {
		return false
	}
	for p := range a {
		if _, ok := b[p]; !ok {
			return false
		}
	}
	return true
}
