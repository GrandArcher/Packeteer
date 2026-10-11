package leakwatch

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const (
	localASN  = 64500
	community = 64500<<16 | 666
)

type fakeSource struct {
	plugin.Base
	mu      sync.Mutex
	sink    func(plugin.LeakSighting)
	healthy bool
}

func (f *fakeSource) SetLeakSink(fn func(plugin.LeakSighting)) { f.sink = fn }
func (f *fakeSource) Healthy() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.healthy
}
func (f *fakeSource) setHealthy(v bool) {
	f.mu.Lock()
	f.healthy = v
	f.mu.Unlock()
}

type rig struct {
	w        *Watcher
	src      *fakeSource
	mu       sync.Mutex
	onWire   map[netip.Prefix]bool
	withdraw []netip.Prefix
	werr     error
	events   []plugin.Event
}

func newRig(t *testing.T, onWire ...string) *rig {
	t.Helper()
	r := &rig{src: &fakeSource{healthy: true}, onWire: map[netip.Prefix]bool{}}
	for _, s := range onWire {
		r.onWire[netip.MustParsePrefix(s)] = true
	}
	r.w = New(Config{
		ASN: localASN, Community: community, Large: "64500:1:2",
		Injected: func(p netip.Prefix) bool { r.mu.Lock(); defer r.mu.Unlock(); return r.onWire[p] },
		Withdraw: func(_ context.Context, p netip.Prefix) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.withdraw = append(r.withdraw, p)
			if r.werr == nil {
				delete(r.onWire, p)
			}
			return r.werr
		},
		Emit: func(e plugin.Event) { r.mu.Lock(); r.events = append(r.events, e); r.mu.Unlock() },
		Log:  slog.New(slog.DiscardHandler),
	}, []Source{{Name: "feed", Type: "fake", Plugin: r.src}})
	return r
}

// feed delivers sightings through the source's sink and evaluates them.
func (r *rig) feed(sgs ...plugin.LeakSighting) {
	for _, s := range sgs {
		r.src.sink(s)
	}
	for range sgs {
		r.w.handle(context.Background(), <-r.w.queue)
	}
}

func sight(prefix string, path []uint32, comms ...uint32) plugin.LeakSighting {
	return plugin.LeakSighting{Prefix: netip.MustParsePrefix(prefix), ASPath: path, Communities: comms, Seen: "rrc00/192.0.2.9"}
}

func TestCommunityLeakWithdrawsOnlyThatRoute(t *testing.T) {
	r := newRig(t, "203.0.113.0/24", "198.51.100.0/24")
	r.feed(sight("203.0.113.0/24", []uint32{64511, 64510}, community))

	if !slices.Equal(r.withdraw, []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}) {
		t.Fatalf("withdrawn %v, want only 203.0.113.0/24", r.withdraw)
	}
	if !r.onWire[netip.MustParsePrefix("198.51.100.0/24")] {
		t.Fatal("the other injected route was touched")
	}
	if !r.w.Held(netip.MustParsePrefix("203.0.113.0/24")) || r.w.Held(netip.MustParsePrefix("198.51.100.0/24")) {
		t.Fatal("held set is wrong")
	}
	if len(r.events) != 1 || r.events[0].Kind != plugin.EventLeakDetected {
		t.Fatalf("events %+v", r.events)
	}
	f := r.events[0].Fields
	if f["prefix"] != "203.0.113.0/24" || f["reason"] != ReasonCommunity || f["action"] != ActionWithdrawn || f["as_path"] != "64511 64510" {
		t.Fatalf("event fields %v", f)
	}
	if r.events[0].Severity != plugin.SeverityCritical {
		t.Fatalf("severity %s", r.events[0].Severity)
	}
}

func TestLargeCommunityLeak(t *testing.T) {
	r := newRig(t, "203.0.113.0/24")
	s := sight("203.0.113.0/24", nil)
	s.LargeCommunities = []string{"64500:1:2"}
	r.feed(s)
	if len(r.withdraw) != 1 {
		t.Fatalf("withdrawn %v", r.withdraw)
	}
}

func TestASPathLeakNeedsInjectedPrefix(t *testing.T) {
	r := newRig(t, "203.0.113.0/24")
	// The operator's own prefix is seen outside with the local ASN all the
	// time and is not an injected route.
	r.feed(sight("192.0.2.0/24", []uint32{64511, localASN}))
	if len(r.events) != 0 || r.w.Held(netip.MustParsePrefix("192.0.2.0/24")) {
		t.Fatalf("own prefix flagged: %+v", r.events)
	}
	r.feed(sight("203.0.113.0/24", []uint32{64511, localASN, 64496}))
	if len(r.withdraw) != 1 || r.events[0].Fields["reason"] != ReasonASPath {
		t.Fatalf("withdraw %v events %+v", r.withdraw, r.events)
	}
}

func TestCleanSightingsRaiseNothing(t *testing.T) {
	r := newRig(t, "203.0.113.0/24")
	r.feed(
		sight("203.0.113.0/24", []uint32{64511, 64496}),               // injected prefix, path outside our AS
		sight("203.0.113.0/24", []uint32{64511}, 64511<<16|1),         // another community
		sight("198.51.100.0/24", []uint32{64511, 64496}, community+1), // near miss
	)
	// Our own router sending the route, local ASN in the path but no tag.
	own := sight("203.0.113.0/24", []uint32{localASN, 64496})
	own.OurExport = true
	r.feed(own)
	if len(r.events) != 0 || len(r.withdraw) != 0 || len(r.w.Status().Leaks) != 0 {
		t.Fatalf("false positive: events %+v withdraw %v", r.events, r.withdraw)
	}
}

func TestOurExportWithCommunityIsALeak(t *testing.T) {
	r := newRig(t, "203.0.113.0/24")
	s := sight("203.0.113.0/24", []uint32{64496}, community)
	s.OurExport = true
	r.feed(s)
	if len(r.withdraw) != 1 {
		t.Fatalf("withdrawn %v", r.withdraw)
	}
}

func TestRepeatSightingIsOneEvent(t *testing.T) {
	r := newRig(t, "203.0.113.0/24")
	s := sight("203.0.113.0/24", nil, community)
	r.feed(s, s, s)
	if len(r.events) != 1 || len(r.withdraw) != 1 {
		t.Fatalf("events %d withdraws %d", len(r.events), len(r.withdraw))
	}
	if got := r.w.Status().Leaks[0].Sightings; got != 3 {
		t.Fatalf("sightings %d", got)
	}
}

func TestLeakOfRouteNotOnWireIsHeldWithoutWithdraw(t *testing.T) {
	r := newRig(t)
	r.feed(sight("203.0.113.0/24", nil, community))
	if len(r.withdraw) != 0 {
		t.Fatalf("withdraw called: %v", r.withdraw)
	}
	if !r.w.Held(netip.MustParsePrefix("203.0.113.0/24")) || r.events[0].Fields["action"] != ActionHeld {
		t.Fatalf("not held: %+v", r.events)
	}
}

func TestWithdrawFailureStaysHeld(t *testing.T) {
	r := newRig(t, "203.0.113.0/24")
	r.werr = errors.New("speaker gone")
	r.feed(sight("203.0.113.0/24", nil, community))
	if !r.w.Held(netip.MustParsePrefix("203.0.113.0/24")) {
		t.Fatal("not held after a failed withdraw")
	}
	if r.events[0].Fields["action"] != ActionWithdrawFailed {
		t.Fatalf("action %q", r.events[0].Fields["action"])
	}
}

func TestClear(t *testing.T) {
	r := newRig(t, "203.0.113.0/24")
	p := netip.MustParsePrefix("203.0.113.0/24")
	r.feed(sight("203.0.113.0/24", nil, community))
	if r.w.Clear(netip.MustParsePrefix("198.51.100.0/24")) {
		t.Fatal("cleared a prefix that was not held")
	}
	if !r.w.Clear(p) || r.w.Held(p) {
		t.Fatal("clear did not release the prefix")
	}
	last := r.events[len(r.events)-1]
	if last.Kind != plugin.EventLeakCleared || last.Fields["prefix"] != "203.0.113.0/24" || !last.Resolves() {
		t.Fatalf("clear event %+v", last)
	}
	if r.events[0].DedupKey() != last.DedupKey() {
		t.Fatalf("detect and clear do not share a dedup key: %q %q", r.events[0].DedupKey(), last.DedupKey())
	}
	// Still visible outside: the next sighting holds it again.
	r.mu.Lock()
	r.onWire[p] = true
	r.mu.Unlock()
	r.feed(sight("203.0.113.0/24", nil, community))
	if !r.w.Held(p) || len(r.withdraw) != 2 {
		t.Fatalf("not held again: withdraws %v", r.withdraw)
	}
}

func TestUnhealthySourceIsUnknownAndStillWithdraws(t *testing.T) {
	r := newRig(t, "203.0.113.0/24")
	r.src.setHealthy(false)
	r.w.pollHealth()
	st := r.w.Status()
	if st.State != "unknown" || st.Sources[0].Healthy {
		t.Fatalf("status %+v", st)
	}
	// Another feed (or the last sighting before the outage) still acts.
	r.feed(sight("203.0.113.0/24", nil, community))
	if len(r.withdraw) != 1 {
		t.Fatal("a down feed blocked a withdraw")
	}
	r.src.setHealthy(true)
	r.w.pollHealth()
	if st := r.w.Status(); st.State != "watching" || !st.Sources[0].Healthy {
		t.Fatalf("status %+v", st)
	}
}

func TestSinkNeverBlocksAndCountsDrops(t *testing.T) {
	r := newRig(t)
	done := make(chan struct{})
	go func() {
		for range queueSize + 10 {
			r.src.sink(sight("203.0.113.0/24", nil))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sink blocked with the queue full")
	}
	if got := r.w.Status().Dropped; got != 10 {
		t.Fatalf("dropped %d, want 10", got)
	}
}

func TestHeldSetIsBounded(t *testing.T) {
	r := newRig(t)
	for i := range maxHeld + 5 {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)
		r.feed(plugin.LeakSighting{Prefix: p, Communities: []uint32{community}})
	}
	if got := len(r.w.Status().Leaks); got != maxHeld {
		t.Fatalf("held %d, want %d", got, maxHeld)
	}
}

func TestRunEvaluatesQueue(t *testing.T) {
	r := newRig(t, "203.0.113.0/24")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.w.Run(ctx); close(done) }()
	r.src.sink(sight("203.0.113.0/24", nil, community))
	p := netip.MustParsePrefix("203.0.113.0/24")
	deadline := time.Now().Add(5 * time.Second)
	for !r.w.Held(p) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if !r.w.Held(p) {
		t.Fatal("Run did not evaluate the sighting")
	}
}

func TestFullHeldSetStillWithdrawsAnInjectedRoute(t *testing.T) {
	r := newRig(t, "203.0.113.0/24")
	for i := range maxHeld {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)
		r.feed(plugin.LeakSighting{Prefix: p, Communities: []uint32{community}})
	}
	r.feed(sight("203.0.113.0/24", nil, community))
	if !slices.Equal(r.withdraw, []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}) || !r.w.Held(netip.MustParsePrefix("203.0.113.0/24")) {
		t.Fatalf("withdrawn %v with the held set full", r.withdraw)
	}
}

func TestASPathRuleIsOffWithoutASN(t *testing.T) {
	r := newRig(t, "203.0.113.0/24")
	r.w.cfg.ASN = 0
	r.feed(sight("203.0.113.0/24", []uint32{64511, localASN, 64496}))
	if len(r.withdraw) != 0 || len(r.events) != 0 || r.w.Held(netip.MustParsePrefix("203.0.113.0/24")) {
		t.Fatalf("transit export flagged with the AS path rule off: withdraw %v events %+v", r.withdraw, r.events)
	}
}

func TestNilWatcherIsInert(t *testing.T) {
	var w *Watcher
	st := w.Status()
	if st.State != "unknown" || len(st.Leaks) != 0 || st.Dropped != 0 {
		t.Fatalf("status %+v", st)
	}
	if w.Held(netip.MustParsePrefix("203.0.113.0/24")) || w.Clear(netip.MustParsePrefix("203.0.113.0/24")) {
		t.Fatal("nil watcher holds a prefix")
	}
}

// TestHandleDoesNotDeadlockWithSync reproduces the announcer's lock order:
// Sync holds its lock and calls Held while handle asks Injected, which takes
// that same lock. handle must not hold w.mu across Injected.
func TestHandleDoesNotDeadlockWithSync(t *testing.T) {
	var amu sync.Mutex // the announcer's c.mu
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	inInjected := make(chan struct{}, 1)
	syncHolds := make(chan struct{})
	var w *Watcher
	w = New(Config{
		ASN: localASN, Community: community,
		Injected: func(netip.Prefix) bool {
			select {
			case inInjected <- struct{}{}:
				<-syncHolds
			default:
			}
			amu.Lock()
			defer amu.Unlock()
			return true
		},
		Withdraw: func(context.Context, netip.Prefix) error { amu.Lock(); defer amu.Unlock(); return nil },
		Log:      slog.New(slog.DiscardHandler),
	}, nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			w.handle(context.Background(), sighting{source: "feed", s: sight("198.51.100.0/24", nil, community)})
		}()
		go func() { // Controller.Sync
			defer wg.Done()
			<-inInjected
			amu.Lock()
			close(syncHolds)
			w.Held(prefix)
			amu.Unlock()
		}()
		wg.Wait()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handle and Sync deadlocked on w.mu and the announcer lock")
	}
	if !w.Held(prefix) {
		t.Fatal("prefix not held after the sighting")
	}
}
