package mitigation

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/announce"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// edgeWire is one speaker shared by the outbound and mitigation
// announcers. Every announce checks, under one lock, that the other
// announcer has no route for the prefix: one Packeteer path per prefix.
type edgeWire struct {
	mu        sync.Mutex
	outbound  map[netip.Prefix]bool
	mitigated map[netip.Prefix]bool
	both      []string
}

func newEdgeWire() *edgeWire {
	return &edgeWire{outbound: map[netip.Prefix]bool{}, mitigated: map[netip.Prefix]bool{}}
}

func (w *edgeWire) violations() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.both...)
}

type edgeOutbound struct {
	plugin.Base
	w *edgeWire
}

func (o edgeOutbound) Announce(_ context.Context, r plugin.Route) error {
	o.w.mu.Lock()
	defer o.w.mu.Unlock()
	if o.w.mitigated[r.Prefix] {
		o.w.both = append(o.w.both, "outbound announced over mitigation: "+r.Prefix.String())
	}
	o.w.outbound[r.Prefix] = true
	return nil
}

func (o edgeOutbound) Withdraw(_ context.Context, p netip.Prefix) error {
	o.w.mu.Lock()
	defer o.w.mu.Unlock()
	delete(o.w.outbound, p)
	return nil
}

func (o edgeOutbound) WithdrawAll(context.Context) error {
	o.w.mu.Lock()
	defer o.w.mu.Unlock()
	clear(o.w.outbound)
	return nil
}

type edgeMitigation struct {
	*fakeAnn
	w *edgeWire
}

func (m edgeMitigation) Announce(ctx context.Context, r plugin.MitigationRoute) error {
	m.w.mu.Lock()
	defer m.w.mu.Unlock()
	if m.w.outbound[r.Prefix] {
		m.w.both = append(m.w.both, "mitigation announced over outbound: "+r.Prefix.String())
	}
	m.w.mitigated[r.Prefix] = true
	return nil
}

func (m edgeMitigation) Withdraw(_ context.Context, p netip.Prefix) error {
	m.w.mu.Lock()
	defer m.w.mu.Unlock()
	delete(m.w.mitigated, p)
	return nil
}

func (m edgeMitigation) WithdrawAll(context.Context) error {
	m.w.mu.Lock()
	defer m.w.mu.Unlock()
	clear(m.w.mitigated)
	return nil
}

// TestHoldsAndInjectedAcrossGoroutines drives the outbound and mitigation
// Syncs from separate goroutines (#492). Mitigation asks outbound's
// Injected and outbound asks mitigation's Holds, each from inside its own
// Sync; with the locks nested both ways this deadlocks. It must finish,
// pass -race, and never put both routes on one prefix.
func TestHoldsAndInjectedAcrossGoroutines(t *testing.T) {
	ctx := context.Background()
	w := newEdgeWire()
	rib := &fakeRIB{ready: true, learned: map[netip.Prefix]bool{victim: true, other: true}}
	cfg := testConfig(config.ModeInject)
	mit, err := New(cfg, edgeMitigation{fakeAnn: newFakeAnn(), w: w}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := mit.SetRIB(rib); err != nil {
		t.Fatal(err)
	}
	ob, err := announce.New(announce.Config{
		Mode: config.ModeInject, LocalPref: 200, Community: "64512:666", MaxImprovements: 5,
		Allowlist: cfg.Allowlist,
		NextHops:  map[string]netip.Addr{"a": netip.MustParseAddr("192.0.2.1"), "b": netip.MustParseAddr("192.0.2.2")},
		Reserved:  mit.Holds,
	}, edgeOutbound{w: w}, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	mit.SetOutbound(ob.Injected)
	imps := []policy.Improvement{{Prefix: victim, Provider: "b", Native: "a"}, {Prefix: other, Provider: "b", Native: "a"}}

	const rounds = 300
	var wg sync.WaitGroup
	wg.Add(4)
	go func() {
		defer wg.Done()
		for range rounds {
			_ = ob.Sync(ctx, imps)
		}
	}()
	go func() {
		defer wg.Done()
		for i := range rounds {
			now := t0.Add(time.Duration(i) * time.Second)
			p := victim
			if i%2 == 1 {
				p = other
			}
			r, err := mit.Add(Request{Prefix: p, Action: plugin.MitigationBlackhole, TTL: 10 * time.Minute}, now)
			if err != nil {
				panic(fmt.Sprintf("add: %v", err))
			}
			_ = mit.Sync(ctx, now)
			mit.Remove(r.ID)
			_ = mit.Sync(ctx, now)
		}
	}()
	go func() {
		defer wg.Done()
		for range rounds {
			_ = mit.Holds(victim)
			_ = ob.Injected(other)
			_ = mit.Status()
		}
	}()
	go func() {
		defer wg.Done()
		for i := range rounds / 10 {
			_ = mit.WithdrawAll(ctx)
			_ = ob.WithdrawAll(ctx)
			if i%2 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
	}()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("outbound and mitigation Syncs on separate goroutines deadlocked")
	}
	if v := w.violations(); len(v) > 0 {
		t.Fatalf("a prefix carried two Packeteer paths (%d times), first: %s", len(v), v[0])
	}
}

// blockingAnn holds every Announce until release is closed.
type blockingAnn struct {
	*fakeAnn
	in      chan struct{}
	release chan struct{}
}

func (b blockingAnn) Announce(ctx context.Context, r plugin.MitigationRoute) error {
	b.in <- struct{}{}
	<-b.release
	return b.fakeAnn.Announce(ctx, r)
}

// A Sync that waits on the announcer does not hold up Status, Holds, or
// Add (#492): they only read or change the rules.
func TestStatusAndHoldsDoNotWaitForAnnounce(t *testing.T) {
	ann := blockingAnn{fakeAnn: newFakeAnn(), in: make(chan struct{}, 1), release: make(chan struct{})}
	mit, err := New(testConfig(config.ModeInject), ann, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := mit.SetRIB(&fakeRIB{ready: true, learned: map[netip.Prefix]bool{victim: true}}); err != nil {
		t.Fatal(err)
	}
	r, err := mit.Add(Request{Prefix: victim, Action: plugin.MitigationBlackhole, TTL: 10 * time.Minute}, t0)
	if err != nil {
		t.Fatal(err)
	}
	synced := make(chan error, 1)
	go func() { synced <- mit.Sync(context.Background(), t0) }()
	<-ann.in
	answered := make(chan struct{})
	go func() {
		defer close(answered)
		if st := mit.Status(); len(st.Rules) != 1 || st.Rules[0].Announced {
			t.Errorf("status during the announce = %+v", st.Rules)
		}
		if !mit.Holds(victim) {
			t.Error("Holds is false while the rule is being announced")
		}
		// Removing the rule mid-announce keeps the prefix held until the
		// route is withdrawn.
		mit.Remove(r.ID)
		if !mit.Holds(victim) {
			t.Error("Holds is false while the removed rule's announce is in flight")
		}
		if _, err := mit.Add(Request{Prefix: other, Action: plugin.MitigationBlackhole, TTL: 10 * time.Minute}, t0); err != nil {
			t.Errorf("add: %v", err)
		}
	}()
	select {
	case <-answered:
	case <-time.After(5 * time.Second):
		t.Fatal("Status, Holds, or Add waited on the announcer")
	}
	close(ann.release)
	if err := <-synced; err != nil {
		t.Fatal(err)
	}
	if _, on := ann.on(victim); !on || !mit.Holds(victim) {
		t.Fatal("the route that was in flight is not on the wire and held")
	}
	if err := mit.Sync(context.Background(), t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, on := ann.on(victim); on || mit.Holds(victim) {
		t.Fatal("the removed rule's route was not withdrawn on the next Sync")
	}
}
