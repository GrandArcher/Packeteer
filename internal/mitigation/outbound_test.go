package mitigation

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/announce"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// outboundAnn is the outbound announcer's wire.
type outboundAnn struct {
	plugin.Base
	mu   sync.Mutex
	wire map[netip.Prefix]bool
}

func (o *outboundAnn) Announce(_ context.Context, r plugin.Route) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.wire[r.Prefix] = true
	return nil
}

func (o *outboundAnn) Withdraw(_ context.Context, p netip.Prefix) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.wire, p)
	return nil
}

func (o *outboundAnn) WithdrawAll(context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	clear(o.wire)
	return nil
}

func (o *outboundAnn) has(p netip.Prefix) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.wire[p]
}

// TestRuleAddedMidRoundWaitsForOutbound adds a rule between the outbound
// Sync and the mitigation Sync of one round (#379), for a prefix outbound
// announces. The prefix never carries both routes: the rule waits, and
// goes out in the next round, after outbound has released the prefix.
func TestRuleAddedMidRoundWaitsForOutbound(t *testing.T) {
	ctx := context.Background()
	mit, mann, rib := newTest(t, config.ModeInject)
	oann := &outboundAnn{wire: map[netip.Prefix]bool{}}
	ob, err := announce.New(announce.Config{
		Mode:            config.ModeInject,
		LocalPref:       200,
		Community:       "64512:666",
		MaxImprovements: 5,
		Allowlist:       []netip.Prefix{victim},
		NextHops:        map[string]netip.Addr{"a": netip.MustParseAddr("192.0.2.1"), "b": netip.MustParseAddr("192.0.2.2")},
		Reserved:        mit.Holds,
	}, oann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	mit.SetOutbound(ob.Injected)
	imps := []policy.Improvement{{Prefix: victim, Provider: "b", Native: "a"}}
	paths := func() int {
		n := 0
		if oann.has(victim) {
			n++
		}
		if _, ok := mann.on(victim); ok {
			n++
		}
		return n
	}

	if err := ob.Sync(ctx, imps); err != nil {
		t.Fatal(err)
	}
	if !oann.has(victim) {
		t.Fatal("outbound did not announce the improvement")
	}

	// The rule arrives after the outbound Sync of this round.
	if _, err := mit.Add(Request{Prefix: victim, Action: plugin.MitigationBlackhole, TTL: 10 * time.Minute}, t0); err != nil {
		t.Fatal(err)
	}
	if err := mit.Sync(ctx, t0); err != nil {
		t.Fatal(err)
	}
	if n := paths(); n != 1 || !oann.has(victim) {
		t.Fatalf("round 1: %d Packeteer paths, outbound up %v; want only the outbound route", n, oann.has(victim))
	}
	if r := mit.Status().Rules[0]; r.Announced || r.Pending != pendingOutbound || mit.Active() != 0 {
		t.Fatalf("rule = %+v, active %d", r, mit.Active())
	}

	// Next round: the rule holds the prefix, so outbound releases it, and
	// then mitigation announces.
	if err := ob.Sync(ctx, imps); err == nil {
		t.Fatal("outbound did not report the reserved prefix")
	}
	if oann.has(victim) {
		t.Fatal("outbound kept a prefix a mitigation rule holds")
	}
	if err := mit.Sync(ctx, t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n := paths(); n != 1 {
		t.Fatalf("round 2: %d Packeteer paths, want 1", n)
	}
	if got, ok := mann.on(victim); !ok || got.Action != plugin.MitigationBlackhole {
		t.Fatalf("mitigation wire = %+v %v", got, ok)
	}
	if r := mit.Status().Rules[0]; !r.Announced || r.Pending != "" {
		t.Fatalf("rule = %+v", r)
	}
}

func TestSetOutboundNil(t *testing.T) {
	var c *Controller
	c.SetOutbound(func(netip.Prefix) bool { return true })
}
