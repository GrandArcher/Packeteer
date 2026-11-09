package announce

import (
	"context"
	"net/netip"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/policy"
)

// Leak watch holds (#199).

func TestHeldPrefixIsWithdrawnAndNeverAnnounced(t *testing.T) {
	rib := learned("198.51.100.0/24", "203.0.113.0/24")
	ann := &fakeAnn{}
	held := map[netip.Prefix]bool{}
	cfg := testCfg()
	cfg.Held = func(p netip.Prefix) bool { return held[p] }
	c, err := New(cfg, ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	imps := []policy.Improvement{imp("198.51.100.0/24", "b"), imp("203.0.113.0/24", "b")}
	if err := c.Sync(context.Background(), imps); err != nil {
		t.Fatal(err)
	}
	wantWire(t, ann, "198.51.100.0/24", "203.0.113.0/24")

	held[pfx("203.0.113.0/24")] = true
	for range 3 {
		if err := c.Sync(context.Background(), imps); err != nil {
			t.Fatalf("a held prefix must not be a sync error: %v", err)
		}
		wantWire(t, ann, "198.51.100.0/24")
	}
	if ann.all != 0 {
		t.Fatal("a hold must not be a bulk withdraw")
	}

	delete(held, pfx("203.0.113.0/24"))
	if err := c.Sync(context.Background(), imps); err != nil {
		t.Fatal(err)
	}
	wantWire(t, ann, "198.51.100.0/24", "203.0.113.0/24")
}

func TestWithdrawPrefixTakesOnlyThatRouteAndItsMoreSpecifics(t *testing.T) {
	rib := learned("198.51.100.0/24", "203.0.113.0/24", "203.0.113.0/25")
	ann := &fakeAnn{}
	cfg := msCfg(10, nil)
	c, err := New(cfg, ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(context.Background(), []policy.Improvement{imp("198.51.100.0/24", "b"), imp("203.0.113.0/24", "b")}); err != nil {
		t.Fatal(err)
	}
	wantWire(t, ann, "198.51.100.0/24", "203.0.113.0/24", "203.0.113.0/25")
	if !c.Injected(pfx("203.0.113.0/25")) || c.Injected(pfx("192.0.2.0/24")) {
		t.Fatal("Injected is wrong")
	}
	if err := c.WithdrawPrefix(context.Background(), pfx("203.0.113.0/24")); err != nil {
		t.Fatal(err)
	}
	wantWire(t, ann, "198.51.100.0/24")
	if c.Active() != 1 || c.Routes() != 1 {
		t.Fatalf("counts %d/%d", c.Active(), c.Routes())
	}
}

func TestHeldMoreSpecificIsNotAnnounced(t *testing.T) {
	rib := learned("203.0.113.0/24", "203.0.113.0/25", "203.0.113.128/25")
	ann := &fakeAnn{}
	cfg := msCfg(10, nil)
	cfg.Held = func(p netip.Prefix) bool { return p == pfx("203.0.113.0/25") }
	c, err := New(cfg, ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(context.Background(), []policy.Improvement{imp("203.0.113.0/24", "b")}); err != nil {
		t.Fatal(err)
	}
	wantWire(t, ann, "203.0.113.0/24", "203.0.113.128/25")
}

func TestOnWireProviderIsTheRouteOnTheWire(t *testing.T) {
	rib := learned("198.51.100.0/24", "203.0.113.0/24", "203.0.113.0/25")
	ann := &fakeAnn{}
	c, err := New(msCfg(10, nil), ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.OnWireProvider(pfx("198.51.100.0/24")); ok {
		t.Fatal("nothing is on the wire yet")
	}
	if err := c.Sync(context.Background(), []policy.Improvement{imp("198.51.100.0/24", "b"), imp("203.0.113.0/24", "b")}); err != nil {
		t.Fatal(err)
	}
	if p, ok := c.OnWireProvider(pfx("198.51.100.0/24")); !ok || p != "b" {
		t.Fatalf("improvement route = %q, %v", p, ok)
	}
	if _, ok := c.OnWireProvider(pfx("203.0.113.0/25")); ok {
		t.Fatal("a learned more-specific is not the improvement's route")
	}
	// A switch to a provider with no next hop fails; the old route stays.
	err = c.Sync(context.Background(), []policy.Improvement{imp("198.51.100.0/24", "nohop"), imp("203.0.113.0/24", "b")})
	if err == nil {
		t.Fatal("a switch to a provider without a next hop must fail")
	}
	if p, ok := c.OnWireProvider(pfx("198.51.100.0/24")); !ok || p != "b" {
		t.Fatalf("after the failed switch the wire still carries b, got %q, %v", p, ok)
	}
	var nilCtl *Controller
	if _, ok := nilCtl.OnWireProvider(pfx("198.51.100.0/24")); ok {
		t.Fatal("a nil controller has nothing on the wire")
	}
}
