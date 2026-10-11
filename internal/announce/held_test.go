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
