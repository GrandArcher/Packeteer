package announce

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type memRIB struct {
	ready bool
	has   map[netip.Prefix]bool
}

func (m memRIB) Ready() bool { return m.ready }
func (m memRIB) Contains(p netip.Prefix) bool {
	return m.has[p.Masked()]
}

type fakeAnn struct {
	plugin.Base
	mu        sync.Mutex
	routes    map[netip.Prefix]plugin.Route
	all       int
	withdraws int
}

func (f *fakeAnn) Announce(_ context.Context, r plugin.Route) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.routes == nil {
		f.routes = map[netip.Prefix]plugin.Route{}
	}
	f.routes[r.Prefix] = r
	return nil
}

func (f *fakeAnn) Withdraw(_ context.Context, p netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.routes, p.Masked())
	f.withdraws++
	return nil
}

func (f *fakeAnn) WithdrawAll(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes = map[netip.Prefix]plugin.Route{}
	f.all++
	return nil
}

func (f *fakeAnn) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.routes)
}

type panicAnn struct{ plugin.Base }

func (panicAnn) Announce(context.Context, plugin.Route) error {
	panic("announced in a non-inject mode")
}
func (panicAnn) Withdraw(context.Context, netip.Prefix) error { panic("withdrew in a non-inject mode") }
func (panicAnn) WithdrawAll(context.Context) error            { panic("withdrew all in a non-inject mode") }

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func testCfg() Config {
	return Config{
		Mode:            "inject",
		LocalPref:       250,
		Community:       "64512:666",
		MaxImprovements: 50,
		Allowlist:       []netip.Prefix{pfx("198.51.100.0/24"), pfx("203.0.113.0/24"), pfx("2001:db8::/32")},
		NextHops: map[string]netip.Addr{
			"a": netip.MustParseAddr("192.0.2.1"),
			"b": netip.MustParseAddr("192.0.2.2"),
			"c": netip.MustParseAddr("2001:db8::2"),
		},
	}
}

func imp(prefix, provider string) policy.Improvement {
	return policy.Improvement{Prefix: pfx(prefix), Provider: provider, Native: "a"}
}

func TestObserveAndSuggestAnnounceNothing(t *testing.T) {
	rib := memRIB{ready: true, has: map[netip.Prefix]bool{pfx("198.51.100.0/24"): true}}
	for _, mode := range []string{"observe", "suggest"} {
		cfg := testCfg()
		cfg.Mode = mode
		c, err := New(cfg, panicAnn{}, rib, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Sync(context.Background(), []policy.Improvement{imp("198.51.100.0/24", "b")}); err != nil {
			t.Fatal(err)
		}
		if err := c.WithdrawAll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInjectAnnounceWithdrawAndGuards(t *testing.T) {
	ctx := context.Background()
	rib := memRIB{ready: true, has: map[netip.Prefix]bool{
		pfx("198.51.100.0/24"): true,
		pfx("203.0.113.0/24"):  true,
		pfx("2001:db8::/32"):   true,
	}}
	ann := &fakeAnn{}
	c, err := New(testCfg(), ann, &rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "b")}); err != nil {
		t.Fatal(err)
	}
	rt, ok := ann.routes[pfx("198.51.100.0/24")]
	if !ok || rt.NextHop.String() != "192.0.2.2" || rt.LocalPref != 250 || len(rt.Communities) != 1 || rt.Communities[0] != "64512:666" || rt.Provider != "b" {
		t.Fatalf("route = %+v", rt)
	}
	before := len(ann.routes)
	if err := c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "b")}); err != nil {
		t.Fatal(err)
	}
	if len(ann.routes) != before || ann.withdraws != 0 {
		t.Fatalf("sync repeated work: routes=%d withdraws=%d", len(ann.routes), ann.withdraws)
	}

	// Flip to the other provider.
	if err := c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "a")}); err != nil {
		t.Fatal(err)
	}
	if ann.routes[pfx("198.51.100.0/24")].NextHop.String() != "192.0.2.1" {
		t.Fatalf("next hop after switch = %s", ann.routes[pfx("198.51.100.0/24")].NextHop)
	}

	// Flip-back (and stale / probe-source loss / ttl): the prefix leaves the set.
	if err := c.Sync(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if ann.count() != 0 {
		t.Fatalf("routes left after retire: %d", ann.count())
	}

	// 203.0.113.0/24 is allowlisted but not in the RIB, so it is refused.
	// 198.51.100.0/24 is in the RIB and is announced in the same round.
	delete(rib.has, pfx("203.0.113.0/24"))
	err = c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "b"), imp("203.0.113.0/24", "b")})
	if err == nil || !strings.Contains(err.Error(), "not in the RIB") {
		t.Fatalf("err = %v", err)
	}
	if _, ok := ann.routes[pfx("203.0.113.0/24")]; ok {
		t.Fatal("announced a prefix that is not in the RIB")
	}
	if _, ok := ann.routes[pfx("198.51.100.0/24")]; !ok {
		t.Fatal("allowlisted in-RIB prefix was not announced")
	}

	// Not allowlisted.
	rib.has[pfx("192.0.2.0/24")] = true
	err = c.Sync(ctx, []policy.Improvement{{Prefix: pfx("192.0.2.0/24"), Provider: "b"}})
	if err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("err = %v", err)
	}
	if _, ok := ann.routes[pfx("192.0.2.0/24")]; ok {
		t.Fatal("announced a prefix that is not allowlisted")
	}

	// Cap.
	cfg := testCfg()
	cfg.MaxImprovements = 1
	ann2 := &fakeAnn{}
	c2, err := New(cfg, ann2, &rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	rib.has[pfx("203.0.113.0/24")] = true
	err = c2.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "b"), imp("203.0.113.0/24", "b")})
	if err == nil || !strings.Contains(err.Error(), "max_improvements") {
		t.Fatalf("err = %v", err)
	}
	if ann2.count() != 1 {
		t.Fatalf("announced %d routes, want 1", ann2.count())
	}

	// RIB session loss withdraws even if the improvement is still listed.
	rib.ready = false
	if err := c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "b")}); err != nil {
		t.Fatal(err)
	}
	if ann.all == 0 || ann.count() != 0 {
		t.Fatalf("session loss: all=%d routes=%d", ann.all, ann.count())
	}

	// Shutdown withdraws whatever is up.
	rib.ready = true
	if err := c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "b")}); err != nil {
		t.Fatal(err)
	}
	if err := c.WithdrawAll(ctx); err != nil {
		t.Fatal(err)
	}
	if ann.count() != 0 {
		t.Fatalf("routes left after WithdrawAll: %d", ann.count())
	}
}

func TestMoreSpecifics(t *testing.T) {
	ctx := context.Background()
	rib := memRIB{ready: true, has: map[netip.Prefix]bool{pfx("198.51.100.0/24"): true, pfx("2001:db8::/32"): true}}
	cfg := testCfg()
	cfg.MoreSpecificBits = 1
	ann := &fakeAnn{}
	c, err := New(cfg, ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "b")}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"198.51.100.0/25", "198.51.100.128/25"} {
		rt, ok := ann.routes[pfx(s)]
		if !ok || rt.NextHop.String() != "192.0.2.2" || rt.LocalPref != 250 || rt.Communities[0] != "64512:666" {
			t.Fatalf("%s = %+v ok=%v", s, rt, ok)
		}
	}
	if _, ok := ann.routes[pfx("198.51.100.0/24")]; ok {
		t.Fatal("announced the covering prefix as well as the more-specifics")
	}
	if err := c.Sync(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if ann.count() != 0 {
		t.Fatalf("more-specifics left after withdraw: %d", ann.count())
	}

	cfg.MoreSpecificBits = 1
	ann = &fakeAnn{}
	c, err = New(cfg, ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx, []policy.Improvement{{Prefix: pfx("2001:db8::/32"), Provider: "c", Native: "a"}}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"2001:db8::/33", "2001:db8:8000::/33"} {
		rt, ok := ann.routes[pfx(s)]
		if !ok || rt.NextHop.String() != "2001:db8::2" {
			t.Fatalf("%s = %+v ok=%v", s, rt, ok)
		}
	}

	cfg.Allowlist = []netip.Prefix{pfx("198.51.100.1/32")}
	c, err = New(cfg, &fakeAnn{}, memRIB{ready: true, has: map[netip.Prefix]bool{pfx("198.51.100.1/32"): true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = c.Sync(ctx, []policy.Improvement{{Prefix: pfx("198.51.100.1/32"), Provider: "b"}})
	if err == nil || !strings.Contains(err.Error(), "does not fit") {
		t.Fatalf("err = %v", err)
	}
}

func TestExpand(t *testing.T) {
	got, err := expand(pfx("198.51.100.0/24"), 2)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"198.51.100.0/26", "198.51.100.64/26", "198.51.100.128/26", "198.51.100.192/26"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i, s := range want {
		if got[i].String() != s {
			t.Fatalf("got[%d] = %s, want %s", i, got[i], s)
		}
	}
	same, err := expand(pfx("203.0.113.0/24"), 0)
	if err != nil || len(same) != 1 || same[0].String() != "203.0.113.0/24" {
		t.Fatalf("same = %v err=%v", same, err)
	}
}
