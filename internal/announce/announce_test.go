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

// MoreSpecifics lists learned prefixes strictly inside any parent.
func (m memRIB) MoreSpecifics(parents []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for q, ok := range m.has {
		if !ok {
			continue
		}
		for _, p := range parents {
			if p.Bits() < q.Bits() && p.Contains(q.Addr()) {
				out = append(out, q)
				break
			}
		}
	}
	sortPrefixes(out)
	return out
}

type fakeAnn struct {
	plugin.Base
	mu        sync.Mutex
	routes    map[netip.Prefix]plugin.Route
	all       int
	withdraws int
	announces int
}

func (f *fakeAnn) Announce(_ context.Context, r plugin.Route) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.routes == nil {
		f.routes = map[netip.Prefix]plugin.Route{}
	}
	f.routes[r.Prefix] = r
	f.announces++
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

func TestHiddenPrefixDoesNotWithdrawActiveRoute(t *testing.T) {
	ctx := context.Background()
	rib := memRIB{ready: true, has: map[netip.Prefix]bool{pfx("198.51.100.0/24"): true}}
	ann := &fakeAnn{}
	c, err := New(testCfg(), ann, &rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "b")}); err != nil {
		t.Fatal(err)
	}

	// The router stopped advertising the prefix because our route won.
	// The decision engine still wants the improvement. Withdrawing here
	// would bring the native path back and the next round would re-announce.
	delete(rib.has, pfx("198.51.100.0/24"))
	if err := c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "b")}); err != nil {
		t.Fatal(err)
	}
	if ann.count() != 1 || ann.withdraws != 0 {
		t.Fatalf("hidden prefix withdrew the route: routes=%d withdraws=%d", ann.count(), ann.withdraws)
	}
	if err := c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "b")}); err != nil {
		t.Fatal(err)
	}
	if ann.count() != 1 || ann.withdraws != 0 {
		t.Fatalf("second sync flapped: routes=%d withdraws=%d", ann.count(), ann.withdraws)
	}

	// A provider switch of a route already on the wire is still applied.
	if err := c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "a")}); err != nil {
		t.Fatal(err)
	}
	if ann.routes[pfx("198.51.100.0/24")].NextHop.String() != "192.0.2.1" || ann.count() != 1 {
		t.Fatalf("switch while hidden: %+v count=%d", ann.routes[pfx("198.51.100.0/24")], ann.count())
	}

	// The decision engine retired it (confirmed leave, flip-back, ttl).
	if err := c.Sync(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if ann.count() != 0 {
		t.Fatalf("retired improvement left a route: %d", ann.count())
	}

	// It cannot be announced again until a neighbor is advertising it.
	err = c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "b")})
	if err == nil || !strings.Contains(err.Error(), "not in the RIB") {
		t.Fatalf("err = %v", err)
	}
	if ann.count() != 0 {
		t.Fatal("announced a prefix that is not in the RIB")
	}
}

func TestAnnounceExactLearnedPrefixOnly(t *testing.T) {
	ctx := context.Background()
	parent := pfx("198.51.100.0/24")
	child := pfx("198.51.100.0/25")
	rib := memRIB{ready: true, has: map[netip.Prefix]bool{parent: true}}
	ann := &fakeAnn{}
	c, err := New(testCfg(), ann, &rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx, []policy.Improvement{imp(parent.String(), "b")}); err != nil {
		t.Fatal(err)
	}
	if ann.count() != 1 {
		t.Fatalf("announced %d routes, want 1", ann.count())
	}
	rt, ok := ann.routes[parent]
	if !ok || rt.NextHop.String() != "192.0.2.2" || rt.LocalPref != 250 || len(rt.Communities) != 1 || rt.Communities[0] != "64512:666" {
		t.Fatalf("route = %+v ok=%v", rt, ok)
	}
	if _, ok := ann.routes[child]; ok {
		t.Fatal("announced a more-specific that is not in the RIB")
	}

	// Covered by the allowlist, and its parent was learned. Still refused:
	// the more-specific itself was never in the RIB.
	err = c.Sync(ctx, []policy.Improvement{imp(child.String(), "b")})
	if err == nil || !strings.Contains(err.Error(), "not in the RIB") {
		t.Fatalf("err = %v", err)
	}
	if _, ok := ann.routes[child]; ok {
		t.Fatal("announced an unlearned more-specific")
	}
	if ann.count() != 0 {
		t.Fatalf("parent route left behind: %d", ann.count())
	}

	// A more-specific the neighbor did advertise is announced as itself.
	rib.has[child] = true
	if err := c.Sync(ctx, []policy.Improvement{imp(child.String(), "b")}); err != nil {
		t.Fatal(err)
	}
	if ann.count() != 1 {
		t.Fatalf("announced %d routes, want the learned more-specific only", ann.count())
	}
	if _, ok := ann.routes[child]; !ok {
		t.Fatal("learned more-specific was not announced")
	}
	if _, ok := ann.routes[parent]; ok {
		t.Fatal("announced the parent of a learned more-specific")
	}
	if err := c.Sync(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if ann.count() != 0 {
		t.Fatalf("route left after withdraw: %d", ann.count())
	}

	// The cap counts routes. One improvement cannot install several.
	rib.has[pfx("203.0.113.0/24")] = true
	cfg := testCfg()
	cfg.MaxImprovements = 1
	ann2 := &fakeAnn{}
	c2, err := New(cfg, ann2, &rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = c2.Sync(ctx, []policy.Improvement{imp(parent.String(), "b"), imp("203.0.113.0/24", "b")})
	if err == nil || !strings.Contains(err.Error(), "max_improvements") {
		t.Fatalf("err = %v", err)
	}
	if ann2.count() != 1 {
		t.Fatalf("cap installed %d routes, want 1", ann2.count())
	}
	for p := range ann2.routes {
		if p != parent && p != pfx("203.0.113.0/24") {
			t.Fatalf("announced %s, which was not decided", p)
		}
	}
}

func TestInboundPrefixesAreReservedAndShareTheCap(t *testing.T) {
	ctx := context.Background()
	rib := memRIB{ready: true, has: map[netip.Prefix]bool{
		pfx("198.51.100.0/24"): true,
		pfx("203.0.113.0/24"):  true,
	}}
	ann := &fakeAnn{}
	cfg := testCfg()
	cfg.MaxImprovements = 2
	cfg.Reserved = func(p netip.Prefix) bool { return p == pfx("203.0.113.0/24") }
	inbound := 1
	cfg.Others = func() int { return inbound }
	c, err := New(cfg, ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "b"), imp("203.0.113.0/24", "b")})
	if err == nil || !strings.Contains(err.Error(), "203.0.113.0/24 is reserved") {
		t.Fatalf("err = %v", err)
	}
	if _, ok := ann.routes[pfx("203.0.113.0/24")]; ok || ann.count() != 1 || c.Active() != 1 {
		t.Fatalf("routes = %v active = %d", ann.routes, c.Active())
	}
	// One outbound plus one inbound fills a cap of 2.
	if err := c.WithdrawAll(ctx); err != nil || c.Active() != 0 {
		t.Fatal(err)
	}
	inbound = 2
	if err := c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "b")}); err == nil || !strings.Contains(err.Error(), "max_improvements") {
		t.Fatalf("shared cap err = %v", err)
	}
	if ann.count() != 0 {
		t.Fatal("announced past the shared cap")
	}
}

type routerAnn struct {
	fakeAnn
	routers []plugin.RouterExport
}

func (r *routerAnn) BindRouters(_ any, community string, routers []plugin.RouterExport) error {
	if community != "64512:666" {
		return nil
	}
	r.routers = routers
	return nil
}

// Per-router reachability (#27) needs an announcer that can apply it; one
// that cannot is refused instead of sending every router every route.
func TestBindRouters(t *testing.T) {
	cfg := testCfg()
	cfg.Routers = []plugin.RouterExport{{Neighbor: netip.MustParseAddr("192.0.2.251"), Blocked: []netip.Addr{netip.MustParseAddr("192.0.2.2")}}}
	rib := memRIB{ready: true}
	c, err := New(cfg, &fakeAnn{}, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Bind(struct{}{}); err == nil || !strings.Contains(err.Error(), "per-router") {
		t.Fatalf("announcer without BindRouters: %v", err)
	}
	ra := &routerAnn{}
	if c, err = New(cfg, ra, rib, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Bind(struct{}{}); err != nil {
		t.Fatal(err)
	}
	if len(ra.routers) != 1 || ra.routers[0].Neighbor != cfg.Routers[0].Neighbor {
		t.Fatalf("routers = %+v", ra.routers)
	}
	// Observe never binds.
	cfg.Mode = "observe"
	if c, err = New(cfg, &fakeAnn{}, rib, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Bind(struct{}{}); err != nil {
		t.Fatal(err)
	}
}

// A mitigation rule (#28) that takes a prefix with an improvement on the
// wire withdraws the improvement first; it returns once the rule lets go.
func TestReservedWithdrawsAnImprovementOnTheWire(t *testing.T) {
	ctx := context.Background()
	rib := memRIB{ready: true, has: map[netip.Prefix]bool{pfx("198.51.100.0/24"): true}}
	ann := &fakeAnn{}
	cfg := testCfg()
	held := false
	cfg.Reserved = func(netip.Prefix) bool { return held }
	c, err := New(cfg, ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	imps := []policy.Improvement{imp("198.51.100.0/24", "b")}
	if err := c.Sync(ctx, imps); err != nil || ann.count() != 1 {
		t.Fatalf("announce: %v", err)
	}
	held = true
	if err := c.Sync(ctx, imps); err == nil || ann.count() != 0 || c.Active() != 0 {
		t.Fatalf("reserved prefix kept its improvement: %v", err)
	}
	held = false
	if err := c.Sync(ctx, imps); err != nil || ann.count() != 1 {
		t.Fatalf("improvement after the rule let go: %v", err)
	}
}
