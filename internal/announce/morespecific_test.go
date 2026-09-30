package announce

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/policy"
)

// More-specific injection (#56, docs/design/more-specific.md).

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func msCfg(maxRoutes int, clk *clock) Config {
	cfg := testCfg()
	cfg.MoreSpecific, cfg.MaxRoutes = true, maxRoutes
	if clk != nil {
		cfg.Now = clk.now
	}
	return cfg
}

func learned(ps ...string) memRIB {
	m := memRIB{ready: true, has: map[netip.Prefix]bool{}}
	for _, p := range ps {
		m.has[pfx(p)] = true
	}
	return m
}

// onWire is the announced prefixes, sorted.
func (f *fakeAnn) onWire() []netip.Prefix {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []netip.Prefix
	for p := range f.routes {
		out = append(out, p)
	}
	sortPrefixes(out)
	return out
}

func wantWire(t *testing.T, ann *fakeAnn, want ...string) {
	t.Helper()
	var w []netip.Prefix
	for _, s := range want {
		w = append(w, pfx(s))
	}
	sortPrefixes(w)
	if got := ann.onWire(); !slices.Equal(got, w) {
		t.Fatalf("on the wire %v, want %v", got, w)
	}
}

// onlyLearned fails when anything on the wire is not exactly in the RIB.
func onlyLearned(t *testing.T, ann *fakeAnn, rib memRIB) {
	t.Helper()
	for _, p := range ann.onWire() {
		if !rib.has[p] {
			t.Fatalf("announced %s, which is not in the learned RIB", p)
		}
	}
}

func TestMoreSpecificOffAnnouncesOnlyTheImprovement(t *testing.T) {
	rib := learned("198.51.100.0/24", "198.51.100.0/25", "198.51.100.128/26")
	ann := &fakeAnn{}
	c, err := New(testCfg(), ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(context.Background(), []policy.Improvement{imp("198.51.100.0/24", "b")}); err != nil {
		t.Fatal(err)
	}
	wantWire(t, ann, "198.51.100.0/24")
	if c.Routes() != 1 || c.Active() != 1 {
		t.Fatalf("routes=%d active=%d, want 1/1", c.Routes(), c.Active())
	}
}

func TestMoreSpecificConfigGuards(t *testing.T) {
	rib := learned("198.51.100.0/24")
	if _, err := New(msCfg(0, nil), &fakeAnn{}, rib, nil); err == nil || !strings.Contains(err.Error(), "max_routes") {
		t.Fatalf("max_routes 0 accepted: %v", err)
	}
	type plainRIB struct{ RIB }
	if _, err := New(msCfg(10, nil), &fakeAnn{}, plainRIB{rib}, nil); err == nil || !strings.Contains(err.Error(), "more-specifics") {
		t.Fatalf("RIB without MoreSpecifics accepted: %v", err)
	}
	// Observe and suggest announce nothing, feature on or not.
	for _, mode := range []string{"observe", "suggest"} {
		cfg := msCfg(10, nil)
		cfg.Mode = mode
		c, err := New(cfg, panicAnn{}, learned("198.51.100.0/24", "198.51.100.0/25"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Sync(context.Background(), []policy.Improvement{imp("198.51.100.0/24", "b")}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMoreSpecificAnnouncesOnlyLearnedPrefixes(t *testing.T) {
	ctx := context.Background()
	// Learned: the /24, two more-specifics inside it, a prefix beside it,
	// and one outside the allowlist. 198.51.100.128/25 and every other
	// child of the /24 is never learned.
	rib := learned("198.51.100.0/24", "198.51.100.0/25", "198.51.100.192/26",
		"203.0.113.0/24", "192.0.2.0/25")
	ann := &fakeAnn{}
	c, err := New(msCfg(100, nil), ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "b")}); err != nil {
		t.Fatal(err)
	}
	wantWire(t, ann, "198.51.100.0/24", "198.51.100.0/25", "198.51.100.192/26")
	onlyLearned(t, ann, rib)
	for _, p := range ann.onWire() {
		r := ann.routes[p]
		if r.NextHop != netip.MustParseAddr("192.0.2.2") || r.Provider != "b" || r.LocalPref != 250 || !slices.Equal(r.Communities, []string{"64512:666"}) {
			t.Fatalf("%s: route %+v lacks the improvement's next hop, local_pref, or community", p, r)
		}
	}
	if c.Active() != 1 || c.Routes() != 3 {
		t.Fatalf("active=%d routes=%d, want 1 improvement and 3 routes", c.Active(), c.Routes())
	}
	// A /24 with no learned more-specifics announces only itself.
	if err := c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "b"), imp("203.0.113.0/24", "b")}); err != nil {
		t.Fatal(err)
	}
	wantWire(t, ann, "198.51.100.0/24", "198.51.100.0/25", "198.51.100.192/26", "203.0.113.0/24")
	// Syncing again does not re-advertise.
	before := ann.announces
	if err := c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "b"), imp("203.0.113.0/24", "b")}); err != nil {
		t.Fatal(err)
	}
	if ann.announces != before {
		t.Fatalf("re-advertised %d routes on an unchanged sync", ann.announces-before)
	}
}

func TestMoreSpecificMaxImprovementsCountsDecisionsNotRoutes(t *testing.T) {
	rib := learned("198.51.100.0/24", "198.51.100.0/25", "198.51.100.128/25", "203.0.113.0/24")
	ann := &fakeAnn{}
	cfg := msCfg(100, nil)
	cfg.MaxImprovements = 1
	c, err := New(cfg, ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = c.Sync(context.Background(), []policy.Improvement{imp("198.51.100.0/24", "b"), imp("203.0.113.0/24", "b")})
	if err == nil || !strings.Contains(err.Error(), "max_improvements (1) reached") {
		t.Fatalf("err = %v, want the improvement cap for the second /24", err)
	}
	wantWire(t, ann, "198.51.100.0/24", "198.51.100.0/25", "198.51.100.128/25")
}

func TestMoreSpecificRouteCapHolds(t *testing.T) {
	ctx := context.Background()
	rib := learned("198.51.100.0/24", "198.51.100.0/25", "198.51.100.128/26", "198.51.100.192/27",
		"203.0.113.0/24", "203.0.113.0/25")
	ann := &fakeAnn{}
	c, err := New(msCfg(4, nil), ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	both := []policy.Improvement{imp("198.51.100.0/24", "b"), imp("203.0.113.0/24", "b")}
	check := func() {
		t.Helper()
		if n := ann.count(); n > 4 {
			t.Fatalf("%d routes on the wire, cap is 4", n)
		}
		onlyLearned(t, ann, rib)
	}

	// The first /24 needs 4 routes and fits exactly. The second needs 2:
	// neither it nor its more-specific is announced.
	err = c.Sync(ctx, both)
	if err == nil || !strings.Contains(err.Error(), "more_specific.max_routes (4) reached: 203.0.113.0/24 needs 2 routes, 4 in use") {
		t.Fatalf("err = %v, want the route cap on 203.0.113.0/24", err)
	}
	check()
	wantWire(t, ann, "198.51.100.0/24", "198.51.100.0/25", "198.51.100.128/26", "198.51.100.192/27")

	// A more-specific learned later does not fit either; the rest stays.
	rib.has[pfx("198.51.100.64/26")] = true
	err = c.Sync(ctx, both)
	if err == nil || !strings.Contains(err.Error(), "1 learned more-specifics of 198.51.100.0/24 not announced") {
		t.Fatalf("err = %v, want the new more-specific capped", err)
	}
	check()
	wantWire(t, ann, "198.51.100.0/24", "198.51.100.0/25", "198.51.100.128/26", "198.51.100.192/27")
	delete(rib.has, pfx("198.51.100.64/26"))

	// Inbound steer routes count toward the cap too.
	others := 0
	cfg := msCfg(4, nil)
	cfg.Others = func() int { return others }
	ann2 := &fakeAnn{}
	c2, err := New(cfg, ann2, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	others = 1
	if err := c2.Sync(ctx, both[:1]); err == nil || !strings.Contains(err.Error(), "needs 4 routes, 1 in use") {
		t.Fatalf("err = %v, want the cap to count an inbound route", err)
	}
	if ann2.count() != 0 {
		t.Fatalf("announced %d routes with no room for the whole improvement", ann2.count())
	}
	others = 0
	if err := c2.Sync(ctx, both[:1]); err != nil {
		t.Fatal(err)
	}
	if ann2.count() != 4 {
		t.Fatalf("announced %d routes, want 4", ann2.count())
	}

	// Room appears when the first improvement retires: the second is
	// announced whole.
	if err := c.Sync(ctx, both[1:]); err != nil {
		t.Fatal(err)
	}
	check()
	wantWire(t, ann, "203.0.113.0/24", "203.0.113.0/25")
}

func TestMoreSpecificRealLeaveWithdrawsAndHideKeeps(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	rib := learned("198.51.100.0/24", "198.51.100.0/25", "198.51.100.128/25")
	ann := &fakeAnn{}
	c, err := New(msCfg(10, clk), ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	imps := []policy.Improvement{imp("198.51.100.0/24", "b")}
	step := func(d time.Duration) {
		t.Helper()
		clk.t = clk.t.Add(d)
		if err := c.Sync(ctx, imps); err != nil {
			t.Fatal(err)
		}
	}
	step(0)
	wantWire(t, ann, "198.51.100.0/24", "198.51.100.0/25", "198.51.100.128/25")

	// The router hides the native /25 right after Packeteer's route wins:
	// gone before it was seen again. It stays.
	delete(rib.has, pfx("198.51.100.0/25"))
	step(time.Second)
	step(10 * time.Second)
	wantWire(t, ann, "198.51.100.0/24", "198.51.100.0/25", "198.51.100.128/25")

	// Back, then gone again within NativePathConfirm: still a hide.
	rib.has[pfx("198.51.100.0/25")] = true
	step(time.Second)
	delete(rib.has, pfx("198.51.100.0/25"))
	step(policy.NativePathConfirm - 2*time.Second)
	wantWire(t, ann, "198.51.100.0/24", "198.51.100.0/25", "198.51.100.128/25")

	// Advertised for longer than NativePathConfirm, then gone: a real
	// leave. Only that more-specific is withdrawn.
	rib.has[pfx("198.51.100.0/25")] = true
	step(time.Second)
	step(policy.NativePathConfirm)
	delete(rib.has, pfx("198.51.100.0/25"))
	step(time.Second)
	wantWire(t, ann, "198.51.100.0/24", "198.51.100.128/25")

	// It is not announced again while it is not learned.
	step(time.Minute)
	wantWire(t, ann, "198.51.100.0/24", "198.51.100.128/25")
	// Learned again, it returns.
	rib.has[pfx("198.51.100.0/25")] = true
	step(time.Second)
	wantWire(t, ann, "198.51.100.0/24", "198.51.100.0/25", "198.51.100.128/25")
}

func TestMoreSpecificsFollowTheImprovement(t *testing.T) {
	ctx := context.Background()
	rib := learned("198.51.100.0/24", "198.51.100.0/25", "198.51.100.128/26")
	ann := &fakeAnn{}
	c, err := New(msCfg(10, nil), ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	all := []string{"198.51.100.0/24", "198.51.100.0/25", "198.51.100.128/26"}
	if err := c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "b")}); err != nil {
		t.Fatal(err)
	}
	wantWire(t, ann, all...)

	// Provider switch moves every route.
	if err := c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "a")}); err != nil {
		t.Fatal(err)
	}
	for _, p := range ann.onWire() {
		if r := ann.routes[p]; r.Provider != "a" || r.NextHop != netip.MustParseAddr("192.0.2.1") {
			t.Fatalf("%s still toward %s via %s after the switch", p, r.Provider, r.NextHop)
		}
	}

	// Retire withdraws them all.
	if err := c.Sync(ctx, nil); err != nil {
		t.Fatal(err)
	}
	wantWire(t, ann)
	if c.Routes() != 0 || c.Active() != 0 {
		t.Fatalf("routes=%d active=%d after retire", c.Routes(), c.Active())
	}

	// Session loss (RIB not ready) withdraws them all.
	if err := c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "b")}); err != nil {
		t.Fatal(err)
	}
	wantWire(t, ann, all...)
	down := rib
	down.ready = false
	c.rib = down
	if err := c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "b")}); err != nil {
		t.Fatal(err)
	}
	wantWire(t, ann)
	if c.Routes() != 0 {
		t.Fatalf("routes=%d after session loss", c.Routes())
	}
	c.rib = rib

	// Shutdown (WithdrawAll) withdraws them all.
	if err := c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "b")}); err != nil {
		t.Fatal(err)
	}
	wantWire(t, ann, all...)
	if err := c.WithdrawAll(ctx); err != nil {
		t.Fatal(err)
	}
	wantWire(t, ann)
	if c.Routes() != 0 {
		t.Fatalf("routes=%d after WithdrawAll", c.Routes())
	}
}

func TestMoreSpecificReservedAndNested(t *testing.T) {
	ctx := context.Background()
	rib := learned("198.51.100.0/24", "198.51.100.0/25", "198.51.100.0/26", "198.51.100.128/26")
	ann := &fakeAnn{}
	reserved := map[netip.Prefix]bool{pfx("198.51.100.128/26"): true}
	cfg := msCfg(10, nil)
	cfg.Reserved = func(p netip.Prefix) bool { return reserved[p] }
	c, err := New(cfg, ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	outer := imp("198.51.100.0/24", "b")
	if err := c.Sync(ctx, []policy.Improvement{outer}); err != nil {
		t.Fatal(err)
	}
	// Inbound or mitigation holds 198.51.100.128/26: not announced.
	wantWire(t, ann, "198.51.100.0/24", "198.51.100.0/25", "198.51.100.0/26")

	// Reserved later: withdrawn.
	reserved[pfx("198.51.100.0/26")] = true
	if err := c.Sync(ctx, []policy.Improvement{outer}); err != nil {
		t.Fatal(err)
	}
	wantWire(t, ann, "198.51.100.0/24", "198.51.100.0/25")
	reserved = map[netip.Prefix]bool{}

	// A learned more-specific that becomes an improvement of its own owns
	// the more-specifics inside it, toward its own provider.
	inner := imp("198.51.100.0/25", "a")
	if err := c.Sync(ctx, []policy.Improvement{outer, inner}); err != nil {
		t.Fatal(err)
	}
	wantWire(t, ann, "198.51.100.0/24", "198.51.100.0/25", "198.51.100.0/26", "198.51.100.128/26")
	for p, want := range map[string]string{"198.51.100.0/24": "b", "198.51.100.0/25": "a", "198.51.100.0/26": "a", "198.51.100.128/26": "b"} {
		if got := ann.routes[pfx(p)].Provider; got != want {
			t.Fatalf("%s toward %s, want %s", p, got, want)
		}
	}
	if c.Active() != 2 || c.Routes() != 4 {
		t.Fatalf("active=%d routes=%d, want 2/4", c.Active(), c.Routes())
	}
	// The inner improvement retires: its prefix and its more-specific go
	// back to the outer improvement's provider.
	if err := c.Sync(ctx, []policy.Improvement{outer}); err != nil {
		t.Fatal(err)
	}
	wantWire(t, ann, "198.51.100.0/24", "198.51.100.0/25", "198.51.100.0/26", "198.51.100.128/26")
	for _, p := range ann.onWire() {
		if ann.routes[p].Provider != "b" {
			t.Fatalf("%s toward %s after the inner improvement retired", p, ann.routes[p].Provider)
		}
	}
	onlyLearned(t, ann, rib)
}
