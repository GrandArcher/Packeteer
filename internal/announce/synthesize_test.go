package announce

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
)

// Synthesized sub-ranges (#122, docs/design/more-specific.md).

func synCfg(maxRoutes int) Config {
	cfg := testCfg()
	cfg.MaxRoutes = maxRoutes
	cfg.Synthesize = &Synthesize{
		Covering: []netip.Prefix{pfx("198.51.100.0/24"), pfx("2001:db8::/32")},
		MaxBits:  1, MaxLenV4: 25, MaxLenV6: 48,
		Marker: "64512:667",
	}
	return cfg
}

func synImp(prefix, cover, provider string) policy.Improvement {
	im := imp(prefix, provider)
	im.Covering = pfx(cover)
	return im
}

func TestSynthesizeOffRefusesEverySubrange(t *testing.T) {
	ann := &fakeAnn{}
	c, err := New(testCfg(), ann, learned("198.51.100.0/24"), nil)
	if err != nil {
		t.Fatal(err)
	}
	err = c.Sync(context.Background(), []policy.Improvement{synImp("198.51.100.0/25", "198.51.100.0/24", "b")})
	if err == nil || !strings.Contains(err.Error(), "synthesize is off") || ann.count() != 0 {
		t.Fatalf("err = %v, routes %d", err, ann.count())
	}
	// Without Covering an unlearned sub-range is refused as before.
	err = c.Sync(context.Background(), []policy.Improvement{imp("198.51.100.0/25", "b")})
	if err == nil || !strings.Contains(err.Error(), "not in the RIB") || ann.count() != 0 {
		t.Fatalf("err = %v, routes %d", err, ann.count())
	}
	if c.Synthesizable([]probe.Result{subResult("198.51.100.0/24", "198.51.100.0/25")}) != nil {
		t.Fatal("synthesizable with synthesize off")
	}
}

func TestSynthesizeConfigGuards(t *testing.T) {
	rib := learned("198.51.100.0/24")
	type plainRIB struct{ RIB }
	if _, err := New(synCfg(10), &fakeAnn{}, plainRIB{rib}, nil); err == nil || !strings.Contains(err.Error(), "learned more-specifics") {
		t.Fatalf("RIB without MoreSpecifics accepted: %v", err)
	}
	if _, err := New(synCfg(0), &fakeAnn{}, rib, nil); err == nil || !strings.Contains(err.Error(), "max_routes") {
		t.Fatalf("no route cap accepted: %v", err)
	}
	cfg := synCfg(10)
	cfg.Synthesize.Marker = "64512:666"
	if _, err := New(cfg, &fakeAnn{}, rib, nil); err == nil || !strings.Contains(err.Error(), "marker_community") {
		t.Fatalf("marker equal to the community accepted: %v", err)
	}
	cfg = synCfg(10)
	cfg.Synthesize.Covering = nil
	if _, err := New(cfg, &fakeAnn{}, rib, nil); err == nil || !strings.Contains(err.Error(), "covering_prefixes") {
		t.Fatalf("no covering prefixes accepted: %v", err)
	}
	// Observe and suggest announce nothing.
	for _, mode := range []string{"observe", "suggest"} {
		cfg := synCfg(10)
		cfg.Mode = mode
		c, err := New(cfg, panicAnn{}, rib, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Sync(context.Background(), []policy.Improvement{synImp("198.51.100.0/25", "198.51.100.0/24", "b")}); err != nil {
			t.Fatal(err)
		}
	}
}

// One sub-range is announced with the community, the marker, and the
// improvement's next hop and local preference; withdraw, WithdrawAll,
// HA standby, and RIB loss each take it off the wire.
func TestSynthesizeAnnounceAndWithdraw(t *testing.T) {
	ctx := context.Background()
	rib := learned("198.51.100.0/24")
	ann := &fakeAnn{}
	var leader atomic.Bool
	leader.Store(true)
	cfg := synCfg(10)
	cfg.Leader = leader.Load
	c, err := New(cfg, ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	imps := []policy.Improvement{synImp("198.51.100.0/25", "198.51.100.0/24", "b")}
	if err := c.Sync(ctx, imps); err != nil {
		t.Fatal(err)
	}
	wantWire(t, ann, "198.51.100.0/25")
	rt := ann.routes[pfx("198.51.100.0/25")]
	if rt.NextHop != netip.MustParseAddr("192.0.2.2") || rt.LocalPref != 250 || !slices.Equal(rt.Communities, []string{"64512:666", "64512:667"}) {
		t.Fatalf("route = %+v", rt)
	}
	if !c.Injected(pfx("198.51.100.0/25")) || c.Routes() != 1 || c.Active() != 1 {
		t.Fatalf("injected=%v routes=%d active=%d", c.Injected(pfx("198.51.100.0/25")), c.Routes(), c.Active())
	}
	// Same again: no re-announce.
	if err := c.Sync(ctx, imps); err != nil || ann.announces != 1 {
		t.Fatalf("re-announced: err=%v announces=%d", err, ann.announces)
	}
	// The improvement retires: withdrawn.
	if err := c.Sync(ctx, nil); err != nil || ann.count() != 0 {
		t.Fatalf("retire kept it: err=%v routes=%d", err, ann.count())
	}
	if err := c.Sync(ctx, imps); err != nil || ann.count() != 1 {
		t.Fatal(err)
	}
	// SIGTERM.
	if err := c.WithdrawAll(ctx); err != nil || ann.count() != 0 || c.Routes() != 0 {
		t.Fatalf("withdraw-all kept it: err=%v routes=%d", err, ann.count())
	}
	// HA standby.
	if err := c.Sync(ctx, imps); err != nil || ann.count() != 1 {
		t.Fatal(err)
	}
	leader.Store(false)
	if err := c.Sync(ctx, imps); err != nil || ann.count() != 0 {
		t.Fatalf("standby kept it: err=%v routes=%d", err, ann.count())
	}
	if err := c.Sync(ctx, imps); err != nil || ann.count() != 0 {
		t.Fatalf("standby announced: err=%v routes=%d", err, ann.count())
	}
	leader.Store(true)
	// Session loss.
	if err := c.Sync(ctx, imps); err != nil || ann.count() != 1 {
		t.Fatal(err)
	}
	down := rib
	down.ready = false
	c.rib = down
	if err := c.Sync(ctx, imps); err != nil || ann.count() != 0 {
		t.Fatalf("rib not ready kept it: err=%v routes=%d", err, ann.count())
	}
}

func TestSynthesizeNoAdvertiseAndASPath(t *testing.T) {
	ctx := context.Background()
	rib := &pathRIB{memRIB: learned("198.51.100.0/24"), native: map[netip.Prefix][]uint32{pfx("198.51.100.0/24"): {64500, 64501}}}
	ann := &fakeAnn{}
	cfg := synCfg(10)
	cfg.Synthesize.NoAdvertise = true
	cfg.ASPath = "native"
	c, err := New(cfg, ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx, []policy.Improvement{synImp("198.51.100.128/25", "198.51.100.0/24", "b")}); err != nil {
		t.Fatal(err)
	}
	rt := ann.routes[pfx("198.51.100.128/25")]
	if !slices.Equal(rt.Communities, []string{"64512:666", "64512:667", "65535:65282"}) || !slices.Equal(rt.ASPath, []uint32{64500, 64501}) {
		t.Fatalf("route = %+v", rt)
	}
}

// Every shape rail refuses: covering prefix outside covering_prefixes, a
// sub-range not inside it, past max_bits, past max_prefix_len, outside
// the allowlist, the covering prefix not in the RIB, and an RPKI state
// that would be invalid.
func TestSynthesizeRails(t *testing.T) {
	ctx := context.Background()
	rib := learned("198.51.100.0/24", "203.0.113.0/24", "198.51.100.0/23", "2001:db8::/32")
	cases := []struct {
		name string
		im   policy.Improvement
		cfg  func(*Config)
		want string
		rib  *memRIB
	}{
		{"covering not listed", synImp("203.0.113.0/25", "203.0.113.0/24", "b"), nil, "not inside synthesize.covering_prefixes", nil},
		{"not inside", synImp("198.51.101.0/25", "198.51.100.0/24", "b"), nil, "not strictly inside", nil},
		{"same length", synImp("198.51.100.0/24", "198.51.100.0/24", "b"), nil, "not strictly inside", nil},
		{"past max_bits", synImp("198.51.100.0/26", "198.51.100.0/24", "b"), func(c *Config) { c.Synthesize.MaxLenV4 = 32 }, "synthesize.max_bits (1)", nil},
		{"past max_prefix_len", synImp("198.51.100.0/25", "198.51.100.0/24", "b"), func(c *Config) { c.Synthesize.MaxLenV4 = 24 }, "synthesize.max_prefix_len (/24)", nil},
		{"v6 past max_prefix_len", synImp("2001:db8::/33", "2001:db8::/32", "c"), func(c *Config) { c.Synthesize.MaxLenV6 = 32 }, "synthesize.max_prefix_len (/32)", nil},
		{"outside allowlist", synImp("198.51.100.0/25", "198.51.100.0/24", "b"), func(c *Config) { c.Allowlist = []netip.Prefix{pfx("203.0.113.0/24")} }, "not allowlisted", nil},
		{"covering not learned", synImp("198.51.100.0/25", "198.51.100.0/24", "b"), nil, "covering prefix 198.51.100.0/24 is not in the RIB", &memRIB{ready: true, has: map[netip.Prefix]bool{pfx("203.0.113.0/24"): true}}},
		{"rpki invalid", synImp("198.51.100.0/25", "198.51.100.0/24", "b"), func(c *Config) {
			c.Synthesize.Invalid = func(sub, cover netip.Prefix) bool {
				return sub == pfx("198.51.100.0/25") && cover == pfx("198.51.100.0/24")
			}
		}, "RPKI state would be invalid", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := synCfg(10)
			if tc.cfg != nil {
				tc.cfg(&cfg)
			}
			r := rib
			if tc.rib != nil {
				r = *tc.rib
			}
			ann := &fakeAnn{}
			c, err := New(cfg, ann, r, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = c.Sync(ctx, []policy.Improvement{tc.im})
			if err == nil || !strings.Contains(err.Error(), tc.want) || ann.count() != 0 {
				t.Fatalf("err = %v, want %q; routes %d", err, tc.want, ann.count())
			}
		})
	}
}

// A learned prefix inside the covering prefix that overlaps the sub-range
// blocks it (that one is more_specific's), and one that appears while the
// sub-range is on the wire withdraws it. One that does not overlap does
// not.
func TestSynthesizeNeverOverlapsALearnedMoreSpecific(t *testing.T) {
	ctx := context.Background()
	ann := &fakeAnn{}
	c, err := New(synCfg(10), ann, learned("198.51.100.0/24", "198.51.100.0/26"), nil)
	if err != nil {
		t.Fatal(err)
	}
	lo := []policy.Improvement{synImp("198.51.100.0/25", "198.51.100.0/24", "b")}
	if err := c.Sync(ctx, lo); err == nil || !strings.Contains(err.Error(), "advertises 198.51.100.0/26, which overlaps it") || ann.count() != 0 {
		t.Fatalf("err = %v, routes %d", err, ann.count())
	}
	hi := []policy.Improvement{synImp("198.51.100.128/25", "198.51.100.0/24", "b")}
	if err := c.Sync(ctx, hi); err != nil {
		t.Fatal(err)
	}
	wantWire(t, ann, "198.51.100.128/25")
	c.rib = learned("198.51.100.0/24", "198.51.100.0/26", "198.51.100.192/27")
	if err := c.Sync(ctx, hi); err == nil || !strings.Contains(err.Error(), "198.51.100.192/27") || ann.count() != 0 {
		t.Fatalf("overlap on the wire kept: err=%v routes=%d", err, ann.count())
	}
}

// A synthesized route on the wire is not checked against the covering
// prefix in the RIB: the decision engine retires it on a confirmed leave.
// The rails and the leak-watch hold and reservations still withdraw it.
func TestSynthesizeOnWireFollowsTheDecision(t *testing.T) {
	ctx := context.Background()
	ann := &fakeAnn{}
	held := map[netip.Prefix]bool{}
	cfg := synCfg(10)
	cfg.Held = func(p netip.Prefix) bool { return held[p] }
	c, err := New(cfg, ann, learned("198.51.100.0/24"), nil)
	if err != nil {
		t.Fatal(err)
	}
	imps := []policy.Improvement{synImp("198.51.100.0/25", "198.51.100.0/24", "b")}
	if err := c.Sync(ctx, imps); err != nil {
		t.Fatal(err)
	}
	c.rib = learned()
	if err := c.Sync(ctx, imps); err != nil || ann.count() != 1 {
		t.Fatalf("hidden covering prefix withdrew: err=%v routes=%d", err, ann.count())
	}
	if why := c.SynthesizeRefusal(pfx("198.51.100.0/25"), pfx("198.51.100.0/24")); why != "" {
		t.Fatalf("on-wire refusal = %q", why)
	}
	if why := c.SynthesizeRefusal(pfx("198.51.100.128/25"), pfx("198.51.100.0/24")); !strings.Contains(why, "is not in the learned RIB") {
		t.Fatalf("new refusal = %q", why)
	}
	held[pfx("198.51.100.0/25")] = true
	if err := c.Sync(ctx, imps); err != nil || ann.count() != 0 {
		t.Fatalf("held kept it: err=%v routes=%d", err, ann.count())
	}
	// A route on the wire under one covering prefix is not kept as an
	// exact prefix.
	held = map[netip.Prefix]bool{}
	c.rib = learned("198.51.100.0/24")
	if err := c.Sync(ctx, imps); err != nil || ann.count() != 1 {
		t.Fatal(err)
	}
	if err := c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/25", "b")}); err == nil || ann.count() != 0 {
		t.Fatalf("exact improvement kept a synthesized route: err=%v routes=%d", err, ann.count())
	}
}

// The route cap counts synthesized routes alongside exact ones, in prefix
// order, and holds the rest back until room appears.
func TestSynthesizeRouteCap(t *testing.T) {
	ctx := context.Background()
	ann := &fakeAnn{}
	c, err := New(synCfg(2), ann, learned("198.51.100.0/24", "203.0.113.0/24"), nil)
	if err != nil {
		t.Fatal(err)
	}
	imps := []policy.Improvement{
		imp("203.0.113.0/24", "b"),
		synImp("198.51.100.0/25", "198.51.100.0/24", "b"),
		synImp("198.51.100.128/25", "198.51.100.0/24", "b"),
	}
	err = c.Sync(ctx, imps)
	if err == nil || !strings.Contains(err.Error(), "max_routes (2) reached: 203.0.113.0/24 needs 1 routes, 2 in use") {
		t.Fatalf("err = %v", err)
	}
	wantWire(t, ann, "198.51.100.0/25", "198.51.100.128/25")
	// One sub-range retires: the waiting exact prefix fits.
	if err := c.Sync(ctx, imps[:2]); err != nil {
		t.Fatal(err)
	}
	wantWire(t, ann, "198.51.100.0/25", "203.0.113.0/24")
	if err := c.Sync(ctx, imps); err == nil || !strings.Contains(err.Error(), "198.51.100.128/25 needs 1 routes, 2 in use") {
		t.Fatalf("second sub-range not held at the cap: %v", err)
	}
	wantWire(t, ann, "198.51.100.0/25", "203.0.113.0/24")
}

func subResult(cover string, subs ...string) probe.Result {
	r := probe.Result{Prefix: pfx(cover), Provider: "b", Time: time.Unix(1_700_000_000, 0)}
	for _, s := range subs {
		r.Subranges = append(r.Subranges, probe.SubrangeResult{Prefix: pfx(s)})
	}
	return r
}

func TestSynthesizableAppliesTheRails(t *testing.T) {
	c, err := New(synCfg(10), &fakeAnn{}, learned("198.51.100.0/24", "198.51.100.192/26", "203.0.113.0/24"), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := c.Synthesizable([]probe.Result{
		subResult("198.51.100.0/24", "198.51.100.0/25", "198.51.100.128/25", "198.51.100.0/26"),
		subResult("203.0.113.0/24", "203.0.113.0/25"),
	})
	want := map[netip.Prefix]netip.Prefix{pfx("198.51.100.0/25"): pfx("198.51.100.0/24")}
	if len(got) != len(want) || got[pfx("198.51.100.0/25")] != pfx("198.51.100.0/24") {
		t.Fatalf("synthesizable = %v, want %v", got, want)
	}
	// Observe lists the same would-be routes.
	cfg := synCfg(10)
	cfg.Mode = "observe"
	o, err := New(cfg, nil, learned("198.51.100.0/24"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := o.Synthesizable([]probe.Result{subResult("198.51.100.0/24", "198.51.100.0/25")}); len(got) != 1 {
		t.Fatalf("observe synthesizable = %v", got)
	}
}
