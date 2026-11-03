package gobgp

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v3/pkg/server"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/inbound"
	"github.com/GrandArcher/Packeteer/internal/mitigation"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// speakerPaths counts the paths the speaker holds for prefix. The router
// does not advertise it, so every one of them is local.
func speakerPaths(t *testing.T, srv *server.BgpServer, prefix string) int {
	t.Helper()
	n := 0
	for _, p := range collect(t, srv, v4Family) {
		if p.prefix == prefix {
			n++
		}
	}
	return n
}

// sharedSpeaker binds the outbound, inbound, and mitigation announcers to
// one speaker, as inject with all three does. The router originates
// learned, next hop 192.0.2.1, before the session comes up.
func sharedSpeaker(t *testing.T, learned ...string) (*fakeRouter, *rib.View, *Announcer, *InboundAnnouncer, *MitigationAnnouncer) {
	t.Helper()
	r := newRouter(t)
	for _, s := range learned {
		p := netip.MustParsePrefix(s)
		addLocal(t, r.srv, plugin.Route{Prefix: p, NextHop: netip.MustParseAddr("192.0.2.1"), LocalPref: 100, Communities: []string{"64496:1"}})
	}
	v := newView(t, r)
	eventually(t, "session", v.Ready)
	for _, s := range learned {
		eventually(t, "learned "+s, func() bool {
			_, ok := v.Exact(netip.MustParsePrefix(s))
			return ok
		})
	}
	out := mustAnnouncer(t)
	if err := out.Bind(v.Server(), "64512:666"); err != nil {
		t.Fatal(err)
	}
	in := mustInbound(t, inboundYAML)
	if err := in.Bind(v.Server(), "64512:666", []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}); err != nil {
		t.Fatal(err)
	}
	m := mustMitigation(t, mitigationYAML)
	allow := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("203.0.113.0/24")}
	if err := m.Bind(v.Server(), "64512:666", allow, 2); err != nil {
		t.Fatal(err)
	}
	return r, v, out, in, m
}

// viewRIB is the learned RIB view as the inbound and mitigation
// controllers read it.
type viewRIB struct{ v *rib.View }

func (g viewRIB) Ready() bool { return g.v.Ready() }

func (g viewRIB) Contains(p netip.Prefix) bool {
	_, ok := g.v.Exact(p)
	return ok
}

func (g viewRIB) NextHop(p netip.Prefix) (netip.Addr, bool) {
	rt, ok := g.v.Exact(p)
	return rt.NextHop, ok
}

// TestSharedPrefixImplicitReplaceAndDeleteByPath records the GoBGP v3.37
// behavior behind SAFE-01 of #486 on a real speaker and a simulated
// router. An inbound steer route and a mitigation route for one prefix are
// both local path-ID 0 paths: the second replaces the first, and the
// inbound withdraw (a delete by path) then removes the mitigation route.
// The mitigation controller therefore waits until inbound releases the
// prefix (TestRuleAddedMidRoundWaitsForInbound).
func TestSharedPrefixImplicitReplaceAndDeleteByPath(t *testing.T) {
	ctx := context.Background()
	r, v, _, in, m := sharedSpeaker(t)
	srv := v.Server()
	own := netip.MustParsePrefix("203.0.113.0/24")

	if err := in.Announce(ctx, plugin.InboundRoute{
		Prefix: own, NextHop: netip.MustParseAddr("192.0.2.1"), LocalPref: 1, Community: "64512:666", Away: []string{"transit-a"},
	}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the steer route", func() bool {
		g, ok := fromUs(collect(t, r.srv, v4Family), own.String())
		return ok && g.nextHop == "192.0.2.1"
	})
	if err := m.Announce(ctx, plugin.MitigationRoute{Prefix: own, Action: plugin.MitigationBlackhole, LocalPref: 250, Community: "64512:666"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the mitigation route replacing the steer", func() bool {
		g, ok := fromUs(collect(t, r.srv, v4Family), own.String())
		return ok && g.nextHop == "192.0.2.66"
	})
	if n := speakerPaths(t, srv, own.String()); n != 1 {
		t.Fatalf("speaker holds %d paths for %s, want 1 (implicit replace)", n, own)
	}

	if err := in.Withdraw(ctx, own); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the inbound withdraw removing the mitigation route", func() bool {
		_, ok := fromUs(collect(t, r.srv, v4Family), own.String())
		return !ok && speakerPaths(t, srv, own.String()) == 0
	})
}

// TestOutboundWithdrawAllKeepsInboundAndMitigation is SAFE-06 of #486:
// the outbound WithdrawAll removes only the routes it published, by UUID,
// so a failed partial reload after it does not leave inbound and
// mitigation counting routes the speaker dropped. Each controller's own
// WithdrawAll then clears the rest.
func TestOutboundWithdrawAllKeepsInboundAndMitigation(t *testing.T) {
	ctx := context.Background()
	r, _, out, in, m := sharedSpeaker(t)
	imp := netip.MustParsePrefix("198.51.100.0/24")
	own := netip.MustParsePrefix("203.0.113.0/24")
	bh := netip.MustParsePrefix("192.0.2.0/24")

	for _, nh := range []string{"192.0.2.2", "192.0.2.3"} {
		// The second announce is a replace: GoBGP re-keys the UUID.
		if err := out.Announce(ctx, plugin.Route{Prefix: imp, NextHop: netip.MustParseAddr(nh), LocalPref: 250, Communities: []string{"64512:666"}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := in.Announce(ctx, plugin.InboundRoute{
		Prefix: own, NextHop: netip.MustParseAddr("192.0.2.1"), LocalPref: 1, Community: "64512:666", Away: []string{"transit-b"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Announce(ctx, plugin.MitigationRoute{Prefix: bh, Action: plugin.MitigationBlackhole, LocalPref: 250, Community: "64512:666"}); err != nil {
		t.Fatal(err)
	}
	wire := func(want ...string) func() bool {
		return func() bool {
			got := map[string]bool{}
			for _, p := range collect(t, r.srv, v4Family) {
				if p.fromUs {
					got[p.prefix] = true
				}
			}
			if len(got) != len(want) {
				return false
			}
			for _, w := range want {
				if !got[w] {
					return false
				}
			}
			return true
		}
	}
	eventually(t, "all three routes", wire(imp.String(), own.String(), bh.String()))

	if err := out.WithdrawAll(ctx); err != nil {
		t.Fatal(err)
	}
	eventually(t, "only the outbound route withdrawn", wire(own.String(), bh.String()))
	if err := out.WithdrawAll(ctx); err != nil {
		t.Fatalf("second outbound withdraw all: %v", err)
	}

	if err := in.WithdrawAll(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.WithdrawAll(ctx); err != nil {
		t.Fatal(err)
	}
	eventually(t, "every route withdrawn", wire())
}

// TestOutboundWithdrawAllKeepsFailedDeletes: a path the speaker cannot
// find by UUID stays tracked and WithdrawAll reports it, so a caller never
// believes a route is gone that it could not withdraw.
func TestOutboundWithdrawAllKeepsFailedDeletes(t *testing.T) {
	ctx := context.Background()
	_, _, out, _, _ := sharedSpeaker(t)
	imp := netip.MustParsePrefix("198.51.100.0/24")
	if err := out.Announce(ctx, plugin.Route{Prefix: imp, NextHop: netip.MustParseAddr("192.0.2.2"), LocalPref: 250, Communities: []string{"64512:666"}}); err != nil {
		t.Fatal(err)
	}
	out.mu.Lock()
	out.paths[imp] = announced{uuid: make([]byte, 16), nextHop: netip.MustParseAddr("192.0.2.2")}
	out.mu.Unlock()
	if err := out.WithdrawAll(ctx); err == nil {
		t.Fatal("withdraw all with an unknown UUID reported success")
	}
	out.mu.Lock()
	_, kept := out.paths[imp]
	out.mu.Unlock()
	if !kept {
		t.Fatal("a failed delete was dropped from the tracked paths")
	}
}

// TestControllersKeepOnePathOnSharedPrefix is the after-the-fix half of
// TestSharedPrefixImplicitReplaceAndDeleteByPath: the real inbound and
// mitigation controllers on the real announcers and speaker. A rule added
// between the inbound and mitigation syncs of one round waits for inbound
// to release the prefix, so the speaker never holds the mitigation route
// over the steer and the steer's withdraw cannot remove it.
func TestControllersKeepOnePathOnSharedPrefix(t *testing.T) {
	ctx := context.Background()
	own := netip.MustParsePrefix("203.0.113.0/24")
	r, v, _, in, m := sharedSpeaker(t, own.String())
	srv := v.Server()
	t0 := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

	mit, err := mitigation.New(mitigation.Config{
		Mode: config.ModeInject, Allowlist: []netip.Prefix{own}, MaxRules: 2,
		DefaultTTL: time.Hour, MaxTTL: 2 * time.Hour, LocalPref: 250, Community: "64512:666",
	}, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := mit.SetRIB(viewRIB{v}); err != nil {
		t.Fatal(err)
	}
	inb, err := inbound.New(inbound.Config{
		Mode: config.ModeInject, Prefixes: []netip.Prefix{own}, Allowlist: []netip.Prefix{own},
		Community: "64512:666", LocalPref: 1, MaxImprovements: 5,
		HoldTime: 5 * time.Minute, TTL: time.Hour, MaxAge: 5 * time.Minute,
		Providers: []string{"transit-a", "transit-b"},
		Excluded:  mit.Holds,
	}, in, viewRIB{v}, nil)
	if err != nil {
		t.Fatal(err)
	}
	mit.SetInbound(inb.OnWire)
	inb.Evaluate(t0, []plugin.Usage{
		{Provider: "transit-a", CommitMbps: 100, Samples: 10, InMbps95: 150, OutMbps95: 10, Updated: t0},
		{Provider: "transit-b", CommitMbps: 100, Samples: 10, InMbps95: 20, OutMbps95: 10, Updated: t0},
	})
	onRouter := func(nh string) func() bool {
		return func() bool {
			g, ok := fromUs(collect(t, r.srv, v4Family), own.String())
			return ok && g.nextHop == nh && speakerPaths(t, srv, own.String()) == 1
		}
	}

	if err := inb.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the steer route", onRouter("192.0.2.1"))
	if _, err := mit.Add(mitigation.Request{Prefix: own, Action: plugin.MitigationBlackhole, TTL: 10 * time.Minute}, t0); err != nil {
		t.Fatal(err)
	}
	if err := mit.Sync(ctx, t0); err != nil {
		t.Fatal(err)
	}
	if mit.Active() != 0 {
		t.Fatal("rule announced over the steer route")
	}
	eventually(t, "the steer route kept", onRouter("192.0.2.1"))

	for i := 1; i <= 2; i++ {
		if err := inb.Sync(ctx); err != nil {
			t.Fatal(err)
		}
		if err := mit.Sync(ctx, t0.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "exactly the blackhole route", onRouter("192.0.2.66"))
	if mit.Active() != 1 || inb.OnWire(own) {
		t.Fatalf("mitigation active %d, inbound on %v", mit.Active(), inb.OnWire(own))
	}
}
