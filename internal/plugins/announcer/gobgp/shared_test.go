package gobgp

import (
	"context"
	"net/netip"
	"testing"

	"github.com/osrg/gobgp/v3/pkg/server"

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
// one speaker, as inject with all three does.
func sharedSpeaker(t *testing.T) (*fakeRouter, *server.BgpServer, *Announcer, *InboundAnnouncer, *MitigationAnnouncer) {
	t.Helper()
	r := newRouter(t)
	v := newView(t, r)
	eventually(t, "session", v.Ready)
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
	return r, v.Server(), out, in, m
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
	r, srv, _, in, m := sharedSpeaker(t)
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
