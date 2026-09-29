package rib

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	api "github.com/osrg/gobgp/v3/api"
)

// newExchangeView is an add-path view with a transit and two exchange
// peers (#27) on the peering LAN 203.0.113.0/24.
func newExchangeView(t *testing.T, r *fakeRouter) *View {
	t.Helper()
	v, err := New(Options{
		ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"), ListenPort: -1,
		Neighbors: []Neighbor{{Address: netip.MustParseAddr("127.0.0.1"), Port: uint16(r.port),
			LocalAddress: netip.MustParseAddr("127.0.0.2"), AddPath: true}},
		Providers: map[netip.Addr]string{
			netip.MustParseAddr("192.0.2.1"):    "transit-a",
			netip.MustParseAddr("203.0.113.11"): "ix-peer-a",
			netip.MustParseAddr("203.0.113.12"): "ix-peer-b",
		},
		AddPath: map[string]bool{"ix-peer-a": true, "ix-peer-b": true},
		PeerASN: map[string]uint32{"ix-peer-a": 64501, "ix-peer-b": 64502},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Stop(context.Background()) })
	return v
}

// An exchange peer passes the route check only with its own path for the
// exact prefix: a peer that does not advertise the prefix, or a path via
// its next hop that does not start with its AS, fails. The chosen
// provider's AS path is readable for bgp.as_path provider, and the
// exchange next hops are counted for /api/exchanges.
func TestExchangePeerRouteCheck(t *testing.T) {
	r := newAddPathRouter(t, 8)
	v := newExchangeView(t, r)
	p := netip.MustParsePrefix("198.51.100.0/24")
	more := netip.MustParsePrefix("198.51.100.128/25")

	r.addID(t, idPath(t, 1, "198.51.100.0/24", "192.0.2.1", []uint32{64496, 64500}))
	r.addID(t, idPath(t, 2, "198.51.100.0/24", "203.0.113.11", []uint32{64501, 64501, 64500}))
	// ix-peer-b advertises only a more-specific; an unconfigured member
	// (203.0.113.13) advertises the /24.
	r.addID(t, idPath(t, 3, "198.51.100.128/25", "203.0.113.12", []uint32{64502}))
	r.addID(t, idPath(t, 4, "198.51.100.0/24", "203.0.113.13", []uint32{64503, 64500}))
	eventually(t, "every path", func() bool { return len(v.Paths(p)) == 3 && len(v.Paths(more)) == 1 })

	if checked, ok := v.RouteCheck(p, "ix-peer-a"); !checked || !ok {
		t.Fatalf("ix-peer-a: checked=%v ok=%v", checked, ok)
	}
	if checked, ok := v.RouteCheck(p, "ix-peer-b"); !checked || ok {
		t.Fatalf("ix-peer-b without the exact prefix: checked=%v ok=%v", checked, ok)
	}
	if checked, _ := v.RouteCheck(p, "transit-a"); checked {
		t.Fatal("transit-a has no route check configured")
	}
	if as, ok := v.ProviderPath(p, "ix-peer-a"); !ok || !slices.Equal(as, []uint32{64501, 64501, 64500}) {
		t.Fatalf("ix-peer-a path = %v %v", as, ok)
	}
	if as, ok := v.ProviderPath(p, "transit-a"); !ok || !slices.Equal(as, []uint32{64496, 64500}) {
		t.Fatalf("transit-a path = %v %v", as, ok)
	}
	if _, ok := v.ProviderPath(p, "ix-peer-b"); ok {
		t.Fatal("ix-peer-b has no path for the /24")
	}

	hops := v.NextHops([]netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")})
	want := []NextHopCount{
		{NextHop: netip.MustParseAddr("203.0.113.11"), Prefixes: 1, ASN: 64501},
		{NextHop: netip.MustParseAddr("203.0.113.12"), Prefixes: 1, ASN: 64502},
		{NextHop: netip.MustParseAddr("203.0.113.13"), Prefixes: 1, ASN: 64503},
	}
	if !slices.Equal(hops, want) {
		t.Fatalf("next hops = %+v", hops)
	}

	// A path via ix-peer-b's next hop that another AS originated (a third
	// party next hop) does not count as ix-peer-b's.
	r.addID(t, idPath(t, 5, "198.51.100.0/24", "203.0.113.12", []uint32{64499, 64500}))
	eventually(t, "third-party path", func() bool { return len(v.Paths(p)) == 4 })
	if _, ok := v.RouteCheck(p, "ix-peer-b"); ok {
		t.Fatal("a path via the peer's next hop from another AS passed the route check")
	}

	// ix-peer-a withdraws: the check fails at once.
	r.delID(t, idPath(t, 2, "198.51.100.0/24", "203.0.113.11", []uint32{64501, 64501, 64500}))
	eventually(t, "ix-peer-a path gone", func() bool {
		_, ok := v.RouteCheck(p, "ix-peer-a")
		return !ok
	})
}

// Without add-path an exchange peer is still checked (fail closed): only
// the router's best path is visible, so a peer that is not the best has
// no route.
func TestExchangePeerCheckedWithoutAddPath(t *testing.T) {
	r := newRouter(t)
	v, err := New(Options{
		ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"), ListenPort: -1,
		Neighbors: []Neighbor{{Address: netip.MustParseAddr("127.0.0.1"), Port: uint16(r.port),
			LocalAddress: netip.MustParseAddr("127.0.0.2")}},
		Providers: map[netip.Addr]string{netip.MustParseAddr("192.0.2.1"): "transit-a", netip.MustParseAddr("203.0.113.11"): "ix-peer-a"},
		PeerASN:   map[string]uint32{"ix-peer-a": 64501},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Stop(context.Background()) })
	r.add(t, "198.51.100.0/24", "192.0.2.1")
	p := netip.MustParsePrefix("198.51.100.0/24")
	eventually(t, "native path", func() bool { _, ok := v.Exact(p); return ok })
	if checked, ok := v.RouteCheck(p, "ix-peer-a"); !checked || ok {
		t.Fatalf("ix-peer-a: checked=%v ok=%v", checked, ok)
	}
}

// Online reconfiguration (#27): a neighbor added to the running speaker
// comes up and its paths are learned; removing it drops its paths and
// leaves the other session alone.
func TestAddRemoveNeighbors(t *testing.T) {
	a := newRouterPeer(t, "127.0.0.1", "192.0.2.254", "127.0.0.2")
	b := newRouterPeer(t, "127.0.0.3", "192.0.2.253", "127.0.0.4")
	a.add(t, "198.51.100.0/24", "192.0.2.1")
	b.add(t, "203.0.113.0/24", "192.0.2.2")
	v := newView(t, a)
	eventually(t, "neighbor a", func() bool { return v.Len() == 1 && v.Ready() })
	since := v.Peers()[0].Since

	nb := Neighbor{Address: netip.MustParseAddr("127.0.0.3"), Port: uint16(b.port), LocalAddress: netip.MustParseAddr("127.0.0.4"), Description: "edge2"}
	if err := v.AddNeighbors(context.Background(), []Neighbor{nb}); err != nil {
		t.Fatal(err)
	}
	if err := v.AddNeighbors(context.Background(), []Neighbor{nb}); err == nil {
		t.Fatal("adding a configured neighbor again must fail")
	}
	eventually(t, "neighbor b learned", func() bool { return v.Len() == 2 })
	if err := v.SetEgress(map[string][]netip.Addr{"transit-b": {nb.Address}}); err != nil {
		t.Fatal(err)
	}
	if d := v.EgressDown(); len(d) != 0 {
		t.Fatalf("EgressDown = %v", d)
	}

	if err := v.RemoveNeighbors(context.Background(), []netip.Addr{nb.Address}); err != nil {
		t.Fatal(err)
	}
	if _, ok := v.Exact(netip.MustParsePrefix("203.0.113.0/24")); ok {
		t.Fatal("removed neighbor's prefix is still learned")
	}
	if len(v.Peers()) != 1 || !v.Ready() || !v.Peers()[0].Since.Equal(since) {
		t.Fatalf("the other session changed: %+v", v.Peers())
	}
	if err := v.SetEgress(map[string][]netip.Addr{"transit-b": {nb.Address}}); err == nil {
		t.Fatal("egress on a removed neighbor must fail")
	}
	// b sees Packeteer go away (the session is deconfigured, not left up).
	eventually(t, "b's session closed", func() bool {
		up := false
		_ = b.srv.ListPeer(context.Background(), &api.ListPeerRequest{}, func(p *api.Peer) {
			up = up || p.GetState().GetSessionState() == api.PeerState_ESTABLISHED
		})
		return !up
	})
}
