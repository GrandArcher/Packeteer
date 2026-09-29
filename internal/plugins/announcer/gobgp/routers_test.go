package gobgp

import (
	"context"
	"net/netip"
	"testing"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"

	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// newRouterAt is a simulated edge listening on addr (a loopback address),
// peered with Packeteer at 127.0.0.2.
func newRouterAt(t *testing.T, addr, rid string) *fakeRouter {
	t.Helper()
	r := &fakeRouter{srv: server.NewBgpServer(server.LoggerOption(&nopLogger{})), port: freePort(t)}
	go r.srv.Serve()
	ctx := context.Background()
	if err := r.srv.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn: asn, RouterId: rid, ListenPort: int32(r.port), ListenAddresses: []string{addr},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := r.srv.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.2", PeerAsn: asn},
		Transport: &api.Transport{PassiveMode: true},
		AfiSafis: []*api.AfiSafi{
			{Config: &api.AfiSafiConfig{Family: v4Family, Enabled: true}},
			{Config: &api.AfiSafiConfig{Family: v6Family, Enabled: true}},
		},
	}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.srv.StopBgp(context.Background(), &api.StopBgpRequest{})
		r.srv.Stop()
	})
	return r
}

// Two simulated edges (#27): edge-a forwards to transit-a and reaches
// transit-b through edge-b; edge-b forwards to transit-b only. transit-c is
// reachable from neither.
func TestBindRoutersPerRouterExport(t *testing.T) {
	ctx := context.Background()
	edgeA := newRouterAt(t, "127.0.0.1", "192.0.2.251")
	edgeB := newRouterAt(t, "127.0.0.3", "192.0.2.252")
	a1, a3 := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.3")
	local := netip.MustParseAddr("127.0.0.2")
	nhA, nhB, nhC := netip.MustParseAddr("192.0.2.21"), netip.MustParseAddr("192.0.2.22"), netip.MustParseAddr("192.0.2.23")
	viaB := netip.MustParseAddr("192.0.2.252")
	v, err := rib.New(rib.Options{
		ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"), ListenPort: -1,
		Neighbors: []rib.Neighbor{
			{Address: a1, Port: uint16(edgeA.port), LocalAddress: local},
			{Address: a3, Port: uint16(edgeB.port), LocalAddress: local},
		},
		Providers: map[netip.Addr]string{nhA: "transit-a", nhB: "transit-b", nhC: "transit-c"},
		Egress:    map[string][]netip.Addr{"transit-a": {a1}, "transit-b": {a3}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Stop(context.Background()) })
	bothUp := func() bool {
		n := 0
		for _, p := range v.Peers() {
			if p.Established {
				n++
			}
		}
		return n == 2
	}
	eventually(t, "both sessions", bothUp)
	if d := v.EgressDown(); len(d) != 0 {
		t.Fatalf("egress down with both sessions up: %v", d)
	}

	a := mustAnnouncer(t)
	routers := []plugin.RouterExport{
		{Neighbor: a1, Via: map[netip.Addr]netip.Addr{nhB: viaB}, Blocked: []netip.Addr{nhC}},
		{Neighbor: a3, Blocked: []netip.Addr{nhA, nhC}},
	}
	if err := a.BindRouters(v.Server(), "64512:666", routers); err != nil {
		t.Fatal(err)
	}
	if err := a.BindRouters(v.Server(), "64512:666", routers); err == nil {
		t.Fatal("second BindRouters accepted")
	}

	route := func(p string, nh netip.Addr, prov string) plugin.Route {
		return plugin.Route{Prefix: netip.MustParsePrefix(p), NextHop: nh, Provider: prov, LocalPref: 250, Communities: []string{"64512:666"}}
	}
	for _, rt := range []plugin.Route{
		route("198.51.100.0/24", nhB, "transit-b"),
		route("203.0.113.0/24", nhA, "transit-a"),
		route("198.51.100.128/25", nhC, "transit-c"),
	} {
		if err := a.Announce(ctx, rt); err != nil {
			t.Fatal(err)
		}
	}
	comm, _ := parseCommunity("64512:666")
	has := func(r *fakeRouter, prefix, nh string) func() bool {
		return func() bool {
			g, ok := fromUs(collect(t, r.srv, v4Family), prefix)
			return ok && g.nextHop == nh && g.lp == 250 && g.comms[comm] && g.comms[noExport]
		}
	}
	lacks := func(r *fakeRouter, prefix string) func() bool {
		return func() bool {
			_, ok := fromUs(collect(t, r.srv, v4Family), prefix)
			return !ok
		}
	}
	eventually(t, "edge-a: transit-b route via edge-b", has(edgeA, "198.51.100.0/24", "192.0.2.252"))
	eventually(t, "edge-b: transit-b route direct", has(edgeB, "198.51.100.0/24", "192.0.2.22"))
	eventually(t, "edge-a: transit-a route direct", has(edgeA, "203.0.113.0/24", "192.0.2.21"))
	for _, r := range []*fakeRouter{edgeA, edgeB} {
		if !lacks(r, "198.51.100.128/25")() {
			t.Fatal("transit-c route reached a router that cannot forward to it")
		}
	}
	if !lacks(edgeB, "203.0.113.0/24")() {
		t.Fatal("transit-a route reached edge-b")
	}

	// A move onto transit-a withdraws the route from edge-b.
	if err := a.Announce(ctx, route("198.51.100.0/24", nhA, "transit-a")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "edge-b: moved route withdrawn", lacks(edgeB, "198.51.100.0/24"))
	eventually(t, "edge-a: moved route direct", has(edgeA, "198.51.100.0/24", "192.0.2.21"))

	// An inbound steer route keeps its next hop and reaches every router,
	// even when that next hop is a provider's.
	in := mustInbound(t, inboundYAML)
	own := netip.MustParsePrefix("192.0.2.128/25")
	if err := in.Bind(v.Server(), "64512:666", []netip.Prefix{own}); err != nil {
		t.Fatal(err)
	}
	if err := in.Announce(ctx, plugin.InboundRoute{
		Prefix: own, NextHop: nhA, LocalPref: 1, Community: "64512:666", Away: []string{"transit-a"},
	}); err != nil {
		t.Fatal(err)
	}
	steer := func(r *fakeRouter) func() bool {
		return func() bool {
			g, ok := fromUs(collect(t, r.srv, v4Family), own.String())
			return ok && g.nextHop == "192.0.2.21" && g.lp == 1
		}
	}
	eventually(t, "edge-a: inbound steer", steer(edgeA))
	eventually(t, "edge-b: inbound steer", steer(edgeB))

	// edge-b's session drops: it is transit-b's only egress.
	if err := edgeB.srv.StopBgp(ctx, &api.StopBgpRequest{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "transit-b egress down", func() bool { return v.EgressDown()["transit-b"] && !v.EgressDown()["transit-a"] })
	if !has(edgeA, "198.51.100.0/24", "192.0.2.21")() {
		t.Fatal("edge-a lost its route when edge-b's session dropped")
	}

	if err := a.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	eventually(t, "edge-a: withdraw all", func() bool {
		for _, p := range collect(t, edgeA.srv, v4Family) {
			if p.fromUs && p.prefix != own.String() {
				return false
			}
		}
		return true
	})
}

func TestBindRoutersRejectsBadTable(t *testing.T) {
	r := newRouter(t)
	v := newView(t, r)
	eventually(t, "session", v.Ready)
	n := netip.MustParseAddr("127.0.0.1")
	bad := map[string][]plugin.RouterExport{
		"none":       nil,
		"duplicate":  {{Neighbor: n}, {Neighbor: n}},
		"mixed af":   {{Neighbor: n, Via: map[netip.Addr]netip.Addr{netip.MustParseAddr("192.0.2.22"): netip.MustParseAddr("2001:db8::1")}}},
		"no address": {{}},
	}
	for name, routers := range bad {
		if err := mustAnnouncer(t).BindRouters(v.Server(), "64512:666", routers); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := mustAnnouncer(t).BindRouters(nil, "64512:666", []plugin.RouterExport{{Neighbor: n}}); err == nil {
		t.Error("nil speaker accepted")
	}
}
