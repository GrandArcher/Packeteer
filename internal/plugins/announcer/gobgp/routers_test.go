package gobgp

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

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

// bgp.as_path (#27): a route carries the AS path the controller chose, and
// an empty one when none is set. A path longer than one AS_SEQUENCE
// segment is split, not truncated.
func TestAnnounceASPath(t *testing.T) {
	ctx := context.Background()
	r := newRouter(t)
	v := newView(t, r)
	eventually(t, "session", v.Ready)
	a := mustAnnouncer(t)
	if err := a.Bind(v.Server(), "64512:666"); err != nil {
		t.Fatal(err)
	}
	long := make([]uint32, 300)
	for i := range long {
		long[i] = 64501
	}
	nh := netip.MustParseAddr("192.0.2.1")
	for p, as := range map[string][]uint32{"198.51.100.0/24": {64501, 64501, 64500}, "203.0.113.0/24": nil, "198.51.100.128/25": long} {
		if err := a.Announce(ctx, plugin.Route{Prefix: netip.MustParsePrefix(p), NextHop: nh, LocalPref: 250,
			Communities: []string{"64512:666"}, ASPath: as}); err != nil {
			t.Fatal(err)
		}
	}
	path := func(p string, want []uint32) func() bool {
		return func() bool {
			g, ok := fromUs(collect(t, r.srv, v4Family), p)
			return ok && slices.Equal(g.asPath, want)
		}
	}
	eventually(t, "provider path", path("198.51.100.0/24", []uint32{64501, 64501, 64500}))
	eventually(t, "empty path", path("203.0.113.0/24", nil))
	eventually(t, "long path", path("198.51.100.128/25", long))
	if err := a.Announce(ctx, plugin.Route{Prefix: netip.MustParsePrefix("198.51.100.0/24"), NextHop: nh, LocalPref: 250,
		Communities: []string{"64512:666"}, ASPath: []uint32{64501, 0}}); err == nil {
		t.Fatal("AS 0 accepted")
	}
}

// Online reconfiguration (#27): SetRouters swaps the per-router table on
// the running speaker without touching the sessions. Every route is
// withdrawn first, so a router the new table blocks does not keep one;
// routes announced afterwards follow the new table. Empty removes it.
func TestSetRoutersReplacesTable(t *testing.T) {
	ctx := context.Background()
	edgeA := newRouterAt(t, "127.0.0.1", "192.0.2.251")
	edgeB := newRouterAt(t, "127.0.0.3", "192.0.2.252")
	a1, a3 := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.3")
	local := netip.MustParseAddr("127.0.0.2")
	nhA := netip.MustParseAddr("192.0.2.21")
	v, err := rib.New(rib.Options{
		ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"), ListenPort: -1,
		Neighbors: []rib.Neighbor{
			{Address: a1, Port: uint16(edgeA.port), LocalAddress: local},
			{Address: a3, Port: uint16(edgeB.port), LocalAddress: local},
		},
		Providers: map[netip.Addr]string{nhA: "transit-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Stop(context.Background()) })
	eventually(t, "both sessions", func() bool {
		n := 0
		for _, p := range v.Peers() {
			if p.Established {
				n++
			}
		}
		return n == 2
	})
	since := map[netip.Addr]time.Time{}
	for _, p := range v.Peers() {
		since[p.Address] = p.Since
	}

	a := mustAnnouncer(t)
	if err := a.BindRouters(v.Server(), "64512:666", []plugin.RouterExport{{Neighbor: a1}, {Neighbor: a3, Blocked: []netip.Addr{nhA}}}); err != nil {
		t.Fatal(err)
	}
	route := plugin.Route{Prefix: netip.MustParsePrefix("198.51.100.0/24"), NextHop: nhA, Provider: "transit-a", LocalPref: 250, Communities: []string{"64512:666"}}
	has := func(r *fakeRouter) func() bool {
		return func() bool { _, ok := fromUs(collect(t, r.srv, v4Family), "198.51.100.0/24"); return ok }
	}
	lacks := func(r *fakeRouter) func() bool { return func() bool { return !has(r)() } }
	if err := a.Announce(ctx, route); err != nil {
		t.Fatal(err)
	}
	eventually(t, "edge-a has the route", has(edgeA))
	if has(edgeB)() {
		t.Fatal("edge-b got a route its table blocks")
	}

	// The new table sends transit-a to edge-b only.
	if err := a.SetRouters(ctx, []plugin.RouterExport{{Neighbor: a1, Blocked: []netip.Addr{nhA}}, {Neighbor: a3}}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "edge-a withdrawn by the swap", lacks(edgeA))
	if err := a.Announce(ctx, route); err != nil {
		t.Fatal(err)
	}
	eventually(t, "edge-b has the route", has(edgeB))
	time.Sleep(300 * time.Millisecond)
	if has(edgeA)() {
		t.Fatal("edge-a got the route after the new table blocked it")
	}

	// No table: every router gets every route.
	if err := a.SetRouters(ctx, nil); err != nil {
		t.Fatal(err)
	}
	eventually(t, "edge-b withdrawn by the swap", lacks(edgeB))
	if err := a.Announce(ctx, route); err != nil {
		t.Fatal(err)
	}
	eventually(t, "edge-a has the route", has(edgeA))
	eventually(t, "edge-b has the route", has(edgeB))
	for _, p := range v.Peers() {
		if !p.Established || !p.Since.Equal(since[p.Address]) {
			t.Fatalf("session %s was reset by the swap: %+v", p.Address, p)
		}
	}
	// And back to a table from none.
	if err := a.SetRouters(ctx, []plugin.RouterExport{{Neighbor: a1}, {Neighbor: a3, Blocked: []netip.Addr{nhA}}}); err != nil {
		t.Fatal(err)
	}
	if err := a.Announce(ctx, route); err != nil {
		t.Fatal(err)
	}
	eventually(t, "edge-b withdrawn", lacks(edgeB))
	eventually(t, "edge-a has the route", has(edgeA))
}

func TestSetRoutersNeedsBind(t *testing.T) {
	if err := mustAnnouncer(t).SetRouters(context.Background(), nil); err == nil {
		t.Fatal("SetRouters on an unbound announcer accepted")
	}
}
