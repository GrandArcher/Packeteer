package rib

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	gobgplog "github.com/osrg/gobgp/v3/pkg/log"
	"github.com/osrg/gobgp/v3/pkg/server"
	"google.golang.org/protobuf/types/known/anypb"
)

// fakeRouter is an in-process GoBGP instance playing the edge router. It
// listens on 127.0.0.1 and expects Packeteer to connect from 127.0.0.2.
type fakeRouter struct {
	srv  *server.BgpServer
	port int
}

const asn = 64512

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func quiet() server.ServerOption {
	return server.LoggerOption(&nopLogger{})
}

type nopLogger struct{}

func (nopLogger) Panic(string, gobgplog.Fields) {}
func (nopLogger) Fatal(string, gobgplog.Fields) {}
func (nopLogger) Error(string, gobgplog.Fields) {}
func (nopLogger) Warn(string, gobgplog.Fields)  {}
func (nopLogger) Info(string, gobgplog.Fields)  {}
func (nopLogger) Debug(string, gobgplog.Fields) {}
func (nopLogger) SetLevel(gobgplog.LogLevel)    {}
func (nopLogger) GetLevel() gobgplog.LogLevel   { return gobgplog.PanicLevel }

func newRouter(t *testing.T) *fakeRouter {
	return newRouterPeer(t, "127.0.0.1", "192.0.2.254", "127.0.0.2")
}

func newRouterPeer(t *testing.T, listen, routerID, peer string) *fakeRouter {
	t.Helper()
	r := &fakeRouter{srv: server.NewBgpServer(quiet()), port: freePort(t)}
	go r.srv.Serve()
	ctx := context.Background()
	if err := r.srv.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn: asn, RouterId: routerID, ListenPort: int32(r.port), ListenAddresses: []string{listen},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := r.srv.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: peer, PeerAsn: asn},
		Transport: &api.Transport{PassiveMode: true},
	}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.stop() })
	return r
}

func (r *fakeRouter) stop() {
	_ = r.srv.StopBgp(context.Background(), &api.StopBgpRequest{})
	r.srv.Stop()
}

func path(t *testing.T, prefix, nexthop string) *api.Path {
	t.Helper()
	p := netip.MustParsePrefix(prefix)
	nlri, _ := anypb.New(&api.IPAddressPrefix{Prefix: p.Addr().String(), PrefixLen: uint32(p.Bits())})
	origin, _ := anypb.New(&api.OriginAttribute{Origin: 0})
	nh, _ := anypb.New(&api.NextHopAttribute{NextHop: nexthop})
	asp, _ := anypb.New(&api.AsPathAttribute{Segments: []*api.AsSegment{{Type: 2, Numbers: []uint32{64496, 64497}}}})
	return &api.Path{Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
		Nlri: nlri, Pattrs: []*anypb.Any{origin, nh, asp}}
}

func (r *fakeRouter) add(t *testing.T, prefix, nexthop string) {
	t.Helper()
	if _, err := r.srv.AddPath(context.Background(), &api.AddPathRequest{Path: path(t, prefix, nexthop)}); err != nil {
		t.Fatal(err)
	}
}

func (r *fakeRouter) del(t *testing.T, prefix, nexthop string) {
	t.Helper()
	if err := r.srv.DeletePath(context.Background(), &api.DeletePathRequest{Path: path(t, prefix, nexthop)}); err != nil {
		t.Fatal(err)
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func newView(t *testing.T, r *fakeRouter) *View {
	t.Helper()
	v, err := New(Options{
		ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"), ListenPort: -1,
		Neighbors: []Neighbor{{Address: netip.MustParseAddr("127.0.0.1"), Port: uint16(r.port),
			LocalAddress: netip.MustParseAddr("127.0.0.2"), Description: "edge1"}},
		Providers: map[netip.Addr]string{
			netip.MustParseAddr("192.0.2.1"): "transit-a",
			netip.MustParseAddr("192.0.2.2"): "transit-b",
		},
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

func TestLearnRoutesAndWithdraw(t *testing.T) {
	r := newRouter(t)
	r.add(t, "198.51.100.0/24", "192.0.2.1")
	r.add(t, "203.0.113.0/24", "192.0.2.2")
	r.add(t, "198.51.100.128/25", "192.0.2.9") // next-hop matches no provider

	changes := make(chan struct{}, 100)
	v := newView(t, r)
	v.OnChange(func() {
		select {
		case changes <- struct{}{}:
		default:
		}
	})

	eventually(t, "session established", v.Ready)
	eventually(t, "3 routes", func() bool { return v.Len() == 3 })

	rt, ok := v.Exact(netip.MustParsePrefix("198.51.100.0/24"))
	if !ok || rt.Provider != "transit-a" || rt.NextHop.String() != "192.0.2.1" || rt.Neighbor.String() != "127.0.0.1" {
		t.Fatalf("route = %+v ok=%v", rt, ok)
	}
	if len(rt.ASPath) != 2 || rt.ASPath[0] != 64496 {
		t.Errorf("as path = %v", rt.ASPath)
	}
	if lm, ok := v.Lookup(netip.MustParseAddr("198.51.100.200")); !ok || lm.Prefix.String() != "198.51.100.128/25" || lm.Provider != "" {
		t.Errorf("LPM = %+v", lm)
	}
	if lm, ok := v.Lookup(netip.MustParseAddr("198.51.100.5")); !ok || lm.Prefix.String() != "198.51.100.0/24" {
		t.Errorf("LPM = %+v", lm)
	}
	if c, ok := v.Covering(netip.MustParsePrefix("203.0.113.64/26")); !ok || c.Provider != "transit-b" {
		t.Errorf("Covering = %+v", c)
	}
	if _, ok := v.Exact(netip.MustParsePrefix("192.0.2.0/24")); ok {
		t.Error("unknown prefix reported as present")
	}
	if _, ok := v.Lookup(netip.MustParseAddr("192.0.2.77")); ok {
		t.Error("LPM matched nothing-covered address")
	}

	// Best-path change: router moves 203.0.113.0/24 to transit-a.
	r.add(t, "203.0.113.0/24", "192.0.2.1")
	eventually(t, "next-hop change", func() bool {
		rt, _ := v.Exact(netip.MustParsePrefix("203.0.113.0/24"))
		return rt.Provider == "transit-a"
	})

	// Withdraw.
	r.del(t, "198.51.100.0/24", "192.0.2.1")
	eventually(t, "withdraw", func() bool {
		_, ok := v.Exact(netip.MustParsePrefix("198.51.100.0/24"))
		return !ok
	})
	if len(changes) == 0 {
		t.Error("OnChange never called")
	}
	ps := v.Peers()
	if len(ps) != 1 || !ps[0].Established || ps[0].Description != "edge1" {
		t.Errorf("peers = %+v", ps)
	}
}

func TestSessionLossClearsRoutes(t *testing.T) {
	r := newRouter(t)
	r.add(t, "198.51.100.0/24", "192.0.2.1")
	v := newView(t, r)
	eventually(t, "route", func() bool { return v.Len() == 1 })
	r.stop()
	eventually(t, "not ready after router stop", func() bool { return !v.Ready() })
	eventually(t, "routes cleared", func() bool { return v.Len() == 0 })
}

// TestNeverExports proves the learn-only guarantee: even a route present in
// Packeteer's own RIB is not advertised to the router.
func TestNeverExports(t *testing.T) {
	r := newRouter(t)
	v := newView(t, r)
	eventually(t, "session", v.Ready)
	if _, err := v.Server().AddPath(context.Background(), &api.AddPathRequest{Path: path(t, "192.0.2.128/25", "192.0.2.1")}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	got := 0
	err := r.srv.ListPath(context.Background(), &api.ListPathRequest{TableType: api.TableType_GLOBAL,
		Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}}, func(*api.Destination) { got++ })
	if err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Fatalf("router received %d routes from Packeteer; export must be rejected", got)
	}
	// Our own local route must not appear in the view either.
	if _, ok := v.Exact(netip.MustParsePrefix("192.0.2.128/25")); ok {
		t.Error("locally originated route leaked into the RIB view")
	}
}

// TestLocalBestDoesNotHideNeighborRoute is the #43 regression: once
// Packeteer's own route is the local best path, the neighbor's advertisement
// must stay visible, and a real withdraw from that neighbor must remove it.
func TestLocalBestDoesNotHideNeighborRoute(t *testing.T) {
	r := newRouter(t)
	r.add(t, "198.51.100.0/24", "192.0.2.1")
	v := newView(t, r)
	p := netip.MustParsePrefix("198.51.100.0/24")
	eventually(t, "learned", func() bool {
		rt, ok := v.Exact(p)
		return ok && rt.Provider == "transit-a" && rt.Neighbor.String() == "127.0.0.1"
	})

	injected := path(t, "198.51.100.0/24", "192.0.2.2")
	lp, err := anypb.New(&api.LocalPrefAttribute{LocalPref: 250})
	if err != nil {
		t.Fatal(err)
	}
	injected.Pattrs = append(injected.Pattrs, lp)
	if _, err := v.Server().AddPath(context.Background(), &api.AddPathRequest{Path: injected}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rt, ok := v.Exact(p)
		if !ok || rt.NextHop.String() != "192.0.2.1" || rt.Provider != "transit-a" {
			t.Fatalf("local best hid the neighbor route: %+v ok=%v", rt, ok)
		}
		time.Sleep(50 * time.Millisecond)
	}

	r.del(t, "198.51.100.0/24", "192.0.2.1")
	eventually(t, "neighbor withdraw", func() bool {
		_, ok := v.Exact(p)
		return !ok
	})
	got := 0
	if err := v.Server().ListPath(context.Background(), &api.ListPathRequest{TableType: api.TableType_GLOBAL,
		Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}}, func(*api.Destination) { got++ }); err != nil {
		t.Fatal(err)
	}
	if got == 0 {
		t.Fatal("local path disappeared with the neighbor withdraw")
	}
}

// TestSessionLossDropsOnlyThatNeighbor keeps the view ready when another
// session is up, and drops prefixes only that neighbor was advertising.
func TestSessionLossDropsOnlyThatNeighbor(t *testing.T) {
	a := newRouterPeer(t, "127.0.0.1", "192.0.2.254", "127.0.0.2")
	b := newRouterPeer(t, "127.0.0.3", "192.0.2.253", "127.0.0.4")
	a.add(t, "198.51.100.0/24", "192.0.2.1")
	b.add(t, "203.0.113.0/24", "192.0.2.2")
	v, err := New(Options{
		ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"), ListenPort: -1,
		Neighbors: []Neighbor{
			{Address: netip.MustParseAddr("127.0.0.1"), Port: uint16(a.port), LocalAddress: netip.MustParseAddr("127.0.0.2")},
			{Address: netip.MustParseAddr("127.0.0.3"), Port: uint16(b.port), LocalAddress: netip.MustParseAddr("127.0.0.4")},
		},
		Providers: map[netip.Addr]string{
			netip.MustParseAddr("192.0.2.1"): "transit-a",
			netip.MustParseAddr("192.0.2.2"): "transit-b",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Stop(context.Background()) })

	eventually(t, "both prefixes", func() bool { return v.Len() == 2 && v.Ready() })
	a.stop()
	eventually(t, "neighbor a prefix gone", func() bool {
		_, ok := v.Exact(netip.MustParsePrefix("198.51.100.0/24"))
		return !ok
	})
	rt, ok := v.Exact(netip.MustParsePrefix("203.0.113.0/24"))
	if !ok || rt.Provider != "transit-b" || rt.Neighbor.String() != "127.0.0.3" {
		t.Fatalf("neighbor b route = %+v ok=%v", rt, ok)
	}
	if !v.Ready() {
		t.Fatal("view reported not-ready while another session was up")
	}
}

func TestLocalPrefChangeUpdatesRoute(t *testing.T) {
	p := netip.MustParsePrefix("198.51.100.0/24")
	nbr := netip.MustParseAddr("192.0.2.254")
	nh := netip.MustParseAddr("192.0.2.1")
	v := &View{
		opt:       Options{Providers: map[netip.Addr]string{nh: "transit-a"}},
		neighbors: map[netip.Addr]bool{nbr: true},
		routes:    map[netip.Prefix]Route{},
		adj:       map[netip.Prefix]map[netip.Addr]Route{},
	}
	if !v.applyPath(learned(t, "198.51.100.0/24", "192.0.2.1", nbr.String(), 100, false)) {
		t.Fatal("first path did not publish")
	}
	rt, ok := v.Exact(p)
	if !ok || rt.localPref != 100 || rt.Provider != "transit-a" {
		t.Fatalf("route = %+v ok=%v", rt, ok)
	}
	if v.applyPath(learned(t, "198.51.100.0/24", "192.0.2.1", nbr.String(), 100, false)) {
		t.Fatal("identical path published again")
	}
	if !v.applyPath(learned(t, "198.51.100.0/24", "192.0.2.1", nbr.String(), 250, false)) {
		t.Fatal("local-pref change was ignored")
	}
	rt, ok = v.Exact(p)
	if !ok || rt.localPref != 250 {
		t.Fatalf("after local-pref change = %+v ok=%v", rt, ok)
	}
}

func learned(t *testing.T, prefix, nexthop, neighbor string, lp uint32, withdraw bool) *api.Path {
	t.Helper()
	p := path(t, prefix, nexthop)
	p.NeighborIp = neighbor
	p.IsWithdraw = withdraw
	attr, err := anypb.New(&api.LocalPrefAttribute{LocalPref: lp})
	if err != nil {
		t.Fatal(err)
	}
	p.Pattrs = append(p.Pattrs, attr)
	return p
}

func TestSelectRoute(t *testing.T) {
	p := netip.MustParsePrefix("198.51.100.0/24")
	low := Route{Prefix: p, NextHop: netip.MustParseAddr("192.0.2.1"), Neighbor: netip.MustParseAddr("192.0.2.11"), localPref: 100}
	high := Route{Prefix: p, NextHop: netip.MustParseAddr("192.0.2.2"), Neighbor: netip.MustParseAddr("192.0.2.12"), localPref: 200}
	tie := Route{Prefix: p, NextHop: netip.MustParseAddr("192.0.2.3"), Neighbor: netip.MustParseAddr("192.0.2.10"), localPref: 100}
	got, ok := selectRoute(map[netip.Addr]Route{low.Neighbor: low, high.Neighbor: high})
	if !ok || got.NextHop != high.NextHop {
		t.Fatalf("higher local-pref = %+v ok=%v", got, ok)
	}
	got, ok = selectRoute(map[netip.Addr]Route{low.Neighbor: low, tie.Neighbor: tie})
	if !ok || got.Neighbor != tie.Neighbor {
		t.Fatalf("tie-break = %+v ok=%v", got, ok)
	}
	if _, ok := selectRoute(nil); ok {
		t.Fatal("empty adj-RIB-in reported a route")
	}
}

func TestNewValidation(t *testing.T) {
	n := []Neighbor{{Address: netip.MustParseAddr("192.0.2.1")}}
	rid := netip.MustParseAddr("192.0.2.10")
	for name, o := range map[string]Options{
		"no asn":       {RouterID: rid, Neighbors: n},
		"v6 router id": {ASN: asn, RouterID: netip.MustParseAddr("2001:db8::1"), Neighbors: n},
		"no neighbors": {ASN: asn, RouterID: rid},
		"bad neighbor": {ASN: asn, RouterID: rid, Neighbors: []Neighbor{{}}},
	} {
		if _, err := New(o); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}
