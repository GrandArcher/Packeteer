package rib

import (
	"context"
	"net/netip"
	"testing"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"google.golang.org/protobuf/types/known/anypb"
)

// newAddPathRouter is a fake edge that sends up to sendMax paths per
// prefix to Packeteer (add-path send, RFC 7911). sendMax 0 offers nothing.
func newAddPathRouter(t *testing.T, sendMax uint32) *fakeRouter {
	t.Helper()
	r := &fakeRouter{srv: server.NewBgpServer(quiet()), port: freePort(t)}
	go r.srv.Serve()
	ctx := context.Background()
	if err := r.srv.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn: asn, RouterId: "192.0.2.254", ListenPort: int32(r.port), ListenAddresses: []string{"127.0.0.1"},
	}}); err != nil {
		t.Fatal(err)
	}
	var afs []*api.AfiSafi
	for _, afi := range []api.Family_Afi{api.Family_AFI_IP, api.Family_AFI_IP6} {
		af := &api.AfiSafi{Config: &api.AfiSafiConfig{Family: &api.Family{Afi: afi, Safi: api.Family_SAFI_UNICAST}, Enabled: true}}
		if sendMax > 0 {
			af.AddPaths = &api.AddPaths{Config: &api.AddPathsConfig{SendMax: sendMax}}
		}
		afs = append(afs, af)
	}
	if err := r.srv.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.2", PeerAsn: asn},
		Transport: &api.Transport{PassiveMode: true},
		AfiSafis:  afs,
	}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.stop() })
	return r
}

// idPath is a path the fake router originates with an add-path identifier,
// so several paths for one prefix coexist in its table.
func idPath(t *testing.T, id uint32, prefix, nexthop string, as []uint32, comms ...uint32) *api.Path {
	t.Helper()
	p := path(t, prefix, nexthop)
	asp, _ := anypb.New(&api.AsPathAttribute{Segments: []*api.AsSegment{{Type: 2, Numbers: as}}})
	p.Pattrs[2] = asp
	if len(comms) > 0 {
		c, _ := anypb.New(&api.CommunitiesAttribute{Communities: comms})
		p.Pattrs = append(p.Pattrs, c)
	}
	p.Identifier = id
	return p
}

func (r *fakeRouter) addID(t *testing.T, p *api.Path) {
	t.Helper()
	if _, err := r.srv.AddPath(context.Background(), &api.AddPathRequest{Path: p}); err != nil {
		t.Fatal(err)
	}
}

func (r *fakeRouter) delID(t *testing.T, p *api.Path) {
	t.Helper()
	if err := r.srv.DeletePath(context.Background(), &api.DeletePathRequest{Path: p}); err != nil {
		t.Fatal(err)
	}
}

const ownComm = 64512<<16 | 666

func newAddPathView(t *testing.T, r *fakeRouter, addPath bool, checked map[string]bool) *View {
	t.Helper()
	v, err := New(Options{
		ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"), ListenPort: -1,
		Neighbors: []Neighbor{{Address: netip.MustParseAddr("127.0.0.1"), Port: uint16(r.port),
			LocalAddress: netip.MustParseAddr("127.0.0.2"), Description: "edge1", AddPath: addPath}},
		Providers: map[netip.Addr]string{
			netip.MustParseAddr("192.0.2.1"): "transit-a",
			netip.MustParseAddr("192.0.2.2"): "transit-b",
			netip.MustParseAddr("192.0.2.3"): "ix",
		},
		AddPath:      checked,
		OwnCommunity: ownComm,
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

func addPathUp(v *View) bool {
	for _, p := range v.Peers() {
		if p.AddPath {
			return true
		}
	}
	return false
}

// The router's inactive transit and IX paths arrive on the iBGP session,
// each with its own path ID. The published native path is the router's
// likely best (shorter AS path), a withdraw removes one path only, and
// the add-path route check follows the paths.
func TestAddPathLearnsInactivePaths(t *testing.T) {
	r := newAddPathRouter(t, 8)
	v := newAddPathView(t, r, true, map[string]bool{"transit-b": true, "ix": true})
	p := netip.MustParsePrefix("198.51.100.0/24")

	a := idPath(t, 1, "198.51.100.0/24", "192.0.2.1", []uint32{64496, 64500})
	b := idPath(t, 2, "198.51.100.0/24", "192.0.2.2", []uint32{64497, 64497, 64500})
	ix := idPath(t, 3, "198.51.100.0/24", "192.0.2.3", []uint32{64498, 64499, 64500})
	r.addID(t, a)
	r.addID(t, b)
	r.addID(t, ix)

	eventually(t, "add-path negotiated", func() bool { return addPathUp(v) })
	eventually(t, "three paths", func() bool { return len(v.Paths(p)) == 3 })
	ids := map[uint32]string{}
	for _, rt := range v.Paths(p) {
		if rt.Source != SourceIBGP || rt.PathID == 0 {
			t.Fatalf("path %+v: want an iBGP path with a path ID", rt)
		}
		ids[rt.PathID] = rt.Provider
	}
	if len(ids) != 3 {
		t.Fatalf("path IDs %v: want three distinct", ids)
	}
	if rt, ok := v.Exact(p); !ok || rt.Provider != "transit-a" {
		t.Fatalf("native = %+v %v, want transit-a (shortest AS path)", rt, ok)
	}
	for _, prov := range []string{"transit-b", "ix"} {
		if c, ok := v.RouteCheck(p, prov); !c || !ok {
			t.Fatalf("RouteCheck(%s) = %v,%v want true,true", prov, c, ok)
		}
	}
	// transit-a is not in the add-path check.
	if c, _ := v.RouteCheck(p, "transit-a"); c {
		t.Fatal("transit-a was checked without add_path")
	}

	r.delID(t, b)
	eventually(t, "transit-b path withdrawn", func() bool { return len(v.Paths(p)) == 2 })
	if c, ok := v.RouteCheck(p, "transit-b"); !c || ok {
		t.Fatalf("after withdraw RouteCheck(transit-b) = %v,%v want true,false", c, ok)
	}
	if c, ok := v.RouteCheck(p, "ix"); !c || !ok {
		t.Fatalf("ix lost with transit-b: %v,%v", c, ok)
	}
	if rt, ok := v.Exact(p); !ok || rt.Provider != "transit-a" {
		t.Fatalf("native after withdraw = %+v %v", rt, ok)
	}

	// The native path leaving publishes the next one; the prefix stays.
	r.delID(t, a)
	eventually(t, "native moves to ix", func() bool {
		rt, ok := v.Exact(p)
		return ok && rt.Provider == "ix"
	})

	// Session loss drops every path and turns the check off.
	r.stop()
	eventually(t, "paths dropped", func() bool { return len(v.Paths(p)) == 0 && !v.Ready() })
	if c, _ := v.RouteCheck(p, "ix"); c {
		t.Fatal("route check applied with the add-path session down")
	}
}

// A path tagged with packeteer_community is Packeteer's own route sent
// back. It never makes the prefix learned or passes the route check.
func TestAddPathIgnoresOwnRoute(t *testing.T) {
	r := newAddPathRouter(t, 8)
	v := newAddPathView(t, r, true, map[string]bool{"transit-b": true})
	own := netip.MustParsePrefix("203.0.113.0/24")
	r.addID(t, idPath(t, 1, "203.0.113.0/24", "192.0.2.2", []uint32{64497}, ownComm))
	r.add(t, "198.51.100.0/24", "192.0.2.1") // marker: updates have arrived
	eventually(t, "marker learned", func() bool {
		_, ok := v.Exact(netip.MustParsePrefix("198.51.100.0/24"))
		return ok && addPathUp(v)
	})
	if _, ok := v.Exact(own); ok {
		t.Fatal("own route made the prefix learned")
	}
	if c, ok := v.RouteCheck(own, "transit-b"); !c || ok {
		t.Fatalf("RouteCheck on own route = %v,%v want true,false", c, ok)
	}
}

// With add_path set but a router that does not send additional paths, the
// session works as before and the add-path route check stays off.
func TestAddPathNotNegotiated(t *testing.T) {
	r := newAddPathRouter(t, 0)
	v := newAddPathView(t, r, true, map[string]bool{"transit-b": true})
	p := netip.MustParsePrefix("198.51.100.0/24")
	r.add(t, "198.51.100.0/24", "192.0.2.1")
	eventually(t, "route learned", func() bool { _, ok := v.Exact(p); return ok })
	for _, ps := range v.Peers() {
		if ps.AddPath {
			t.Fatal("add-path reported without router send")
		}
	}
	if c, _ := v.RouteCheck(p, "transit-b"); c {
		t.Fatal("route check applied without negotiated add-path")
	}
}

func TestAddPathWithBMPOnlyRejected(t *testing.T) {
	_, err := New(Options{ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"),
		Neighbors: []Neighbor{{Address: netip.MustParseAddr("192.0.2.1"), AddPath: true}},
		BMP:       map[string]string{"transit-b": BMPOnly}, AddPath: map[string]bool{"transit-b": true}})
	if err == nil {
		t.Fatal("add_path with bmp only accepted")
	}
}
