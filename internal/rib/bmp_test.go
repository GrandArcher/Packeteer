package rib

import (
	"context"
	"net/netip"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var (
	edge     = netip.MustParseAddr("192.0.2.254")
	edge2    = netip.MustParseAddr("192.0.2.253")
	transitA = netip.MustParseAddr("192.0.2.1")
	transitB = netip.MustParseAddr("192.0.2.2")
	lab      = netip.MustParsePrefix("198.51.100.0/24")
)

func bmpView(t *testing.T, usage map[string]string) *View {
	t.Helper()
	v, err := New(Options{
		ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"),
		Neighbors: []Neighbor{{Address: edge}},
		Providers: map[netip.Addr]string{transitA: "transit-a", transitB: "transit-b"},
		BMP:       usage, OwnCommunity: 64512<<16 | 666,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// paths is a post-policy route monitoring event: routes the router accepted.
func paths(router, peer netip.Addr, ps ...plugin.RIBPath) plugin.RIBEvent {
	return plugin.RIBEvent{Kind: plugin.RIBPaths, Router: router, Peer: plugin.RIBPeer{Address: peer}, Paths: ps, PostPolicy: true}
}

func announce(p netip.Prefix, nh netip.Addr, as ...uint32) plugin.RIBPath {
	return plugin.RIBPath{Prefix: p, NextHop: nh, ASPath: as}
}

func TestRouteSnapshotAltPaths(t *testing.T) {
	v := bmpView(t, map[string]string{"transit-a": BMPPrefer, "transit-b": BMPPrefer})
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPeerUp, Router: edge, Peer: plugin.RIBPeer{Address: transitA}})
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPeerUp, Router: edge, Peer: plugin.RIBPeer{Address: transitB}})
	v.ApplyRIB(paths(edge, transitB, announce(lab, transitB, 64497, 64497, 64500)))
	v.ApplyRIB(paths(edge, transitA, announce(lab, transitA, 64496, 64500)))
	def := netip.MustParsePrefix("0.0.0.0/0")
	v.ApplyRIB(paths(edge, transitB, announce(def, transitB, 64501)))

	routes, alts := v.RouteSnapshot()
	if len(routes) != 2 {
		t.Fatalf("routes = %+v", routes)
	}
	if len(alts) != 1 || alts[0].Prefix != lab || alts[0].Provider != "transit-b" {
		t.Fatalf("alts = %+v", alts)
	}
	if len(alts[0].ASPath) != 3 || alts[0].ASPath[0] != 64497 || alts[0].ASPath[2] != 64500 {
		t.Fatalf("as path = %v", alts[0].ASPath)
	}
	for _, a := range alts {
		if a.Provider == "transit-a" || a.Prefix.Bits() == 0 {
			t.Fatalf("native or default path leaked: %+v", a)
		}
	}
	// The copy is independent of the view.
	alts[0].ASPath[0] = 1
	_, again := v.RouteSnapshot()
	if len(again) != 1 || again[0].ASPath[0] != 64497 {
		t.Fatalf("snapshot aliased the view: %+v", again)
	}

	v.ApplyRIB(paths(edge, transitB, plugin.RIBPath{Prefix: lab, Withdraw: true}))
	if _, left := v.RouteSnapshot(); len(left) != 0 {
		t.Fatalf("withdrawn alt still present: %+v", left)
	}
}

func TestBMPUsageValidation(t *testing.T) {
	_, err := New(Options{ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"),
		Neighbors: []Neighbor{{Address: edge}}, BMP: map[string]string{"transit-a": "always"}})
	if err == nil {
		t.Fatal("invalid bmp usage accepted")
	}
}

func TestBMPOffIgnoresPaths(t *testing.T) {
	v := bmpView(t, nil)
	g := v.Generation()
	v.ApplyRIB(paths(edge, transitA, announce(lab, transitA, 64496)))
	if _, ok := v.Exact(lab); ok {
		t.Fatal("a BMP path counted for a provider with bmp off")
	}
	if c, _ := v.RouteCheck(lab, "transit-a"); c {
		t.Fatal("route check applied with bmp off")
	}
	if v.Generation() == g {
		t.Fatal("peer state change did not bump the generation")
	}
}

func TestBMPAdjInWithUnknownNextHopIsIgnored(t *testing.T) {
	v := bmpView(t, map[string]string{"transit-a": BMPPrefer})
	v.ApplyRIB(paths(edge, transitA, announce(lab, netip.MustParseAddr("192.0.2.99"), 64499)))
	if _, ok := v.Exact(lab); ok {
		t.Fatal("an Adj-RIB-In path with no provider made the prefix learned")
	}
	// A Loc-RIB path with no provider is kept: the router's best is not a
	// provider, so there is no native exit to improve on.
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPaths, Router: edge, Peer: plugin.RIBPeer{LocRIB: true},
		Paths: []plugin.RIBPath{announce(lab, netip.MustParseAddr("192.0.2.99"), 64499)}})
	rt, ok := v.Exact(lab)
	if !ok || rt.Provider != "" || !rt.LocRIB {
		t.Fatalf("loc-rib path = %+v ok=%v", rt, ok)
	}
}

func TestBMPInactivePathAndNativeEstimate(t *testing.T) {
	v := bmpView(t, map[string]string{"transit-a": BMPPrefer, "transit-b": BMPPrefer})
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPeerUp, Router: edge, Peer: plugin.RIBPeer{Address: transitA}})
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPeerUp, Router: edge, Peer: plugin.RIBPeer{Address: transitB}})
	v.ApplyRIB(paths(edge, transitB, announce(lab, transitB, 64497, 64497, 64500)))
	v.ApplyRIB(paths(edge, transitA, announce(lab, transitA, 64496, 64500)))
	rt, ok := v.Exact(lab)
	if !ok || rt.Provider != "transit-a" || rt.Source != SourceBMP || rt.Router != edge {
		t.Fatalf("native estimate (shortest AS path) = %+v ok=%v", rt, ok)
	}
	if ps := v.Paths(lab); len(ps) != 2 || ps[0].Provider != "transit-a" || ps[1].Provider != "transit-b" {
		t.Fatalf("paths = %+v", ps)
	}
	if c, ok := v.RouteCheck(lab, "transit-b"); !c || !ok {
		t.Fatalf("inactive path via transit-b: checked=%v ok=%v", c, ok)
	}
	// transit-b withdraws: the route check now refuses it.
	v.ApplyRIB(paths(edge, transitB, plugin.RIBPath{Prefix: lab, Withdraw: true}))
	if c, ok := v.RouteCheck(lab, "transit-b"); !c || ok {
		t.Fatalf("after withdraw: checked=%v ok=%v", c, ok)
	}
	// A Loc-RIB path is the router's own choice and wins the estimate.
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPaths, Router: edge, Peer: plugin.RIBPeer{LocRIB: true},
		Paths: []plugin.RIBPath{announce(lab, transitB, 64497, 64497, 64500)}})
	if rt, _ := v.Exact(lab); !rt.LocRIB || rt.Provider != "transit-b" {
		t.Fatalf("loc-rib did not win: %+v", rt)
	}
}

func TestBMPOnlyIgnoresIBGPPaths(t *testing.T) {
	v := bmpView(t, map[string]string{"transit-a": BMPOnly})
	v.mu.Lock()
	v.applyPath(learned(t, lab.String(), transitA.String(), edge.String(), 100, false))
	v.mu.Unlock()
	if _, ok := v.Exact(lab); ok {
		t.Fatal("iBGP path via a bmp only provider was used")
	}
	if c, ok := v.RouteCheck(lab, "transit-a"); !c || ok {
		t.Fatalf("only without a BMP path: checked=%v ok=%v", c, ok)
	}
	v.ApplyRIB(paths(edge, transitA, announce(lab, transitA, 64496)))
	if rt, ok := v.Exact(lab); !ok || rt.Source != SourceBMP {
		t.Fatalf("BMP path = %+v ok=%v", rt, ok)
	}
	// iBGP stays first for a provider that is not only.
	v.mu.Lock()
	v.applyPath(learned(t, lab.String(), transitB.String(), edge.String(), 100, false))
	v.mu.Unlock()
	if rt, _ := v.Exact(lab); rt.Source != SourceIBGP || rt.Provider != "transit-b" {
		t.Fatalf("iBGP path should be published first: %+v", rt)
	}
}

func TestBMPPreferFallsBackWithoutSession(t *testing.T) {
	v := bmpView(t, map[string]string{"transit-b": BMPPrefer})
	if c, _ := v.RouteCheck(lab, "transit-b"); c {
		t.Fatal("prefer checked before any BMP session reported transit-b's peer")
	}
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPeerUp, Router: edge, Peer: plugin.RIBPeer{Address: transitB}})
	if c, ok := v.RouteCheck(lab, "transit-b"); !c || ok {
		t.Fatalf("prefer with the peer up and no path: checked=%v ok=%v", c, ok)
	}
	// The router's iBGP best via transit-b is evidence too.
	v.mu.Lock()
	v.applyPath(learned(t, lab.String(), transitB.String(), edge.String(), 100, false))
	v.mu.Unlock()
	if c, ok := v.RouteCheck(lab, "transit-b"); !c || !ok {
		t.Fatalf("iBGP path via transit-b: checked=%v ok=%v", c, ok)
	}
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPeerDown, Router: edge, Peer: plugin.RIBPeer{Address: transitB}})
	if c, _ := v.RouteCheck(lab, "transit-b"); c {
		t.Fatal("prefer still checked after the peer went down")
	}
}

func TestBMPRouterDownDropsOnlyThatRouter(t *testing.T) {
	v := bmpView(t, map[string]string{"transit-a": BMPOnly, "transit-b": BMPOnly})
	other := netip.MustParsePrefix("203.0.113.0/24")
	v.ApplyRIB(paths(edge, transitA, announce(lab, transitA, 64496)))
	v.ApplyRIB(paths(edge2, transitB, announce(other, transitB, 64497)))
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBRouterDown, Router: edge})
	if _, ok := v.Exact(lab); ok {
		t.Fatal("paths from a router whose BMP session ended are still published")
	}
	if _, ok := v.Exact(other); !ok {
		t.Fatal("another router's paths were dropped")
	}
	if ps := v.BMPPeers(); len(ps) != 1 || ps[0].Router != edge2 {
		t.Fatalf("peers = %+v", ps)
	}
	_ = v.Stop(context.Background())
	if v.Len() != 0 || len(v.BMPPeers()) != 0 {
		t.Fatal("Stop left BMP state behind")
	}
}

func TestBMPIgnoresLargePacketeerCommunity(t *testing.T) {
	v, err := New(Options{
		ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"),
		Neighbors: []Neighbor{{Address: edge}},
		Providers: map[netip.Addr]string{transitA: "transit-a", transitB: "transit-b"},
		BMP:       map[string]string{"transit-b": BMPOnly},
		OwnLarge:  "4200000000:1:666",
	})
	if err != nil {
		t.Fatal(err)
	}
	tagged := announce(lab, transitB, 64497)
	tagged.LargeCommunities = []string{"64496:1:1", "4200000000:1:666"}
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPaths, Router: edge, Peer: plugin.RIBPeer{LocRIB: true},
		Paths: []plugin.RIBPath{tagged}})
	if _, ok := v.Exact(lab); ok {
		t.Fatal("a Loc-RIB path tagged with the large packeteer community made the prefix learned")
	}
	plain := announce(lab, transitB, 64497)
	plain.LargeCommunities = []string{"4200000000:1:1"}
	v.ApplyRIB(paths(edge, transitB, plain))
	if rt, ok := v.Exact(lab); !ok || rt.Provider != "transit-b" {
		t.Fatalf("a different large community was ignored: %+v ok=%v", rt, ok)
	}
}

func TestBMPNeverMakesViewReady(t *testing.T) {
	v := bmpView(t, map[string]string{"transit-a": BMPOnly})
	v.ApplyRIB(paths(edge, transitA, announce(lab, transitA, 64496)))
	if v.Ready() {
		t.Fatal("BMP alone made the view ready; readiness needs the iBGP session the announcer uses")
	}
}

// A router reports Packeteer's own injected route back over BMP: in the
// Adj-RIB-In of Packeteer's iBGP session and, once it wins, in Loc-RIB. Its
// next hop is the steered provider, so if it counted it would pass its own
// route check and keep the prefix learned after the provider withdrew.
func TestBMPIgnoresPacketeerOwnRoutes(t *testing.T) {
	v := bmpView(t, map[string]string{"transit-a": BMPOnly, "transit-b": BMPOnly})
	own := uint32(64512<<16 | 666)
	self := plugin.RIBPeer{Address: netip.MustParseAddr("192.0.2.10"), BGPID: netip.MustParseAddr("192.0.2.10")}
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPeerUp, Router: edge, Peer: self})
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPaths, Router: edge, Peer: self,
		Paths: []plugin.RIBPath{announce(lab, transitB, 64497)}, PostPolicy: true})
	if _, ok := v.Exact(lab); ok {
		t.Fatal("a path on Packeteer's own session (BGP ID = router_id) made the prefix learned")
	}
	if len(v.BMPPeers()) != 0 {
		t.Fatalf("Packeteer's own session counted as a BMP peer: %+v", v.BMPPeers())
	}
	tagged := announce(lab, transitB, 64497)
	tagged.Communities = []uint32{64496<<16 | 1, own}
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPaths, Router: edge, Peer: plugin.RIBPeer{LocRIB: true},
		Paths: []plugin.RIBPath{tagged}})
	if _, ok := v.Exact(lab); ok {
		t.Fatal("a Loc-RIB path tagged packeteer_community made the prefix learned")
	}
	if c, ok := v.RouteCheck(lab, "transit-b"); !c || ok {
		t.Fatalf("own route passed the route check: checked=%v ok=%v", c, ok)
	}
	// The real transit-b path, then Packeteer's route replacing it in
	// Loc-RIB: the Loc-RIB entry is dropped, the Adj-RIB-In path stays.
	v.ApplyRIB(paths(edge, transitB, announce(lab, transitB, 64497)))
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPaths, Router: edge, Peer: plugin.RIBPeer{LocRIB: true},
		Paths: []plugin.RIBPath{announce(lab, transitA, 64496)}})
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPaths, Router: edge, Peer: plugin.RIBPeer{LocRIB: true},
		Paths: []plugin.RIBPath{tagged}})
	if rt, ok := v.Exact(lab); !ok || rt.LocRIB || rt.Provider != "transit-b" {
		t.Fatalf("after own route replaced Loc-RIB: %+v ok=%v", rt, ok)
	}
	// transit-b withdraws: nothing of Packeteer's keeps the prefix.
	v.ApplyRIB(paths(edge, transitB, plugin.RIBPath{Prefix: lab, Withdraw: true}))
	if _, ok := v.Exact(lab); ok {
		t.Fatal("prefix still learned after the only real path was withdrawn")
	}
}

// Pre-policy Adj-RIB-In holds routes the router's import policy rejects
// (bogons, RPKI invalid, a hijacked more-specific). One of those must never
// make a prefix learned, appear in Routes, or pass a route check.
func TestBMPPrePolicyPathsNeverCount(t *testing.T) {
	v := bmpView(t, map[string]string{"transit-a": BMPOnly, "transit-b": BMPPrefer})
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPeerUp, Router: edge, Peer: plugin.RIBPeer{Address: transitB}})
	g := v.Generation()
	pre := paths(edge, transitA, announce(lab, transitA, 64496))
	pre.PostPolicy = false
	v.ApplyRIB(pre)
	pre = paths(edge, transitB, announce(lab, transitB, 64497))
	pre.PostPolicy = false
	v.ApplyRIB(pre)
	if _, ok := v.Exact(lab); ok {
		t.Fatal("a pre-policy path made the prefix learned")
	}
	if rs := v.Routes(); len(rs) != 0 {
		t.Fatalf("pre-policy paths in Routes: %+v", rs)
	}
	if ps := v.Paths(lab); len(ps) != 0 {
		t.Fatalf("pre-policy paths stored: %+v", ps)
	}
	for _, prov := range []string{"transit-a", "transit-b"} {
		if c, ok := v.RouteCheck(lab, prov); !c || ok {
			t.Fatalf("%s: pre-policy path passed the route check: checked=%v ok=%v", prov, c, ok)
		}
	}
	if v.Generation() != g {
		t.Fatal("pre-policy paths changed the view")
	}
	// The same route after the router accepts it counts.
	v.ApplyRIB(paths(edge, transitA, announce(lab, transitA, 64496)))
	if _, ok := v.Exact(lab); !ok {
		t.Fatal("post-policy path not learned")
	}
}

// Setting rib_sources with every provider off leaves the view as it was:
// even a Loc-RIB path with no provider is ignored.
func TestBMPAllOffIgnoresLocRIB(t *testing.T) {
	v := bmpView(t, map[string]string{"transit-a": BMPOff})
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPaths, Router: edge, Peer: plugin.RIBPeer{LocRIB: true},
		Paths: []plugin.RIBPath{announce(lab, netip.MustParseAddr("192.0.2.99"), 64499)}})
	if rt, ok := v.Exact(lab); ok {
		t.Fatalf("Loc-RIB path counted with every provider off: %+v", rt)
	}
}

// With several edges, a provider's path counts for its route check only on
// a router that reports the provider's BGP peer up. A path through the
// provider on another router (relayed over iBGP there, or left behind) does
// not pass.
func TestBMPRouteCheckPerRouter(t *testing.T) {
	v := bmpView(t, map[string]string{"transit-b": BMPPrefer})
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPeerUp, Router: edge, Peer: plugin.RIBPeer{Address: transitB}})
	// edge2 has transit-b's path from its iBGP peer edge.
	v.ApplyRIB(paths(edge2, edge, announce(lab, transitB, 64497)))
	if c, ok := v.RouteCheck(lab, "transit-b"); !c || ok {
		t.Fatalf("path on another router passed: checked=%v ok=%v", c, ok)
	}
	v.ApplyRIB(paths(edge, transitB, announce(lab, transitB, 64497)))
	if c, ok := v.RouteCheck(lab, "transit-b"); !c || !ok {
		t.Fatalf("path on the provider's router: checked=%v ok=%v", c, ok)
	}
	// edge loses the transit-b session: edge2's copy does not keep the
	// check passing, and prefer falls back to no check.
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPeerDown, Router: edge, Peer: plugin.RIBPeer{Address: transitB}})
	if c, _ := v.RouteCheck(lab, "transit-b"); c {
		t.Fatal("prefer still checked with no router reporting transit-b up")
	}
}
