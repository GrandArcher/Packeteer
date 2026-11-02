package rib

import (
	"context"
	"net/netip"
	"runtime"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func bmpAloneView(t *testing.T) *View {
	t.Helper()
	v, err := New(Options{
		ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"),
		Providers: map[netip.Addr]string{transitA: "transit-a", transitB: "transit-b"},
		BMP:       map[string]string{"transit-a": BMPPrefer, "transit-b": BMPOnly},
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func peerUp(router, peer netip.Addr) plugin.RIBEvent {
	return plugin.RIBEvent{Kind: plugin.RIBPeerUp, Router: router, Peer: plugin.RIBPeer{Address: peer}}
}

func TestBMPAloneNeedsAProviderOnBMP(t *testing.T) {
	_, err := New(Options{ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"),
		Providers: map[netip.Addr]string{transitA: "transit-a"}, BMP: map[string]string{"transit-a": BMPOff}})
	if err == nil {
		t.Fatal("a view with no neighbors and no provider on BMP was accepted")
	}
}

// With no iBGP neighbor the view is learned over BMP alone (#237). It is
// ready only while a feed reports a peer up; a lost feed drops its paths
// and, with no other router, makes the view not ready so consumers
// withdraw. A reconnect that reports the peer and its routes again makes
// it ready and learned again.
func TestBMPAloneReadyFollowsTheFeed(t *testing.T) {
	v := bmpAloneView(t)
	if v.Ready() {
		t.Fatal("ready before any BMP session")
	}
	v.ApplyRIB(peerUp(edge, transitA))
	v.ApplyRIB(peerUp(edge, transitB))
	if !v.Ready() {
		t.Fatal("not ready with BMP peers up")
	}
	v.ApplyRIB(paths(edge, transitA, announce(lab, transitA, 64496, 64500)))
	v.ApplyRIB(paths(edge, transitB, announce(lab, transitB, 64497, 64497, 64500)))
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPaths, Router: edge, Peer: plugin.RIBPeer{LocRIB: true},
		Paths: []plugin.RIBPath{announce(lab, transitA, 64496, 64500)}})
	rt, ok := v.Exact(lab)
	if !ok || rt.Provider != "transit-a" || !rt.LocRIB {
		t.Fatalf("published = %+v ok=%v, want the Loc-RIB path via transit-a", rt, ok)
	}
	if checked, pass := v.RouteCheck(lab, "transit-b"); !checked || !pass {
		t.Fatalf("route check transit-b = %v %v", checked, pass)
	}

	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPeerDown, Router: edge, Peer: plugin.RIBPeer{Address: transitB}})
	if !v.Ready() {
		t.Fatal("one peer down made the view not ready while another is up")
	}
	if checked, pass := v.RouteCheck(lab, "transit-b"); !checked || pass {
		t.Fatalf("route check transit-b after its peer down = %v %v", checked, pass)
	}

	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBRouterDown, Router: edge})
	if v.Ready() {
		t.Fatal("ready after the only BMP feed dropped")
	}
	if _, ok := v.Exact(lab); ok || v.Len() != 0 {
		t.Fatal("paths from the dropped feed are still published")
	}

	v.ApplyRIB(peerUp(edge, transitA))
	v.ApplyRIB(paths(edge, transitA, announce(lab, transitA, 64496, 64500)))
	if !v.Ready() {
		t.Fatal("not ready after the router reconnected")
	}
	if rt, ok := v.Exact(lab); !ok || rt.Provider != "transit-a" {
		t.Fatalf("after reconnect = %+v ok=%v", rt, ok)
	}
}

func TestBMPAloneSeveralRouters(t *testing.T) {
	v := bmpAloneView(t)
	other := netip.MustParsePrefix("203.0.113.0/24")
	v.ApplyRIB(peerUp(edge, transitA))
	v.ApplyRIB(peerUp(edge2, transitB))
	v.ApplyRIB(paths(edge, transitA, announce(lab, transitA, 64496)))
	v.ApplyRIB(paths(edge2, transitB, announce(other, transitB, 64497)))
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBRouterDown, Router: edge})
	if !v.Ready() {
		t.Fatal("one router's feed dropping made the view not ready while another feed is up")
	}
	if _, ok := v.Exact(lab); ok {
		t.Fatal("the dropped router's paths are still published")
	}
	if rt, ok := v.Exact(other); !ok || rt.Router != edge2 {
		t.Fatalf("the other router's path = %+v ok=%v", rt, ok)
	}
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBRouterDown, Router: edge2})
	if v.Ready() {
		t.Fatal("ready with every feed gone")
	}
}

func TestBMPAloneRefusesNeighbors(t *testing.T) {
	v := bmpAloneView(t)
	if err := v.AddNeighbors(context.Background(), []Neighbor{{Address: edge}}); err == nil {
		t.Fatal("an iBGP neighbor was added to a view learned over BMP alone")
	}
	if len(v.Peers()) != 0 {
		t.Fatalf("peers = %+v", v.Peers())
	}
}

// A Statistics Report count is kept per peer for display. It neither marks
// a peer up nor survives the peer going down.
func TestBMPPeerAdjRIBInCount(t *testing.T) {
	v := bmpAloneView(t)
	count := func(n int) plugin.RIBEvent {
		return plugin.RIBEvent{Kind: plugin.RIBPrefixCount, Router: edge, Peer: plugin.RIBPeer{Address: transitA}, Prefixes: n}
	}
	v.ApplyRIB(count(7))
	if len(v.BMPPeers()) != 0 || v.Ready() {
		t.Fatal("a statistics report marked a peer up")
	}
	v.ApplyRIB(peerUp(edge, transitA))
	if ps := v.BMPPeers(); len(ps) != 1 || ps[0].AdjRIBIn != nil {
		t.Fatalf("peers before a report = %+v", ps)
	}
	g := v.Generation()
	v.ApplyRIB(count(950000))
	ps := v.BMPPeers()
	if len(ps) != 1 || ps[0].AdjRIBIn == nil || *ps[0].AdjRIBIn != 950000 || ps[0].Peer != transitA {
		t.Fatalf("peers = %+v", ps)
	}
	if v.Generation() != g {
		t.Fatal("a count changed the route generation")
	}
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPeerDown, Router: edge, Peer: plugin.RIBPeer{Address: transitA}})
	v.ApplyRIB(peerUp(edge, transitA))
	if ps := v.BMPPeers(); len(ps) != 1 || ps[0].AdjRIBIn != nil {
		t.Fatalf("count survived a peer down: %+v", ps)
	}
}

// One BMP path per prefix is held inline, a second promotes the prefix to
// a map, and withdrawing back to one releases it.
func TestBMPPathsInline(t *testing.T) {
	v := bmpAloneView(t)
	v.ApplyRIB(paths(edge, transitA, announce(lab, transitA, 64496)))
	if s := v.bmp[lab]; s.n != 1 || s.many != nil {
		t.Fatalf("one path: n=%d map=%v", s.n, s.many != nil)
	}
	v.ApplyRIB(paths(edge, transitB, announce(lab, transitB, 64497)))
	if s := v.bmp[lab]; s.n != 2 || s.many == nil {
		t.Fatalf("two paths: n=%d map=%v", s.n, s.many != nil)
	}
	if got := v.Paths(lab); len(got) != 2 {
		t.Fatalf("paths = %+v", got)
	}
	v.ApplyRIB(paths(edge, transitA, plugin.RIBPath{Prefix: lab, Withdraw: true}))
	if s := v.bmp[lab]; s.n != 1 || s.many != nil || s.one.Provider != "transit-b" {
		t.Fatalf("after withdraw: n=%d map=%v one=%+v", s.n, s.many != nil, s.one)
	}
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBRouterDown, Router: edge})
	if _, ok := v.bmp[lab]; ok || v.Len() != 0 {
		t.Fatal("router down left BMP paths behind")
	}
}

// TestBMPPathsAreCompact locks the BMP layout at full-table scale (#237):
// one path per prefix stays inline, and an Adj-RIB-In path next to the
// Loc-RIB path is a two-entry slice. The map per prefix this replaced
// measured about 1,300 and 1,870 bytes a prefix.
func TestBMPPathsAreCompact(t *testing.T) {
	const n = 50000
	for _, tc := range []struct {
		name   string
		locRIB bool
		limit  float64
	}{{"adj-rib-in", false, 950}, {"adj-rib-in and loc-rib", true, 1650}} {
		v := bmpAloneView(t)
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		batch := make([]plugin.RIBPath, 0, 256)
		flush := func() {
			v.ApplyRIB(paths(edge, transitA, batch...))
			if tc.locRIB {
				v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPaths, Router: edge, Peer: plugin.RIBPeer{LocRIB: true}, Paths: batch})
			}
			batch = batch[:0]
		}
		for i := range n {
			p := netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(i >> 16), byte(i >> 8), byte(i), 0}), 24)
			batch = append(batch, announce(p, transitA, 64496, 64500))
			if len(batch) == cap(batch) {
				flush()
			}
		}
		flush()
		runtime.GC()
		runtime.ReadMemStats(&after)
		per := float64(after.HeapAlloc-before.HeapAlloc) / n
		t.Logf("%s: %.0f bytes/prefix", tc.name, per)
		if v.Len() != n {
			t.Fatalf("%s: len = %d", tc.name, v.Len())
		}
		if per > tc.limit {
			t.Fatalf("%s: %.0f bytes/prefix; want <= %.0f", tc.name, per, tc.limit)
		}
	}
}
