package rib

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Session type comes from the path (#146). An exchange peer is not a
// route server just because it has an AS. MED stays display-only: it
// does not move the exit, and the route check still keys off the first AS.
func TestSessionTypeIsNotEveryExchangePeer(t *testing.T) {
	nbr := "192.0.2.254"
	edge := netip.MustParseAddr(nbr)
	member := netip.MustParseAddr("203.0.113.11")
	other := netip.MustParseAddr("203.0.113.12")
	rs := netip.MustParseAddr("203.0.113.1")
	rs2 := netip.MustParseAddr("203.0.113.2")
	lan := netip.MustParsePrefix("203.0.113.0/24")
	v, err := New(Options{
		ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"),
		Neighbors: []Neighbor{{Address: edge}},
		Providers: map[netip.Addr]string{
			member: "ix-peer-a",
			other:  "ix-peer-b",
		},
		PeerASN: map[string]uint32{"ix-peer-a": 64501, "ix-peer-b": 64502},
		BMP:     map[string]string{"ix-peer-a": BMPPrefer, "ix-peer-b": BMPPrefer},
		LANs:    []netip.Prefix{lan},
	})
	if err != nil {
		t.Fatal(err)
	}
	p := netip.MustParsePrefix("198.51.100.0/24")
	med := uint32(40)
	v.mu.Lock()
	if !v.applyPath(medPath(t, 1, nbr, p.String(), member.String(), []uint32{64501, 64500}, 100, &med)) {
		t.Fatal("iBGP member path did not publish")
	}
	v.mu.Unlock()

	ib := pathVia(t, v, p, SourceIBGP, edge)
	if ib.Via != ViaUnknown || strings.Contains(ib.MEDFrom, "route server") {
		t.Fatalf("iBGP add-path before BMP = %+v", ib)
	}
	if ib.MEDFrom != "iBGP 192.0.2.254, ix-peer-a" {
		t.Fatalf("iBGP label = %q", ib.MEDFrom)
	}
	if checked, ok := v.RouteCheck(p, "ix-peer-a"); !checked || !ok {
		t.Fatalf("route check before a label: checked=%v ok=%v", checked, ok)
	}

	// Bilateral: the BMP neighbor is the member, equal to the next hop.
	// The member must not be named as the route server.
	v.ApplyRIB(bmpMED(edge, member, p, member, []uint32{64501, 64500}, 1, &med))
	bi := pathVia(t, v, p, SourceBMP, member)
	if bi.Via != ViaBilateral || strings.Contains(bi.MEDFrom, "route server") || strings.Contains(bi.MEDFrom, "AS64501") {
		t.Fatalf("bilateral path = %+v", bi)
	}
	if bi.MEDFrom != "peer 203.0.113.11, ix-peer-a" {
		t.Fatalf("bilateral label = %q", bi.MEDFrom)
	}
	ib = pathVia(t, v, p, SourceIBGP, edge)
	if ib.Via != ViaBilateral || strings.Contains(ib.MEDFrom, "route server") {
		t.Fatalf("BMP did not confirm bilateral: %+v", ib)
	}
	hops := v.NextHops([]netip.Prefix{lan})
	if got := hopViaOf(t, hops, member); got != ViaBilateral {
		t.Fatalf("peer via = %q", got)
	}

	// A neighbor off the LAN that is not the next hop is not a route server,
	// even though the provider is an exchange peer.
	off := netip.MustParseAddr("192.0.2.50")
	v.ApplyRIB(bmpMED(edge, off, p, other, []uint32{64502, 64500}, 1, &med))
	gotOff := pathVia(t, v, p, SourceBMP, off)
	if gotOff.Via != ViaUnknown || strings.Contains(gotOff.MEDFrom, "route server") {
		t.Fatalf("off-LAN path = %+v", gotOff)
	}

	// Route server: the neighbor is on the LAN and is not the member.
	// Drop the bilateral path first so confirmation is unambiguous.
	v.ApplyRIB(bmpWithdraw(edge, member, p, 1))
	v.ApplyRIB(bmpMED(edge, rs, p, member, []uint32{64501, 64500}, 2, &med))
	server := pathVia(t, v, p, SourceBMP, rs)
	if server.Via != ViaRouteServer || server.MEDFrom != "peer 203.0.113.1, route server 203.0.113.1" {
		t.Fatalf("route server path = %+v", server)
	}
	if strings.Contains(server.MEDFrom, "ix-peer-a") || strings.Contains(server.MEDFrom, "AS64501") {
		t.Fatalf("member named as the route server: %q", server.MEDFrom)
	}
	ib = pathVia(t, v, p, SourceIBGP, edge)
	if ib.Via != ViaRouteServer || ib.MEDFrom != "iBGP 192.0.2.254, route server 203.0.113.1" {
		t.Fatalf("BMP did not confirm the route server: %+v", ib)
	}
	best, ok := v.Exact(p)
	if !ok || best.NextHop != member || best.Via != ViaRouteServer {
		t.Fatalf("exit changed: %+v %v", best, ok)
	}
	if checked, ok := v.RouteCheck(p, "ix-peer-a"); !checked || !ok {
		t.Fatalf("route check after the label: checked=%v ok=%v", checked, ok)
	}
	if got := hopViaOf(t, v.NextHops([]netip.Prefix{lan}), member); got != ViaRouteServer {
		t.Fatalf("peer via after route server = %q", got)
	}

	// A second route server still confirms the type, and does not name a member.
	v.ApplyRIB(bmpMED(edge, rs2, p, member, []uint32{64501, 64500}, 3, &med))
	ib = pathVia(t, v, p, SourceIBGP, edge)
	if ib.Via != ViaRouteServer || ib.MEDFrom != "iBGP 192.0.2.254, route server" || strings.Contains(ib.MEDFrom, "ix-peer-a") {
		t.Fatalf("two route servers = %+v", ib)
	}
	// Each BMP path keeps its own neighbor in the label.
	one := pathVia(t, v, p, SourceBMP, rs)
	if one.MEDFrom != "peer 203.0.113.1, route server 203.0.113.1" {
		t.Fatalf("first route server label = %q", one.MEDFrom)
	}

	// Both session types for one next hop: iBGP stays unknown.
	v.ApplyRIB(bmpMED(edge, member, p, member, []uint32{64501, 64500}, 4, &med))
	ib = pathVia(t, v, p, SourceIBGP, edge)
	if ib.Via != ViaUnknown || strings.Contains(ib.MEDFrom, "route server") {
		t.Fatalf("mixed BMP evidence = %+v", ib)
	}
	if pathVia(t, v, p, SourceBMP, rs).Via != ViaRouteServer || pathVia(t, v, p, SourceBMP, member).Via != ViaBilateral {
		t.Fatal("mixed evidence relabeled a BMP path")
	}
	if got := hopViaOf(t, v.NextHops([]netip.Prefix{lan}), member); got != ViaUnknown {
		t.Fatalf("mixed peer via = %q", got)
	}

	// The route server withdraws. The bilateral path remains and confirms it.
	v.ApplyRIB(bmpWithdraw(edge, rs, p, 2))
	v.ApplyRIB(bmpWithdraw(edge, rs2, p, 3))
	ib = pathVia(t, v, p, SourceIBGP, edge)
	if ib.Via != ViaBilateral || strings.Contains(ib.MEDFrom, "route server") {
		t.Fatalf("after route servers withdrew: %+v", ib)
	}

	// No BMP left: iBGP is unknown again.
	v.ApplyRIB(bmpWithdraw(edge, member, p, 4))
	ib = pathVia(t, v, p, SourceIBGP, edge)
	if ib.Via != ViaUnknown || strings.Contains(ib.MEDFrom, "route server") {
		t.Fatalf("after BMP withdrew: %+v", ib)
	}

	// Loc-RIB follows the same confirmation. With no Adj-RIB-In it is unknown.
	v.ApplyRIB(plugin.RIBEvent{
		Kind: plugin.RIBPaths, Router: edge, Peer: plugin.RIBPeer{LocRIB: true},
		Paths: []plugin.RIBPath{{
			Prefix: p, NextHop: member, ASPath: []uint32{64501, 64500}, MED: &med,
		}},
	})
	loc := pathLoc(t, v, p)
	if loc.Via != ViaUnknown || strings.Contains(loc.MEDFrom, "route server") {
		t.Fatalf("loc-rib without BMP = %+v", loc)
	}
	v.ApplyRIB(bmpMED(edge, rs, p, member, []uint32{64501, 64500}, 5, &med))
	loc = pathLoc(t, v, p)
	if loc.Via != ViaRouteServer || loc.MEDFrom != "loc-rib 192.0.2.254, route server 203.0.113.1" {
		t.Fatalf("loc-rib confirmed = %+v", loc)
	}
}

func bmpMED(router, peer netip.Addr, p netip.Prefix, nh netip.Addr, as []uint32, id uint32, med *uint32) plugin.RIBEvent {
	return plugin.RIBEvent{
		Kind: plugin.RIBPaths, Router: router, Peer: plugin.RIBPeer{Address: peer}, PostPolicy: true,
		Paths: []plugin.RIBPath{{Prefix: p, NextHop: nh, ASPath: as, PathID: id, MED: med}},
	}
}

func bmpWithdraw(router, peer netip.Addr, p netip.Prefix, id uint32) plugin.RIBEvent {
	return plugin.RIBEvent{
		Kind: plugin.RIBPaths, Router: router, Peer: plugin.RIBPeer{Address: peer}, PostPolicy: true,
		Paths: []plugin.RIBPath{{Prefix: p, PathID: id, Withdraw: true}},
	}
}

func pathVia(t *testing.T, v *View, p netip.Prefix, source string, neighbor netip.Addr) Route {
	t.Helper()
	for _, rt := range v.Paths(p) {
		if rt.Source == source && rt.Neighbor == neighbor && !rt.LocRIB {
			return rt
		}
	}
	t.Fatalf("no %s path from %s", source, neighbor)
	return Route{}
}

func pathLoc(t *testing.T, v *View, p netip.Prefix) Route {
	t.Helper()
	for _, rt := range v.Paths(p) {
		if rt.LocRIB {
			return rt
		}
	}
	t.Fatal("no loc-rib path")
	return Route{}
}

func hopViaOf(t *testing.T, hops []NextHopCount, nh netip.Addr) string {
	t.Helper()
	for _, h := range hops {
		if h.NextHop == nh {
			return h.Via
		}
	}
	t.Fatalf("next hop %s not counted", nh)
	return ""
}
