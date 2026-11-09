package rib

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// #156: per member, a prefix is route-server only, bilateral only, or both,
// judged by BMP Adj-RIB-In paths. A path the router merely selected (iBGP,
// Loc-RIB) takes its session type from the next hop, so it must not put
// its prefix in a class.
func TestMemberAvailabilityClasses(t *testing.T) {
	nbr := "192.0.2.254"
	edge := netip.MustParseAddr(nbr)
	member := netip.MustParseAddr("203.0.113.11")
	other := netip.MustParseAddr("203.0.113.12")
	rs := netip.MustParseAddr("203.0.113.1")
	lan := netip.MustParsePrefix("203.0.113.0/24")
	v, err := New(Options{
		ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"),
		Neighbors: []Neighbor{{Address: edge}},
		Providers: map[netip.Addr]string{member: "ix-peer-a", other: "ix-peer-b"},
		PeerASN:   map[string]uint32{"ix-peer-a": 64501, "ix-peer-b": 64502},
		BMP:       map[string]string{"ix-peer-a": BMPPrefer, "ix-peer-b": BMPPrefer},
		LANs:      []netip.Prefix{lan},
	})
	if err != nil {
		t.Fatal(err)
	}
	pfx := func(s string) netip.Prefix { return netip.MustParsePrefix(s) }
	rsOnly, bilOnly, both, ibgpOnly, locOnly := pfx("192.0.2.0/25"), pfx("192.0.2.128/25"), pfx("198.51.100.0/24"), pfx("203.0.113.128/25"), pfx("2001:db8::/32")
	as := []uint32{64501, 64500}

	v.ApplyRIB(bmpMED(edge, rs, rsOnly, member, as, 1, nil))
	v.ApplyRIB(bmpMED(edge, member, bilOnly, member, as, 1, nil))
	v.ApplyRIB(bmpMED(edge, rs, both, member, as, 2, nil))
	v.ApplyRIB(bmpMED(edge, member, both, member, as, 2, nil))
	// The other member only has a bilateral path.
	v.ApplyRIB(bmpMED(edge, other, bilOnly, other, []uint32{64502, 64500}, 3, nil))
	v.mu.Lock()
	if !v.applyPath(medPath(t, 1, nbr, ibgpOnly.String(), member.String(), as, 100, nil)) {
		t.Fatal("iBGP path did not publish")
	}
	v.mu.Unlock()
	v.ApplyRIB(plugin.RIBEvent{
		Kind: plugin.RIBPaths, Router: edge, Peer: plugin.RIBPeer{LocRIB: true},
		Paths: []plugin.RIBPath{{Prefix: locOnly, NextHop: member, ASPath: as}},
	})

	byHop := map[netip.Addr]NextHopCount{}
	for _, h := range v.NextHops([]netip.Prefix{lan}) {
		byHop[h.NextHop] = h
	}
	a := byHop[member]
	if a.RouteServerOnly != 1 || a.BilateralOnly != 1 || a.Both != 1 || a.Prefixes != 5 {
		t.Fatalf("member counts = %+v, want 1/1/1 of 5 prefixes (iBGP and Loc-RIB only prefixes are unclassified)", a)
	}
	if b := byHop[other]; b.RouteServerOnly != 0 || b.BilateralOnly != 1 || b.Both != 0 {
		t.Fatalf("other member counts = %+v", b)
	}

	for class, want := range map[string]netip.Prefix{AvailRouteServerOnly: rsOnly, AvailBilateralOnly: bilOnly, AvailBoth: both} {
		got, total := v.MemberPrefixes(member, class, 10)
		if total != 1 || !slices.Equal(got, []netip.Prefix{want}) {
			t.Errorf("%s = %v of %d, want [%v]", class, got, total, want)
		}
	}
	if got, total := v.MemberPrefixes(other, AvailBilateralOnly, 10); total != 1 || !slices.Equal(got, []netip.Prefix{bilOnly}) {
		t.Errorf("other bilateral = %v of %d", got, total)
	}

	// The route server withdraws the shared prefix: it becomes bilateral only.
	v.ApplyRIB(bmpWithdraw(edge, rs, both, 2))
	got, total := v.MemberPrefixes(member, AvailBilateralOnly, 10)
	if total != 2 || !slices.Equal(got, []netip.Prefix{bilOnly, both}) {
		t.Errorf("bilateral only after the route server withdrew = %v of %d", got, total)
	}
	// limit cuts the list and keeps the full count.
	if got, total := v.MemberPrefixes(member, AvailBilateralOnly, 1); total != 2 || len(got) != 1 {
		t.Errorf("limit 1 = %v of %d", got, total)
	}
}
