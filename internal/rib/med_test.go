package rib

import (
	"net/netip"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/protobuf/types/known/anypb"
)

func medPath(t *testing.T, id uint32, neighbor, prefix, nexthop string, as []uint32, lp uint32, med *uint32) *api.Path {
	t.Helper()
	p := idPath(t, id, prefix, nexthop, as)
	p.NeighborIp = neighbor
	if lp != 0 {
		a, err := anypb.New(&api.LocalPrefAttribute{LocalPref: lp})
		if err != nil {
			t.Fatal(err)
		}
		p.Pattrs = append(p.Pattrs, a)
	}
	if med != nil {
		a, err := anypb.New(&api.MultiExitDiscAttribute{Med: *med})
		if err != nil {
			t.Fatal(err)
		}
		p.Pattrs = append(p.Pattrs, a)
	}
	return p
}

func TestMEDIsDisplayOnly(t *testing.T) {
	nbr := "192.0.2.254"
	v, err := New(Options{
		ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"),
		Neighbors: []Neighbor{{Address: netip.MustParseAddr(nbr)}},
		Providers: map[netip.Addr]string{
			netip.MustParseAddr("192.0.2.1"):    "transit-a",
			netip.MustParseAddr("192.0.2.2"):    "transit-a",
			netip.MustParseAddr("203.0.113.11"): "ix-rs",
		},
		PeerASN: map[string]uint32{"ix-rs": 64501},
		BMP:     map[string]string{"transit-a": BMPPrefer, "ix-rs": BMPPrefer},
		LANs:    []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
	})
	if err != nil {
		t.Fatal(err)
	}
	pfx := "198.51.100.0/24"
	p := netip.MustParsePrefix(pfx)
	high, low := uint32(500), uint32(0)
	// The lower MED is the BGP-preferred one. Selection must ignore it:
	// higher local preference wins, then the shorter AS path.
	v.mu.Lock()
	if !v.applyPath(medPath(t, 1, nbr, pfx, "192.0.2.1", []uint32{64496, 64500}, 200, &high)) {
		t.Fatal("high local-pref path did not publish")
	}
	v.applyPath(medPath(t, 2, nbr, pfx, "192.0.2.2", []uint32{64496, 64497, 64500}, 100, &low))
	v.mu.Unlock()

	best, ok := v.Exact(p)
	if !ok || best.NextHop.String() != "192.0.2.1" || best.MED == nil || *best.MED != 500 {
		t.Fatalf("selected = %+v %v", best, ok)
	}
	if best.MEDFrom != "iBGP 192.0.2.254, transit-a" || best.Via != ViaUnknown {
		t.Fatalf("med label = %q via = %q", best.MEDFrom, best.Via)
	}
	paths := v.Paths(p)
	if len(paths) != 2 {
		t.Fatalf("paths = %d", len(paths))
	}
	var inactive Route
	for _, rt := range paths {
		if rt.PathID == 2 {
			inactive = rt
		}
	}
	if inactive.MED == nil || *inactive.MED != 0 || inactive.NextHop.String() != "192.0.2.2" {
		t.Fatalf("inactive MED 0 path = %+v", inactive)
	}

	// A route-server MED stays on the inactive BMP path. The neighbor
	// (203.0.113.1) is on the exchange LAN and is not the member next
	// hop, so the label names that neighbor, not the member (ix-rs).
	// It must not replace the iBGP exit.
	rsMED := uint32(40)
	v.ApplyRIB(plugin.RIBEvent{
		Kind:       plugin.RIBPaths,
		Router:     netip.MustParseAddr(nbr),
		Peer:       plugin.RIBPeer{Address: netip.MustParseAddr("203.0.113.1"), ASN: 64498},
		PostPolicy: true,
		Paths: []plugin.RIBPath{{
			Prefix: p, NextHop: netip.MustParseAddr("203.0.113.11"),
			ASPath: []uint32{64501, 64500}, PathID: 7, MED: &rsMED,
		}},
	})
	best, _ = v.Exact(p)
	if best.NextHop.String() != "192.0.2.1" {
		t.Fatalf("route server MED changed the exit to %s", best.NextHop)
	}
	var rs Route
	for _, rt := range v.Paths(p) {
		if rt.Source == SourceBMP {
			rs = rt
		}
	}
	if rs.MED == nil || *rs.MED != 40 || rs.Via != ViaRouteServer ||
		rs.MEDFrom != "peer 203.0.113.1, route server 203.0.113.1" {
		t.Fatalf("route server path = %+v", rs)
	}
	none := medPath(t, 3, nbr, "203.0.113.0/24", "192.0.2.1", []uint32{64496}, 100, nil)
	v.mu.Lock()
	v.applyPath(none)
	v.mu.Unlock()
	got, ok := v.Exact(netip.MustParsePrefix("203.0.113.0/24"))
	if !ok || got.MED != nil || got.MEDFrom != "" || got.Via != ViaUnknown {
		t.Fatalf("absent MED = %+v %q via %q", got.MED, got.MEDFrom, got.Via)
	}
}
