package rib

import (
	"net/netip"
	"testing"

	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestApplyPathIgnoresLargeOwnCommunity(t *testing.T) {
	nbr := netip.MustParseAddr("192.0.2.1")
	nh := netip.MustParseAddr("192.0.2.2")
	v, err := New(Options{
		ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"),
		Neighbors: []Neighbor{{Address: nbr}},
		Providers: map[netip.Addr]string{nh: "transit-b"},
		OwnLarge:  "4200000000:1:666",
	})
	if err != nil {
		t.Fatal(err)
	}
	own := netip.MustParsePrefix("203.0.113.0/24")
	p := path(t, own.String(), nh.String())
	p.NeighborIp = nbr.String()
	lc, err := anypb.New(&api.LargeCommunitiesAttribute{Communities: []*api.LargeCommunity{{
		GlobalAdmin: 4200000000, LocalData1: 1, LocalData2: 666,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	p.Pattrs = append(p.Pattrs, lc)
	v.mu.Lock()
	if v.applyPath(p) {
		v.mu.Unlock()
		t.Fatal("own large community changed the view")
	}
	v.mu.Unlock()
	if _, ok := v.Exact(own); ok {
		t.Fatal("large own community made the prefix learned")
	}

	otherPfx := netip.MustParsePrefix("198.51.100.0/24")
	other := path(t, otherPfx.String(), nh.String())
	other.NeighborIp = nbr.String()
	otherLC, err := anypb.New(&api.LargeCommunitiesAttribute{Communities: []*api.LargeCommunity{{
		GlobalAdmin: 4200000000, LocalData1: 1, LocalData2: 1,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	other.Pattrs = append(other.Pattrs, otherLC)
	v.mu.Lock()
	changed := v.applyPath(other)
	v.mu.Unlock()
	if !changed {
		t.Fatal("a different large community was ignored")
	}
	rt, ok := v.Exact(otherPfx)
	if !ok || rt.Provider != "transit-b" {
		t.Fatalf("learned = %+v ok=%v", rt, ok)
	}
}
