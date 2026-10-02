package rib

import (
	"net/netip"
	"testing"
)

func TestSuggestNextHopsReadsOnly(t *testing.T) {
	v, err := New(Options{
		ASN: 64512, RouterID: netip.MustParseAddr("192.0.2.10"),
		Neighbors: []Neighbor{{Address: netip.MustParseAddr("192.0.2.254")}},
		Providers: map[netip.Addr]string{netip.MustParseAddr("192.0.2.1"): "transit-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	configured := netip.MustParseAddr("192.0.2.1")
	discovered := netip.MustParseAddr("192.0.2.9")
	onLAN := netip.MustParseAddr("203.0.113.50")
	pfx := netip.MustParsePrefix("198.51.100.0/24")
	other := netip.MustParsePrefix("203.0.113.0/24")
	nbr := netip.MustParseAddr("192.0.2.254")
	v.adj[pfx] = map[adjKey]Route{
		{neighbor: nbr}:        {Prefix: pfx, NextHop: configured, ASPath: []uint32{64496}},
		{neighbor: nbr, id: 1}: {Prefix: pfx, NextHop: discovered, ASPath: []uint32{64500}},
		{neighbor: nbr, id: 2}: {Prefix: other, NextHop: discovered, ASPath: []uint32{64496}},
		{neighbor: nbr, id: 3}: {Prefix: other, NextHop: discovered, ASPath: []uint32{64496}},
		{neighbor: nbr, id: 4}: {Prefix: pfx, NextHop: onLAN, ASPath: []uint32{64501}},
	}
	bmpPfx := netip.MustParsePrefix("192.0.2.0/24")
	bmpHop := netip.MustParseAddr("198.51.100.9")
	v.bmp[bmpPfx] = map[bmpPathKey]Route{
		{}: {Prefix: bmpPfx, NextHop: bmpHop, ASPath: []uint32{64497}},
	}
	before := v.Generation()
	got := v.SuggestNextHops([]netip.Addr{configured}, []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")})
	if v.Generation() != before || len(v.routes) != 0 || len(v.opt.Providers) != 1 {
		t.Fatalf("suggest changed the view gen=%d routes=%d providers=%d", v.Generation(), len(v.routes), len(v.opt.Providers))
	}
	if len(got) != 2 {
		t.Fatalf("suggestions = %+v", got)
	}
	if got[0].NextHop != discovered || got[0].ASN != 64496 || got[0].Prefixes != 2 {
		t.Fatalf("first = %+v", got[0])
	}
	if got[1].NextHop != bmpHop || got[1].ASN != 64497 || got[1].Prefixes != 1 {
		t.Fatalf("bmp = %+v", got[1])
	}
	for _, c := range got {
		if c.NextHop == configured || c.NextHop == onLAN {
			t.Fatalf("configured or exchange hop suggested: %+v", c)
		}
	}
}

func TestSuggestNextHopsCaps(t *testing.T) {
	v, err := New(Options{
		ASN: 64512, RouterID: netip.MustParseAddr("192.0.2.10"),
		Neighbors: []Neighbor{{Address: netip.MustParseAddr("192.0.2.254")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	nbr := netip.MustParseAddr("192.0.2.254")
	for i := 1; i <= maxSuggestNextHops+1; i++ {
		hop := netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
		pfx := netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), 32)
		v.adj[pfx] = map[adjKey]Route{
			{neighbor: nbr, id: uint32(i)}: {Prefix: pfx, NextHop: hop, ASPath: []uint32{64496}},
		}
	}
	got := v.SuggestNextHops(nil, nil)
	if len(got) != maxSuggestNextHops {
		t.Fatalf("len = %d", len(got))
	}
	if got[0].NextHop != netip.MustParseAddr("192.0.2.1") || got[len(got)-1].NextHop != netip.MustParseAddr("192.0.2.64") {
		t.Fatalf("range %s .. %s", got[0].NextHop, got[len(got)-1].NextHop)
	}
}
