package rib

import (
	"net/netip"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// #158: per next hop, prefixes are counted by the RFC 6811 state of their
// paths' origins.
func TestNextHopsRPKICounts(t *testing.T) {
	edge := netip.MustParseAddr("192.0.2.254")
	member := netip.MustParseAddr("203.0.113.11")
	lan := netip.MustParsePrefix("203.0.113.0/24")
	v, err := New(Options{
		ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"),
		Neighbors: []Neighbor{{Address: edge}},
		Providers: map[netip.Addr]string{member: "ix-peer-a"},
		PeerASN:   map[string]uint32{"ix-peer-a": 64501},
		BMP:       map[string]string{"ix-peer-a": BMPPrefer},
		LANs:      []netip.Prefix{lan},
	})
	if err != nil {
		t.Fatal(err)
	}
	valid := netip.MustParsePrefix("198.51.100.0/24")
	invalid := netip.MustParsePrefix("203.0.113.0/24")
	notFound := netip.MustParsePrefix("192.0.2.0/24")
	v.ApplyRIB(bmpMED(edge, member, valid, member, []uint32{64501, 64500}, 1, nil))
	v.ApplyRIB(bmpMED(edge, member, invalid, member, []uint32{64501, 64599}, 2, nil))
	v.ApplyRIB(bmpMED(edge, member, notFound, member, []uint32{64501, 64555}, 3, nil))

	validate := func(p netip.Prefix, origin uint32) plugin.RPKIValidity {
		switch {
		case p == valid && origin == 64500:
			return plugin.RPKIValid
		case p == invalid && origin == 64599:
			return plugin.RPKIInvalid
		}
		return plugin.RPKINotFound
	}
	hops := v.NextHopsRPKI([]netip.Prefix{lan}, validate)
	if len(hops) != 1 {
		t.Fatalf("hops = %+v", hops)
	}
	r := hops[0].RPKI
	if r == nil || r.Valid != 1 || r.Invalid != 1 || r.NotFound != 1 || r.Unknown != 0 {
		t.Fatalf("rpki counts = %+v", r)
	}

	// Without a validator the counts are absent, not zeroes.
	plain := v.NextHopsRPKI([]netip.Prefix{lan}, nil)
	if plain[0].RPKI != nil {
		t.Fatalf("nil validator still counted: %+v", plain[0].RPKI)
	}
}

// Two paths for one prefix through one next hop count once, at the most
// severe state.
func TestNextHopsRPKISamePrefixSeverity(t *testing.T) {
	edge := netip.MustParseAddr("192.0.2.254")
	member := netip.MustParseAddr("203.0.113.11")
	lan := netip.MustParsePrefix("203.0.113.0/24")
	v, err := New(Options{
		ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"),
		Neighbors: []Neighbor{{Address: edge}},
		Providers: map[netip.Addr]string{member: "ix-peer-a"},
		PeerASN:   map[string]uint32{"ix-peer-a": 64501},
		BMP:       map[string]string{"ix-peer-a": BMPPrefer},
		LANs:      []netip.Prefix{lan},
	})
	if err != nil {
		t.Fatal(err)
	}
	p := netip.MustParsePrefix("198.51.100.0/24")
	// Two add-path paths for the same prefix, one valid and one invalid.
	v.ApplyRIB(bmpMED(edge, member, p, member, []uint32{64501, 64500}, 1, nil))
	v.ApplyRIB(bmpMED(edge, member, p, member, []uint32{64501, 64599}, 2, nil))
	validate := func(_ netip.Prefix, origin uint32) plugin.RPKIValidity {
		if origin == 64500 {
			return plugin.RPKIValid
		}
		return plugin.RPKIInvalid
	}
	hops := v.NextHopsRPKI([]netip.Prefix{lan}, validate)
	if len(hops) != 1 {
		t.Fatalf("hops = %+v", hops)
	}
	r := hops[0].RPKI
	if r == nil || r.Invalid != 1 || r.Valid != 0 || r.NotFound != 0 || r.Unknown != 0 {
		t.Fatalf("rpki counts = %+v", r)
	}
}
