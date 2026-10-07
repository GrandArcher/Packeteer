package exchange

import (
	"net/netip"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/rib"
)

func TestBuild(t *testing.T) {
	a := netip.MustParseAddr
	exs := []Exchange{{
		Name: "ix-lab",
		LANs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		Peers: []Peer{
			{Name: "ix-peer-a", ASN: 64501, NextHop: a("203.0.113.11")},
			{Name: "ix-peer-b", ASN: 64502, NextHop: a("203.0.113.12")},
			{Name: "ix-peer-c", ASN: 64504, NextHop: a("203.0.113.14")},
		},
	}}
	hops := []rib.NextHopCount{
		{NextHop: a("192.0.2.21"), Prefixes: 900, ASN: 64496}, // a transit, not on the LAN
		{NextHop: a("203.0.113.11"), Prefixes: 12, ASN: 64501, Via: rib.ViaBilateral},
		{NextHop: a("203.0.113.12"), Prefixes: 3, ASN: 64599, Via: rib.ViaRouteServer},
		{NextHop: a("203.0.113.13"), Prefixes: 5, ASN: 64503, Via: rib.ViaUnknown},
		{NextHop: a("203.0.113.15"), Prefixes: 5, ASN: 64505},
	}
	got := Build(exs, hops, map[string]bool{"ix-peer-a": true}, map[string]int{"ix-peer-a": 2, "transit-a": 7})
	if len(got) != 1 {
		t.Fatalf("stats = %+v", got)
	}
	st := got[0]
	if st.Prefixes != 25 || st.Improvements != 2 || len(st.Peers) != 3 {
		t.Fatalf("totals = %+v", st)
	}
	pa, pb, pc := st.Peers[0], st.Peers[1], st.Peers[2]
	if pa.Prefixes != 12 || !pa.Up || pa.Improvements != 2 || pa.ObservedASN != 0 || pa.Via != rib.ViaBilateral {
		t.Fatalf("peer a = %+v", pa)
	}
	if pb.ObservedASN != 64599 || pb.Up || pb.Via != rib.ViaRouteServer {
		t.Fatalf("peer b (wrong AS) = %+v", pb)
	}
	if pc.Prefixes != 0 || pc.ObservedASN != 0 || pc.Via != rib.ViaUnknown {
		t.Fatalf("peer c (silent) = %+v", pc)
	}
	if len(st.Discovered) != 2 || st.Discovered[0].NextHop != "203.0.113.13" || st.Discovered[0].ASN != 64503 || st.Discovered[1].NextHop != "203.0.113.15" {
		t.Fatalf("discovered = %+v", st.Discovered)
	}
	if l := LANs(exs); len(l) != 1 {
		t.Fatalf("lans = %v", l)
	}
	if got := Build(nil, hops, nil, nil); len(got) != 0 {
		t.Fatalf("no exchanges = %+v", got)
	}
}
