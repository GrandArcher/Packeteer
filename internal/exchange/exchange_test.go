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
	got := Build(exs, hops, map[string]bool{"ix-peer-a": true}, map[string][]Move{"ix-peer-a": {{Prefix: "192.0.2.0/24", VolumeMbps: 40.5}, {Prefix: "198.51.100.0/24"}}, "transit-a": {{Prefix: "203.0.113.0/25"}}})
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
	if pa.MovedMbps != 40.5 || len(pa.Moves) != 2 || pa.Moves[0].Prefix != "192.0.2.0/24" || pa.Moves[0].VolumeMbps != 40.5 || pa.Moves[1].VolumeMbps != 0 {
		t.Fatalf("peer a moves = %+v", pa)
	}
	// Another provider's improvements are not counted, and a peer with none
	// has an empty list, not null.
	if pb.Moves == nil || len(pb.Moves) != 0 || pb.MovedMbps != 0 {
		t.Fatalf("peer b moves = %+v", pb)
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

// #156: a member whose route server feed lacks prefixes it sends
// bilaterally is flagged; a member with no bilateral-only prefix is not.
func TestAvailabilityFlags(t *testing.T) {
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
		{NextHop: a("203.0.113.11"), Prefixes: 10, RouteServerOnly: 2, BilateralOnly: 3, Both: 5},
		{NextHop: a("203.0.113.12"), Prefixes: 4, BilateralOnly: 4},
		{NextHop: a("203.0.113.13"), Prefixes: 6, RouteServerOnly: 6},
		{NextHop: a("203.0.113.14"), Prefixes: 3, Both: 3},
	}
	st := Build(exs, hops, nil, nil)[0]
	pa, pb, pc := st.Peers[0], st.Peers[1], st.Peers[2]
	if pa.Availability != (Availability{RouteServerOnly: 2, BilateralOnly: 3, Both: 5, Flag: FlagRSPartial}) {
		t.Errorf("peer a = %+v", pa.Availability)
	}
	if pb.Availability.Flag != FlagRSMissing || pb.Availability.BilateralOnly != 4 {
		t.Errorf("peer b (bilateral only, the exchange has a route server) = %+v", pb.Availability)
	}
	if pc.Availability.Flag != "" {
		t.Errorf("peer c (everything on both) = %+v", pc.Availability)
	}
	if len(st.Discovered) != 1 || st.Discovered[0].NextHop != "203.0.113.13" || st.Discovered[0].Prefixes != 6 {
		t.Errorf("discovered = %+v", st.Discovered)
	}

	// With no route server path anywhere, a bilateral-only member is not
	// flagged: the exchange may have no route server in view.
	noRS := Build(exs, []rib.NextHopCount{{NextHop: a("203.0.113.12"), Prefixes: 4, BilateralOnly: 4}}, nil, nil)[0]
	if f := noRS.Peers[1].Availability.Flag; f != "" {
		t.Errorf("flag with no route server in view = %q", f)
	}
}

// #156: the flags are decided per exchange. The same next hop on two
// exchanges is flagged only where the exchange shows route server paths
// for another member.
func TestAvailabilityFlagsPerExchange(t *testing.T) {
	a := netip.MustParseAddr
	member := Peer{Name: "ix-peer-a", ASN: 64501, NextHop: a("203.0.113.11")}
	exs := []Exchange{
		{Name: "ix-wide", LANs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, Peers: []Peer{member, {Name: "ix-peer-rs", ASN: 64502, NextHop: a("203.0.113.200")}}},
		{Name: "ix-narrow", LANs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/25")}, Peers: []Peer{member}},
	}
	hops := []rib.NextHopCount{
		{NextHop: a("203.0.113.11"), Prefixes: 4, BilateralOnly: 4},
		{NextHop: a("203.0.113.200"), Prefixes: 5, RouteServerOnly: 5},
	}
	got := Build(exs, hops, nil, nil)
	if f := got[0].Peers[0].Availability.Flag; f != FlagRSMissing {
		t.Errorf("ix-wide flag = %q, want %q", f, FlagRSMissing)
	}
	if f := got[1].Peers[0].Availability.Flag; f != "" {
		t.Errorf("ix-narrow flag = %q, want none (no route server path on that exchange)", f)
	}
	if got[1].Prefixes != 4 {
		t.Errorf("ix-narrow prefixes = %d, want 4 (a next hop outside its LAN is not counted)", got[1].Prefixes)
	}
}
