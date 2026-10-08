package exchange

import (
	"net/netip"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestLANPrefixRelations(t *testing.T) {
	v4 := netip.MustParsePrefix("203.0.113.0/24")
	v6 := netip.MustParsePrefix("2001:db8:ffff::/64")
	lans := []netip.Prefix{v4, v6}

	if !PrefixInside(lans, v4) || !PrefixInside(lans, netip.MustParsePrefix("203.0.113.128/25")) {
		t.Fatal("equal and more-specific prefixes are inside the LAN")
	}
	wide := netip.MustParsePrefix("203.0.112.0/22")
	if PrefixInside(lans, wide) || PrefixInside(lans, netip.MustParsePrefix("198.51.100.0/24")) {
		t.Fatal("a wider or disjoint prefix is not inside the LAN")
	}
	if !Overlaps(wide, v4) || !Overlaps(v4, netip.MustParsePrefix("203.0.113.0/25")) || !Overlaps(v4, v4) {
		t.Fatal("overlap includes contains, inside, and equal")
	}
	if Overlaps(v4, netip.MustParsePrefix("203.0.112.0/24")) || Overlaps(v4, v6) {
		t.Fatal("adjacent prefixes and mixed families do not overlap")
	}
	if got, ok := Covering(lans, netip.MustParseAddr("2001:db8:ffff::5")); !ok || got != v6 {
		t.Fatalf("covering = %s ok=%v", got, ok)
	}
	if _, ok := Covering(lans, netip.MustParseAddr("198.51.100.1")); ok {
		t.Fatal("customer address has no covering LAN")
	}
}

func TestFilterTargets(t *testing.T) {
	lans := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8:ffff::/64"),
	}
	before := LANDrops()
	in := []plugin.Target{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Host: netip.MustParseAddr("198.51.100.10")},
		{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Host: netip.MustParseAddr("203.0.113.10")},
		{Prefix: netip.MustParsePrefix("203.0.113.128/25")},
		{Prefix: netip.MustParsePrefix("203.0.112.0/22"), Host: netip.MustParseAddr("203.0.113.9")},
		{Prefix: netip.MustParsePrefix("203.0.112.0/23"), Host: netip.MustParseAddr("203.0.112.9"), Candidate: true},
		{Prefix: netip.MustParsePrefix("198.51.100.0/25"), Host: netip.MustParseAddr("203.0.113.8"), Candidate: true},
		{Prefix: netip.MustParsePrefix("2001:db8:ffff::/64")},
		{Prefix: netip.MustParsePrefix("2001:db8:1::/48")},
	}
	// The candidate whose host is not inside its prefix is still cleared
	// when the host is on the LAN: that address must not be probed.
	// 198.51.100.0/25 does not contain 203.0.113.8; the filter still
	// refuses the LAN address.
	got := FilterTargets(lans, in)
	if LANDrops()-before != 5 {
		t.Fatalf("drops = %d, want 5", LANDrops()-before)
	}
	want := []string{"198.51.100.0/24", "203.0.112.0/23", "198.51.100.0/25", "2001:db8:1::/48"}
	if len(got) != len(want) {
		t.Fatalf("targets = %+v", got)
	}
	for i, p := range want {
		if got[i].Prefix.String() != p {
			t.Fatalf("target %d = %s, want %s", i, got[i].Prefix, p)
		}
	}
	if !got[0].Host.IsValid() || got[0].Host.String() != "198.51.100.10" {
		t.Fatalf("customer host = %s", got[0].Host)
	}
	if got[2].Host.IsValid() || got[2].Candidate {
		t.Fatalf("LAN candidate was kept: %+v", got[2])
	}
	// The input slice is not rewritten.
	if in[1].Prefix.String() != "203.0.113.0/24" {
		t.Fatal("filter mutated its input")
	}
	if again := FilterTargets(nil, in); len(again) != len(in) {
		t.Fatal("no LANs must keep every target")
	}
}

func TestFilterNormalizedKeepsRepresentativeHost(t *testing.T) {
	lans := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	before := LANDrops()
	in := []plugin.Target{
		{Prefix: netip.MustParsePrefix("203.0.112.0/22"), Host: netip.MustParseAddr("203.0.112.1")},
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Host: netip.MustParseAddr("203.0.113.10"), Pinned: true},
		{Prefix: netip.MustParsePrefix("198.51.100.0/25"), Host: netip.MustParseAddr("203.0.113.10"), Candidate: true},
		{Prefix: netip.MustParsePrefix("203.0.113.0/25"), Host: netip.MustParseAddr("203.0.113.1")},
	}
	got := FilterNormalized(lans, in)
	if LANDrops()-before != 3 {
		t.Fatalf("drops = %d, want 3", LANDrops()-before)
	}
	if len(got) != 2 || got[0].Prefix.String() != "203.0.112.0/22" || got[0].Host.String() != "203.0.112.1" {
		t.Fatalf("representative = %+v", got)
	}
	if got[1].Candidate || got[1].Prefix.String() != "198.51.100.0/25" || got[1].Host.String() != "203.0.113.10" {
		t.Fatalf("candidate = %+v", got[1])
	}
}
