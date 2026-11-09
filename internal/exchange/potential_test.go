package exchange

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func potentialInput() PotentialInput {
	origin := map[string]uint32{
		"198.51.100.0/25":   64510, // route server member
		"198.51.100.128/25": 64510,
		"192.0.2.0/24":      64511, // bilateral peer
		"203.0.113.0/24":    64512, // discovered, session type unknown
		"2001:db8:1::/48":   64513, // not at an exchange
		"2001:db8:2::/48":   64512,
		"192.0.2.128/25":    64496, // the local AS
	}
	onLAN := map[string]bool{"198.51.100.0/25": true, "192.0.2.0/24": true}
	return PotentialInput{
		Volumes: []plugin.PrefixVolume{
			vol("198.51.100.0/25", 80),
			vol("198.51.100.128/25", 40),
			vol("192.0.2.0/24", 300),
			vol("203.0.113.0/24", 20),
			vol("2001:db8:1::/48", 900),
			vol("2001:db8:2::/48", 10),
			vol("192.0.2.128/25", 5000),
			vol("10.0.0.0/8", 700), // no covering route
			vol("198.51.100.0/24", 0),
		},
		Origin: func(p netip.Prefix) (uint32, bool) {
			asn, ok := origin[p.String()]
			return asn, ok && asn != 64496
		},
		OnLAN: func(p netip.Prefix) bool { return onLAN[p.String()] },
		Exchanges: []Stats{
			{Name: "ix-lab", Peers: []PeerStats{
				{Name: "ix-peer-a", ASN: 64510, NextHop: "203.0.113.11", Via: "route_server"},
				{Name: "ix-peer-b", ASN: 64511, NextHop: "203.0.113.12", Via: "bilateral"},
			}, Discovered: []Discovered{
				{NextHop: "203.0.113.13", ASN: 64512, Via: "unknown"},
				{NextHop: "203.0.113.14", Via: "unknown"},
			}},
			{Name: "ix-two", Discovered: []Discovered{{NextHop: "198.51.100.77", ASN: 64510, Via: "bilateral"}}},
		},
	}
}

// #154: ASNs are ranked by bytes and each is joined with the members that
// carry its AS and the prefixes that already have a path on a LAN.
func TestPotentialPeersRanksAndClassifies(t *testing.T) {
	got := BuildPotentialPeers(potentialInput(), "", 100)
	want := []struct {
		asn      uint32
		class    string
		prefixes int
		lan      int
		members  int
	}{
		{64513, ClassAbsent, 1, 0, 0},
		{64511, ClassBilateral, 1, 1, 1},
		{64510, ClassRouteServer, 2, 1, 2},
		{64512, ClassUnknown, 2, 0, 1},
	}
	if len(got.Rows) != len(want) || got.ASNs != 4 {
		t.Fatalf("rows = %+v", got)
	}
	for i, w := range want {
		r := got.Rows[i]
		if r.ASN != w.asn || r.Class != w.class || r.Prefixes != w.prefixes || r.LANPrefixes != w.lan || len(r.Members) != w.members {
			t.Errorf("row %d = %+v, want %+v", i, r, w)
		}
	}
	rs := got.Rows[2]
	if rs.Mbps != 120 || rs.LANBytes != vol("198.51.100.0/25", 80).Bytes || rs.Bytes != rs.LANBytes+vol("198.51.100.128/25", 40).Bytes {
		t.Errorf("route server row bytes = %+v", rs)
	}
	if rs.Members[0].Peer != "ix-peer-a" || rs.Members[1].Exchange != "ix-two" || rs.Members[1].Peer != "" {
		t.Errorf("members = %+v", rs.Members)
	}
	// 10.0.0.0/8 has no covering route and the local AS is not a destination.
	if got.UnattributedBytes != vol("10.0.0.0/8", 700).Bytes+vol("192.0.2.128/25", 5000).Bytes {
		t.Errorf("unattributed = %d", got.UnattributedBytes)
	}
	if c := got.Classes[ClassRouteServer]; c.ASNs != 1 || c.Bytes != rs.Bytes {
		t.Errorf("classes = %+v", got.Classes)
	}
}

func TestPotentialPeersClassFilterAndLimit(t *testing.T) {
	got := BuildPotentialPeers(potentialInput(), ClassUnknown, 100)
	if got.ASNs != 1 || len(got.Rows) != 1 || got.Rows[0].ASN != 64512 || got.Bytes != got.Rows[0].Bytes {
		t.Fatalf("unknown = %+v", got)
	}
	if len(got.Classes) != 4 {
		t.Errorf("classes should cover every class: %+v", got.Classes)
	}
	cut := BuildPotentialPeers(potentialInput(), "", 2)
	if !cut.Truncated || len(cut.Rows) != 2 || cut.ASNs != 4 || cut.Rows[0].ASN != 64513 {
		t.Errorf("cut = %+v", cut)
	}
	none := BuildPotentialPeers(PotentialInput{}, ClassBilateral, 10)
	if none.Rows == nil || len(none.Rows) != 0 || none.Truncated {
		t.Errorf("empty = %+v", none)
	}
}

// A route server beats a bilateral session of the same AS, and a bilateral
// one beats an unknown type.
func TestPotentialClassPrecedence(t *testing.T) {
	m := func(via string) MemberRef { return MemberRef{Via: via} }
	for _, c := range []struct {
		members []MemberRef
		want    string
	}{
		{nil, ClassAbsent},
		{[]MemberRef{m("unknown"), m("bilateral")}, ClassBilateral},
		{[]MemberRef{m("bilateral"), m("route_server")}, ClassRouteServer},
		{[]MemberRef{m("unknown")}, ClassUnknown},
	} {
		if got := classOf(c.members); got != c.want {
			t.Errorf("classOf(%+v) = %q, want %q", c.members, got, c.want)
		}
	}
}

func TestPotentialPeersCSV(t *testing.T) {
	var b strings.Builder
	if err := BuildPotentialPeers(potentialInput(), ClassRouteServer, 10).WriteCSV(&b); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 2 || lines[0] != "asn,class,bytes,mbps,prefixes,lan_prefixes,lan_bytes,members" ||
		lines[1] != "AS64510,route_server,150000000,120.00,2,1,100000000,ix-lab/ix-peer-a ix-two/198.51.100.77" {
		t.Errorf("csv = %q", b.String())
	}
}

func TestValidPotentialClass(t *testing.T) {
	for _, c := range []string{ClassRouteServer, ClassBilateral, ClassUnknown, ClassAbsent} {
		if !ValidPotentialClass(c) {
			t.Errorf("%q invalid", c)
		}
	}
	if ValidPotentialClass("") || ValidPotentialClass("both") {
		t.Error("accepted a bad class")
	}
}
