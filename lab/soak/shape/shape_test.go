package shape

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

// The checked-in file is statistics only: no field can carry a prefix or an
// AS number, and nothing in it looks like one.
func TestShapeFileHasNoPrefixOrASN(t *testing.T) {
	raw, err := os.ReadFile("shape.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(raw); err != nil {
		t.Fatalf("shape.json: %v", err)
	}
	for name, re := range map[string]*regexp.Regexp{
		"dotted address": regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`),
		"IPv6 address":   regexp.MustCompile(`(?i)[0-9a-f]*:[0-9a-f]*:`),
		"CIDR":           regexp.MustCompile(`\d/\d`),
		"AS number":      regexp.MustCompile(`(?i)\bAS ?\d`),
	} {
		if re.Match(raw) {
			t.Errorf("shape.json holds a %s", name)
		}
	}
	// Every number in a histogram key is a small count (a length, a hop
	// count), never an AS number, and the schema has no free-form field.
	var keys = regexp.MustCompile(`"(\d+)": \d+`)
	for _, m := range keys.FindAllStringSubmatch(string(raw), -1) {
		if len(m[1]) > 3 {
			t.Errorf("histogram key %s is too large to be a length or a count", m[1])
		}
	}
	for _, unknown := range []string{`"peer"`, `"asn"`, `"prefix"`, `"origin_as"`} {
		if strings.Contains(string(raw), unknown) {
			t.Errorf("shape.json has a %s field", unknown)
		}
	}
}

func TestShapeIsAFullTable(t *testing.T) {
	s := Default()
	if s.Routes < 900000 || s.IPv4.Prefixes < 500000 || s.IPv6.Prefixes < 100000 {
		t.Fatalf("not a full table: %d routes, %d IPv4, %d IPv6", s.Routes, s.IPv4.Prefixes, s.IPv6.Prefixes)
	}
	if got := s.SetsPerMillion(); got < 50000 || got > 1000000 {
		t.Fatalf("%.0f attribute sets per million routes", got)
	}
}

func TestParseRejects(t *testing.T) {
	good, err := os.ReadFile("shape.json")
	if err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(string) string{
		"unknown field":    func(s string) string { return strings.Replace(s, `"peers"`, `"peer_asn": 64496, "peers"`, 1) },
		"address in label": func(s string) string { return strings.Replace(s, `"RIPE RIS rrc00 bview"`, `"192.0.2.1"`, 1) },
		"routes mismatch":  func(s string) string { return strings.Replace(s, `"routes":`, `"routes": 1+`, 1) },
		"no peers":         func(s string) string { return strings.Replace(s, `"peers": 3`, `"peers": 0`, 1) },
	} {
		if _, err := Parse([]byte(mod(string(good)))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDistPickIsWeighted(t *testing.T) {
	d := NewDist(map[int]int{1: 1, 5: 3})
	var lo, hi uint64
	hi = ^uint64(0)
	if got := d.Pick(lo); got != 1 {
		t.Fatalf("lowest draw picks %d, want 1", got)
	}
	if got := d.Pick(hi); got != 5 {
		t.Fatalf("highest draw picks %d, want 5", got)
	}
	// A quarter of the range is the first bin.
	if d.Pick(hi/4-1) != 1 || d.Pick(hi/4+hi/100) != 5 {
		t.Fatal("bin edge is not at the first count's share")
	}
}

func route(t *testing.T, path []uint32, origin uint8, comms []uint32, large int, med bool) []bgp.PathAttributeInterface {
	t.Helper()
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(origin),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, path)}),
	}
	if len(comms) > 0 {
		attrs = append(attrs, bgp.NewPathAttributeCommunities(comms))
	}
	if large > 0 {
		var lc []*bgp.LargeCommunity
		for i := range large {
			lc = append(lc, bgp.NewLargeCommunity(64496, uint32(i), 1))
		}
		attrs = append(attrs, bgp.NewPathAttributeLargeCommunities(lc))
	}
	if med {
		attrs = append(attrs, bgp.NewPathAttributeMultiExitDisc(10))
	}
	return attrs
}

func TestAccumulatorCounts(t *testing.T) {
	a := NewAccumulator()
	a.Add(false, 24, route(t, []uint32{64496, 64497}, 0, []uint32{64496<<16 | 1}, 0, false))
	a.Add(false, 24, route(t, []uint32{64496, 64497}, 0, []uint32{64496<<16 | 1}, 0, false)) // same set
	a.Add(true, 48, route(t, []uint32{64498}, 2, nil, 2, true))
	long := make([]uint32, MaxASPath+10)
	a.Add(true, 32, route(t, long, 1, make([]uint32, MaxCommunities+5), MaxLargeCommunities+3, false))
	s := a.Shape()
	eq := func(name string, got, want int) {
		t.Helper()
		if got != want {
			t.Errorf("%s = %d, want %d", name, got, want)
		}
	}
	eq("routes", s.Routes, 4)
	eq("ipv4", s.IPv4.Length[24], 2)
	eq("ipv6 /48", s.IPv6.Length[48], 1)
	eq("ipv6 /32", s.IPv6.Length[32], 1)
	eq("path 2", s.ASPathLength[2], 2)
	eq("path 1", s.ASPathLength[1], 1)
	eq("path folded at cap", s.ASPathLength[MaxASPath], 1)
	eq("one community", s.Communities[1], 2)
	eq("communities folded at cap", s.Communities[MaxCommunities], 1)
	eq("two large", s.LargeCommunities[2], 1)
	eq("large folded at cap", s.LargeCommunities[MaxLargeCommunities], 1)
	eq("origin incomplete", s.Origin[2], 1)
	eq("origin EGP", s.Origin[1], 1)
	eq("med", s.MEDRoutes, 1)
	eq("distinct sets", s.AttributeSets, 3)
}

func TestPoolAddsPeers(t *testing.T) {
	one := func(v6 bool, plen int) Shape {
		a := NewAccumulator()
		a.Add(v6, plen, route(t, []uint32{64496}, 0, nil, 0, false))
		s := a.Shape()
		s.Peers = 1
		return s
	}
	p := Pool("test", "2026-01-01", []Shape{one(false, 24), one(true, 48)})
	if p.Peers != 2 || p.Routes != 2 || p.IPv4.Length[24] != 1 || p.IPv6.Length[48] != 1 ||
		p.ASPathLength[1] != 2 || p.AttributeSets != 2 {
		t.Fatalf("pool %+v", p)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}
