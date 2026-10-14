package netpfx

import (
	"net/netip"
	"slices"
	"testing"
)

func TestSort(t *testing.T) {
	ps := []netip.Prefix{
		netip.MustParsePrefix("10.0.1.0/24"),
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("10.0.0.0/16"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	Sort(ps)
	want := []string{"10.0.0.0/16", "10.0.0.0/24", "10.0.1.0/24", "2001:db8::/32"}
	var got []string
	for _, p := range ps {
		got = append(got, p.String())
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Sort = %v, want %v", got, want)
	}
}

func TestCoveredBy(t *testing.T) {
	list := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	for _, c := range []struct {
		p    string
		want bool
	}{
		{"192.0.2.0/24", true},
		{"192.0.2.128/25", true},
		{"192.0.0.0/16", false},
		{"198.51.100.0/24", false},
	} {
		if got := CoveredBy(list, netip.MustParsePrefix(c.p)); got != c.want {
			t.Errorf("CoveredBy(%s) = %v, want %v", c.p, got, c.want)
		}
	}
}

func TestRelation(t *testing.T) {
	for _, c := range []struct{ q, p, want string }{
		{"198.51.100.0/24", "198.51.100.0/24", RelExact},
		{"198.51.100.0/24", "198.51.0.0/16", RelCovering},
		{"198.51.100.0/24", "198.51.100.128/25", RelMoreSpecific},
		{"198.51.100.0/24", "198.51.101.0/24", ""},
		{"198.51.100.0/24", "198.51.100.0/23", RelCovering},
		{"198.51.100.0/24", "0.0.0.0/0", ""},
		{"198.51.100.7/32", "198.51.100.0/24", RelCovering},
		{"0.0.0.0/0", "198.51.100.0/24", RelMoreSpecific},
		{"2001:db8::/32", "2001:db8:1::/48", RelMoreSpecific},
		{"2001:db8::/32", "198.51.100.0/24", ""},
		{"::/0", "0.0.0.0/0", ""},
	} {
		if got := Relation(netip.MustParsePrefix(c.q), netip.MustParsePrefix(c.p)); got != c.want {
			t.Errorf("Relation(%s, %s) = %q, want %q", c.q, c.p, got, c.want)
		}
	}
}

func TestParseASN(t *testing.T) {
	for _, c := range []struct {
		in   string
		want uint32
		ok   bool
	}{
		{"64496", 64496, true},
		{"AS64496", 64496, true},
		{" as64496 ", 64496, true},
		{"4294967295", 4294967295, true},
		{"0", 0, false},
		{"AS0", 0, false},
		{"4294967296", 0, false},
		{"AS", 0, false},
		{"-1", 0, false},
		{"64496x", 0, false},
	} {
		if got, ok := ParseASN(c.in); got != c.want || ok != c.ok {
			t.Errorf("ParseASN(%q) = %d, %v; want %d, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestLastAS(t *testing.T) {
	if got := LastAS([]uint32{64496, 64497, 64498}); got != 64498 {
		t.Errorf("LastAS = %d", got)
	}
	if got := LastAS(nil); got != 0 {
		t.Errorf("LastAS(nil) = %d", got)
	}
}

func TestMatch(t *testing.T) {
	q := netip.MustParsePrefix("198.51.100.0/24")
	p := netip.MustParsePrefix("198.51.100.128/25")
	other := netip.MustParsePrefix("203.0.113.0/24")
	for _, c := range []struct {
		name    string
		q       netip.Prefix
		asns    []uint32
		p       netip.Prefix
		origins []uint32
		rel     string
		ok      bool
	}{
		{"related prefix", q, nil, p, nil, RelMoreSpecific, true},
		{"related prefix wins over origin", q, []uint32{64496}, q, []uint32{64496}, RelExact, true},
		{"origin only", netip.Prefix{}, []uint32{64496}, other, []uint32{64497, 64496}, "", true},
		{"origin after an unrelated prefix", q, []uint32{64496}, other, []uint32{64496}, "", true},
		{"no match", q, []uint32{64496}, other, []uint32{64497}, "", false},
		{"zero origin never matches", netip.Prefix{}, []uint32{0}, other, []uint32{0}, "", false},
	} {
		rel, ok := Match(c.q, c.asns, c.p, c.origins...)
		if rel != c.rel || ok != c.ok {
			t.Errorf("%s: Match = %q, %v; want %q, %v", c.name, rel, ok, c.rel, c.ok)
		}
	}
}
