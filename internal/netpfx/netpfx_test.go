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
