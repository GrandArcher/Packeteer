package geoip

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/geoip/geoiptest"
)

func pfx(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestNetworks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.mmdb")
	db := geoiptest.Build(map[string]string{
		"203.0.113.0/26":   "XA",
		"203.0.113.64/26":  "XA",
		"203.0.113.128/25": "XB",
		"198.51.100.0/28":  "XA",
		"2001:db8:1::/48":  "XA",
	})
	if err := os.WriteFile(path, db, 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := d.Networks("XA", true)
	if err != nil {
		t.Fatal(err)
	}
	if want := pfx("198.51.100.0/28", "203.0.113.0/25"); !slices.Equal(got, want) {
		t.Fatalf("XA v4 = %v, want %v", got, want)
	}
	got, _ = d.Networks("XA", false)
	if want := pfx("2001:db8:1::/48"); !slices.Equal(got, want) {
		t.Fatalf("XA v6 = %v, want %v", got, want)
	}
	got, _ = d.Networks("ZZ", true)
	if len(got) != 0 {
		t.Fatalf("ZZ = %v", got)
	}
	if _, err := Open(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file opened")
	}
}

func TestAggregate(t *testing.T) {
	got := Aggregate(pfx("192.0.2.0/26", "192.0.2.64/26", "192.0.2.128/25", "192.0.2.5/32", "198.51.100.1/32", "198.51.100.2/32"))
	want := pfx("192.0.2.0/24", "198.51.100.1/32", "198.51.100.2/32")
	if !slices.Equal(got, want) {
		t.Fatalf("Aggregate = %v, want %v", got, want)
	}
}

func TestValidCountry(t *testing.T) {
	for c, ok := range map[string]bool{"NL": true, "nl": false, "NLD": false, "": false, "X1": false} {
		if ValidCountry(c) != ok {
			t.Errorf("ValidCountry(%q) = %v", c, !ok)
		}
	}
}
