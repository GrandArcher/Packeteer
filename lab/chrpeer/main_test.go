package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	api "github.com/osrg/gobgp/v3/api"
)

func TestParse(t *testing.T) {
	p, err := parsePrefixes(" 198.51.100.0/24, 203.0.113.0/24 ,")
	if err != nil || len(p) != 2 || p[1].String() != "203.0.113.0/24" {
		t.Fatalf("parsePrefixes = %v, %v", p, err)
	}
	for _, bad := range []string{"198.51.100.1/24", "2001:db8::/32", "x"} {
		if _, err := parsePrefixes(bad); err == nil {
			t.Errorf("parsePrefixes(%q) accepted", bad)
		}
	}
	c, err := parseCommunities("64512:666")
	if err != nil || len(c) != 1 || c[0] != 64512<<16|666 {
		t.Fatalf("parseCommunities = %v, %v", c, err)
	}
	if _, err := parseCommunities("70000:1"); err == nil {
		t.Error("parseCommunities accepted 70000:1")
	}
}

func TestRecorder(t *testing.T) {
	file := filepath.Join(t.TempDir(), "routes")
	r := &recorder{file: file, paths: map[string]string{}}
	path, err := buildPath(mustPrefix(t, "198.51.100.0/24"), "192.0.2.2", []uint32{64512<<16 | 666, noExport}, true)
	if err != nil {
		t.Fatal(err)
	}
	r.update(path)
	if got := read(t, file); got != "198.51.100.0/24 192.0.2.2 64512:666,no-export\n" {
		t.Fatalf("routes = %q", got)
	}
	plain, err := buildPath(mustPrefix(t, "203.0.113.0/24"), "192.0.2.1", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	r.update(plain)
	if got := read(t, file); got != "198.51.100.0/24 192.0.2.2 64512:666,no-export\n203.0.113.0/24 192.0.2.1 -\n" {
		t.Fatalf("routes = %q", got)
	}
	path.IsWithdraw = true
	r.update(path)
	if got := read(t, file); got != "203.0.113.0/24 192.0.2.1 -\n" {
		t.Fatalf("after withdraw routes = %q", got)
	}
	r.clear()
	if got := read(t, file); got != "" {
		t.Fatalf("after clear routes = %q", got)
	}
	// An eBGP path carries no local preference.
	for _, a := range plain.Pattrs {
		var lp api.LocalPrefAttribute
		if a.UnmarshalTo(&lp) == nil {
			t.Fatal("eBGP path has LOCAL_PREF")
		}
	}
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	ps, err := parsePrefixes(s)
	if err != nil || len(ps) != 1 {
		t.Fatal(err)
	}
	return ps[0]
}

func read(t *testing.T, f string) string {
	t.Helper()
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
