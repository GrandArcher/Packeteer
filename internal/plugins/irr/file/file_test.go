package file

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func newSource(t *testing.T, cfg string) *Source {
	t.Helper()
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(cfg), &node); err != nil {
		t.Fatal(err)
	}
	p, err := New(plugin.NewConfig(node.Content[0]), plugin.Env{Name: "local"})
	if err != nil {
		t.Fatal(err)
	}
	return p.(*Source)
}

func copyFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func origins(rs []plugin.IRRRoute) []uint32 {
	var out []uint32
	for _, r := range rs {
		out = append(out, r.Origin)
	}
	return out
}

// #214: an RPSL dump answers exact route/route6 lookups with the database
// of each object, skips the RPKI pseudo-source, expands nested as-sets
// once per set, and gives aut-num names. The data time is the file time.
func TestRPSLFile(t *testing.T) {
	path := copyFixture(t, "irr.db")
	mod := time.Date(2026, 10, 20, 1, 2, 3, 0, time.UTC)
	if err := os.Chtimes(path, mod, mod); err != nil {
		t.Fatal(err)
	}
	s := newSource(t, "{path: "+path+"}")
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	rs, at, err := s.Routes(ctx, netip.MustParsePrefix("198.51.100.0/24"))
	if err != nil || !slices.Equal(origins(rs), []uint32{64496, 64497}) || rs[0].Database != "RADB" || !at.Equal(mod) {
		t.Fatalf("routes = %+v at %s err %v", rs, at, err)
	}
	if rs, _, _ = s.Routes(ctx, netip.MustParsePrefix("198.51.100.0/25")); len(rs) != 0 {
		t.Fatalf("a more-specific matched a route object: %+v", rs)
	}
	if rs, _, _ = s.Routes(ctx, netip.MustParsePrefix("2001:db8::/32")); !slices.Equal(origins(rs), []uint32{64496}) {
		t.Fatalf("route6 = %+v", rs)
	}
	if rs, _, _ = s.Routes(ctx, netip.MustParsePrefix("203.0.113.0/24")); len(rs) != 0 {
		t.Fatalf("RPKI pseudo-source counted: %+v", rs)
	}
	members, _, err := s.ASSetMembers(ctx, "as-example")
	if err != nil || !slices.Equal(members, []uint32{64496, 64497, 64498}) {
		t.Fatalf("as-set = %v %v", members, err)
	}
	if members, _, err = s.ASSetMembers(ctx, "AS-MISSING"); err != nil || len(members) != 0 {
		t.Fatalf("missing as-set = %v %v", members, err)
	}
	if name, _, err := s.ASName(ctx, 64496); err != nil || name != "EXAMPLE-NET-AS" {
		t.Fatalf("as-name = %q %v", name, err)
	}
}

// bgpq4 lists are named after the origin; an exact entry matches only the
// prefix and a range entry the lengths it covers. bgpq4 has no as-sets or
// aut-nums, so those lookups are unsupported, not empty.
func TestBGPQ4File(t *testing.T) {
	s := newSource(t, "{path: "+copyFixture(t, "bgpq4.json")+", format: bgpq4}")
	ctx := context.Background()
	for prefix, want := range map[string][]uint32{
		"198.51.100.0/24":  {64496},
		"198.51.100.0/25":  nil,
		"2001:db8::/32":    {64496},
		"2001:db8:1::/48":  {64496},
		"2001:db8:1::/49":  nil,
		"203.0.113.0/24":   {64497},
		"203.0.113.128/25": {64497},
		"203.0.113.0/26":   nil,
		"192.0.2.0/24":     nil,
	} {
		rs, _, err := s.Routes(ctx, netip.MustParsePrefix(prefix))
		if err != nil || !slices.Equal(origins(rs), want) {
			t.Errorf("%s = %v %v, want %v", prefix, origins(rs), err, want)
		}
	}
	if _, _, err := s.ASSetMembers(ctx, "AS-EXAMPLE"); !errors.Is(err, plugin.ErrIRRUnsupported) {
		t.Fatalf("as-set err = %v", err)
	}
	if _, _, err := s.ASName(ctx, 64496); !errors.Is(err, plugin.ErrIRRUnsupported) {
		t.Fatalf("aut-num err = %v", err)
	}
}

// A changed file is read again; a broken one keeps the last good data and
// its data time, so it ages out; a list not named after an AS is refused.
func TestFileReloadKeepsLastGood(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "irr.json")
	write := func(body string, mod time.Time) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	first := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	write(`{"AS64496": [{"prefix": "198.51.100.0/24", "exact": true}]}`, first)
	s := newSource(t, "{path: "+path+", format: bgpq4}")
	ctx := context.Background()
	p := netip.MustParsePrefix("198.51.100.0/24")
	if rs, at, err := s.Routes(ctx, p); err != nil || !slices.Equal(origins(rs), []uint32{64496}) || !at.Equal(first) {
		t.Fatalf("first = %v %s %v", origins(rs), at, err)
	}
	second := first.Add(time.Hour)
	write(`{"AS64497": [{"prefix": "198.51.100.0/24", "exact": true}]}`, second)
	if rs, at, err := s.Routes(ctx, p); err != nil || !slices.Equal(origins(rs), []uint32{64497}) || !at.Equal(second) {
		t.Fatalf("reloaded = %v %s %v", origins(rs), at, err)
	}
	write(`{"EXAMPLE": [{"prefix": "198.51.100.0/24", "exact": true}]}`, second.Add(time.Hour))
	if rs, at, err := s.Routes(ctx, p); err != nil || !slices.Equal(origins(rs), []uint32{64497}) || !at.Equal(second) {
		t.Fatalf("broken file = %v %s %v, want the last good data", origins(rs), at, err)
	}
	fresh := newSource(t, "{path: "+path+", format: bgpq4}")
	if _, _, err := fresh.Routes(ctx, p); err == nil || !strings.Contains(err.Error(), "name each list after its origin AS") {
		t.Fatalf("no good data err = %v", err)
	}
	missing := newSource(t, "{path: "+filepath.Join(dir, "none.db")+"}")
	if err := missing.Start(ctx); err != nil {
		t.Fatalf("a missing file failed Start: %v", err)
	}
	if _, _, err := missing.Routes(ctx, p); err == nil {
		t.Fatal("a missing file answered")
	}
}

func TestFileConfig(t *testing.T) {
	for cfg, want := range map[string]string{
		"{}":                            "path is required",
		"{path: /x, format: radb}":      `format "radb" must be rpsl or bgpq4`,
		"{path: /x, unknown_key: true}": "unknown_key",
	} {
		var node yaml.Node
		if err := yaml.Unmarshal([]byte(cfg), &node); err != nil {
			t.Fatal(err)
		}
		if _, err := New(plugin.NewConfig(node.Content[0]), plugin.Env{}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err %v, want %q", cfg, err, want)
		}
	}
	if s := newSource(t, "{path: /x}"); s.cfg.Format != FormatRPSL {
		t.Fatalf("default format = %q", s.cfg.Format)
	}
}

// #289: the prefixes registered for an origin, from route objects and from
// bgpq4 lists (a range counts as its base prefix).
func TestOriginPrefixes(t *testing.T) {
	ctx := context.Background()
	s := newSource(t, "{path: "+copyFixture(t, "irr.db")+"}")
	got, _, err := s.OriginPrefixes(ctx, 64496)
	want := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("rpsl = %v %v, want %v", got, err, want)
	}
	if got, _, _ = s.OriginPrefixes(ctx, 64511); len(got) != 0 {
		t.Fatalf("unknown origin = %v", got)
	}
	b := newSource(t, "{path: "+copyFixture(t, "bgpq4.json")+", format: bgpq4}")
	if got, _, err = b.OriginPrefixes(ctx, 64497); err != nil || !slices.Equal(got, []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}) {
		t.Fatalf("bgpq4 = %v %v", got, err)
	}
	// #289: a file keeps no object text, so registry hygiene offers no
	// delete from it.
	if _, _, err = s.RouteObjects(ctx, want[0]); !errors.Is(err, plugin.ErrIRRUnsupported) {
		t.Fatalf("rpsl RouteObjects err = %v", err)
	}
}
