package nonbgp

import (
	"context"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/probe"
)

func announcedTable(t *testing.T) *Table {
	t.Helper()
	cov := &fakeCovering{ans: pfx("2001:db8::/32"), asn: 64496}
	tbl, _ := newTestTable(4, cov)
	tbl.Lookup(addr("2001:db8:1::1"))
	tbl.Lookup(addr("2001:db8:2::1"))
	for tbl.lookupOne(context.Background()) {
	}
	tbl.Refresh()
	// A block with no announced prefix: never shared.
	tbl.Lookup(addr("203.0.113.9"))
	tbl.Refresh()
	return tbl
}

func TestForHerdSharesOnlyTheAnnouncedPrefix(t *testing.T) {
	tbl := announcedTable(t)
	syn := pfx("2001:db8::/46")
	if !tbl.Has(syn) {
		t.Fatalf("test setup: routes = %v", routePrefixes(tbl))
	}
	batch := []probe.Result{
		{Prefix: syn, Provider: "isp-a"},
		{Prefix: syn, Provider: "isp-b"},
		{Prefix: pfx("203.0.113.0/24"), Provider: "isp-a"},
		{Prefix: pfx("192.0.2.0/24"), Provider: "isp-a"},
	}
	// A repeat for the same announced prefix and provider adds nothing.
	batch = append(batch, probe.Result{Prefix: syn, Provider: "isp-a"})
	got := ForHerd(tbl, batch)
	if len(got) != 2 {
		t.Fatalf("shared %d results, want one per provider: %+v", len(got), got)
	}
	for _, r := range got {
		if r.Prefix != pfx("2001:db8::/32") {
			t.Errorf("result for %s shared as %s, want the announced prefix", r.Provider, r.Prefix)
		}
	}
	if batch[0].Prefix != syn {
		t.Fatal("ForHerd changed the caller's results")
	}
}

func TestHerdViewKnowsOnlyAnnouncedPrefixes(t *testing.T) {
	tbl := announcedTable(t)
	v := HerdView{Table: tbl, ProviderASN: map[string]uint32{"isp-a": 64500, "isp-b": 0}}
	if !v.Ready() {
		t.Fatal("not ready")
	}
	if _, ok := v.Exact(pfx("2001:db8::/32")); !ok {
		t.Error("the announced prefix is not known")
	}
	for _, p := range []string{"2001:db8::/46", "2001:db8:1::/48", "203.0.113.0/24"} {
		if _, ok := v.Exact(pfx(p)); ok {
			t.Errorf("%s is a synthetic or unannounced prefix and must not be known", p)
		}
	}
	paths := v.ProviderPaths(pfx("2001:db8::/32"), "isp-a")
	if len(paths) != 1 || len(paths[0]) != 1 || paths[0][0] != 64496 {
		t.Fatalf("path through isp-a = %v", paths)
	}
	if v.ProviderPaths(pfx("2001:db8::/32"), "isp-b") != nil {
		t.Error("a provider with no asn got a path")
	}
	if v.ProviderPaths(pfx("2001:db8::/32"), "isp-z") != nil {
		t.Error("an unknown provider got a path")
	}

	// Once the blocks age out the prefix is no longer served.
	tbl2, clk := newTestTable(4, &fakeCovering{ans: pfx("2001:db8::/32"), asn: 64496})
	tbl2.Lookup(addr("2001:db8:1::1"))
	tbl2.lookupOne(context.Background())
	tbl2.Refresh()
	v2 := HerdView{Table: tbl2, ProviderASN: map[string]uint32{"isp-a": 64500}}
	if _, ok := v2.Exact(pfx("2001:db8::/32")); !ok {
		t.Fatal("setup: announced prefix not known")
	}
	clk.add(2 * tbl2.opt.Idle)
	tbl2.Refresh()
	if _, ok := v2.Exact(pfx("2001:db8::/32")); ok {
		t.Fatal("an announced prefix with no active block is still served")
	}
}
