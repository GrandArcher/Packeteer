package announce

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// pathRIB adds learned AS paths to memRIB (bgp.as_path, #27).
type pathRIB struct {
	memRIB
	native   map[netip.Prefix][]uint32
	provider map[string][]uint32 // provider -> path for every prefix
}

func (r *pathRIB) NativePath(p netip.Prefix) ([]uint32, bool) {
	as, ok := r.native[p]
	return as, ok
}

func (r *pathRIB) ProviderPath(_ netip.Prefix, provider string) ([]uint32, bool) {
	as, ok := r.provider[provider]
	return as, ok
}

func TestASPathModes(t *testing.T) {
	ctx := context.Background()
	p := pfx("198.51.100.0/24")
	newRIB := func() *pathRIB {
		return &pathRIB{
			memRIB:   memRIB{ready: true, has: map[netip.Prefix]bool{p: true}},
			native:   map[netip.Prefix][]uint32{p: {64496, 64500}},
			provider: map[string][]uint32{"b": {64501, 64501, 64500}},
		}
	}
	for mode, want := range map[string][]uint32{
		"":         nil,
		"empty":    nil,
		"native":   {64496, 64500},
		"provider": {64501, 64501, 64500},
	} {
		ann := &fakeAnn{}
		cfg := testCfg()
		cfg.ASPath = mode
		c, err := New(cfg, ann, newRIB(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Sync(ctx, []policy.Improvement{imp(p.String(), "b")}); err != nil {
			t.Fatal(err)
		}
		if got := ann.routes[p].ASPath; !slices.Equal(got, want) {
			t.Errorf("%q: as path %v, want %v", mode, got, want)
		}
	}

	// provider falls back to the native path when the provider's own path
	// is not visible (a transit without add-path or BMP).
	ann := &fakeAnn{}
	cfg := testCfg()
	cfg.ASPath = "provider"
	rib := newRIB()
	c, err := New(cfg, ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx, []policy.Improvement{imp(p.String(), "a")}); err != nil {
		t.Fatal(err)
	}
	if got := ann.routes[p].ASPath; !slices.Equal(got, []uint32{64496, 64500}) {
		t.Fatalf("fallback path %v", got)
	}
	// The router hides the native route once Packeteer's wins: the path
	// on the wire is kept, and nothing is re-announced.
	delete(rib.native, p)
	delete(rib.has, p)
	before := ann.announces
	if err := c.Sync(ctx, []policy.Improvement{imp(p.String(), "a")}); err != nil {
		t.Fatal(err)
	}
	if ann.announces != before {
		t.Fatal("hidden native path re-announced the route")
	}
	// The provider's path changes: the route is replaced with it.
	rib.provider["a"] = []uint32{64496, 64499, 64500}
	if err := c.Sync(ctx, []policy.Improvement{imp(p.String(), "a")}); err != nil {
		t.Fatal(err)
	}
	if got := ann.routes[p].ASPath; !slices.Equal(got, []uint32{64496, 64499, 64500}) || ann.announces != before+1 {
		t.Fatalf("changed path %v after %d announces", got, ann.announces-before)
	}

	// A RIB without paths cannot serve native or provider.
	cfg.ASPath = "native"
	if _, err := New(cfg, &fakeAnn{}, memRIB{}, nil); err == nil || !strings.Contains(err.Error(), "learned AS paths") {
		t.Fatalf("plain RIB: %v", err)
	}
	cfg.ASPath = "origin"
	if _, err := New(cfg, &fakeAnn{}, rib, nil); err == nil {
		t.Fatal("unknown as_path accepted")
	}
}

// reloadAnn records SetRouters.
type reloadAnn struct {
	fakeAnn
	tables [][]plugin.RouterExport
}

func (r *reloadAnn) BindRouters(any, string, []plugin.RouterExport) error { return nil }

func (r *reloadAnn) SetRouters(ctx context.Context, routers []plugin.RouterExport) error {
	r.tables = append(r.tables, routers)
	return r.WithdrawAll(ctx)
}

// Online reconfiguration (#27): SetRouters withdraws, and the next Sync
// announces the same improvements again under the new table.
func TestSetRoutersReannounces(t *testing.T) {
	ctx := context.Background()
	p := pfx("198.51.100.0/24")
	rib := memRIB{ready: true, has: map[netip.Prefix]bool{p: true}}
	ann := &reloadAnn{}
	c, err := New(testCfg(), ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	imps := []policy.Improvement{imp(p.String(), "b")}
	if err := c.Sync(ctx, imps); err != nil || c.Active() != 1 {
		t.Fatalf("sync: %v active=%d", err, c.Active())
	}
	table := []plugin.RouterExport{{Neighbor: netip.MustParseAddr("192.0.2.251")}}
	if err := c.SetRouters(ctx, table); err != nil {
		t.Fatal(err)
	}
	if c.Active() != 0 || ann.count() != 0 || len(ann.tables) != 1 || len(c.Routers()) != 1 {
		t.Fatalf("after SetRouters: active=%d routes=%d tables=%d", c.Active(), ann.count(), len(ann.tables))
	}
	if err := c.Sync(ctx, imps); err != nil || ann.count() != 1 {
		t.Fatalf("re-announce: %v routes=%d", err, ann.count())
	}

	// An announcer without SetRouters cannot reload.
	c2, err := New(testCfg(), &fakeAnn{}, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c2.SetRouters(ctx, table); err == nil {
		t.Fatal("announcer without SetRouters accepted a new table")
	}
	// Observe keeps the table and touches nothing.
	cfg := testCfg()
	cfg.Mode = "observe"
	c3, err := New(cfg, panicAnn{}, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c3.SetRouters(ctx, table); err != nil || len(c3.Routers()) != 1 {
		t.Fatalf("observe: %v", err)
	}
}
