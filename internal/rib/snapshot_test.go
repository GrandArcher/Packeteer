package rib

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
)

const snapNeighbor = "192.0.2.254"

func snapView(t *testing.T) *View {
	t.Helper()
	v, err := New(Options{
		ASN: 64512, RouterID: netip.MustParseAddr("192.0.2.10"),
		Neighbors: []Neighbor{{Address: netip.MustParseAddr(snapNeighbor)}},
		Providers: map[netip.Addr]string{netip.MustParseAddr("192.0.2.1"): "transit-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// snapEvent delivers paths the way the BGP watch does, under the write lock.
func snapEvent(v *View, paths ...*api.Path) {
	v.handleEvent(&api.WatchEventResponse{Event: &api.WatchEventResponse_Table{
		Table: &api.WatchEventResponse_TableEvent{Paths: paths}}})
}

// snapPrefixes returns documentation sub-prefixes: 192.0.2.0/24 split down
// to /28, plus the two other documentation /24s.
func snapPrefixes() []string {
	out := []string{"198.51.100.0/24", "203.0.113.0/24", "192.0.2.0/24"}
	base := netip.MustParseAddr("192.0.2.0")
	for bits, count := 25, 2; bits <= 28; bits, count = bits+1, count*2 {
		step := 1 << (32 - bits)
		for i := 0; i < count; i++ {
			a := base.As4()
			off := i * step
			a[3] = byte(off)
			out = append(out, netip.PrefixFrom(netip.AddrFrom4(a), bits).String())
		}
	}
	return out
}

func prefixesOf(rs []Route) []netip.Prefix {
	out := make([]netip.Prefix, len(rs))
	for i, r := range rs {
		out[i] = r.Prefix
	}
	return out
}

func wantPrefixes(live map[string]string) []netip.Prefix {
	var out []netip.Prefix
	for s := range live {
		out = append(out, netip.MustParsePrefix(s))
	}
	slices.SortFunc(out, cmpPrefix)
	return out
}

func TestSnapshotFollowsUpdates(t *testing.T) {
	v := snapView(t)
	all := snapPrefixes()
	live := map[string]string{}
	step := func(name string, announce, withdraw []string, nh string) {
		t.Helper()
		var paths []*api.Path
		for _, s := range announce {
			paths = append(paths, learned(t, s, nh, snapNeighbor, 100, false))
			live[s] = nh
		}
		for _, s := range withdraw {
			paths = append(paths, learned(t, s, nh, snapNeighbor, 100, true))
			delete(live, s)
		}
		snapEvent(v, paths...)
		got := v.Routes()
		if !slices.Equal(prefixesOf(got), wantPrefixes(live)) {
			t.Fatalf("%s: prefixes = %v, want %v", name, prefixesOf(got), wantPrefixes(live))
		}
		for _, r := range got {
			if r.NextHop.String() != live[r.Prefix.String()] {
				t.Fatalf("%s: %s next hop = %s, want %s", name, r.Prefix, r.NextHop, live[r.Prefix.String()])
			}
		}
	}
	step("first fill", all, nil, "192.0.2.1")
	if v.dirty == nil {
		t.Fatal("snapshot was not kept after a read")
	}
	step("withdraw some", nil, all[1:9], "192.0.2.1")
	step("change next hop and add back", all[5:12], nil, "192.0.2.2")
	step("withdraw the first and last", nil, []string{all[0], all[len(all)-1]}, "192.0.2.2")
	step("add the first back", all[:1], nil, "192.0.2.3")
	step("withdraw all", nil, all, "192.0.2.3")
	if n := len(v.Routes()); n != 0 {
		t.Fatalf("%d routes after withdrawing all", n)
	}
}

func TestSnapshotIsReusedUntilAChange(t *testing.T) {
	v := snapView(t)
	snapEvent(v, learned(t, "198.51.100.0/24", "192.0.2.1", snapNeighbor, 100, false))
	a := v.snapshot()
	if b := v.snapshot(); &a[0] != &b[0] {
		t.Fatal("snapshot was rebuilt with no change")
	}
	snapEvent(v, learned(t, "198.51.100.0/24", "192.0.2.1", snapNeighbor, 100, false))
	if b := v.snapshot(); &a[0] != &b[0] {
		t.Fatal("snapshot was rebuilt after an update that changed no route")
	}
	snapEvent(v, learned(t, "203.0.113.0/24", "192.0.2.1", snapNeighbor, 100, false))
	if b := v.snapshot(); len(b) != 2 {
		t.Fatalf("snapshot has %d routes after an add, want 2", len(b))
	}
}

// A reader may hold a snapshot while the next one is built, so a refresh
// must not write into the slice or the routes it returned earlier.
func TestSnapshotRefreshLeavesEarlierSnapshotAlone(t *testing.T) {
	v := snapView(t)
	snapEvent(v,
		learned(t, "192.0.2.0/24", "192.0.2.1", snapNeighbor, 100, false),
		learned(t, "198.51.100.0/24", "192.0.2.1", snapNeighbor, 100, false),
		learned(t, "203.0.113.0/24", "192.0.2.1", snapNeighbor, 100, false))
	old := v.snapshot()
	oldCopy := slices.Clone(old)
	oldRoute := *old[1]

	snapEvent(v,
		learned(t, "198.51.100.0/24", "192.0.2.2", snapNeighbor, 100, false),
		learned(t, "192.0.2.0/24", "192.0.2.1", snapNeighbor, 100, true),
		learned(t, "192.0.2.128/25", "192.0.2.1", snapNeighbor, 100, false))
	fresh := v.snapshot()

	if !slices.Equal(old, oldCopy) {
		t.Fatal("refresh rewrote the earlier snapshot slice")
	}
	if got := *old[1]; got.NextHop != oldRoute.NextHop || got.NextHop.String() != "192.0.2.1" {
		t.Fatalf("refresh modified a published route: %+v", got)
	}
	if len(fresh) != 3 || fresh[0].Prefix.String() != "192.0.2.128/25" || fresh[1].NextHop.String() != "192.0.2.2" {
		t.Fatalf("fresh snapshot = %v", prefixesOf(copyRoutes(fresh)))
	}
}

func TestSnapshotDroppedWhenManyPrefixesChange(t *testing.T) {
	v := &View{routes: map[netip.Prefix]*Route{}}
	add := func(from, to int) {
		for i := from; i < to; i++ {
			v.setRoute(Route{Prefix: netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x::/48", i))})
		}
	}
	add(0, 10)
	if n := len(v.Routes()); n != 10 || v.dirty == nil {
		t.Fatalf("first read: %d routes, snapshot kept = %v", n, v.dirty != nil)
	}
	// The limit grows with the table, so add well past it.
	more := 2 * dirtyLimit(10)
	add(10, 10+more)
	if v.snap != nil || v.dirty != nil {
		t.Fatalf("snapshot kept after %d new prefixes on a table of 10", more)
	}
	got := v.Routes()
	if len(got) != 10+more || !slices.IsSortedFunc(prefixesOf(got), cmpPrefix) {
		t.Fatalf("rebuild: %d routes, sorted = %v", len(got), slices.IsSortedFunc(prefixesOf(got), cmpPrefix))
	}
	if v.dirty == nil {
		t.Fatal("rebuilt snapshot was not kept")
	}
}

func TestStopDropsSnapshot(t *testing.T) {
	v := snapView(t)
	snapEvent(v, learned(t, "198.51.100.0/24", "192.0.2.1", snapNeighbor, 100, false))
	if len(v.Routes()) != 1 {
		t.Fatal("route not learned")
	}
	if err := v.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := len(v.Routes()); n != 0 {
		t.Fatalf("%d routes served from the snapshot after Stop", n)
	}
}

// The point of the snapshot: a reader that is slow in its own callback must
// not hold up the BGP watch path.
func TestFullTableReadDoesNotBlockUpdates(t *testing.T) {
	v := snapView(t)
	snapEvent(v,
		learned(t, "192.0.2.0/24", "192.0.2.1", snapNeighbor, 100, false),
		learned(t, "198.51.100.0/24", "192.0.2.1", snapNeighbor, 100, false))

	inside, release := make(chan struct{}), make(chan struct{})
	done := make(chan int)
	go func() {
		var once sync.Once
		_, n := v.Find(func(Route) bool {
			once.Do(func() { close(inside) })
			<-release
			return true
		}, func(a, b Route) bool { return netpfx.Less(a.Prefix, b.Prefix) }, 10)
		done <- n
	}()
	<-inside

	applied := make(chan struct{})
	go func() {
		snapEvent(v, learned(t, "203.0.113.0/24", "192.0.2.1", snapNeighbor, 100, false))
		close(applied)
	}()
	select {
	case <-applied:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("a BGP update waited behind a full-table read")
	}
	close(release)
	if n := <-done; n != 2 {
		t.Fatalf("Find matched %d, want the 2 routes of the snapshot it started from", n)
	}
	if _, ok := v.Exact(netip.MustParsePrefix("203.0.113.0/24")); !ok {
		t.Fatal("the update was not applied")
	}
}

func TestSnapshotReadersAndWritersConcurrently(t *testing.T) {
	v := snapView(t)
	all := snapPrefixes()
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				rs := v.Routes()
				if !slices.IsSortedFunc(prefixesOf(rs), cmpPrefix) {
					t.Error("Routes not sorted")
					return
				}
				v.LearnedWithin([]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, nil, 100)
				v.MoreSpecifics([]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")})
				v.RouteSnapshot()
			}
		}()
	}
	live := map[string]bool{}
	for round := range 200 {
		var paths []*api.Path
		for i, s := range all {
			if (i+round)%3 == 0 {
				paths = append(paths, learned(t, s, "192.0.2.1", snapNeighbor, 100, true))
				delete(live, s)
			} else {
				paths = append(paths, learned(t, s, "192.0.2.1", snapNeighbor, uint32(100+round%2), false))
				live[s] = true
			}
		}
		snapEvent(v, paths...)
	}
	close(stop)
	readers.Wait()

	want := map[string]string{}
	for s := range live {
		want[s] = ""
	}
	if got := v.Routes(); !slices.Equal(prefixesOf(got), wantPrefixes(want)) {
		t.Fatalf("final snapshot = %v, want %v", prefixesOf(got), wantPrefixes(want))
	}
}
