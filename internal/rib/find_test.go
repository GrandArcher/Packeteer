package rib

import (
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
)

// setRoute stores r as the selected route the way republishLocked does,
// for tests that build a view without a session.
func (v *View) setRoute(r Route) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.routes[r.Prefix] = &r
	v.markDirtyLocked(r.Prefix)
}

func byPrefix(a, b Route) bool { return netpfx.Less(a.Prefix, b.Prefix) }

func TestFindKeepsTheFirstMatchesInPrefixOrder(t *testing.T) {
	v := &View{routes: map[netip.Prefix]*Route{}}
	for _, s := range []string{"198.51.100.0/24", "192.0.2.0/24", "203.0.113.0/24", "192.0.2.128/25", "2001:db8::/32"} {
		p := netip.MustParsePrefix(s)
		v.setRoute(Route{Prefix: p, ASPath: []uint32{64496, 64510}})
	}
	v.setRoute(Route{Prefix: netip.MustParsePrefix("203.0.113.0/24"), ASPath: []uint32{64496, 64511}})

	got, n := v.Find(func(r Route) bool { return r.ASPath[len(r.ASPath)-1] == 64510 }, byPrefix, 2)
	if n != 4 || len(got) != 2 || got[0].Prefix.String() != "192.0.2.0/24" || got[1].Prefix.String() != "192.0.2.128/25" {
		t.Fatalf("Find(origin 64510, 2) = %v of %d", got, n)
	}
	got, n = v.Find(func(r Route) bool { return r.Prefix.Addr().Is6() }, byPrefix, 5)
	if n != 1 || len(got) != 1 || got[0].Prefix.String() != "2001:db8::/32" {
		t.Fatalf("Find(v6) = %v of %d", got, n)
	}
	// The order is the caller's: newest first, then by prefix.
	v.setRoute(Route{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASPath: []uint32{64510}, Age: time.Unix(500, 0)})
	got, _ = v.Find(func(r Route) bool { return r.ASPath[len(r.ASPath)-1] == 64510 }, func(a, b Route) bool {
		return a.Age.After(b.Age) || (a.Age.Equal(b.Age) && netpfx.Less(a.Prefix, b.Prefix))
	}, 2)
	if len(got) != 2 || got[0].Prefix.String() != "198.51.100.0/24" || got[1].Prefix.String() != "192.0.2.0/24" {
		t.Fatalf("Find newest first = %v", got)
	}
	if got, n = v.Find(func(Route) bool { return false }, byPrefix, 5); len(got) != 0 || n != 0 {
		t.Fatalf("Find(none) = %v of %d", got, n)
	}
}
