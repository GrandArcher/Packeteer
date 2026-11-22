package gobgp

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TestWithdrawAllUnderLargeRIBIsFast is #719: the shutdown WithdrawAll of
// 1,000 routes, each replaced once (the implicit withdraw that re-keys
// GoBGP's UUID), over a large learned table. A delete by UUID scans the
// whole global table per route, which with the soak's 1,000,000 learned
// prefixes outlasted the 30 s container stop grace and left the routes on
// the fast sessions. Every route must be gone from the router while the
// session is still up, within a budget far below the 10 s shutdown
// bound.
func TestWithdrawAllUnderLargeRIBIsFast(t *testing.T) {
	if testing.Short() {
		t.Skip("loads a large learned table")
	}
	const learned, injected = 100000, 1000
	ctx := context.Background()
	r := newRouter(t)
	prefix := func(i int) netip.Prefix {
		return netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x:%x::/64", i>>16, i&0xffff))
	}
	for i := range learned {
		addLocal(t, r.srv, plugin.Route{Prefix: prefix(i), NextHop: netip.MustParseAddr("2001:db8::1"), LocalPref: 100, Communities: []string{"64496:1"}})
	}
	v := newView(t, r)
	eventually(t, "session", v.Ready)
	deadline := time.Now().Add(2 * time.Minute)
	for v.Len() < learned {
		if time.Now().After(deadline) {
			t.Fatalf("learned %d of %d prefixes", v.Len(), learned)
		}
		time.Sleep(100 * time.Millisecond)
	}
	out := mustAnnouncer(t)
	if err := out.Bind(v.Server(), "64512:666"); err != nil {
		t.Fatal(err)
	}
	for _, nh := range []string{"2001:db8::2", "2001:db8::3"} {
		for i := range injected {
			if err := out.Announce(ctx, plugin.Route{Prefix: prefix(i), NextHop: netip.MustParseAddr(nh), LocalPref: 250, Communities: []string{"64512:666"}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	ours := func() int {
		n := 0
		for _, p := range collect(t, r.srv, v6Family) {
			if p.fromUs && p.nextHop == "2001:db8::3" {
				n++
			}
		}
		return n
	}
	eventually(t, "every replaced route on the router", func() bool { return ours() == injected })

	start := time.Now()
	if err := out.WithdrawAll(ctx); err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	t.Logf("withdrew %d routes over %d learned prefixes in %s", injected, learned, took)
	if took > 2*time.Second {
		t.Fatalf("WithdrawAll took %s, want under 2s", took)
	}
	eventually(t, "every route withdrawn from the router", func() bool {
		for _, p := range collect(t, r.srv, v6Family) {
			if p.fromUs {
				return false
			}
		}
		return true
	})
	if !v.Ready() {
		t.Fatal("the session dropped; the withdraw must reach the router over a live session")
	}
	if n := v.Len(); n != learned {
		t.Fatalf("learned table has %d prefixes after the withdraw, want %d", n, learned)
	}
}
