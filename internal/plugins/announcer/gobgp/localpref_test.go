package gobgp

import (
	"context"
	"net/netip"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// The local preference on the path is the route's, including a value that
// is not the usual 250. The community and NO_EXPORT stay, and a later
// announce replaces the value. Withdraw removes the path.
func TestAnnouncedLocalPrefIsTheRoutes(t *testing.T) {
	ctx := context.Background()
	r := newRouter(t)
	v := newView(t, r)
	eventually(t, "session", v.Ready)
	a := mustAnnouncer(t)
	if err := a.Bind(v.Server(), "64512:666"); err != nil {
		t.Fatal(err)
	}
	p := netip.MustParsePrefix("203.0.113.0/24")
	nh := netip.MustParseAddr("192.0.2.2")
	comm, err := parseCommunity("64512:666")
	if err != nil {
		t.Fatal(err)
	}
	for _, lp := range []uint32{400, 180} {
		if err := a.Announce(ctx, plugin.Route{
			Prefix: p, NextHop: nh, LocalPref: lp, Communities: []string{"64512:666"}, Provider: "transit-b",
		}); err != nil {
			t.Fatal(err)
		}
		var got seen
		eventually(t, "local pref on the router", func() bool {
			g, ok := fromUs(collect(t, r.srv, v4Family), p.String())
			got = g
			return ok && g.lp == lp && g.comms[comm] && g.comms[noExport] && g.nextHop == nh.String()
		})
		if got.lp != lp || !got.comms[comm] || !got.comms[noExport] {
			t.Fatalf("local_pref %d path = %+v", lp, got)
		}
	}
	if err := a.Withdraw(ctx, p); err != nil {
		t.Fatal(err)
	}
	eventually(t, "withdraw", func() bool {
		_, ok := fromUs(collect(t, r.srv, v4Family), p.String())
		return !ok
	})
}
