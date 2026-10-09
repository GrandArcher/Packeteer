package gobgp

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func definedList(t *testing.T, srv *server.BgpServer, typ api.DefinedType, name string) []string {
	t.Helper()
	var list []string
	err := srv.ListDefinedSet(context.Background(), &api.ListDefinedSetRequest{DefinedType: typ, Name: name}, func(ds *api.DefinedSet) {
		if ds.GetName() == name {
			list = append(list, ds.GetList()...)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func addLocal(t *testing.T, srv *server.BgpServer, r plugin.Route) {
	t.Helper()
	path, err := buildPath(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.AddPath(context.Background(), &api.AddPathRequest{Path: path}); err != nil {
		t.Fatal(err)
	}
}

func absent(t *testing.T, srv *server.BgpServer, prefixes ...string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		paths := collect(t, srv, v4Family)
		for _, p := range prefixes {
			if _, ok := fromUs(paths, p); ok {
				t.Fatalf("route %s was exported", p)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Extras ride on the route. The export policy matches only the packeteer
// community, so a local route that carries an extra and not that community
// stays off the peer.
func TestExportPolicyMatchesOnlyPacketeerCommunity(t *testing.T) {
	ctx := context.Background()
	r := newRouter(t)
	v := newView(t, r)
	eventually(t, "session", v.Ready)
	a := mustAnnouncer(t)
	if err := a.Bind(v.Server(), "64512:0666"); err != nil {
		t.Fatal(err)
	}
	if a.community != "64512:666" {
		t.Fatalf("bound community = %q", a.community)
	}
	if got := definedList(t, v.Server(), api.DefinedType_COMMUNITY, setName); !slices.Equal(got, []string{"^64512:666$"}) {
		t.Fatalf("community set = %v", got)
	}
	if got := definedList(t, v.Server(), api.DefinedType_LARGE_COMMUNITY, setName); len(got) != 0 {
		t.Fatalf("large set = %v", got)
	}

	p := netip.MustParsePrefix("203.0.113.0/24")
	if err := a.Announce(ctx, plugin.Route{
		Prefix: p, NextHop: netip.MustParseAddr("192.0.2.2"), LocalPref: 250, Provider: "transit-b",
		Communities: []string{"64512:666", "64512:0100", "64512:1:50", "64512:100"},
	}); err != nil {
		t.Fatal(err)
	}
	extraOnly := netip.MustParsePrefix("198.51.100.0/24")
	addLocal(t, v.Server(), plugin.Route{
		Prefix: extraOnly, NextHop: netip.MustParseAddr("192.0.2.1"), LocalPref: 250,
		Communities: []string{"64512:100", "64512:1:50"},
	})
	otherLarge := netip.MustParsePrefix("198.51.100.128/25")
	addLocal(t, v.Server(), plugin.Route{
		Prefix: otherLarge, NextHop: netip.MustParseAddr("192.0.2.1"), LocalPref: 250,
		Communities: []string{"64512:9:9"},
	})

	comm, _ := parseCommunity("64512:666")
	extra, _ := parseCommunity("64512:100")
	var got seen
	eventually(t, "announced attributes", func() bool {
		g, ok := fromUs(collect(t, r.srv, v4Family), p.String())
		got = g
		return ok && g.lp == 250 && g.comms[comm] && g.comms[extra] && g.comms[noExport] && g.large["64512:1:50"] && g.nextHop == "192.0.2.2"
	})
	if !got.comms[comm] || !got.comms[extra] || !got.comms[noExport] || !got.large["64512:1:50"] {
		t.Fatalf("path = %+v", got)
	}
	absent(t, r.srv, extraOnly.String(), otherLarge.String())
}

func TestExportPolicyMatchesLargePacketeerCommunity(t *testing.T) {
	ctx := context.Background()
	r := newRouter(t)
	v := newView(t, r)
	eventually(t, "session", v.Ready)
	a := mustAnnouncer(t)
	const pack = "4200000000:1:666"
	if err := a.Bind(v.Server(), pack); err != nil {
		t.Fatal(err)
	}
	if got := definedList(t, v.Server(), api.DefinedType_LARGE_COMMUNITY, setName); !slices.Equal(got, []string{"^" + pack + "$"}) {
		t.Fatalf("large set = %v", got)
	}
	if got := definedList(t, v.Server(), api.DefinedType_COMMUNITY, setName); len(got) != 0 {
		t.Fatalf("standard set = %v", got)
	}

	p := netip.MustParsePrefix("203.0.113.0/24")
	if err := a.Announce(ctx, plugin.Route{
		Prefix: p, NextHop: netip.MustParseAddr("192.0.2.2"), LocalPref: 180, Provider: "transit-b",
		Communities: []string{pack, "64512:100"},
	}); err != nil {
		t.Fatal(err)
	}
	stdOnly := netip.MustParsePrefix("198.51.100.0/24")
	addLocal(t, v.Server(), plugin.Route{
		Prefix: stdOnly, NextHop: netip.MustParseAddr("192.0.2.1"), LocalPref: 250,
		Communities: []string{"64512:100"},
	})
	other := netip.MustParsePrefix("198.51.100.128/25")
	addLocal(t, v.Server(), plugin.Route{
		Prefix: other, NextHop: netip.MustParseAddr("192.0.2.1"), LocalPref: 250,
		Communities: []string{"4200000000:1:667"},
	})
	match := netip.MustParsePrefix("203.0.113.128/25")
	addLocal(t, v.Server(), plugin.Route{
		Prefix: match, NextHop: netip.MustParseAddr("192.0.2.1"), LocalPref: 250,
		Communities: []string{pack, "64512:9"},
	})

	extra, _ := parseCommunity("64512:100")
	var got seen
	eventually(t, "large packeteer community on the peer", func() bool {
		g, ok := fromUs(collect(t, r.srv, v4Family), p.String())
		got = g
		return ok && g.lp == 180 && g.large[pack] && g.comms[extra] && g.comms[noExport] && !g.comms[0]
	})
	if !got.large[pack] || !got.comms[noExport] || !got.comms[extra] {
		t.Fatalf("path = %+v", got)
	}
	eventually(t, "matching large community exported", func() bool {
		_, ok := fromUs(collect(t, r.srv, v4Family), match.String())
		return ok
	})
	absent(t, r.srv, stdOnly.String(), other.String())
}

func TestFlowSpecEncodesLargePacketeerCommunity(t *testing.T) {
	m := &MitigationAnnouncer{
		flowspec:  true,
		marker:    "64512:668",
		community: "4200000000:1:666",
		allow:     []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
	}
	path, err := m.flowSpecPath(plugin.FlowSpecRoute{
		Destination: netip.MustParsePrefix("198.51.100.0/24"),
		Action:      plugin.MitigationFlowSpecDrop,
		LocalPref:   250,
		Community:   "4200000000:1:666",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, comms, large := decodeAttrs(path.Pattrs)
	marker, _ := parseCommunity("64512:668")
	if !comms[marker] || !comms[noExport] || len(comms) != 2 || !large["4200000000:1:666"] || len(large) != 1 {
		t.Fatalf("comms = %v large = %v", comms, large)
	}
}
