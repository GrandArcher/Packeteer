package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/internal/plugins/ribsource/bmp"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// startStation runs Packeteer's BMP station on a free loopback port, fed
// into a view learned over BMP alone (#237), as the bmp profile's config
// sets them up.
func startStation(t *testing.T) (*bmp.Station, *rib.View, int) {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal([]byte("listen: \"127.0.0.1:0\"\nrouters: ["+routerAddrs[0]+"]\n"), &n); err != nil {
		t.Fatal(err)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	src, err := bmp.New(plugin.NewConfig(n.Content[0]), plugin.Env{Name: "bmp", Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	providers := map[netip.Addr]string{}
	usage := map[string]string{}
	for k, name := range []string{"transit-a", "transit-b"} {
		providers[netip.MustParseAddr(nextHopsV4[k])] = name
		providers[netip.MustParseAddr(nextHopsV6[k])] = name + "6"
		usage[name], usage[name+"6"] = rib.BMPOnly, rib.BMPOnly
	}
	view, err := rib.New(rib.Options{ASN: labASN, RouterID: netip.MustParseAddr("192.0.2.10"),
		Providers: providers, BMP: usage, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	src.SetRIBSink(view.ApplyRIB)
	st := src.(*bmp.Station)
	if err := st.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(st.Addr().String())
	p, _ := strconv.Atoi(port)
	return st, view, p
}

// The bmp profile's router feeds the real station: every entry is learned
// with an Adj-RIB-In path from each provider, every provider peer is
// reported up, churn withdraws and announces again, and the view goes not
// ready, empty, when the station closes the feed.
func TestBMPRouterFeedsStation(t *testing.T) {
	st, view, port := startStation(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tbl := newTable(v4Count + 3000)
	f := &fleet{adv: newAdvertised()}
	rt := newBMPRouter(0, port, tbl, f.adv)
	t.Cleanup(rt.stop)
	f.routers = []*router{rt}
	if err := rt.accept(); err != nil {
		t.Skipf("loopback %s not usable: %v", routerAddrs[0], err)
	}
	go rt.serve(ctx, make(chan struct{}))
	eventually(t, "the whole table", func() bool { return view.Len() == tbl.n })
	if !view.Ready() {
		t.Fatal("view not ready with the BMP feed up")
	}
	if peers := view.BMPPeers(); len(peers) != 2*bmpProviders {
		t.Fatalf("BMP peers = %+v, want each provider in both families", peers)
	}
	for _, i := range []int{0, 7, v4Count, tbl.n - 1} {
		six := ""
		if i >= v4Count {
			six = "6"
		}
		// Paths sort the peers by address.
		ps := view.Paths(tbl.prefix(i))
		if len(ps) != 2 || ps[0].Provider != "transit-a"+six || ps[1].Provider != "transit-b"+six ||
			ps[0].LocRIB || ps[1].LocRIB {
			t.Fatalf("entry %d paths = %+v, want one Adj-RIB-In path per provider", i, ps)
		}
		if checked, ok := view.RouteCheck(tbl.prefix(i), "transit-b"+six); !checked || !ok {
			t.Fatalf("entry %d: transit-b%s route check = %v %v", i, six, checked, ok)
		}
	}

	f.withdraw(v4Count+5, v4Count+15)
	eventually(t, "churn withdraw", func() bool { return view.Len() == tbl.n-10 })
	f.announce(v4Count+5, v4Count+15)
	eventually(t, "churn announce", func() bool { return view.Len() == tbl.n })

	if err := st.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if view.Ready() || view.Len() != 0 {
		t.Fatalf("after the feed closed: ready=%v len=%d", view.Ready(), view.Len())
	}
	eventually(t, "the router noticing the close", func() bool { return !rt.established() && rt.drops.Load() == 1 })
}

func TestBMPProfileValidation(t *testing.T) {
	base := Profile{BMP: true, Prefixes: 20000, Duration: 60e9, Warmup: 10e9, Sample: 2e9}
	if err := base.validate(); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]Profile{
		"inject":   func() Profile { q := base; q.Inject = 10; return q }(),
		"sessions": func() Profile { q := base; q.Sessions = 2; return q }(),
	} {
		if err := p.validate(); err == nil {
			t.Errorf("%s: a bmp profile with %s was accepted", name, name)
		}
	}
}
