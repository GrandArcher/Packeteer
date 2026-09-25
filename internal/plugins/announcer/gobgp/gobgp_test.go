package gobgp

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	gobgplog "github.com/osrg/gobgp/v3/pkg/log"
	"github.com/osrg/gobgp/v3/pkg/server"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const asn = 64512

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type nopLogger struct{}

func (nopLogger) Panic(string, gobgplog.Fields) {}
func (nopLogger) Fatal(string, gobgplog.Fields) {}
func (nopLogger) Error(string, gobgplog.Fields) {}
func (nopLogger) Warn(string, gobgplog.Fields)  {}
func (nopLogger) Info(string, gobgplog.Fields)  {}
func (nopLogger) Debug(string, gobgplog.Fields) {}
func (nopLogger) SetLevel(gobgplog.LogLevel)    {}
func (nopLogger) GetLevel() gobgplog.LogLevel   { return gobgplog.PanicLevel }

type fakeRouter struct {
	srv  *server.BgpServer
	port int
}

func newRouter(t *testing.T) *fakeRouter {
	t.Helper()
	r := &fakeRouter{srv: server.NewBgpServer(server.LoggerOption(&nopLogger{})), port: freePort(t)}
	go r.srv.Serve()
	ctx := context.Background()
	if err := r.srv.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn: asn, RouterId: "192.0.2.254", ListenPort: int32(r.port), ListenAddresses: []string{"127.0.0.1"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := r.srv.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.2", PeerAsn: asn},
		Transport: &api.Transport{PassiveMode: true},
		AfiSafis: []*api.AfiSafi{
			{Config: &api.AfiSafiConfig{Family: v4Family, Enabled: true}},
			{Config: &api.AfiSafiConfig{Family: v6Family, Enabled: true}},
		},
	}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.srv.StopBgp(context.Background(), &api.StopBgpRequest{})
		r.srv.Stop()
	})
	return r
}

func newView(t *testing.T, r *fakeRouter) *rib.View {
	t.Helper()
	v, err := rib.New(rib.Options{
		ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"), ListenPort: -1,
		Neighbors: []rib.Neighbor{{Address: netip.MustParseAddr("127.0.0.1"), Port: uint16(r.port),
			LocalAddress: netip.MustParseAddr("127.0.0.2")}},
		Providers: map[netip.Addr]string{netip.MustParseAddr("192.0.2.1"): "transit-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Stop(context.Background()) })
	return v
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

type seen struct {
	prefix  string
	nextHop string
	lp      uint32
	comms   map[uint32]bool
	fromUs  bool
}

func collect(t *testing.T, srv *server.BgpServer, fam *api.Family) []seen {
	t.Helper()
	var out []seen
	err := srv.ListPath(context.Background(), &api.ListPathRequest{TableType: api.TableType_GLOBAL, Family: fam}, func(d *api.Destination) {
		for _, p := range d.Paths {
			s := seen{comms: map[uint32]bool{}, fromUs: p.NeighborIp == "127.0.0.2"}
			if pref, ok := decodePrefix(p.Nlri); ok {
				s.prefix = pref.String()
			}
			s.nextHop, s.lp, s.comms = decodeAttrs(p.Pattrs)
			out = append(out, s)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func fromUs(paths []seen, prefix string) (seen, bool) {
	for _, p := range paths {
		if p.fromUs && p.prefix == prefix {
			return p, true
		}
	}
	return seen{}, false
}

func decodePrefix(a *anypb.Any) (netip.Prefix, bool) {
	if a == nil {
		return netip.Prefix{}, false
	}
	var n api.IPAddressPrefix
	if err := a.UnmarshalTo(&n); err != nil {
		return netip.Prefix{}, false
	}
	p, err := netip.ParsePrefix(n.Prefix + "/" + itoa(int(n.PrefixLen)))
	if err != nil {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func decodeAttrs(attrs []*anypb.Any) (string, uint32, map[uint32]bool) {
	var nh string
	var lp uint32
	comms := map[uint32]bool{}
	for _, a := range attrs {
		var nhA api.NextHopAttribute
		var mp api.MpReachNLRIAttribute
		var lpa api.LocalPrefAttribute
		var ca api.CommunitiesAttribute
		switch {
		case a.MessageIs(&nhA):
			if a.UnmarshalTo(&nhA) == nil {
				nh = nhA.NextHop
			}
		case a.MessageIs(&mp):
			if a.UnmarshalTo(&mp) == nil && len(mp.NextHops) > 0 {
				nh = mp.NextHops[0]
			}
		case a.MessageIs(&lpa):
			if a.UnmarshalTo(&lpa) == nil {
				lp = lpa.LocalPref
			}
		case a.MessageIs(&ca):
			if a.UnmarshalTo(&ca) == nil {
				for _, c := range ca.Communities {
					comms[c] = true
				}
			}
		}
	}
	return nh, lp, comms
}

func mustAnnouncer(t *testing.T) *Announcer {
	t.Helper()
	a, err := New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	return a.(*Announcer)
}

func TestAnnounceWithdrawNoLeakNoGracefulRestart(t *testing.T) {
	ctx := context.Background()
	r := newRouter(t)
	// A route the router originated. Packeteer must not reflect it.
	nlri, _ := anypb.New(&api.IPAddressPrefix{Prefix: "198.51.100.0", PrefixLen: 24})
	origin, _ := anypb.New(&api.OriginAttribute{Origin: 0})
	nh, _ := anypb.New(&api.NextHopAttribute{NextHop: "192.0.2.1"})
	if _, err := r.srv.AddPath(ctx, &api.AddPathRequest{Path: &api.Path{
		Family: v4Family, Nlri: nlri, Pattrs: []*anypb.Any{origin, nh},
	}}); err != nil {
		t.Fatal(err)
	}
	v := newView(t, r)
	eventually(t, "session", v.Ready)
	eventually(t, "learned route", func() bool {
		_, ok := v.Exact(netip.MustParsePrefix("198.51.100.0/24"))
		return ok
	})

	a := mustAnnouncer(t)
	if err := a.Announce(ctx, plugin.Route{
		Prefix: netip.MustParsePrefix("203.0.113.0/24"), NextHop: netip.MustParseAddr("192.0.2.2"),
		LocalPref: 250, Communities: []string{"64512:666"},
	}); err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("unbound announce err = %v", err)
	}
	if err := a.Bind(v.Server(), "64512:666"); err != nil {
		t.Fatal(err)
	}

	// Untagged local path: the export policy must keep it off the wire.
	bad, _ := anypb.New(&api.IPAddressPrefix{Prefix: "192.0.2.128", PrefixLen: 25})
	if _, err := v.Server().AddPath(ctx, &api.AddPathRequest{Path: &api.Path{
		Family: v4Family, Nlri: bad, Pattrs: []*anypb.Any{origin, nh},
	}}); err != nil {
		t.Fatal(err)
	}

	if err := a.Announce(ctx, plugin.Route{
		Prefix: netip.MustParsePrefix("203.0.113.0/24"), NextHop: netip.MustParseAddr("192.0.2.2"),
		LocalPref: 250, Communities: []string{"64512:666"}, Provider: "transit-b",
	}); err != nil {
		t.Fatal(err)
	}
	v6 := plugin.Route{
		Prefix: netip.MustParsePrefix("2001:db8:1::/48"), NextHop: netip.MustParseAddr("2001:db8::2"),
		LocalPref: 250, Communities: []string{"64512:666"},
	}
	if err := a.Announce(ctx, v6); err != nil {
		t.Fatal(err)
	}

	var got seen
	eventually(t, "v4 route on the router", func() bool {
		g, ok := fromUs(collect(t, r.srv, v4Family), "203.0.113.0/24")
		got = g
		return ok
	})
	comm, err := parseCommunity("64512:666")
	if err != nil {
		t.Fatal(err)
	}
	if got.nextHop != "192.0.2.2" || got.lp != 250 || !got.comms[comm] || !got.comms[noExport] {
		t.Fatalf("announced path = %+v comms=%v", got, got.comms)
	}
	eventually(t, "v6 route on the router", func() bool {
		g, ok := fromUs(collect(t, r.srv, v6Family), "2001:db8:1::/48")
		if !ok || g.nextHop != "2001:db8::2" || g.lp != 250 || !g.comms[comm] || !g.comms[noExport] {
			got = g
			return false
		}
		return true
	})

	for _, p := range collect(t, r.srv, v4Family) {
		if p.fromUs && (p.prefix == "192.0.2.128/25" || p.prefix == "198.51.100.0/24") {
			t.Fatalf("leaked %s to the router", p.prefix)
		}
	}

	// No graceful restart on the session Packeteer opened.
	err = v.Server().ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) {
		gr := p.GetGracefulRestart()
		if gr != nil && (gr.Enabled || gr.LocalRestarting || gr.LonglivedEnabled) {
			t.Errorf("graceful restart enabled: %+v", gr)
		}
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := a.Withdraw(ctx, netip.MustParsePrefix("203.0.113.0/24")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "v4 withdraw", func() bool {
		_, ok := fromUs(collect(t, r.srv, v4Family), "203.0.113.0/24")
		return !ok
	})

	if err := a.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	eventually(t, "withdraw all on stop", func() bool {
		_, ok := fromUs(collect(t, r.srv, v6Family), "2001:db8:1::/48")
		return !ok
	})
}

func TestRefusesUntaggedOrUnpref(t *testing.T) {
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
	cases := []plugin.Route{
		{Prefix: p, NextHop: nh, LocalPref: 250},
		{Prefix: p, NextHop: nh, LocalPref: 250, Communities: []string{"64512:1"}},
		{Prefix: p, NextHop: nh, Communities: []string{"64512:666"}},
		{Prefix: p, NextHop: netip.MustParseAddr("2001:db8::1"), LocalPref: 250, Communities: []string{"64512:666"}},
	}
	for _, rt := range cases {
		if err := a.Announce(ctx, rt); err == nil {
			t.Fatalf("announced invalid route %+v", rt)
		}
	}
	if n := len(collect(t, r.srv, v4Family)); n != 0 {
		// The router may have nothing; any path from us is a failure.
		for _, s := range collect(t, r.srv, v4Family) {
			if s.fromUs {
				t.Fatalf("invalid route was exported: %+v", s)
			}
		}
	}
}

func TestConfigRejectsUnknown(t *testing.T) {
	c, err := plugin.ConfigFromYAML("local_pref: 1\n")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(c, plugin.Env{}); err == nil {
		t.Fatal("want unknown field error")
	}
}
