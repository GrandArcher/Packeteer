package bmp

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	gobmp "github.com/osrg/gobgp/v3/pkg/packet/bmp"
	"gopkg.in/yaml.v3"
)

var quietLog = slog.New(slog.NewTextHandler(io.Discard, nil))

func cfg(t *testing.T, s string) plugin.Config {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(s), &n); err != nil {
		t.Fatal(err)
	}
	if len(n.Content) == 0 {
		return plugin.NewConfig(nil)
	}
	return plugin.NewConfig(n.Content[0])
}

func newStation(t *testing.T, s string) *Station {
	t.Helper()
	p, err := New(cfg(t, s), plugin.Env{Name: "bmp", Logger: quietLog})
	if err != nil {
		t.Fatal(err)
	}
	return p.(*Station)
}

func TestConfigValidation(t *testing.T) {
	bad := map[string]string{
		"no routers":    `listen: "127.0.0.1:0"`,
		"bad router":    "routers: [edge]",
		"dup router":    "routers: [192.0.2.254, 192.0.2.254]",
		"bad policy":    "routers: [192.0.2.254]\npolicy: both",
		"pre-policy":    "routers: [192.0.2.254]\npolicy: pre",
		"idle too low":  "routers: [192.0.2.254]\nidle_timeout: 1s",
		"idle negative": "routers: [192.0.2.254]\nidle_timeout: -1m",
		"bad listen":    "routers: [192.0.2.254]\nlisten: nope",
		"hostname":      "routers: [192.0.2.254]\nlisten: edge:11019",
		"port range":    "routers: [192.0.2.254]\nlisten: \":70000\"",
		"unknown field": "routers: [192.0.2.254]\nroute_server: true",
	}
	for name, c := range bad {
		if _, err := New(cfg(t, c), plugin.Env{Logger: quietLog}); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	s := newStation(t, "routers: [192.0.2.254]")
	if s.listen != ":11019" || !s.locRIB || s.idle != 0 {
		t.Fatalf("defaults: %+v", s)
	}
	s = newStation(t, "routers: [192.0.2.254]\npolicy: post\nloc_rib: false\nlisten: \"[::]:1790\"\nidle_timeout: 90s")
	if s.locRIB || s.listen != "[::]:1790" || s.idle != 90*time.Second {
		t.Fatalf("explicit: %+v", s)
	}
}

var router = netip.MustParseAddr("127.0.0.1")

func peer(a string, as uint32) plugin.RIBPeer {
	// The synthetic stream uses each peer's address as its BGP ID.
	return plugin.RIBPeer{Address: netip.MustParseAddr(a), ASN: as, BGPID: netip.MustParseAddr(a)}
}

func decodeAll(t *testing.T, msgs [][]byte) ([]plugin.RIBEvent, bool) {
	t.Helper()
	d := newDecoder(router, true, quietLog)
	var out []plugin.RIBEvent
	for i, m := range msgs {
		evs, stop := d.message(m)
		out = append(out, evs...)
		if stop {
			if i != len(msgs)-1 {
				t.Fatalf("stopped at message %d of %d", i, len(msgs))
			}
			return out, true
		}
	}
	return out, false
}

func TestDecodeRecordedStream(t *testing.T) {
	evs, stopped := decodeAll(t, recorded(t))
	if !stopped {
		t.Fatal("termination not seen")
	}
	a, b, ix := peer("192.0.2.21", 64496), peer("192.0.2.22", 64497), peer("192.0.2.23", 64498)
	loc := plugin.RIBPeer{LocRIB: true}
	type want struct {
		kind  plugin.RIBEventKind
		peer  plugin.RIBPeer
		paths string
	}
	wants := []want{
		{plugin.RIBPeerUp, a, ""},
		{plugin.RIBPeerUp, b, ""},
		{plugin.RIBPeerDown, ix, ""}, // add-path: ignored
		{plugin.RIBPaths, a, "+198.51.100.0/24 192.0.2.21 [64496 64500]"},
		{plugin.RIBPaths, b, "+198.51.100.0/24 192.0.2.22 [64497 64497 64500];+203.0.113.0/24 192.0.2.22 [64497 64497 64500]"},
		{plugin.RIBPaths, b, "+2001:db8:100::/48 2001:db8::22 [64497 64500]"},
		// pre-policy, Adj-RIB-Out, and the add-path peer produce nothing.
		{plugin.RIBPaths, loc, "+198.51.100.0/24 192.0.2.21 [64496 64500]"},
		{plugin.RIBPaths, b, "-203.0.113.0/24;-2001:db8:100::/48"},
		{plugin.RIBPeerDown, b, ""}, // undecodable UPDATE
		// transit-b's next update is ignored until a new peer up.
		{plugin.RIBPeerDown, a, ""},
	}
	if len(evs) != len(wants) {
		for _, e := range evs {
			t.Logf("%v %v %s", e.Kind, e.Peer, fmtPaths(e.Paths))
		}
		t.Fatalf("got %d events, want %d", len(evs), len(wants))
	}
	for i, w := range wants {
		e := evs[i]
		if e.Kind == plugin.RIBPaths && e.PostPolicy == e.Peer.LocRIB {
			t.Errorf("event %d: PostPolicy = %v for loc_rib=%v", i, e.PostPolicy, e.Peer.LocRIB)
		}
		if e.Kind != w.kind || e.Peer != w.peer || e.Router != router || fmtPaths(e.Paths) != w.paths {
			t.Errorf("event %d: got %v %+v %q, want %v %+v %q", i, e.Kind, e.Peer, fmtPaths(e.Paths), w.kind, w.peer, w.paths)
		}
	}
}

func TestDecodeWithoutLocRIB(t *testing.T) {
	d := newDecoder(router, false, quietLog)
	for _, m := range recorded(t) {
		evs, _ := d.message(m)
		for _, e := range evs {
			if e.Peer.LocRIB {
				t.Fatalf("loc_rib false still reported Loc-RIB: %+v", e)
			}
			if e.Kind == plugin.RIBPaths && slices.ContainsFunc(e.Paths, func(p plugin.RIBPath) bool {
				return p.Prefix == netip.MustParsePrefix("192.0.2.0/25")
			}) {
				t.Fatalf("pre-policy route reported: %+v", e)
			}
		}
	}
}

// A silent router is dropped after idle_timeout, and its paths with it.
func TestStationIdleTimeoutDropsRouter(t *testing.T) {
	st, sk := startStation(t, "127.0.0.1")
	st.idle = 200 * time.Millisecond
	c := dial(t, st)
	defer c.Close()
	if _, err := c.Write(recorded(t)[1]); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "router down after idle", func() bool {
		evs := sk.snapshot()
		return len(evs) == 2 && evs[0].Kind == plugin.RIBPeerUp && evs[1].Kind == plugin.RIBRouterDown
	})
}

func fmtPaths(ps []plugin.RIBPath) string {
	var s []string
	for _, p := range ps {
		if p.Withdraw {
			s = append(s, "-"+p.Prefix.String())
			continue
		}
		as := make([]string, len(p.ASPath))
		for i, a := range p.ASPath {
			as[i] = itoa(a)
		}
		s = append(s, "+"+p.Prefix.String()+" "+p.NextHop.String()+" ["+strings.Join(as, " ")+"]")
	}
	return strings.Join(s, ";")
}

func itoa(a uint32) string {
	if a == 0 {
		return "0"
	}
	var b []byte
	for a > 0 {
		b = append([]byte{byte('0' + a%10)}, b...)
		a /= 10
	}
	return string(b)
}

func TestReadMessagesRejectsBadFraming(t *testing.T) {
	for name, raw := range map[string][]byte{
		"version":   {1, 0, 0, 0, 6, 4},
		"short len": {3, 0, 0, 0, 5, 4},
		"huge len":  {3, 0x10, 0, 0, 0, 4},
		"truncated": {3, 0, 0, 0, 20, 4, 1, 2},
	} {
		err := readMessages(strings.NewReader(string(raw)), func([]byte) error { return nil })
		if err == nil || err == io.EOF {
			t.Errorf("%s: want framing error, got %v", name, err)
		}
	}
}

// sink collects events from the station goroutines.
type sink struct {
	mu  sync.Mutex
	evs []plugin.RIBEvent
}

func (s *sink) add(e plugin.RIBEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evs = append(s.evs, e)
}

func (s *sink) snapshot() []plugin.RIBEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.evs)
}

func waitFor(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func startStation(t *testing.T, routers string) (*Station, *sink) {
	t.Helper()
	st := newStation(t, "listen: \"127.0.0.1:0\"\nrouters: ["+routers+"]")
	sk := &sink{}
	st.SetRIBSink(sk.add)
	if err := st.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Stop(context.Background()) })
	return st, sk
}

func dial(t *testing.T, st *Station) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", st.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestStationReplaysRecordedStream(t *testing.T) {
	st, sk := startStation(t, "127.0.0.1")
	c := dial(t, st)
	defer c.Close()
	msgs := recorded(t)
	// Everything but the termination: the session stays up.
	for _, m := range msgs[:len(msgs)-1] {
		if _, err := c.Write(m); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "peer down for transit-a", func() bool {
		evs := sk.snapshot()
		return len(evs) > 0 && evs[len(evs)-1].Kind == plugin.RIBPeerDown && evs[len(evs)-1].Peer.Address == netip.MustParseAddr("192.0.2.21")
	})
	want, _ := decodeAll(t, msgs)
	if got := sk.snapshot(); len(got) != len(want) {
		t.Fatalf("station delivered %d events, decoder %d", len(got), len(want))
	}
	// Termination ends the session and drops every path from the router.
	if _, err := c.Write(msgs[len(msgs)-1]); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "router down", func() bool {
		evs := sk.snapshot()
		return evs[len(evs)-1].Kind == plugin.RIBRouterDown && evs[len(evs)-1].Router == router
	})
}

func TestStationDropsRouterOnDisconnect(t *testing.T) {
	st, sk := startStation(t, "127.0.0.1")
	c := dial(t, st)
	msgs := recorded(t)
	for _, m := range msgs[:fullRIB] {
		if _, err := c.Write(m); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "loc-rib path", func() bool {
		for _, e := range sk.snapshot() {
			if e.Peer.LocRIB {
				return true
			}
		}
		return false
	})
	_ = c.Close()
	waitFor(t, "router down", func() bool {
		evs := sk.snapshot()
		return evs[len(evs)-1].Kind == plugin.RIBRouterDown
	})
}

func TestStationStopDropsSessions(t *testing.T) {
	st, sk := startStation(t, "127.0.0.1")
	c := dial(t, st)
	defer c.Close()
	if _, err := c.Write(recorded(t)[1]); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "peer up", func() bool { return len(sk.snapshot()) == 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := st.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	evs := sk.snapshot()
	if evs[len(evs)-1].Kind != plugin.RIBRouterDown {
		t.Fatalf("Stop returned before the router's paths were dropped: %+v", evs)
	}
}

func TestStationRefusesUnlistedRouter(t *testing.T) {
	st, sk := startStation(t, "192.0.2.254")
	c := dial(t, st)
	defer c.Close()
	for _, m := range recorded(t) {
		_, _ = c.Write(m)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("station did not close a session from an unlisted address")
	}
	if evs := sk.snapshot(); len(evs) != 0 {
		t.Fatalf("unlisted router produced events: %+v", evs)
	}
}

func TestStationReconnectReplacesSession(t *testing.T) {
	st, sk := startStation(t, "127.0.0.1")
	msgs := recorded(t)
	c1 := dial(t, st)
	defer c1.Close()
	if _, err := c1.Write(msgs[1]); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "first peer up", func() bool { return len(sk.snapshot()) == 1 })
	c2 := dial(t, st)
	defer c2.Close()
	if _, err := c2.Write(msgs[1]); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "second peer up", func() bool { return len(sk.snapshot()) == 3 })
	evs := sk.snapshot()
	if evs[1].Kind != plugin.RIBRouterDown || evs[2].Kind != plugin.RIBPeerUp {
		t.Fatalf("old session's paths must be dropped before the new session reports: %+v", evs)
	}
}

// TestRecordedStreamIntoRIB replays the stream into the RIB view the way
// the controller wires it and checks prefix presence, the native path,
// and the per-provider route check at each checkpoint.
func TestRecordedStreamIntoRIB(t *testing.T) {
	v, err := rib.New(rib.Options{
		ASN: 64512, RouterID: netip.MustParseAddr("192.0.2.10"),
		Neighbors: []rib.Neighbor{{Address: netip.MustParseAddr("192.0.2.254")}},
		Providers: map[netip.Addr]string{
			netip.MustParseAddr("192.0.2.21"):   "transit-a",
			netip.MustParseAddr("192.0.2.22"):   "transit-b",
			netip.MustParseAddr("2001:db8::22"): "transit-b6",
			netip.MustParseAddr("192.0.2.23"):   "ix",
		},
		BMP:    map[string]string{"transit-a": rib.BMPOnly, "transit-b": rib.BMPPrefer, "transit-b6": rib.BMPPrefer},
		Logger: quietLog,
	})
	if err != nil {
		t.Fatal(err)
	}
	d := newDecoder(router, true, quietLog)
	msgs := recorded(t)
	replay := func(from, to int) {
		for _, m := range msgs[from:to] {
			evs, _ := d.message(m)
			for _, e := range evs {
				v.ApplyRIB(e)
			}
		}
	}
	p1 := netip.MustParsePrefix("198.51.100.0/24")
	p2 := netip.MustParsePrefix("203.0.113.0/24")
	p6 := netip.MustParsePrefix("2001:db8:100::/48")
	never := netip.MustParsePrefix("192.0.2.0/25") // pre-policy only

	check := func(step string, p netip.Prefix, provider string, wantChecked, wantOK bool) {
		t.Helper()
		c, ok := v.RouteCheck(p, provider)
		if c != wantChecked || ok != wantOK {
			t.Errorf("%s: RouteCheck(%s, %s) = %v,%v want %v,%v", step, p, provider, c, ok, wantChecked, wantOK)
		}
	}

	replay(0, fullRIB)
	rt, ok := v.Exact(p1)
	if !ok || rt.Provider != "transit-a" || !rt.LocRIB || rt.Source != rib.SourceBMP {
		t.Fatalf("native for %s: %+v %v (want the Loc-RIB path via transit-a)", p1, rt, ok)
	}
	if paths := v.Paths(p1); len(paths) != 3 {
		t.Fatalf("paths for %s: %+v (want transit-a, transit-b, loc-rib; the add-path peer ignored)", p1, paths)
	}
	if rt, ok := v.Exact(p2); !ok || rt.Provider != "transit-b" {
		t.Fatalf("%s: %+v %v (inactive path via transit-b only)", p2, rt, ok)
	}
	if _, ok := v.Exact(p6); !ok {
		t.Fatalf("%s missing", p6)
	}
	if _, ok := v.Exact(never); ok {
		t.Fatalf("%s came from pre-policy and must be ignored", never)
	}
	check("full", p1, "transit-b", true, true)
	check("full", p1, "transit-a", true, true)
	check("full", p2, "transit-a", true, false) // only: no path, refused
	check("full", p2, "transit-b", true, true)
	check("full", p1, "ix", false, false) // bmp off: no check

	replay(fullRIB, withdrawn)
	if _, ok := v.Exact(p2); ok {
		t.Fatalf("%s still present after withdraw and peer drop", p2)
	}
	if _, ok := v.Exact(p6); ok {
		t.Fatalf("%s still present after MP_UNREACH", p6)
	}
	// transit-b's session was dropped: prefer falls back to no check.
	check("transit-b dropped", p1, "transit-b", false, false)

	replay(withdrawn, len(msgs))
	// Loc-RIB still has it, but no router reports transit-a's session up,
	// so the only provider fails its route check.
	check("transit-a down", p1, "transit-a", true, false)
	if rt, ok := v.Exact(p1); !ok || !rt.LocRIB {
		t.Fatalf("after peer down %s: %+v %v", p1, rt, ok)
	}
	v.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBRouterDown, Router: router})
	if n := v.Len(); n != 0 {
		t.Fatalf("router down left %d prefixes: %+v", n, v.Routes())
	}
	check("router down", p1, "transit-a", true, false)
	if peers := v.BMPPeers(); len(peers) != 0 {
		t.Fatalf("router down left peers: %+v", peers)
	}
}

// The decoder passes the peer's BGP ID and the path communities through,
// so the RIB view can drop Packeteer's own session and tagged routes.
func TestDecodeBGPIDAndCommunities(t *testing.T) {
	d := newDecoder(router, true, quietLog)
	self := peerHeader(t, gobmp.BMP_PEER_TYPE_GLOBAL, gobmp.BMP_PEER_FLAG_POST_POLICY, "192.0.2.10", 64512, "192.0.2.10")
	upd := v4Update("192.0.2.22", []uint32{64497}, "198.51.100.0/24")
	body := upd.Body.(*bgp.BGPUpdate)
	body.PathAttributes = append(body.PathAttributes, bgp.NewPathAttributeCommunities([]uint32{64512<<16 | 666, uint32(bgp.COMMUNITY_NO_EXPORT)}))
	evs, _ := d.message(ser(t, gobmp.NewBMPRouteMonitoring(*self, upd)))
	if len(evs) != 1 || len(evs[0].Paths) != 1 {
		t.Fatalf("events = %+v", evs)
	}
	if got := evs[0].Peer.BGPID; got != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("BGPID = %v", got)
	}
	if got := evs[0].Paths[0].Communities; len(got) != 2 || got[0] != 64512<<16|666 {
		t.Fatalf("communities = %v", got)
	}
}

// Add-path changes the NLRI of routes the router receives only when the
// router offers Receive and the peer offers Send. FRR offers Receive by
// default on every session; that alone must not drop the peer.
func TestAddPathNegotiation(t *testing.T) {
	openWith := func(mode bgp.BGPAddPathMode) *bgp.BGPMessage {
		caps := []bgp.ParameterCapabilityInterface{bgp.NewCapMultiProtocol(bgp.RF_IPv4_UC)}
		if mode != 0 {
			caps = append(caps, bgp.NewCapAddPath([]*bgp.CapAddPathTuple{bgp.NewCapAddPathTuple(bgp.RF_IPv4_UC, mode)}))
		}
		return bgp.NewBGPOpenMessage(64512, 90, "192.0.2.254", []bgp.OptionParameterInterface{bgp.NewOptionParameterCapability(caps)})
	}
	cases := []struct {
		name          string
		local, remote bgp.BGPAddPathMode
		want          bool
	}{
		{"none", 0, 0, false},
		{"frr default (receive both sides)", bgp.BGP_ADD_PATH_RECEIVE, bgp.BGP_ADD_PATH_RECEIVE, false},
		{"router sends only", bgp.BGP_ADD_PATH_SEND, bgp.BGP_ADD_PATH_RECEIVE, false},
		{"router receives, peer sends", bgp.BGP_ADD_PATH_RECEIVE, bgp.BGP_ADD_PATH_SEND, true},
		{"both", bgp.BGP_ADD_PATH_BOTH, bgp.BGP_ADD_PATH_BOTH, true},
		{"peer silent", bgp.BGP_ADD_PATH_BOTH, 0, false},
	}
	ph := peerHeader(t, gobmp.BMP_PEER_TYPE_GLOBAL, 0, "192.0.2.21", 64496, "192.0.2.21")
	for _, c := range cases {
		up := gobmp.NewBMPPeerUpNotification(*ph, "192.0.2.254", 179, 40001, openWith(c.local), openWith(c.remote))
		got := addPath(up.Body.(*gobmp.BMPPeerUpNotification)) != ""
		if got != c.want {
			t.Errorf("%s: add-path = %v, want %v", c.name, got, c.want)
		}
	}
}
