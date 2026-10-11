package bmp

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	gobmp "github.com/osrg/gobgp/v3/pkg/packet/bmp"
)

const leakASN = 64500

func newLeak(t *testing.T, yaml string) *LeakStation {
	t.Helper()
	p, err := NewLeakSource(cfg(t, yaml), plugin.Env{ASN: leakASN, Logger: quietLog})
	if err != nil {
		t.Fatal(err)
	}
	return p.(*LeakStation)
}

func TestLeakConfigValidation(t *testing.T) {
	bad := map[string]string{
		"no routers":    `listen: "127.0.0.1:0"`,
		"bad router":    "external_routers: [edge]",
		"dup router":    "own_routers: [192.0.2.254, 192.0.2.254]",
		"both lists":    "external_routers: [192.0.2.254]\nown_routers: [192.0.2.254]",
		"idle too low":  "own_routers: [192.0.2.254]\nidle_timeout: 1s",
		"bad listen":    "own_routers: [192.0.2.254]\nlisten: nope",
		"unknown field": "own_routers: [192.0.2.254]\nloc_rib: true",
	}
	for name, c := range bad {
		if _, err := NewLeakSource(cfg(t, c), plugin.Env{ASN: leakASN, Logger: quietLog}); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	l := newLeak(t, "own_routers: [192.0.2.254]")
	if l.st.listen != ":11020" || !l.st.adjOut || l.st.locRIB {
		t.Fatalf("defaults %+v", l.st)
	}
}

type sightings struct {
	mu  sync.Mutex
	got []plugin.LeakSighting
}

func (s *sightings) add(x plugin.LeakSighting) { s.mu.Lock(); s.got = append(s.got, x); s.mu.Unlock() }
func (s *sightings) snap() []plugin.LeakSighting {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]plugin.LeakSighting(nil), s.got...)
}

func tagged(nh string, path []uint32, comms []uint32, nlri ...string) *bgp.BGPMessage {
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, path)}),
		bgp.NewPathAttributeNextHop(nh),
		bgp.NewPathAttributeCommunities(comms),
	}
	var n []*bgp.IPAddrPrefix
	for _, s := range nlri {
		n = append(n, prefix4(s))
	}
	return bgp.NewBGPUpdateMessage(nil, attrs, n)
}

func dialFrom(t *testing.T, st *Station, local string) net.Conn {
	t.Helper()
	c, err := net.DialTCP("tcp", &net.TCPAddr{IP: net.ParseIP(local)}, st.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLeakStationReadsOutsideViewAndOwnExport(t *testing.T) {
	l := newLeak(t, "listen: \"127.0.0.1:0\"\nexternal_routers: [127.0.0.2]\nown_routers: [127.0.0.1]")
	var sg sightings
	l.SetLeakSink(sg.add)
	if l.Healthy() {
		t.Fatal("healthy before any router connected")
	}
	if err := l.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer l.Stop(context.Background())

	post := uint8(gobmp.BMP_PEER_FLAG_POST_POLICY)
	out := post | gobmp.BMP_PEER_FLAG_ADJ_RIB_TYP
	hdr := func(flags uint8, addr string, as uint32) *gobmp.BMPPeerHeader {
		return peerHeader(t, gobmp.BMP_PEER_TYPE_GLOBAL, flags, addr, as, addr)
	}
	community := uint32(leakASN<<16 | 666)

	// The edge router: Adj-RIB-Out toward an eBGP peer is read; toward the
	// iBGP controller session, and its Adj-RIB-In, are not.
	edge := dialFrom(t, l.st, "127.0.0.1")
	defer edge.Close()
	for _, m := range [][]byte{
		ser(t, gobmp.NewBMPRouteMonitoring(*hdr(out, "192.0.2.10", leakASN), tagged("192.0.2.254", []uint32{64496}, []uint32{community}, "198.51.100.0/24"))),
		ser(t, gobmp.NewBMPRouteMonitoring(*hdr(post, "192.0.2.9", 64511), tagged("192.0.2.9", []uint32{64511}, []uint32{community}, "198.51.100.128/25"))),
		ser(t, gobmp.NewBMPRouteMonitoring(*hdr(out, "192.0.2.9", 64511), tagged("192.0.2.254", []uint32{64496}, []uint32{community}, "203.0.113.0/24"))),
	} {
		if _, err := edge.Write(m); err != nil {
			t.Fatal(err)
		}
	}
	// An outside router: its post-policy Adj-RIB-In is read; pre-policy
	// and its Adj-RIB-Out are not.
	ext := dialFrom(t, l.st, "127.0.0.2")
	defer ext.Close()
	for _, m := range [][]byte{
		ser(t, gobmp.NewBMPRouteMonitoring(*hdr(0, "192.0.2.1", leakASN), tagged("192.0.2.1", []uint32{leakASN, 64496}, nil, "192.0.2.0/25"))),
		ser(t, gobmp.NewBMPRouteMonitoring(*hdr(out, "192.0.2.1", leakASN), tagged("192.0.2.1", []uint32{leakASN}, nil, "192.0.2.128/25"))),
		ser(t, gobmp.NewBMPRouteMonitoring(*hdr(post, "192.0.2.1", leakASN), tagged("192.0.2.1", []uint32{leakASN, 64496}, nil, "203.0.113.0/24"))),
	} {
		if _, err := ext.Write(m); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "two sightings", func() bool { return len(sg.snap()) >= 2 })
	waitFor(t, "healthy", l.Healthy)
	// Each router's wanted message is its last, and a session is read in
	// order: the unwanted ones before it were already dropped.
	got := sg.snap()
	if len(got) != 2 {
		t.Fatalf("got %d sightings: %+v", len(got), got)
	}
	by := map[string]plugin.LeakSighting{}
	for _, s := range got {
		by[s.Seen] = s
	}
	e, x := by["127.0.0.1"], by["127.0.0.2"]
	if !e.OurExport || e.Prefix != netip.MustParsePrefix("203.0.113.0/24") || len(e.Communities) != 1 || e.Communities[0] != community {
		t.Fatalf("edge sighting %+v", e)
	}
	if x.OurExport || x.Prefix != netip.MustParsePrefix("203.0.113.0/24") || len(x.ASPath) != 2 || x.ASPath[0] != leakASN {
		t.Fatalf("outside sighting %+v", x)
	}

	edge.Close()
	ext.Close()
	waitFor(t, "unhealthy after both routers left", func() bool { return !l.Healthy() })
}

func TestLeakStationRefusesUnlistedRouter(t *testing.T) {
	l := newLeak(t, "listen: \"127.0.0.1:0\"\nexternal_routers: [127.0.0.2]")
	if err := l.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer l.Stop(context.Background())
	c := dialFrom(t, l.st, "127.0.0.1")
	defer c.Close()
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := c.Read(buf); err == nil || strings.Contains(err.Error(), "timeout") {
		t.Fatalf("session from an unlisted address stayed open: %v", err)
	}
	if l.Healthy() {
		t.Fatal("healthy with only a refused session")
	}
}

func TestRIBSourceStillIgnoresAdjRIBOut(t *testing.T) {
	d := newDecoder(router, true, quietLog)
	out := peerHeader(t, gobmp.BMP_PEER_TYPE_GLOBAL, gobmp.BMP_PEER_FLAG_ADJ_RIB_TYP|gobmp.BMP_PEER_FLAG_POST_POLICY, "192.0.2.9", 64511, "192.0.2.9")
	evs, _ := d.message(ser(t, gobmp.NewBMPRouteMonitoring(*out, v4Update("192.0.2.254", []uint32{64511}, "203.0.113.0/24"))))
	if len(evs) != 0 {
		t.Fatalf("the RIB source read Adj-RIB-Out: %+v", evs)
	}
}
