package bmp

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	gobmp "github.com/osrg/gobgp/v3/pkg/packet/bmp"
)

// shortNextHop is a BGP UPDATE for 192.0.2.0/24 whose NEXT_HOP is 2 bytes
// instead of 4: the trigger of GO-2026-4736 (GoBGP issue 3305).
var shortNextHop = append(bytes.Repeat([]byte{0xff}, 16),
	0x00, 0x27, // message length 39
	bgp.BGP_MSG_UPDATE,
	0x00, 0x00, // no withdrawn routes
	0x00, 0x0c, // 12 bytes of path attributes
	0x40, 0x01, 0x01, 0x00, // ORIGIN IGP
	0x40, 0x02, 0x00, // empty AS_PATH
	0x40, 0x03, 0x02, 0xc0, 0x00, // NEXT_HOP with length 2
	0x18, 0xc0, 0x00, 0x02, // NLRI 192.0.2.0/24
)

// logBuffer is a log sink that station goroutines and the test share.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func startLoggedStation(t *testing.T, fn func(plugin.RIBEvent)) (*Station, *logBuffer) {
	t.Helper()
	lb := &logBuffer{}
	p, err := New(cfg(t, "listen: \"127.0.0.1:0\"\nrouters: [127.0.0.1]"), plugin.Env{Logger: slog.New(slog.NewTextHandler(lb, nil))})
	if err != nil {
		t.Fatal(err)
	}
	st := p.(*Station)
	st.SetRIBSink(fn)
	if err := st.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Stop(context.Background()) })
	return st, lb
}

// The station must never reach the GoBGP code that panics on this UPDATE.
func TestShortNextHopPanicsGoBGPValidator(t *testing.T) {
	m, err := bgp.ParseBGPMessage(shortNextHop)
	if err == nil || m == nil {
		t.Fatalf("parse: msg %v err %v, want a partial message and an error", m, err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("bgp.ValidateUpdateMsg did not panic: GoBGP may be fixed, recheck GO-2026-4736 in .govulncheck-ignore")
		}
	}()
	_, _ = bgp.ValidateUpdateMsg(m.Body.(*bgp.BGPUpdate), map[bgp.RouteFamily]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: 0}, false, false, false)
}

func TestStationSurvivesShortNextHop(t *testing.T) {
	sk := &sink{}
	st, lb := startLoggedStation(t, sk.add)
	c := dial(t, st)
	defer c.Close()
	msgs := recorded(t)
	a := peerHeader(t, gobmp.BMP_PEER_TYPE_GLOBAL, gobmp.BMP_PEER_FLAG_POST_POLICY, "192.0.2.21", 64496, "192.0.2.21")
	for _, m := range [][]byte{msgs[1], msgs[4], rawMessage(t, gobmp.BMP_MSG_ROUTE_MONITORING, a, shortNextHop), msgs[1], msgs[4]} {
		if _, err := c.Write(m); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "five events", func() bool { return len(sk.snapshot()) >= 5 })
	transitA := peer("192.0.2.21", 64496)
	want := []plugin.RIBEventKind{plugin.RIBPeerUp, plugin.RIBPaths, plugin.RIBPeerDown, plugin.RIBPeerUp, plugin.RIBPaths}
	evs := sk.snapshot()
	for i, e := range evs {
		if i >= len(want) || e.Kind != want[i] || e.Peer != transitA {
			t.Fatalf("event %d: %+v; want %v for transit-a", i, e, want)
		}
	}
	if evs[2].Reason != "undecodable route monitoring" {
		t.Fatalf("peer down reason %q", evs[2].Reason)
	}
	// The peer's paths come back after its next peer up, on the same session.
	if p := evs[4].Paths; len(p) != 1 || p[0].Prefix != netip.MustParsePrefix("198.51.100.0/24") {
		t.Fatalf("paths after recovery: %s", fmtPaths(p))
	}
	if st.sessions() != 1 {
		t.Fatalf("sessions %d, want the router still connected", st.sessions())
	}
	logs := lb.String()
	if !strings.Contains(logs, "undecodable route monitoring; dropping peer") || !strings.Contains(logs, "nexthop length isn't correct") {
		t.Fatalf("missing decode warning in log:\n%s", logs)
	}
}

func TestStationRecoversPanicPerRouter(t *testing.T) {
	sk := &sink{}
	var panicked atomic.Bool
	st, lb := startLoggedStation(t, func(e plugin.RIBEvent) {
		if e.Kind == plugin.RIBPaths && !panicked.Swap(true) {
			panic("sink bug")
		}
		sk.add(e)
	})
	msgs := recorded(t)
	c := dial(t, st)
	defer c.Close()
	for _, m := range [][]byte{msgs[1], msgs[4]} {
		if _, err := c.Write(m); err != nil {
			t.Fatal(err)
		}
	}
	// The station closes the session and drops the router's paths.
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("read after panic: %v, want EOF", err)
	}
	waitFor(t, "router down", func() bool {
		evs := sk.snapshot()
		return len(evs) > 0 && evs[len(evs)-1].Kind == plugin.RIBRouterDown
	})
	if logs := lb.String(); !strings.Contains(logs, "panic handling a message") || !strings.Contains(logs, "sink bug") {
		t.Fatalf("panic not logged:\n%s", logs)
	}
	// The process and the listener are still up: the router reconnects.
	c2 := dial(t, st)
	defer c2.Close()
	for _, m := range [][]byte{msgs[1], msgs[4]} {
		if _, err := c2.Write(m); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "paths after reconnect", func() bool {
		evs := sk.snapshot()
		return evs[len(evs)-1].Kind == plugin.RIBPaths
	})
}

// GoBGP recovers its own panic on a peer up too short for its fields and
// returns the empty message with an error. It must not count as a peer up.
func TestDecodeShortPeerUpDropsPeer(t *testing.T) {
	msgs := recorded(t)
	d := newDecoder(router, true, quietLog)
	ix := peer("192.0.2.23", 64498)
	if evs, _ := d.message(msgs[3]); len(evs) != 1 || evs[0].Kind != plugin.RIBPeerUp || d.addPath[ix] == nil {
		t.Fatalf("ix peer up: %+v", evs)
	}
	ixUp := peerHeader(t, gobmp.BMP_PEER_TYPE_GLOBAL, 0, "192.0.2.23", 64498, "192.0.2.23")
	evs, _ := d.message(rawMessage(t, gobmp.BMP_MSG_PEER_UP_NOTIFICATION, ixUp, make([]byte, 10)))
	if len(evs) != 1 || evs[0].Kind != plugin.RIBPeerDown || evs[0].Peer != ix || evs[0].Reason != "undecodable message" {
		t.Fatalf("short peer up: %+v, want a peer down", evs)
	}
	// Its routes stay ignored until a whole peer up arrives.
	if evs, _ := d.message(msgs[9]); len(evs) != 0 {
		t.Fatalf("route after short peer up: %+v", evs)
	}
}
