package exchange

import (
	"net/netip"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var (
	monRouter = netip.MustParseAddr("192.0.2.254")
	monPeer   = netip.MustParseAddr("203.0.113.11")
)

func monPeerEvent(kind plugin.RIBEventKind, reason string) plugin.RIBEvent {
	return plugin.RIBEvent{Kind: kind, Router: monRouter, Peer: plugin.RIBPeer{Address: monPeer}, Reason: reason}
}

func monCount(n int) plugin.RIBEvent {
	return plugin.RIBEvent{Kind: plugin.RIBPrefixCount, Router: monRouter, Peer: plugin.RIBPeer{Address: monPeer}, Prefixes: n}
}

func newMonitor() *PeerMonitor {
	return NewPeerMonitor([]PeerSpec{{Exchange: "ix-lab", Name: "ix-peer-a", NextHop: monPeer, MaxPrefix: 100, WarnPct: 90}})
}

func TestPeerMonitorUpDown(t *testing.T) {
	m := newMonitor()
	up := m.Observe(monPeerEvent(plugin.RIBPeerUp, ""))
	if len(up) != 1 || up[0].Kind != PeerChangeUp || up[0].Exchange != "ix-lab" || up[0].Peer != "ix-peer-a" {
		t.Fatalf("up = %+v", up)
	}
	if again := m.Observe(monPeerEvent(plugin.RIBPeerUp, "")); len(again) != 0 {
		t.Fatalf("repeat up = %+v", again)
	}
	down := m.Observe(monPeerEvent(plugin.RIBPeerDown, "remote system closed: Cease subcode 1 (maximum number of prefixes reached)"))
	if len(down) != 1 || down[0].Kind != PeerChangeDown || down[0].Reason == "" {
		t.Fatalf("down = %+v", down)
	}
	if again := m.Observe(monPeerEvent(plugin.RIBPeerDown, "remote system closed")); len(again) != 0 {
		t.Fatalf("repeat down = %+v", again)
	}
}

func TestPeerMonitorMaxPrefix(t *testing.T) {
	m := newMonitor()
	m.Observe(monPeerEvent(plugin.RIBPeerUp, ""))
	if evs := m.Observe(monCount(89)); len(evs) != 0 {
		t.Fatalf("89 below 90%% = %+v", evs)
	}
	high := m.Observe(monCount(90))
	if len(high) != 1 || high[0].Kind != PeerChangePrefixHigh || high[0].Prefixes != 90 || high[0].MaxPrefix != 100 {
		t.Fatalf("high = %+v", high)
	}
	if m.Prefixes()["ix-peer-a"] != 90 {
		t.Fatalf("prefixes = %v", m.Prefixes())
	}
	if evs := m.Observe(monCount(95)); len(evs) != 0 {
		t.Fatalf("still high = %+v", evs)
	}
	ok := m.Observe(monCount(89))
	if len(ok) != 1 || ok[0].Kind != PeerChangePrefixOK {
		t.Fatalf("clear = %+v", ok)
	}
	if evs := m.Observe(monCount(10)); len(evs) != 0 {
		t.Fatalf("below again = %+v", evs)
	}
}

func TestPeerMonitorDownClearsWarningAndCount(t *testing.T) {
	m := newMonitor()
	m.Observe(monPeerEvent(plugin.RIBPeerUp, ""))
	m.Observe(monCount(95))
	evs := m.Observe(monPeerEvent(plugin.RIBPeerDown, "peer de-configured"))
	if len(evs) != 2 || evs[0].Kind != PeerChangePrefixOK || evs[1].Kind != PeerChangeDown {
		t.Fatalf("down with warning = %+v", evs)
	}
	if n, ok := m.Prefixes()["ix-peer-a"]; !ok || n != 0 {
		t.Fatalf("count after down = %v", m.Prefixes())
	}
}

func TestPeerMonitorRouterDownClearsWarning(t *testing.T) {
	m := newMonitor()
	m.Observe(monPeerEvent(plugin.RIBPeerUp, ""))
	m.Observe(monCount(95))
	evs := m.Observe(plugin.RIBEvent{Kind: plugin.RIBRouterDown, Router: monRouter})
	if len(evs) != 1 || evs[0].Kind != PeerChangePrefixOK {
		t.Fatalf("router down = %+v", evs)
	}
	if n := m.Prefixes()["ix-peer-a"]; n != 0 {
		t.Fatalf("count after router down = %d", n)
	}
	if up := m.Observe(monPeerEvent(plugin.RIBPeerUp, "")); len(up) != 1 || up[0].Kind != PeerChangeUp {
		t.Fatalf("up after router down = %+v", up)
	}
}

// A Statistics Report must not flip a down peer up: the next Peer Up still
// reports, so exchange.peer_up resolves exchange.peer_down.
func TestPeerMonitorStatsAfterDownKeepsDown(t *testing.T) {
	for _, tc := range []struct {
		name string
		down plugin.RIBEvent
	}{
		{"peer down", monPeerEvent(plugin.RIBPeerDown, "remote system closed")},
		{"router down", plugin.RIBEvent{Kind: plugin.RIBRouterDown, Router: monRouter}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newMonitor()
			m.Observe(monPeerEvent(plugin.RIBPeerUp, ""))
			m.Observe(tc.down)
			if evs := m.Observe(monCount(5)); len(evs) != 0 {
				t.Fatalf("stats after down = %+v", evs)
			}
			up := m.Observe(monPeerEvent(plugin.RIBPeerUp, ""))
			if len(up) != 1 || up[0].Kind != PeerChangeUp {
				t.Fatalf("up after stats = %+v", up)
			}
		})
	}
}

// A stats report before any Peer Up does not claim the peer is up, and a
// later Peer Down is still reported.
func TestPeerMonitorStatsDoNotMarkUp(t *testing.T) {
	m := newMonitor()
	if evs := m.Observe(monCount(5)); len(evs) != 0 {
		t.Fatalf("stats = %+v", evs)
	}
	down := m.Observe(monPeerEvent(plugin.RIBPeerDown, "remote system closed"))
	if len(down) != 1 || down[0].Kind != PeerChangeDown {
		t.Fatalf("down after stats = %+v", down)
	}
}

// Two routers with a BMP session to the same peer address keep separate
// state: one going down or reporting down does not touch the other.
func TestPeerMonitorKeysByRouter(t *testing.T) {
	routerB := netip.MustParseAddr("192.0.2.253")
	ev := func(kind plugin.RIBEventKind, r netip.Addr) plugin.RIBEvent {
		return plugin.RIBEvent{Kind: kind, Router: r, Peer: plugin.RIBPeer{Address: monPeer}}
	}
	count := func(r netip.Addr, n int) plugin.RIBEvent {
		e := ev(plugin.RIBPrefixCount, r)
		e.Prefixes = n
		return e
	}
	m := newMonitor()
	for _, r := range []netip.Addr{monRouter, routerB} {
		up := m.Observe(ev(plugin.RIBPeerUp, r))
		if len(up) != 1 || up[0].Router != r {
			t.Fatalf("up on %s = %+v", r, up)
		}
	}
	m.Observe(count(monRouter, 95))
	m.Observe(count(routerB, 20))
	if got := m.Prefixes()["ix-peer-a"]; got != 115 {
		t.Fatalf("summed prefixes = %d, want 115", got)
	}

	// Router A going down clears only A's count and warning.
	evs := m.Observe(plugin.RIBEvent{Kind: plugin.RIBRouterDown, Router: monRouter})
	if len(evs) != 1 || evs[0].Kind != PeerChangePrefixOK || evs[0].Router != monRouter {
		t.Fatalf("router A down = %+v", evs)
	}
	if got := m.Prefixes()["ix-peer-a"]; got != 20 {
		t.Fatalf("prefixes after router A down = %d, want 20", got)
	}

	// B still has the peer up, so a repeat up on B is silent and a down on B
	// is reported even though A saw nothing.
	if evs := m.Observe(ev(plugin.RIBPeerUp, routerB)); len(evs) != 0 {
		t.Fatalf("repeat up on B = %+v", evs)
	}
	down := m.Observe(ev(plugin.RIBPeerDown, routerB))
	if len(down) != 1 || down[0].Kind != PeerChangeDown || down[0].Router != routerB {
		t.Fatalf("down on B = %+v", down)
	}
	// A's session was reset by its router going down, not reported down, so
	// its next Peer Up is announced.
	if up := m.Observe(ev(plugin.RIBPeerUp, monRouter)); len(up) != 1 || up[0].Router != monRouter {
		t.Fatalf("up on A = %+v", up)
	}
}

func TestPeerMonitorIgnoresUnwatchedAndLocRIB(t *testing.T) {
	m := newMonitor()
	if evs := m.Observe(plugin.RIBEvent{Kind: plugin.RIBPeerUp, Router: monRouter, Peer: plugin.RIBPeer{Address: netip.MustParseAddr("198.51.100.9")}}); len(evs) != 0 {
		t.Fatalf("unwatched peer = %+v", evs)
	}
	if evs := m.Observe(plugin.RIBEvent{Kind: plugin.RIBPrefixCount, Router: monRouter, Peer: plugin.RIBPeer{LocRIB: true}, Prefixes: 5}); len(evs) != 0 {
		t.Fatalf("loc-rib = %+v", evs)
	}
}

func TestPeerMonitorZeroMaxPrefixNeverWarns(t *testing.T) {
	m := NewPeerMonitor([]PeerSpec{{Exchange: "ix-lab", Name: "ix-peer-a", NextHop: monPeer}})
	m.Observe(monPeerEvent(plugin.RIBPeerUp, ""))
	if evs := m.Observe(monCount(1000000)); len(evs) != 0 {
		t.Fatalf("warning without max_prefix = %+v", evs)
	}
}

func TestNilPeerMonitor(t *testing.T) {
	var m *PeerMonitor
	if evs := m.Observe(monPeerEvent(plugin.RIBPeerUp, "")); evs != nil {
		t.Fatalf("nil monitor = %+v", evs)
	}
	if got := m.Prefixes(); got != nil {
		t.Fatalf("nil monitor prefixes = %v", got)
	}
}
