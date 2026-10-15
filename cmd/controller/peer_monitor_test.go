package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// peerMonitorConfig is one exchange peer with a max_prefix, documentation
// addresses and ASNs only.
const peerMonitorConfig = `mode: observe
asn: 64512
router_id: 192.0.2.10
exchanges:
  - name: ix-lab
    lans: [203.0.113.0/24]
    max_prefix_warn_pct: 80
    peers:
      - name: ix-peer-a
        asn: 64501
        next_hop: 203.0.113.11
        source_ip: 192.0.2.31
        max_prefix: 1000
bgp:
  neighbors:
    - address: 192.0.2.254
      add_path: true
`

func TestExchangePeerMonitorEvents(t *testing.T) {
	cfg, err := config.Parse([]byte(peerMonitorConfig))
	if err != nil {
		t.Fatal(err)
	}
	mon := exchangePeerMonitor(cfg)
	if mon == nil {
		t.Fatal("no monitor built for a configured exchange")
	}
	router := netip.MustParseAddr("192.0.2.254")
	addr := netip.MustParseAddr("203.0.113.11")
	now := time.Unix(0, 0)

	up := mon.Observe(plugin.RIBEvent{Kind: plugin.RIBPeerUp, Router: router, Peer: plugin.RIBPeer{Address: addr}})
	if len(up) != 1 {
		t.Fatalf("up = %+v", up)
	}
	if ev := peerChangeEvent(now, up[0]); ev.Kind != plugin.EventExchangePeerUp ||
		ev.Fields["exchange"] != "ix-lab" || ev.Fields["peer"] != "ix-peer-a" {
		t.Fatalf("up event = %+v", ev)
	}

	high := mon.Observe(plugin.RIBEvent{Kind: plugin.RIBPrefixCount, Router: router, Peer: plugin.RIBPeer{Address: addr}, Prefixes: 800})
	if len(high) != 1 {
		t.Fatalf("count = %+v", high)
	}
	if ev := peerChangeEvent(now, high[0]); ev.Kind != plugin.EventExchangeMaxPrefix ||
		ev.Fields["prefixes"] != "800" || ev.Fields["max_prefix"] != "1000" {
		t.Fatalf("high event = %+v", ev)
	}

	// A peer down while the warning is open clears it, then reports down.
	down := mon.Observe(plugin.RIBEvent{Kind: plugin.RIBPeerDown, Router: router, Peer: plugin.RIBPeer{Address: addr},
		Reason: "remote system closed: Cease subcode 1 (maximum number of prefixes reached)"})
	if len(down) != 2 || down[0].Kind != exchange.PeerChangePrefixOK || down[1].Kind != exchange.PeerChangeDown {
		t.Fatalf("down = %+v", down)
	}
	if ev := peerChangeEvent(now, down[1]); ev.Kind != plugin.EventExchangePeerDown ||
		ev.Fields["reason"] == "" {
		t.Fatalf("down event = %+v", ev)
	}
	if ev := peerChangeEvent(now, exchange.PeerChange{Kind: exchange.PeerChangeKind(99)}); ev.Kind != "" {
		t.Fatalf("unknown change produced %+v", ev)
	}
}

func TestRIBSinkEmitsExchangePeerEvents(t *testing.T) {
	cfg, err := config.Parse([]byte(peerMonitorConfig))
	if err != nil {
		t.Fatal(err)
	}
	view, err := newRIB(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	mon := exchangePeerMonitor(cfg)
	var got []plugin.Event
	sink := ribSink(view, nil, "bmp", mon, func(e plugin.Event) { got = append(got, e) })
	sink(plugin.RIBEvent{Kind: plugin.RIBPeerUp, Router: netip.MustParseAddr("192.0.2.254"),
		Peer: plugin.RIBPeer{Address: netip.MustParseAddr("203.0.113.11")}})
	if len(got) != 1 || got[0].Kind != plugin.EventExchangePeerUp {
		t.Fatalf("events = %+v", got)
	}
	// The same event still reaches the view.
	peers := view.BMPPeers()
	if len(peers) != 1 || peers[0].Peer != netip.MustParseAddr("203.0.113.11") {
		t.Fatalf("view did not see the peer up: %+v", peers)
	}
}
