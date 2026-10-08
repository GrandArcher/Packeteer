package main

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// newRIB passes exchange LANs into the view (#146). Without them a BMP
// neighbor on the peering LAN would not be recognized as a route server.
func TestExchangeLANsReachTheRIB(t *testing.T) {
	cfg, err := config.Parse([]byte(`
mode: observe
asn: 64512
router_id: 192.0.2.10
exchanges:
  - name: ix-lab
    lans: [203.0.113.0/24]
    bmp: prefer
    peers:
      - name: ix-peer-a
        asn: 64501
        next_hop: 203.0.113.11
        source_ip: 192.0.2.31
      - name: ix-peer-b
        asn: 64502
        next_hop: 203.0.113.12
        source_ip: 192.0.2.32
bgp:
  neighbors:
    - address: 192.0.2.254
      add_path: true
rib_sources:
  - type: bmp
    config:
      routers: [192.0.2.254]
`))
	if err != nil {
		t.Fatal(err)
	}
	view, err := newRIB(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	edge := netip.MustParseAddr("192.0.2.254")
	p := netip.MustParsePrefix("198.51.100.0/24")
	med := uint32(10)
	view.ApplyRIB(plugin.RIBEvent{
		Kind: plugin.RIBPaths, Router: edge, PostPolicy: true,
		Peer: plugin.RIBPeer{Address: netip.MustParseAddr("203.0.113.1")},
		Paths: []plugin.RIBPath{{
			Prefix: p, NextHop: netip.MustParseAddr("203.0.113.11"),
			ASPath: []uint32{64501, 64500}, MED: &med,
		}},
	})
	view.ApplyRIB(plugin.RIBEvent{
		Kind: plugin.RIBPaths, Router: edge, PostPolicy: true,
		Peer: plugin.RIBPeer{Address: netip.MustParseAddr("203.0.113.12")},
		Paths: []plugin.RIBPath{{
			Prefix: p, NextHop: netip.MustParseAddr("203.0.113.12"),
			ASPath: []uint32{64502, 64500}, MED: &med,
		}},
	})
	var server, direct rib.Route
	for _, rt := range view.Paths(p) {
		switch rt.Neighbor.String() {
		case "203.0.113.1":
			server = rt
		case "203.0.113.12":
			direct = rt
		}
	}
	if server.Via != rib.ViaRouteServer || server.MEDFrom != "peer 203.0.113.1, route server 203.0.113.1" ||
		strings.Contains(server.MEDFrom, "ix-peer-a") {
		t.Fatalf("route server path = %+v", server)
	}
	if direct.Via != rib.ViaBilateral || strings.Contains(direct.MEDFrom, "route server") {
		t.Fatalf("bilateral path = %+v", direct)
	}
	// The route check is unchanged. A route-server BMP neighbor is not the
	// member's session, so ix-peer-a still fails closed. The bilateral
	// peer's own session passes.
	if checked, ok := view.RouteCheck(p, "ix-peer-a"); !checked || ok {
		t.Fatalf("ix-peer-a route check: checked=%v ok=%v", checked, ok)
	}
	if checked, ok := view.RouteCheck(p, "ix-peer-b"); !checked || !ok {
		t.Fatalf("ix-peer-b route check: checked=%v ok=%v", checked, ok)
	}
}
