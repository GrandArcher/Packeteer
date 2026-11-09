package main

import (
	"net/netip"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// #154: the origin AS is the last AS of the covering learned route, a path
// through the exchange LAN is read from the covering route's paths, and the
// local AS is not a destination.
func TestPotentialPeersReportJoinsOriginAndLANPaths(t *testing.T) {
	cfg := mustParse(t, offloadConfig)
	view, err := newRIB(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	edge := netip.MustParseAddr("192.0.2.254")
	learn := func(prefix, peer string, asPath ...uint32) {
		t.Helper()
		view.ApplyRIB(plugin.RIBEvent{
			Kind: plugin.RIBPaths, Router: edge, PostPolicy: true,
			Peer:  plugin.RIBPeer{Address: netip.MustParseAddr(peer)},
			Paths: []plugin.RIBPath{{Prefix: netip.MustParsePrefix(prefix), NextHop: netip.MustParseAddr(peer), ASPath: asPath}},
		})
	}
	// AS64500 behind a transit, also reachable through the LAN.
	learn("198.51.100.0/24", "192.0.2.1", 64496, 64500)
	learn("198.51.100.0/24", "203.0.113.11", 64501, 64500)
	// Another AS64500 prefix, transit only.
	learn("192.0.2.0/25", "192.0.2.2", 64497, 64500)
	// AS64520 is on no exchange.
	learn("2001:db8:1::/48", "192.0.2.1", 64496, 64520)
	// The local AS originates this one.
	learn("192.0.2.128/25", "192.0.2.1", 64496, 64512)

	plugins := &pluginhost.Set{Sources: []pluginhost.Instance[plugin.TargetSource]{{Name: "flows", Type: "static", Plugin: &rowsSrc{rows: []plugin.PrefixVolume{
		offloadVolume("198.51.100.0/25", 100), // no exact route: covered by the /24
		offloadVolume("192.0.2.0/25", 60),
		offloadVolume("2001:db8:1::/48", 500),
		offloadVolume("192.0.2.128/25", 900),
		offloadVolume("10.0.0.0/8", 50),
	}}}}}
	stats := func() []exchange.Stats {
		return []exchange.Stats{{Name: "ix-lab", Peers: []exchange.PeerStats{{Name: "ix-peer-a", ASN: 64500, NextHop: "203.0.113.11", Via: "route_server"}}}}
	}
	report := potentialPeersReport(64512, plugins, view, cfg.Exchanges[0].ExchangeLANs(), stats)

	got := report("", 100)
	if len(got.Rows) != 2 {
		t.Fatalf("report = %+v", got)
	}
	absent, rs := got.Rows[0], got.Rows[1]
	if absent.ASN != 64520 || absent.Class != exchange.ClassAbsent || absent.LANPrefixes != 0 {
		t.Errorf("first row = %+v", absent)
	}
	if rs.ASN != 64500 || rs.Class != exchange.ClassRouteServer || rs.Prefixes != 2 || rs.LANPrefixes != 1 ||
		rs.LANBytes != offloadVolume("198.51.100.0/25", 100).Bytes || len(rs.Members) != 1 || rs.Members[0].Peer != "ix-peer-a" {
		t.Errorf("second row = %+v", rs)
	}
	if got.UnattributedBytes != offloadVolume("10.0.0.0/8", 50).Bytes+offloadVolume("192.0.2.128/25", 900).Bytes {
		t.Errorf("unattributed = %d", got.UnattributedBytes)
	}
	if only := report(exchange.ClassRouteServer, 100); len(only.Rows) != 1 || only.Rows[0].ASN != 64500 || only.ASNs != 1 {
		t.Errorf("class filter = %+v", only)
	}
}
