package main

import (
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/registry"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var registryConfig = strings.Replace(bmpConfig, "    - address: 192.0.2.254\n", "    - address: 192.0.2.254\n      add_path: true\n", 1) + `
exchanges:
  - name: ix-lab
    lans: [203.0.113.0/24]
    port: {capacity_mbps: 10000}
    peers:
      - {name: ix-peer-a, asn: 64501, next_hop: 203.0.113.11, source_ip: 192.0.2.31, fwmark: 1}
      - {name: ix-peer-b, asn: 64502, next_hop: 203.0.113.12, source_ip: 192.0.2.31, fwmark: 2}
      - {name: ix-peer-c, asn: 64503, next_hop: 203.0.113.13, source_ip: 192.0.2.32}
  - name: ix-other
    lans: [198.51.100.0/24]
    peers:
      - {name: other-peer, asn: 64504, next_hop: 198.51.100.11, source_ip: 192.0.2.33}
lookup:
  type: peeringdb
  config:
    exchanges:
      - {name: ix-lab, ix_id: 7}
registry:
  enabled: true
  asns: [64496, 64512]
`

// #289: the scan sees the prefixes the configured ASNs originate (an empty
// path is the edge's own ASN), and the ASNs behind them as the customer
// cone, from the learned RIB only.
func TestRegistryObserverReadsLearnedRIB(t *testing.T) {
	cfg, err := config.Parse([]byte(registryConfig))
	if err != nil {
		t.Fatal(err)
	}
	view, err := newRIB(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	edge := netip.MustParseAddr("192.0.2.254")
	send := func(prefix string, path ...uint32) {
		view.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPaths, Router: edge, Peer: plugin.RIBPeer{Address: netip.MustParseAddr("192.0.2.21")}, PostPolicy: true,
			Paths: []plugin.RIBPath{{Prefix: netip.MustParsePrefix(prefix), NextHop: netip.MustParseAddr("192.0.2.21"), ASPath: path}}})
	}
	send("198.51.100.0/24", 64500, 64496)
	send("203.0.113.0/24", 64500, 64496, 64497)
	send("192.0.2.0/24")
	send("2001:db8::/32", 64500, 64499)

	own := map[uint32]bool{64496: true, 64512: true}
	obs := registry.Observed{Announced: map[netip.Prefix]uint32{}, Downstream: map[uint32]bool{}}
	observeRIB(view, cfg.ASN, own, &obs)
	wantAnnounced := map[netip.Prefix]uint32{netip.MustParsePrefix("198.51.100.0/24"): 64496, netip.MustParsePrefix("192.0.2.0/24"): 64512}
	if !maps.Equal(obs.Announced, wantAnnounced) {
		t.Fatalf("announced = %v, want %v", obs.Announced, wantAnnounced)
	}
	if !maps.Equal(obs.Downstream, map[uint32]bool{64497: true}) {
		t.Fatalf("downstream = %v, want only AS64497 (the origin behind AS64496)", obs.Downstream)
	}

	// No established session means the view is not ready, and then nothing
	// is compared: an empty view must not read as every prefix unregistered.
	if got := registryObserver(cfg, view)(); got.Ready || len(got.Announced) != 0 {
		t.Fatalf("observer on a view with no session = %+v", got)
	}
}

// #289: a session lists the distinct source addresses of its peers, the
// port speed, and the PeeringDB ix id from the lookup block; an exchange
// the lookup does not name has ix id 0.
func TestRegistrySessions(t *testing.T) {
	cfg, err := config.Parse([]byte(registryConfig))
	if err != nil {
		t.Fatal(err)
	}
	got := registrySessions(cfg)
	want := []plugin.RegistrySession{
		{Exchange: "ix-lab", IXID: 7, SpeedMbps: 10000, Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.31"), netip.MustParseAddr("192.0.2.32")}},
		{Exchange: "ix-other", Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.33")}},
	}
	if !slices.EqualFunc(got, want, func(a, b plugin.RegistrySession) bool {
		return a.Exchange == b.Exchange && a.IXID == b.IXID && a.SpeedMbps == b.SpeedMbps && slices.Equal(a.Addrs, b.Addrs)
	}) {
		t.Fatalf("sessions = %+v, want %+v", got, want)
	}
}

// #289: the service exists only when the block is on.
func TestNewRegistryOffWithoutBlock(t *testing.T) {
	cfg, err := config.Parse([]byte(bmpConfig))
	if err != nil {
		t.Fatal(err)
	}
	if newRegistry(cfg, nil, nil, nil, nil) != nil {
		t.Fatal("registry built without a registry block")
	}
}
