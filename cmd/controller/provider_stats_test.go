package main

import (
	"context"
	"net/netip"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// #349: a provider's Mbps is the flow volume of the prefixes the RIB shows
// leaving through it. A prefix outside the learned view counts nowhere, and
// without a flow source there is no number at all.
func TestProviderTrafficSumsVolumeByExit(t *testing.T) {
	cfg := mustParse(t, offloadConfig)
	view, err := newRIB(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	edge := netip.MustParseAddr("192.0.2.254")
	learn := func(prefix, hop string, asPath ...uint32) {
		t.Helper()
		view.ApplyRIB(plugin.RIBEvent{
			Kind: plugin.RIBPaths, Router: edge, PostPolicy: true,
			Peer:  plugin.RIBPeer{Address: netip.MustParseAddr(hop)},
			Paths: []plugin.RIBPath{{Prefix: netip.MustParsePrefix(prefix), NextHop: netip.MustParseAddr(hop), ASPath: asPath}},
		})
	}
	learn("198.51.100.0/24", "192.0.2.1", 64496, 64500)
	learn("203.0.113.0/25", "192.0.2.1", 64496, 64501)
	learn("192.0.2.0/25", "192.0.2.2", 64497, 64500)
	decider := policy.NewEngine(policy.Config{Mode: "observe"}, nil)
	flows := &pluginhost.Set{Sources: []pluginhost.Instance[plugin.TargetSource]{{Name: "flows", Type: "static", Plugin: &rowsSrc{rows: []plugin.PrefixVolume{
		offloadVolume("198.51.100.0/24", 80),
		offloadVolume("203.0.113.0/25", 20),
		offloadVolume("192.0.2.0/25", 120),
		offloadVolume("2001:db8:1::/48", 900),
	}}}}}

	got, flow := providerTraffic(flows, view, decider)()
	if !flow || len(got) != 2 || got["transit-a"] != 100 || got["transit-b"] != 120 {
		t.Fatalf("traffic = %v, flow %v", got, flow)
	}

	// A source that cannot report volume is not a flow source.
	targets := &pluginhost.Set{Sources: []pluginhost.Instance[plugin.TargetSource]{{Name: "list", Type: "static", Plugin: noVolume{}}}}
	if got, flow := providerTraffic(targets, view, decider)(); flow || got != nil {
		t.Fatalf("no flow source: %v, %v", got, flow)
	}
	if _, flow := providerTraffic(nil, view, decider)(); flow {
		t.Fatal("nil plugin set reported flow")
	}
}

type noVolume struct{ plugin.Base }

func (noVolume) Targets(context.Context) ([]plugin.Target, error) { return nil, nil }
