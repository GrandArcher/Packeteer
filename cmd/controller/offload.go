package main

import (
	"context"
	"maps"
	"net/netip"
	"slices"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/rib"
)

// exitOf names the provider a prefix leaves through. The exit of a prefix
// is the improvement's provider in inject, where the route is announced, and
// the provider the RIB shows otherwise. It is empty when the prefix is not
// in the learned view. It reads only.
func exitOf(decider *policy.Engine, view *rib.View) func(netip.Prefix) string {
	steered := map[netip.Prefix]string{}
	if decider.Mode() == config.ModeInject {
		for _, im := range decider.Improvements() {
			steered[im.Prefix] = im.Provider
		}
	}
	return func(p netip.Prefix) string {
		if name, ok := steered[p]; ok {
			return name
		}
		if view == nil {
			return ""
		}
		rt, ok := view.Exact(p)
		if !ok {
			return ""
		}
		return rt.Provider
	}
}

// offloadReport builds the transit-to-exchange offload report (#152) from
// the sources' volumes, the learned RIB, and the engine's improvements. It
// reads only.
func offloadReport(cfg *config.Config, plugins *pluginhost.Set, view *rib.View, decider *policy.Engine) func(limit int) exchange.Offload {
	var transits []exchange.Transit
	for _, p := range cfg.Providers {
		if p.Exchange == "" {
			transits = append(transits, exchange.Transit{Name: p.Name, Cost: p.Cost})
		}
	}
	var peers []exchange.OffloadPeer
	for _, ex := range cfg.Exchanges {
		for _, p := range ex.Peers {
			peers = append(peers, exchange.OffloadPeer{Exchange: ex.Name, Name: p.Name})
		}
	}
	return func(limit int) exchange.Offload {
		in := exchange.OffloadInput{
			Volumes:  slices.Collect(maps.Values(collectVolumeRows(context.Background(), plugins))),
			Transits: transits,
			Peers:    peers,
			Exit:     exitOf(decider, view),
			Advertises: func(p netip.Prefix, peer string) bool {
				checked, ok := view.RouteCheck(p, peer)
				return checked && ok
			},
		}
		return exchange.BuildOffload(in, limit)
	}
}
