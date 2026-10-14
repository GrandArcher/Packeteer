package main

import (
	"context"
	"maps"
	"net/netip"
	"slices"

	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/rib"
)

// potentialPeersReport builds the potential-peers report (#154) from the
// sources' volumes, the origin AS of the covering learned route, and the
// exchange view. It reads only: no session is opened and nothing is
// announced or steered. localASN is skipped as an origin.
func potentialPeersReport(localASN uint32, plugins *pluginhost.Set, view *rib.View, lans []netip.Prefix, stats func() []exchange.Stats) func(class string, limit int) exchange.PotentialPeers {
	return func(class string, limit int) exchange.PotentialPeers {
		in := exchange.PotentialInput{
			Volumes: slices.Collect(maps.Values(collectVolumeRows(context.Background(), plugins))),
			Origin: func(p netip.Prefix) (uint32, bool) {
				rt, ok := view.Covering(p)
				if !ok || len(rt.ASPath) == 0 {
					return 0, false
				}
				asn := rt.ASPath[len(rt.ASPath)-1]
				return asn, asn != localASN
			},
			OnLAN: func(p netip.Prefix) bool {
				cover, ok := view.Covering(p)
				if !ok {
					return false
				}
				for _, rt := range view.Paths(cover.Prefix) {
					if exchange.ContainsAddr(lans, rt.NextHop) {
						return true
					}
				}
				return false
			},
			Exchanges: stats(),
		}
		return exchange.BuildPotentialPeers(in, class, limit)
	}
}
