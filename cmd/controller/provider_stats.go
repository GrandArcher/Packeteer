package main

import (
	"context"

	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/provseries"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// providerTraffic is each provider's current Mbps: the sum of the flow
// sources' volumes over the prefixes that leave through it, and whether any
// source reports volume at all. A prefix that is not in the learned view has
// no exit and counts nowhere. It reads only.
func providerTraffic(plugins *pluginhost.Set, view *rib.View, decider *policy.Engine) func() (map[string]float64, bool) {
	return func() (map[string]float64, bool) {
		if !hasVolumeSource(plugins) {
			return nil, false
		}
		exit := exitOf(decider, view)
		out := map[string]float64{}
		for p, v := range collectVolumeRows(context.Background(), plugins) {
			if name := exit(p); name != "" {
				out[name] += v.Mbps()
			}
		}
		return out, true
	}
}

func hasVolumeSource(plugins *pluginhost.Set) bool {
	if plugins == nil {
		return false
	}
	for _, src := range plugins.SourcesSnapshot() {
		if _, ok := src.Plugin.(plugin.VolumeSource); ok {
			return true
		}
	}
	return false
}

// wireProviderStats serves the Providers page and the Overview latency chart.
func wireProviderStats(srv *httpapi.Server, series *provseries.Series, plugins *pluginhost.Set, view *rib.View, decider *policy.Engine) {
	srv.SetProviderStats(httpapi.ProviderStats{Series: series.Stats, Traffic: providerTraffic(plugins, view, decider)})
}
