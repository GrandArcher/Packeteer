package main

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/all"
	"github.com/GrandArcher/Packeteer/internal/provseries"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/internal/syshealth"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// newRecorder returns nil when no storage plugin is configured. It reads
// the RIB view for origin ASNs and asks policy plugins that have a GeoIP
// database for countries. History never announces or changes a decision.
func newRecorder(cfg *config.Config, plugins *pluginhost.Set, log *slog.Logger, view func() *rib.View, health *syshealth.Tracker, series *provseries.Series) *history.Recorder {
	if plugins == nil || plugins.Storage == nil {
		return nil
	}
	describe := func(p netip.Prefix) (uint32, string) {
		var asn uint32
		if v := view(); v != nil && v.Ready() {
			if rt, ok := v.Exact(p); ok && len(rt.ASPath) > 0 {
				asn = rt.ASPath[len(rt.ASPath)-1]
			}
		}
		// Read per call: a reload can add or remove a policy.
		for _, pol := range plugins.PoliciesSnapshot() {
			if g, ok := pol.Plugin.(plugin.CountryLookup); ok {
				if c := g.Country(p.Addr()); c != "" {
					return asn, c
				}
			}
		}
		return asn, ""
	}
	var peers map[string]string
	for _, p := range cfg.Providers {
		if p.Exchange != "" {
			if peers == nil {
				peers = map[string]string{}
			}
			peers[p.Name] = p.Exchange
		}
	}
	return history.New(history.Options{
		Store:     plugins.Storage.Plugin,
		Mode:      cfg.Mode,
		Logger:    log.With("component", "history"),
		Describe:  describe,
		Volumes:   func(ctx context.Context) map[netip.Prefix]float64 { return collectVolumes(ctx, plugins) },
		Exchanges: peers,
		Series:    series,
		OnWrite:   func(err error) { health.Record(historyKey, err) },
	})
}
