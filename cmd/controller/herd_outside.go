package main

import (
	"log/slog"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/leakwatch"
	"github.com/GrandArcher/Packeteer/internal/linkout"
	"github.com/GrandArcher/Packeteer/internal/outside"
	"github.com/GrandArcher/Packeteer/internal/rpki"
)

// newHerdOutside builds the outside sources the operator chose for the herd
// dashboard (#296), each on its own switch. Only atlas is returned apart,
// because it has a refresh loop to run. Every source is display only.
func newHerdOutside(cfg *config.Config, lw *leakwatch.Watcher, rpkiSet *rpki.Set, links *linkout.Set, log *slog.Logger) (*outside.Set, *outside.Atlas) {
	var sources []outside.Source
	var atlas *outside.Atlas
	o := cfg.Herd.Outside
	if o.Atlas.Enabled {
		atlas = outside.NewAtlas(outside.AtlasOptions{Measurements: o.Atlas.Measurements, Probes: o.Atlas.Probes, Refresh: o.Atlas.Refresh, Log: log})
		sources = append(sources, atlas)
	}
	if o.RIS {
		sources = append(sources, outside.RIS{Status: lw.Status})
	}
	if o.RPKI {
		sources = append(sources, outside.RPKI{Validate: rpkiSet.Validate, Updated: rpkiSet.Updated})
	}
	if o.Links {
		sources = append(sources, outside.Links{Set: links})
	}
	return outside.NewSet(sources...), atlas
}
