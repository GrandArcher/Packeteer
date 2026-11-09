package main

import (
	"log/slog"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/irr"
	"github.com/GrandArcher/Packeteer/internal/onlyinvalid"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/internal/rpki"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// newOnlyInvalid builds the invalid only path report (#401). It is nil
// when rpki.only_invalid is off. It reads the learned RIB, the rpki set,
// the irr checker, and the hijack feeds; it announces nothing, and a SLURM
// exception is written only when an admin approves it.
func newOnlyInvalid(cfg *config.Config, plugins *pluginhost.Set, view *rib.View, rpkiSet *rpki.Set, irrChecker *irr.Checker,
	emit func(plugin.Event), audit *auth.Auditor, log *slog.Logger) *onlyinvalid.Service {
	if !cfg.OnlyInvalidOn() || plugins == nil || view == nil || !rpkiSet.Enabled() {
		return nil
	}
	log = log.With("component", "onlyinvalid")
	deps := onlyinvalid.Deps{RIB: view, RPKI: rpkiSet, Emit: emit, Log: log}
	if irrChecker.Enabled() {
		deps.IRR = irrChecker.Lookup
	}
	for _, f := range plugins.HijackFeeds {
		deps.Feeds = append(deps.Feeds, onlyinvalid.Feed{Name: f.Name, Plugin: f.Plugin})
	}
	o := cfg.RPKI.OnlyInvalid
	svc := &onlyinvalid.Service{Detector: onlyinvalid.NewDetector(deps, o.StableAfter)}
	if s := o.SLURM; s != nil {
		svc.Exceptions = onlyinvalid.NewExceptions(onlyinvalid.SLURMConfig{Path: s.Path, Prefixes: s.SLURMPrefixes(), ReviewAfter: s.ReviewAfter}, svc.Detector, audit)
		if _, err := svc.Exceptions.List(); err != nil {
			log.Error("rpki.only_invalid.slurm: proposals and approvals are refused until the file is fixed", "err", err)
		}
	}
	return svc
}

// wireOnlyInvalid gives the API the cases and the exceptions.
func wireOnlyInvalid(svc *onlyinvalid.Service, httpSrv *httpapi.Server) {
	if svc == nil || httpSrv == nil {
		return
	}
	httpSrv.SetOnlyInvalid(svc)
}
