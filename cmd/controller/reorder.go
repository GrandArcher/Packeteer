package main

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// newReorderMonitor builds probe.reorder (#224): trains from every local
// provider's source toward each responder, on the engine's packet
// budgets. Nil when the block is omitted. The responders' probers are
// built here from the registry (twamp, icmp) with their defaults; the
// train's spacing and port come from the request. Measurement only.
func newReorderMonitor(cfg *config.Config, log *slog.Logger, lim probe.Limiter, perASN *probe.ASNLimits, excl *probe.Exclusion) (*probe.ReorderMonitor, error) {
	rc := cfg.Probe.Reorder
	if rc == nil {
		return nil, nil
	}
	var providers []probe.Provider
	for _, p := range cfg.Providers {
		if cfg.Remote(p) {
			continue
		}
		src, err := parseAddr(p.SourceIP)
		if err != nil {
			return nil, err
		}
		providers = append(providers, probe.Provider{Name: p.Name, Source: src, Marking: markingOf(p)})
	}
	// The config type names the prober plugin; the monitor's type decides
	// whether the reading is an estimate.
	types := map[string]string{config.ReorderResponderTWAMP: probe.ResponderTWAMP, config.ReorderResponderICMP: probe.ResponderICMP}
	probers := map[string]plugin.Prober{}
	var responders []probe.Responder
	for _, r := range rc.Responders {
		addr, err := netip.ParseAddr(r.Address)
		if err != nil {
			return nil, fmt.Errorf("probe.reorder responder %q: %w", r.Address, err)
		}
		typ, ok := types[r.Type]
		if !ok {
			return nil, fmt.Errorf("probe.reorder responder %s: unknown type %q", r.Address, r.Type)
		}
		pr, ok := probers[r.Type]
		if !ok {
			pr, err = plugin.Probers.New(r.Type, plugin.NewConfig(nil),
				plugin.Env{Name: "reorder-" + r.Type, Logger: log.With("plugin", "reorder-"+r.Type), Getenv: os.Getenv})
			if err != nil {
				return nil, fmt.Errorf("probe.reorder: %w", err)
			}
			probers[r.Type] = pr
		}
		responders = append(responders, probe.Responder{Address: addr, Port: uint16(r.Port), Type: typ, Prober: pr})
	}
	return probe.NewReorderMonitor(probe.ReorderOptions{
		Providers:  providers,
		Responders: responders,
		Packets:    rc.Packets,
		Spacing:    rc.Spacing,
		Timeout:    rc.Timeout,
		Interval:   rc.Interval,
		Flows:      rc.Flows,
		Limiter:    lim,
		PerASN:     perASN,
		Exclude:    excl,
		Logger:     log,
	})
}

// reorderPackets is the most packets one reordering train asks of the
// packet budgets. Zero when probe.reorder is off.
func reorderPackets(cfg *config.Config) int {
	if cfg.Probe.Reorder == nil {
		return 0
	}
	return cfg.Probe.Reorder.Packets
}
