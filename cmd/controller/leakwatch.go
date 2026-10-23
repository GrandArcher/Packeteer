package main

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/leakwatch"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/rpki"
)

// newLeakWatch returns nil when leak_watch is off (#199). injected and
// withdraw reach the outbound announcer, which is built after the watch
// (the callers read it through a variable assigned later). With RPKI on,
// a leak is labeled from the decision sources, never the display
// fallback (#200).
func newLeakWatch(cfg *config.Config, plugins *pluginhost.Set, out emitter, injected func(netip.Prefix) bool,
	withdraw func(context.Context, netip.Prefix) error, origins *rpki.Set, log *slog.Logger) (*leakwatch.Watcher, error) {
	if !cfg.LeakWatching() {
		return nil, nil
	}
	std, large, err := ownCommunity(cfg.PacketeerCommunity)
	if err != nil {
		return nil, err
	}
	var srcs []leakwatch.Source
	for _, s := range plugins.LeakSources {
		srcs = append(srcs, leakwatch.Source{Name: s.Name, Type: s.Type, Plugin: s.Plugin})
	}
	var asn uint32
	if cfg.LeakWatch.ASPathRule {
		asn = cfg.ASN
	}
	lc := leakwatch.Config{
		ASN: asn, Community: std, Large: large,
		Injected: injected, Withdraw: withdraw, Emit: out.Emit,
		Log: log.With("component", "leakwatch"),
	}
	if origins.Enabled() {
		lc.RPKI = origins.Lookup
	}
	return leakwatch.New(lc, srcs), nil
}

// leakControl is the API's handle on the watch. Clearing a hold wakes the
// decision loop so a prefix the engine still wants can return at once.
type leakControl struct {
	w    *leakwatch.Watcher
	poke func()
}

func (c leakControl) Status() leakwatch.Status { return c.w.Status() }

func (c leakControl) Clear(p netip.Prefix) bool {
	ok := c.w.Clear(p)
	if ok {
		c.poke()
	}
	return ok
}
