package main

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// exchangeHealth builds the next-hop targets and the health tracker for the
// exchanges that have health on (#149). It returns nil when none do.
func exchangeHealth(cfg *config.Config) ([]probe.HopTarget, *exchange.Health) {
	var targets []probe.HopTarget
	var specs []exchange.HealthSpec
	byName := map[string]config.Provider{}
	for _, p := range cfg.Providers {
		byName[p.Name] = p
	}
	for _, ex := range cfg.Exchanges {
		if !ex.Health.On() {
			continue
		}
		sp := exchange.HealthSpec{Exchange: ex.Name, HealthOptions: exchange.HealthOptions{
			LossPct: ex.Health.LossPct, RTT: time.Duration(ex.Health.RTTMS) * time.Millisecond,
			MinPeers: ex.Health.MinPeers, MinPercent: ex.Health.MinPercent, Window: ex.Health.Window,
		}}
		for _, p := range ex.Peers {
			src, serr := netip.ParseAddr(byName[p.Name].SourceIP)
			nh, nerr := netip.ParseAddr(p.NextHop)
			if serr != nil || nerr != nil {
				continue // Validate reports it
			}
			targets = append(targets, probe.HopTarget{Provider: p.Name, Source: src, NextHop: nh, Marking: markingOf(byName[p.Name])})
			sp.Peers = append(sp.Peers, p.Name)
		}
		specs = append(specs, sp)
	}
	if len(specs) == 0 {
		return nil, nil
	}
	return targets, exchange.NewHealth(specs)
}

// healthRound probes every target once and feeds the tracker. A prober
// error is an unmeasured sample, not a degraded peer: it says nothing
// about the exchange.
func healthRound(ctx context.Context, p *probe.Engine, h *exchange.Health, targets []probe.HopTarget, now func() time.Time, emit func(plugin.Event)) {
	results := p.ProbeHops(ctx, targets)
	if ctx.Err() != nil {
		return
	}
	samples := make([]exchange.HopSample, 0, len(results))
	for _, r := range results {
		samples = append(samples, exchange.HopSample{Peer: r.Provider, Measured: r.Err == "",
			LossPct: r.Stats.LossPct, RTT: r.Stats.RTTAvg})
	}
	t := now()
	for _, c := range h.Update(t, samples) {
		emit(healthEvent(t, c))
	}
}

// runExchangeHealth probes the exchange peers' next hops once per probe
// interval until ctx ends. It announces and withdraws nothing.
func runExchangeHealth(ctx context.Context, p *probe.Engine, h *exchange.Health, targets []probe.HopTarget, interval func() time.Duration, emit func(plugin.Event)) {
	for {
		healthRound(ctx, p, h, targets, time.Now, emit)
		timer := time.NewTimer(interval())
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func healthEvent(now time.Time, c exchange.Change) plugin.Event {
	fields := map[string]string{"exchange": c.Exchange, "degraded_peers": strings.Join(c.DegradedPeers, ","),
		"degraded": strconv.Itoa(len(c.DegradedPeers)), "peers": strconv.Itoa(c.Peers)}
	if !c.Degraded {
		return plugin.NewEvent(plugin.EventExchangeRecovered, now,
			fmt.Sprintf("exchange %s recovered: %d of %d peers degraded", c.Exchange, len(c.DegradedPeers), c.Peers), fields)
	}
	return plugin.NewEvent(plugin.EventExchangeDegraded, now,
		fmt.Sprintf("exchange %s is degraded: %d of %d peers fail their next-hop probe (the exchange or our port, not one member)",
			c.Exchange, len(c.DegradedPeers), c.Peers), fields)
}
