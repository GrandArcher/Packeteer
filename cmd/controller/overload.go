package main

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/portload"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// overloadLimited reports whether any provider has an interface capacity
// limit (#307).
func overloadLimited(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, p := range cfg.Providers {
		if p.InterfaceCapacityThresholdPct > 0 {
			return true
		}
	}
	return false
}

// fillOverloadInputs reads the interface rates and capacities the limit
// judges, and the flow volume a steer would add, when a provider has a
// limit. The volume is the one commit control and improvement weights
// read, so a scorer that already collected it is not asked twice.
func fillOverloadInputs(ctx context.Context, in *policy.Input, cfg *config.Config, plugins *pluginhost.Set) {
	if in == nil || !overloadLimited(cfg) {
		return
	}
	in.Load = loadsOf(collectTelemetry(ctx, plugins))
	if !scorerPlans(plugins) && in.WeightVolumeMbps == nil {
		in.WeightVolumeMbps = collectVolumes(ctx, plugins)
	}
}

// loadsOf is each telemetry row's outbound rate and capacity by provider.
func loadsOf(rows []plugin.Usage) map[string]policy.Load {
	out := make(map[string]policy.Load, len(rows))
	for _, u := range rows {
		out[u.Provider] = policy.Load{CapacityMbps: u.CapacityMbps, OutMbps: u.OutMbps, Updated: u.Updated}
	}
	return out
}

// underLimit lists the limited providers whose fresh reading is at or below
// their limit.
func underLimit(cfg *config.Config, loads map[string]policy.Load, now time.Time) map[string]bool {
	out := map[string]bool{}
	for _, p := range cfg.Providers {
		l, ok := loads[p.Name]
		if p.InterfaceCapacityThresholdPct <= 0 || !ok || l.CapacityMbps <= 0 || !portload.Fresh(l.Updated, now, portload.DefaultMaxAge) {
			continue
		}
		out[p.Name] = l.OutMbps <= l.CapacityMbps*p.InterfaceCapacityThresholdPct/100
	}
	return out
}

// overloads reports the performance steers the interface capacity limit
// refused or shed (#307). A shed is one event each. A refusal repeats every
// round for as long as the steer stays wanted, so it is reported once per
// prefix and provider until it is allowed or gone. A provider that was
// reported and is back at or below its limit with nothing refused is
// cleared. under is the limited providers that are at or below it.
func (w *eventWatch) overloads(now time.Time, notes []policy.Overload, under map[string]bool) {
	if w == nil || w.out == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	active := map[string]bool{}
	seen := map[string]bool{}
	for _, n := range notes {
		active[n.Provider] = true
		w.overloaded[n.Provider] = true
		key := n.Provider + "|" + n.Prefix.String()
		kind, msg := plugin.EventOverloadShed, fmt.Sprintf("%s: %s", n.Prefix, n.Reason)
		if n.Action == policy.OverloadRefused {
			seen[key] = true
			if w.refused[key] {
				continue
			}
			w.refused[key] = true
			kind = plugin.EventOverloadRefused
		}
		w.out.Emit(plugin.NewEvent(kind, now, msg, map[string]string{
			"provider": n.Provider, "prefix": n.Prefix.String(), "action": n.Action,
			"used_pct": pct1(n.UsedPct), "projected_pct": pct1(n.ProjectedPct), "limit_pct": pct1(n.LimitPct),
			"volume_mbps": strconv.FormatFloat(n.VolumeMbps, 'f', 1, 64),
		}))
	}
	for key := range w.refused {
		if !seen[key] {
			delete(w.refused, key)
		}
	}
	for prov := range w.overloaded {
		if active[prov] || !under[prov] {
			continue
		}
		delete(w.overloaded, prov)
		w.out.Emit(plugin.NewEvent(plugin.EventOverloadCleared, now, prov+" is back under its interface capacity limit", map[string]string{"provider": prov}))
	}
}

func pct1(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }
