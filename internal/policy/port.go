package policy

import (
	"net/netip"
	"time"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/internal/portload"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// portRefused starts the reason of every decision an exchange port refused
// (#643); the explanation reads it to tell that the port was full.
const portRefused = "exchange port: "

// usageByProvider is the first telemetry row of each provider.
func (in Input) usageByProvider() map[string]plugin.Usage {
	out := map[string]plugin.Usage{}
	for _, u := range in.Usage {
		if _, seen := out[u.Provider]; u.Provider != "" && !seen {
			out[u.Provider] = u
		}
	}
	return out
}

// planPorts is each configured exchange port with its telemetry row.
func planPorts(cfg Config, usage map[string]plugin.Usage) []plugin.PlanPort {
	var out []plugin.PlanPort
	for _, pt := range cfg.Ports {
		row, have := usage[pt.Name]
		out = append(out, plugin.PlanPort{Name: pt.Name, CapacityMbps: pt.CapacityMbps, CommitMbps: pt.CommitMbps, Usage: row, HaveRow: have})
	}
	return out
}

// readPorts books the exchange ports (#643) on the ledger the commit and
// cost scorers use, from cfg.Ports and the port rows in in.Usage. A steer
// the port's sample does not hold yet is moved from its native provider to
// its provider: every steer outside inject mode, where nothing is on the
// wire, and in inject a steer newer than the sample.
func (g *loadGate) readPorts(st State, in Input, cfg Config, now time.Time) {
	usage := in.usageByProvider()
	plan := plugin.PlanInput{Now: now, Ports: planPorts(cfg, usage)}
	portOf := map[string]string{}
	for _, pp := range cfg.Providers {
		if pp.Port != "" {
			portOf[pp.Name] = pp.Port
			plan.Providers = append(plan.Providers, plugin.PlanProvider{Name: pp.Name, Port: pp.Port})
		}
	}
	g.ports = portload.NewLedger(plan, portload.DefaultMaxAge)
	pending := func(provider string, imp Improvement) bool {
		name := portOf[provider]
		return name != "" && (cfg.Mode != "inject" || imp.Since.After(usage[name].Updated))
	}
	for _, p := range netpfx.SortedKeys(st.Improvements) {
		imp := st.Improvements[p]
		if portOf[imp.Native] == portOf[imp.Provider] {
			continue
		}
		if pending(imp.Native, imp) {
			g.ports.Move(imp.Native, "", g.vols[p])
		}
		if pending(imp.Provider, imp) {
			g.ports.Move("", imp.Provider, g.vols[p])
		}
	}
}

// refusePort says why a steer of p from one provider onto another would
// not fit the destination's exchange port, by the rule the commit and cost
// scorers apply to their moves (portload.Ledger.Refusal).
func (g *loadGate) refusePort(from, to string, p netip.Prefix) (string, bool) {
	if g == nil || g.ports == nil {
		return "", false
	}
	if why := g.ports.Refusal(from, to, g.vols[p]); why != "" {
		return portRefused + why, true
	}
	return "", false
}

// movePort books p's volume leaving one provider and arriving on another,
// on their ports.
func (g *loadGate) movePort(from, to string, p netip.Prefix) {
	if g != nil && g.ports != nil {
		g.ports.Move(from, to, g.vols[p])
	}
}
