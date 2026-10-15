package policy

import (
	"net/netip"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// costFirst returns the scorer's cost policy when it asks for cost
// precedence.
func costFirst(scorer plugin.Scorer) (plugin.CostPolicy, bool) {
	cp, ok := scorer.(plugin.CostPolicy)
	if !ok || !cp.CostFirst() {
		return nil, false
	}
	if _, plans := scorer.(plugin.Planner); !plans {
		return nil, false
	}
	return cp, true
}

// annotateCost sets the observed volume on every improvement and change, and
// the cost estimate on those whose native and steered providers both have a
// cost. It does not change a decision.
func annotateCost(st State, out *Output, cfg Config, volume map[netip.Prefix]float64) {
	for p, imp := range st.Improvements {
		st.Improvements[p] = withCost(imp, cfg, volume)
	}
	for i, ch := range out.Changes {
		if ch.Old.Provider != "" {
			out.Changes[i].Old = withCost(ch.Old, cfg, volume)
		}
		if ch.New.Provider != "" {
			out.Changes[i].New = withCost(ch.New, cfg, volume)
		}
	}
}

// withCost returns imp with VolumeMbps, CostDelta, and EstSavings recomputed.
func withCost(imp Improvement, cfg Config, volume map[netip.Prefix]float64) Improvement {
	imp.VolumeMbps, imp.CostDelta, imp.EstSavings = volume[imp.Prefix], 0, 0
	nat, ok1 := providerCost(cfg, imp.Native)
	cur, ok2 := providerCost(cfg, imp.Provider)
	if ok1 && ok2 {
		imp.CostDelta = nat - cur
		if volume[imp.Prefix] > 0 {
			imp.EstSavings = imp.CostDelta * volume[imp.Prefix]
		}
	}
	return imp
}
