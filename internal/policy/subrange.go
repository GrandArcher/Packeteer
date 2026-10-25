package policy

import (
	"net/netip"
	"sort"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// noteSubranges adds one provider's sub-range measurements (#121) to the
// prefix's sub-range table. A sub-range is usable for that provider only
// when the provider's prefix candidate is usable and the sub-range itself
// was measured.
func noteSubranges(subs map[netip.Prefix]map[netip.Prefix]*SubrangeDecision, r probe.Result, pc Candidate, scorer plugin.Scorer) {
	if len(r.Subranges) == 0 {
		return
	}
	m := subs[r.Prefix]
	if m == nil {
		m = map[netip.Prefix]*SubrangeDecision{}
		subs[r.Prefix] = m
	}
	for _, sr := range r.Subranges {
		d := m[sr.Prefix]
		if d == nil {
			d = &SubrangeDecision{Prefix: sr.Prefix}
			m[sr.Prefix] = d
		}
		if sr.Weight > d.Weight {
			d.Weight = sr.Weight
		}
		c := Candidate{Provider: r.Provider, LossPct: sr.Stats.LossPct, RTTAvg: sr.Stats.RTTAvg, Jitter: sr.Stats.Jitter,
			ReorderPct: pc.ReorderPct, Usable: pc.Usable, Why: pc.Why}
		switch {
		case !c.Usable:
		case !sr.OK():
			c.Usable, c.Why = false, "probe error"
		case sr.Stats.Sent == 0:
			c.Usable, c.Why = false, "no packets sent"
		}
		if c.Usable {
			c.Score = scorer.Score(plugin.PathStats{Provider: r.Provider, LossPct: c.LossPct, RTTAvg: c.RTTAvg, Jitter: c.Jitter, ReorderPct: c.ReorderPct})
		}
		d.Candidates = append(d.Candidates, c)
	}
}

// attachSubranges records the prefix's sub-ranges on its decision, busiest
// first, with the best provider of each, and flags the prefix
// heterogeneous when two sub-ranges have different best providers. It
// changes no action, recommendation, or improvement.
func attachSubranges(d *Decision, m map[netip.Prefix]*SubrangeDecision, excluded map[string]bool) {
	if len(m) == 0 {
		return
	}
	list := make([]SubrangeDecision, 0, len(m))
	for _, s := range m {
		sort.Slice(s.Candidates, func(a, b int) bool { return s.Candidates[a].Provider < s.Candidates[b].Provider })
		if best, ok := bestCandidate(s.Candidates, excluded, ""); ok {
			s.Best = best.Provider
		}
		list = append(list, *s)
	}
	sort.Slice(list, func(a, b int) bool {
		if list[a].Weight != list[b].Weight {
			return list[a].Weight > list[b].Weight
		}
		return netpfx.Less(list[a].Prefix, list[b].Prefix)
	})
	best := ""
	for _, s := range list {
		if s.Best == "" {
			continue
		}
		if best == "" {
			best = s.Best
		} else if s.Best != best {
			d.Heterogeneous = true
		}
	}
	d.Subranges = list
}
