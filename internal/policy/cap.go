package policy

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// trimToCap drops active improvements until the set fits cfg.MaxImprovements.
// Planned moves go first, then performance, then VIP, then static pins.
// Inside a rank the smallest gain goes first (a missing score is no gain),
// and a larger prefix goes before a smaller one so the smaller prefix is
// kept. The retire ignores hold_time and does not start a cooldown: the
// cap fell, and raising it may admit the prefix again on the next round.
func trimToCap(st State, decIdx map[netip.Prefix]*Decision, byPrefix map[netip.Prefix][]Candidate, policies map[netip.Prefix]plugin.PolicyVerdict, cfg Config, retire func(netip.Prefix, string, bool)) {
	if cfg.MaxImprovements < 0 || len(st.Improvements) <= cfg.MaxImprovements {
		return
	}
	type item struct {
		p    netip.Prefix
		rank int
		gain float64
	}
	items := make([]item, 0, len(st.Improvements))
	for p, imp := range st.Improvements {
		items = append(items, item{p: p, rank: rankOf(imp, policies), gain: improvementGain(byPrefix[p], imp)})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].rank != items[j].rank {
			return items[i].rank > items[j].rank
		}
		if items[i].gain != items[j].gain {
			return items[i].gain < items[j].gain
		}
		return netpfx.Less(items[j].p, items[i].p)
	})
	reason := fmt.Sprintf("max_improvements (%d) reached", cfg.MaxImprovements)
	for _, it := range items {
		if len(st.Improvements) <= cfg.MaxImprovements {
			break
		}
		imp := st.Improvements[it.p]
		retire(it.p, reason, false)
		if d := decIdx[it.p]; d != nil {
			d.Action, d.Reason, d.Current = ActionRetire, reason, imp.Native
		}
	}
}

// rankOf is the admission lane of an improvement already in the table.
// VIP is a performance move whose current policy says vip.
func rankOf(imp Improvement, policies map[netip.Prefix]plugin.PolicyVerdict) int {
	switch {
	case planned(imp.Cause):
		return rankPlanned
	case imp.Cause == plugin.CauseStatic:
		return rankStatic
	}
	if v, ok := policies[imp.Prefix]; ok && v.Action == plugin.PolicyVIP {
		return rankVIP
	}
	return rankPerformance
}

// improvementGain is the native score minus the current provider's score.
// A missing measurement is no gain, so that improvement is retired ahead
// of one that is still clearly better.
func improvementGain(cands []Candidate, imp Improvement) float64 {
	var nat, cur float64
	var haveNat, haveCur bool
	for _, c := range cands {
		if !c.Usable {
			continue
		}
		if c.Provider == imp.Native {
			nat, haveNat = c.Score, true
		}
		if c.Provider == imp.Provider {
			cur, haveCur = c.Score, true
		}
	}
	if !haveNat || !haveCur {
		return 0
	}
	return nat - cur
}

// planned reports whether an improvement belongs to the planner lane.
func planned(cause string) bool {
	return cause == plugin.CauseCommit || cause == plugin.CauseCost
}

// displaceCommit retires one commit or cost improvement so a performance
// move can use the slot. The smallest volume goes first (it relieves the least);
// equal volume breaks by prefix. The prefix takes a hold_time cooldown so
// the commit steer cannot return on the next round and take the slot back.
func displaceCommit(st State, decIdx map[netip.Prefix]*Decision, volume map[netip.Prefix]float64, retire func(netip.Prefix, string, bool)) bool {
	var pick netip.Prefix
	var pickVol float64
	found := false
	for p, imp := range st.Improvements {
		if !planned(imp.Cause) {
			continue
		}
		vol := 0.0
		if volume != nil {
			vol = volume[p]
		}
		if !found || vol < pickVol || (vol == pickVol && netpfx.Less(p, pick)) {
			pick, pickVol, found = p, vol, true
		}
	}
	if !found {
		return false
	}
	imp := st.Improvements[pick]
	const reason = "displaced by a performance improvement"
	retire(pick, reason, true)
	setDecision(decIdx[pick], ActionRetire, reason, imp.Native, "", imp.Cause)
	return true
}
