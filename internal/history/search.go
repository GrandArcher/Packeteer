package history

import (
	"cmp"
	"net/netip"
	"slices"
	"time"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// SearchQuery is the stored-history side of the global search (#172). A
// row matches when its prefix is related to Prefix (equal, covering, or
// more specific) or its origin ASN is in ASNs. Limit caps each list.
type SearchQuery struct {
	Prefix netip.Prefix
	ASNs   []uint32
	From   time.Time
	To     time.Time
	Limit  int
}

// SearchImprovement is a stored improvement that matched. Relation is
// empty when it matched by origin ASN only.
type SearchImprovement struct {
	ImprovementRow
	Relation string `json:"relation,omitempty"`
}

// SearchRollup is one prefix's probe rollups in the range, across
// providers and days. LossPct and RTTMs average the probes that returned
// statistics and are nil when none did.
type SearchRollup struct {
	Prefix    string   `json:"prefix"`
	Relation  string   `json:"relation,omitempty"`
	OriginASN uint32   `json:"origin_asn,omitempty"`
	Providers []string `json:"providers"`
	LastDay   string   `json:"last_day"`
	Days      int      `json:"days"`
	Probes    int      `json:"probes"`
	Failed    int      `json:"failed"`
	LossPct   *float64 `json:"loss_pct,omitempty"`
	RTTMs     *float64 `json:"rtt_ms,omitempty"`
}

// SearchResult holds the matches newest first. The totals count every
// match; the lists hold at most Limit of them.
type SearchResult struct {
	Improvements      []SearchImprovement `json:"improvements"`
	ImprovementsTotal int                 `json:"improvements_total"`
	Rollups           []SearchRollup      `json:"rollups"`
	RollupsTotal      int                 `json:"rollups_total"`
}

// Search finds the improvements and probe rollups of h that match q. It
// is pure and reads only.
func Search(h plugin.History, q SearchQuery) SearchResult {
	a := newAgg(h, Query{From: q.From, To: q.To, Now: q.To})
	match := func(p netip.Prefix, origin uint32) (string, bool) {
		return netpfx.Match(q.Prefix, q.ASNs, p, origin)
	}
	res := SearchResult{Improvements: []SearchImprovement{}, Rollups: []SearchRollup{}}

	imps := []SearchImprovement{}
	for _, r := range a.imps {
		if rel, ok := match(r.Prefix, improvementOrigin(r, a.info)); ok {
			imps = append(imps, SearchImprovement{ImprovementRow: improvementRow(r, a.hours(r)), Relation: rel})
		}
	}
	slices.SortFunc(imps, func(x, y SearchImprovement) int {
		return cmp.Or(y.Start.Compare(x.Start), cmp.Compare(x.Prefix, y.Prefix), cmp.Compare(x.Provider, y.Provider))
	})
	res.ImprovementsTotal = len(imps)
	res.Improvements = imps[:min(len(imps), q.Limit)]

	type sum struct {
		SearchRollup
		measured int
		loss     float64
		rtt      float64
		days     map[string]bool
	}
	byPrefix := map[netip.Prefix]*sum{}
	for _, b := range a.buckets {
		origin := a.info[b.Prefix].OriginASN
		rel, ok := match(b.Prefix, origin)
		if !ok {
			continue
		}
		s := byPrefix[b.Prefix]
		if s == nil {
			s = &sum{SearchRollup: SearchRollup{Prefix: b.Prefix.String(), Relation: rel, OriginASN: origin}, days: map[string]bool{}}
			byPrefix[b.Prefix] = s
		}
		day := b.Day.UTC().Format(time.DateOnly)
		s.days[day] = true
		s.LastDay = max(s.LastDay, day)
		if !slices.Contains(s.Providers, b.Provider) {
			s.Providers = append(s.Providers, b.Provider)
		}
		s.Probes += b.Probes
		s.Failed += b.Failed
		s.measured += b.Measured
		s.loss += b.LossSum
		s.rtt += b.RTTSumMs
	}
	rolls := make([]SearchRollup, 0, len(byPrefix))
	for _, s := range byPrefix {
		s.Days = len(s.days)
		slices.Sort(s.Providers)
		if s.measured > 0 {
			n := float64(s.measured)
			s.LossPct, s.RTTMs = ptr(round(s.loss/n)), ptr(round(s.rtt/n))
		}
		rolls = append(rolls, s.SearchRollup)
	}
	slices.SortFunc(rolls, func(x, y SearchRollup) int {
		return cmp.Or(cmp.Compare(y.LastDay, x.LastDay), cmp.Compare(x.Prefix, y.Prefix))
	})
	res.RollupsTotal = len(rolls)
	res.Rollups = rolls[:min(len(rolls), q.Limit)]
	return res
}
