package history

import (
	"cmp"
	"net/netip"
	"slices"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// PrefixDay is one provider's probe rollup toward one prefix on one UTC
// day (#179). Averages are over the probes that returned statistics and
// are nil when none did.
type PrefixDay struct {
	Day      string   `json:"day"`
	Provider string   `json:"provider"`
	Probes   int      `json:"probes"`
	Failed   int      `json:"failed"`
	LossPct  *float64 `json:"loss_pct,omitempty"`
	RTTMs    *float64 `json:"rtt_ms,omitempty"`
	JitterMs *float64 `json:"jitter_ms,omitempty"`
}

// PrefixHistory is the stored history of one prefix for a range: its daily
// probe rollups, oldest first, and every improvement that overlaps the
// range, newest first. Mode on an improvement is the mode it started in;
// only inject announces.
type PrefixHistory struct {
	Prefix       string           `json:"prefix"`
	From         time.Time        `json:"from"`
	To           time.Time        `json:"to"`
	Days         []PrefixDay      `json:"days"`
	Improvements []ImprovementRow `json:"improvements"`
	// RPKI is the origin-validation state of every learned path toward
	// the prefix over the range, newest first (#200).
	RPKI []RPKIRow `json:"rpki"`
}

// RPKIRow is one provider's learned path, by origin AS, in one
// origin-validation state from First to Last (#200). Source is the
// rpki.sources entry that answered; empty while no source had data.
type RPKIRow struct {
	Provider string              `json:"provider"`
	Origin   uint32              `json:"origin_asn"`
	State    plugin.RPKIValidity `json:"state"`
	Source   string              `json:"source,omitempty"`
	First    time.Time           `json:"first"`
	Last     time.Time           `json:"last"`
}

// BuildPrefix filters h to prefix p. It is pure and exact: a covering or
// a covered prefix is a different prefix and is not included.
func BuildPrefix(h plugin.History, p netip.Prefix, q Query) PrefixHistory {
	if q.Now.IsZero() || q.Now.After(q.To) {
		q.Now = q.To
	}
	out := PrefixHistory{Prefix: p.String(), From: q.From.UTC(), To: q.To.UTC(), Days: []PrefixDay{}, Improvements: []ImprovementRow{}, RPKI: []RPKIRow{}}
	a := newAgg(h, q)
	for _, b := range a.buckets {
		if b.Prefix != p {
			continue
		}
		d := PrefixDay{Day: b.Day.UTC().Format(time.DateOnly), Provider: b.Provider, Probes: b.Probes, Failed: b.Failed}
		if b.Measured > 0 {
			n := float64(b.Measured)
			d.LossPct, d.RTTMs, d.JitterMs = ptr(round(b.LossSum/n)), ptr(round(b.RTTSumMs/n)), ptr(round(b.JitterSum/n))
		}
		out.Days = append(out.Days, d)
	}
	slices.SortFunc(out.Days, func(x, y PrefixDay) int {
		return cmp.Or(cmp.Compare(x.Day, y.Day), cmp.Compare(x.Provider, y.Provider))
	})
	var imps []plugin.ImprovementRecord
	for _, r := range a.imps {
		if r.Prefix == p {
			imps = append(imps, r)
		}
	}
	slices.SortFunc(imps, func(x, y plugin.ImprovementRecord) int {
		return cmp.Or(y.Start.Compare(x.Start), cmp.Compare(x.ID, y.ID))
	})
	for _, r := range imps {
		out.Improvements = append(out.Improvements, improvementRow(r, a.hours(r)))
	}
	for _, r := range h.RPKIRoutes {
		if r.Prefix == p {
			out.RPKI = append(out.RPKI, RPKIRow{Provider: r.Provider, Origin: r.Origin, State: r.State, Source: r.Source, First: r.First, Last: r.Last})
		}
	}
	slices.SortFunc(out.RPKI, func(x, y RPKIRow) int {
		return cmp.Or(y.First.Compare(x.First), cmp.Compare(x.Provider, y.Provider), cmp.Compare(x.Origin, y.Origin))
	})
	return out
}

func ptr(v float64) *float64 { return &v }
