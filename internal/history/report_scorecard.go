package history

import (
	"cmp"
	"math"
	"net/netip"
	"slices"
	"strconv"
)

// Weighting values of a scorecard row.
const (
	WeightFlow  = "flow"
	WeightEqual = "equal"
)

// ScorecardRow is one provider's measured path toward one destination
// origin ASN (#209). The percentiles are over the daily means of every
// prefix of the ASN that the provider measured, each weighted by the
// prefix's observed flow volume. Rank 1 is the best provider for the ASN.
// A provider whose probes never got a reply has no RTT or jitter.
type ScorecardRow struct {
	Provider  string `json:"provider"`
	OriginASN uint32 `json:"origin_asn"`
	Rank      int    `json:"rank"`
	Prefixes  int    `json:"prefixes"`
	Probes    int    `json:"probes"`
	// FailedPct is the share of probes that got no reply.
	FailedPct  float64 `json:"failed_pct"`
	VolumeMbps float64 `json:"volume_mbps"`
	// Weighting is "flow" when any prefix of the ASN has a known volume and
	// "equal" when none of the ASN's prefixes has, so every daily mean
	// counts the same. In a "flow" row a prefix with no known volume
	// carries no weight.
	Weighting  string   `json:"weighting"`
	LossP50Pct *float64 `json:"loss_p50_pct,omitempty"`
	LossP95Pct *float64 `json:"loss_p95_pct,omitempty"`
	RTTP50Ms   *float64 `json:"rtt_p50_ms,omitempty"`
	RTTP95Ms   *float64 `json:"rtt_p95_ms,omitempty"`
	JitP50Ms   *float64 `json:"jitter_p50_ms,omitempty"`
	JitP95Ms   *float64 `json:"jitter_p95_ms,omitempty"`
}

// sample is one prefix-day mean and the weight it counts with.
type sample struct {
	v, w float64
	pfx  netip.Prefix
}

// weightedPercentile is the nearest-rank percentile p (1-100) of s: the
// smallest value whose cumulative weight reaches p percent of the total.
// It is nil when s has no weight.
func weightedPercentile(s []sample, p float64) *float64 {
	var total float64
	for _, x := range s {
		total += x.w
	}
	if total <= 0 {
		return nil
	}
	sorted := slices.Clone(s)
	slices.SortFunc(sorted, func(a, b sample) int { return cmp.Compare(a.v, b.v) })
	var cum float64
	for _, x := range sorted {
		cum += x.w
		if cum*100 >= p*total {
			v := round(x.v)
			return &v
		}
	}
	v := round(sorted[len(sorted)-1].v)
	return &v
}

// scorecard builds one row per provider and origin ASN. A prefix with no
// learned origin is left out, as in the asns report. Providers are ranked
// against each other within an ASN by median loss, then 95th percentile
// loss, then median RTT; rows that tie on all three share a rank. Rows are
// ordered by the ASN's volume, then ASN, then rank.
func (a *agg) scorecard(rep *Report) {
	type key struct {
		provider string
		asn      uint32
	}
	type acc struct {
		probes, failed    int
		prefixes          map[netip.Prefix]bool
		loss, rtt, jitter []sample
	}
	m := map[key]*acc{}
	asnPrefixes := map[uint32]map[netip.Prefix]bool{}
	for _, b := range a.buckets {
		asn := a.info[b.Prefix].OriginASN
		n := b.Measured + b.Failed
		if asn == 0 || n == 0 {
			continue
		}
		k := key{b.Provider, asn}
		x := m[k]
		if x == nil {
			x = &acc{prefixes: map[netip.Prefix]bool{}}
			m[k] = x
		}
		if asnPrefixes[asn] == nil {
			asnPrefixes[asn] = map[netip.Prefix]bool{}
		}
		asnPrefixes[asn][b.Prefix] = true
		x.probes += n
		x.failed += b.Failed
		x.prefixes[b.Prefix] = true
		// A probe with no reply is full loss, so a path that never answers
		// ranks last instead of vanishing.
		x.loss = append(x.loss, sample{v: (b.LossSum + 100*float64(b.Failed)) / float64(n), pfx: b.Prefix})
		if b.Measured > 0 {
			meas := float64(b.Measured)
			x.rtt = append(x.rtt, sample{v: b.RTTSumMs / meas, pfx: b.Prefix})
			x.jitter = append(x.jitter, sample{v: b.JitterSum / meas, pfx: b.Prefix})
		}
	}
	asnVolume := map[uint32]float64{}
	for asn, ps := range asnPrefixes {
		for p := range ps {
			asnVolume[asn] += a.info[p].VolumeMbps
		}
	}
	rows := make([]ScorecardRow, 0, len(m))
	for k, x := range m {
		var volume float64
		for p := range x.prefixes {
			volume += a.info[p].VolumeMbps
		}
		// One basis per ASN, so the providers ranked against each other
		// are weighted alike. A prefix with no known volume then weighs 0.
		weighting := WeightEqual
		if asnVolume[k.asn] > 0 {
			weighting = WeightFlow
		}
		for _, s := range [][]sample{x.loss, x.rtt, x.jitter} {
			for i := range s {
				s[i].w = 1
				if weighting == WeightFlow {
					s[i].w = a.info[s[i].pfx].VolumeMbps
				}
			}
		}
		rows = append(rows, ScorecardRow{
			Provider: k.provider, OriginASN: k.asn, Prefixes: len(x.prefixes), Probes: x.probes,
			FailedPct: round(100 * float64(x.failed) / float64(x.probes)), VolumeMbps: round(volume), Weighting: weighting,
			LossP50Pct: weightedPercentile(x.loss, 50), LossP95Pct: weightedPercentile(x.loss, 95),
			RTTP50Ms: weightedPercentile(x.rtt, 50), RTTP95Ms: weightedPercentile(x.rtt, 95),
			JitP50Ms: weightedPercentile(x.jitter, 50), JitP95Ms: weightedPercentile(x.jitter, 95),
		})
	}
	rankScorecard(rows)
	slices.SortFunc(rows, func(x, y ScorecardRow) int {
		if c := cmp.Compare(asnVolume[y.OriginASN], asnVolume[x.OriginASN]); c != 0 {
			return c
		}
		if c := cmp.Compare(x.OriginASN, y.OriginASN); c != 0 {
			return c
		}
		if c := cmp.Compare(x.Rank, y.Rank); c != 0 {
			return c
		}
		return cmp.Compare(x.Provider, y.Provider)
	})
	rep.Rows = rows
	for _, r := range rows {
		rep.lines = append(rep.lines, []string{r.Provider, strconv.FormatUint(uint64(r.OriginASN), 10), strconv.Itoa(r.Rank),
			strconv.Itoa(r.Prefixes), strconv.Itoa(r.Probes), f(r.FailedPct), f(r.VolumeMbps), r.Weighting,
			optS(r.LossP50Pct), optS(r.LossP95Pct), optS(r.RTTP50Ms), optS(r.RTTP95Ms), optS(r.JitP50Ms), optS(r.JitP95Ms)})
	}
}

// worse is a figure that is absent counting as the worst.
func worse(v *float64) float64 {
	if v == nil {
		return math.Inf(1)
	}
	return *v
}

func rankOrder(x, y ScorecardRow) int {
	if c := cmp.Compare(worse(x.LossP50Pct), worse(y.LossP50Pct)); c != 0 {
		return c
	}
	if c := cmp.Compare(worse(x.LossP95Pct), worse(y.LossP95Pct)); c != 0 {
		return c
	}
	return cmp.Compare(worse(x.RTTP50Ms), worse(y.RTTP50Ms))
}

// rankScorecard sets Rank on each row against the other rows of its ASN.
func rankScorecard(rows []ScorecardRow) {
	slices.SortFunc(rows, func(x, y ScorecardRow) int {
		if c := cmp.Compare(x.OriginASN, y.OriginASN); c != 0 {
			return c
		}
		if c := rankOrder(x, y); c != 0 {
			return c
		}
		return cmp.Compare(x.Provider, y.Provider)
	})
	for i := range rows {
		switch {
		case i > 0 && rows[i].OriginASN == rows[i-1].OriginASN && rankOrder(rows[i-1], rows[i]) == 0:
			rows[i].Rank = rows[i-1].Rank
		case i > 0 && rows[i].OriginASN == rows[i-1].OriginASN:
			rows[i].Rank = rows[i-1].Rank + 1
		default:
			rows[i].Rank = 1
		}
	}
}
