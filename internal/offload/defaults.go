package offload

import (
	"errors"
	"math"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// QualitySample is one provider's measurement of one prefix, from the latest
// decision round. Score is the scorer's number, lower is better.
type QualitySample struct {
	Prefix   netip.Prefix
	Provider string
	Score    float64
	LossPct  float64
	RTT      time.Duration
}

// ProviderQuality is a provider's measured quality over the traffic that
// rides it: the mean of its samples weighted by each prefix's volume.
type ProviderQuality struct {
	Provider string  `json:"provider"`
	Score    float64 `json:"score"`
	LossPct  float64 `json:"loss_pct"`
	RTTMs    float64 `json:"rtt_ms"`
	// Prefixes is how many samples contributed, VolumeMbps their summed
	// weight (the sample count when no volume is known).
	Prefixes   int     `json:"prefixes"`
	VolumeMbps float64 `json:"volume_mbps"`
}

// WeighQuality averages samples per provider, weighting each by the rate of
// its prefix. With no rates every sample weighs the same, and with rates a
// prefix that has none, or a zero one, carries no traffic and is skipped. A
// provider with no weighted sample is absent: its quality is unknown, never
// zero. The result is ordered by provider.
func WeighQuality(samples []QualitySample, rates map[netip.Prefix]float64) []ProviderQuality {
	type sum struct {
		w, score, loss, rttMs float64
		n                     int
	}
	by := map[string]*sum{}
	for _, s := range samples {
		w := 1.0
		if len(rates) > 0 {
			w = rates[s.Prefix]
		}
		if !(w > 0) || math.IsInf(w, 0) || math.IsNaN(s.Score) || math.IsInf(s.Score, 0) {
			continue
		}
		a := by[s.Provider]
		if a == nil {
			a = &sum{}
			by[s.Provider] = a
		}
		a.w += w
		a.score += w * s.Score
		a.loss += w * s.LossPct
		a.rttMs += w * float64(s.RTT) / float64(time.Millisecond)
		a.n++
	}
	out := make([]ProviderQuality, 0, len(by))
	for name, a := range by {
		out = append(out, ProviderQuality{Provider: name, Score: a.score / a.w, LossPct: a.loss / a.w,
			RTTMs: a.rttMs / a.w, Prefixes: a.n, VolumeMbps: a.w})
	}
	slices.SortFunc(out, func(a, b ProviderQuality) int { return strings.Compare(a.Provider, b.Provider) })
	return out
}

// RankerConfig is the hysteresis of a ranking.
type RankerConfig struct {
	// Margin: a provider passes the one ranked above it only when its score is
	// lower by more than Margin x that score. 0 is no hysteresis.
	Margin float64
	// Cooldown is how long the order stays after it last changed.
	Cooldown time.Duration
}

// RankedProvider is a provider's place in the order. Known is false when it
// has no measurement: it ranks last, and never above a measured provider.
type RankedProvider struct {
	ProviderQuality
	Rank  int  `json:"rank"`
	Known bool `json:"known"`
}

// Ranker keeps the order of a set of providers (the candidate defaults of one
// router) steady: a change needs a clear margin and waits out a cooldown, so
// measurement noise does not reorder defaults. It is not safe for concurrent
// use.
type Ranker struct {
	cfg       RankerConfig
	order     []string
	changedAt time.Time
}

// NewRanker returns a Ranker, or the first defect in cfg.
func NewRanker(cfg RankerConfig) (*Ranker, error) {
	switch {
	case math.IsNaN(cfg.Margin) || math.IsInf(cfg.Margin, 0) || cfg.Margin < 0:
		return nil, errors.New("offload: rank margin must be a finite number, 0 or more")
	case cfg.Cooldown < 0:
		return nil, errors.New("offload: rank cooldown must not be negative")
	}
	return &Ranker{cfg: cfg}, nil
}

// Rank orders providers at now by their quality in q. The first order is
// the plain one, best score first. After that the standing order moves only
// past the margin and only once the cooldown since its last change has run
// out. A provider that leaves the set drops out; one that joins starts last and
// moves up only past the margin.
func (r *Ranker) Rank(now time.Time, providers []string, q []ProviderQuality) []RankedProvider {
	known := make(map[string]ProviderQuality, len(q))
	for _, p := range q {
		known[p.Provider] = p
	}
	set := slices.Clone(providers)
	slices.Sort(set)
	set = slices.Compact(set)

	// raw is the order with no history: measured first by score, then by name.
	raw := slices.Clone(set)
	slices.SortStableFunc(raw, func(a, b string) int {
		qa, oka := known[a]
		qb, okb := known[b]
		switch {
		case oka && okb && qa.Score != qb.Score:
			if qa.Score < qb.Score {
				return -1
			}
			return 1
		case oka != okb:
			if oka {
				return -1
			}
			return 1
		}
		return strings.Compare(a, b)
	})

	order := r.order[:0:0]
	for _, p := range r.order {
		if slices.Contains(set, p) {
			order = append(order, p)
		}
	}
	for _, p := range raw {
		if !slices.Contains(order, p) {
			order = append(order, p)
		}
	}
	if len(r.order) == 0 {
		order = raw
	} else if r.changedAt.IsZero() || now.Sub(r.changedAt) >= r.cfg.Cooldown {
		before := slices.Clone(order)
		r.settle(order, known)
		if !slices.Equal(before, order) {
			r.changedAt = now
		}
	}
	r.order = order

	out := make([]RankedProvider, len(order))
	for i, p := range order {
		qp, ok := known[p]
		qp.Provider = p
		out[i] = RankedProvider{ProviderQuality: qp, Rank: i + 1, Known: ok}
	}
	return out
}

// settle moves each provider above its neighbor while it beats that
// neighbor by the margin. Every move removes a pair the plain order would not
// have, so it ends.
func (r *Ranker) settle(order []string, known map[string]ProviderQuality) {
	beats := func(b, a string) bool {
		qb, ok := known[b]
		if !ok {
			return false
		}
		qa, ok := known[a]
		return !ok || qa.Score-qb.Score > r.cfg.Margin*math.Abs(qa.Score)
	}
	for moved := true; moved; {
		moved = false
		for i := 1; i < len(order); i++ {
			if beats(order[i], order[i-1]) {
				order[i], order[i-1] = order[i-1], order[i]
				moved = true
			}
		}
	}
}
