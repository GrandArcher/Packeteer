package plugin

import "sort"

// Percentile95 returns the 95th percentile by nearest rank: sort ascending
// and take the 1-based rank ceil(0.95*N). The rank is computed as
// (95*N+99)/100 so a value that is not exact in binary floating point
// cannot move the index. N of 0 returns 0, false. The input slice is not
// modified.
//
// For a multiple of 20 this is the sample that remains after the top 5%
// are discarded. For N of 10 the rank is 10, the maximum, because 5% of
// 10 is not a whole sample under this rule.
func Percentile95(values []float64) (float64, bool) {
	n := len(values)
	if n == 0 {
		return 0, false
	}
	cp := append([]float64(nil), values...)
	sort.Float64s(cp)
	rank := (95*n + 99) / 100
	if rank < 1 {
		rank = 1
	}
	if rank > n {
		rank = n
	}
	return cp[rank-1], true
}

// Summarize applies mode to samples. In95 and Out95 are always the 95th
// percentile of each direction. Usage is set only when Single is true.
func Summarize(mode PercentileMode, samples []RateSample) PercentileSummary {
	n := len(samples)
	if n == 0 {
		return PercentileSummary{}
	}
	inVals := make([]float64, n)
	outVals := make([]float64, n)
	maxVals := make([]float64, n)
	for i, s := range samples {
		inVals[i] = s.In
		outVals[i] = s.Out
		maxVals[i] = s.In
		if s.Out > maxVals[i] {
			maxVals[i] = s.Out
		}
	}
	in95, _ := Percentile95(inVals)
	out95, _ := Percentile95(outVals)
	out := PercentileSummary{In95: in95, Out95: out95, Samples: n}
	switch mode {
	case PercentileGreater:
		out.Usage, _ = Percentile95(maxVals)
		out.Single = true
	case PercentileGreaterSeparate:
		out.Usage = in95
		if out95 > out.Usage {
			out.Usage = out95
		}
		out.Single = true
	default:
		// separate, and any unknown mode: two figures, no combined usage.
	}
	return out
}
