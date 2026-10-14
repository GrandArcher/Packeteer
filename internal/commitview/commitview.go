// Package commitview turns stored 95th-percentile samples (#127) and the
// recorded commit improvements into what the Commit & Cost page draws: per
// provider, the sample line, the running billable 95th, and where commit
// control moved traffic. It reads; it does not announce or decide.
package commitview

import (
	"cmp"
	"slices"
	"time"

	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Steps are the ranges the page offers, in days, and the width of a point
// on each. A sample is taken every few minutes (telemetry interval), so a
// point keeps the busiest sample of its width and the 95th as it stood at
// the point's last sample.
var Steps = map[int]time.Duration{1: 5 * time.Minute, 7: 30 * time.Minute, 30: 2 * time.Hour}

// mega converts the stored bits per second to Mbps.
const mega = 1e6

// Point is one drawn point. NewPeriod marks the first point of a billing
// period, where the 95th starts over.
type Point struct {
	At        time.Time `json:"at"`
	Mbps      float64   `json:"mbps"`
	P95Mbps   float64   `json:"p95_mbps"`
	NewPeriod bool      `json:"new_period,omitempty"`
}

// Move is traffic commit control moved (or, in observe, recommended moving)
// at one time. Direction is "off" for traffic taken off the provider and
// "onto" for traffic put on it; Peer is the provider on the other side.
type Move struct {
	At        time.Time `json:"at"`
	Direction string    `json:"direction"`
	Peer      string    `json:"peer"`
	Prefixes  int       `json:"prefixes"`
	Announced bool      `json:"announced"`
}

// Series builds the points from a binding's samples, oldest first. The
// samples must reach back to the start of the billing period that holds
// from, because the running 95th counts the whole period; those before from
// feed the 95th and are not drawn. mode decides what a sample and the
// billable figure are: the larger direction under greater and
// greater_separate, and the outbound direction under separate, as commit
// control reads it (plugin.Usage.BillableMbps).
func Series(mode plugin.PercentileMode, samples []plugin.UsageSample, from time.Time, step time.Duration) []Point {
	out := []Point{}
	var period []plugin.RateSample
	var periodStart time.Time
	var cur *Point
	var curBucket int64
	var curN int
	// The 95th of a point is that of the period up to the point's last
	// sample, so it is computed once per point, not once per sample.
	flush := func() {
		if cur != nil {
			cur.P95Mbps = billable(plugin.Summarize(mode, period[:curN]))
			out = append(out, *cur)
			cur = nil
		}
	}
	for _, s := range samples {
		if !s.PeriodStart.Equal(periodStart) {
			flush()
			periodStart, period = s.PeriodStart, period[:0]
		}
		bucket := s.At.UnixNano() / int64(step)
		if cur != nil && bucket != curBucket {
			flush()
		}
		period = append(period, plugin.RateSample{In: s.InBps, Out: s.OutBps})
		if s.At.Before(from) {
			continue
		}
		mbps := s.OutBps / mega
		if mode != plugin.PercentileSeparate {
			mbps = max(s.InBps, s.OutBps) / mega
		}
		if cur == nil {
			cur, curBucket = &Point{NewPeriod: len(period) == 1}, bucket
		}
		cur.At, cur.Mbps, curN = s.At, max(cur.Mbps, mbps), len(period)
	}
	flush()
	return out
}

func billable(sum plugin.PercentileSummary) float64 {
	if sum.Single {
		return sum.Usage / mega
	}
	return sum.Out95 / mega
}

// Moves groups the commit improvements that touch provider into markers: one
// per direction, peer, announced-or-not, and step-wide bucket, with the
// number of prefixes that moved. rows start no earlier than from.
func Moves(rows []history.ImprovementRow, provider string, from time.Time, step time.Duration) []Move {
	type key struct {
		direction, peer string
		announced       bool
		bucket          int64
	}
	groups := map[key]*Move{}
	for _, r := range rows {
		if r.Cause != plugin.CauseCommit || r.Start.Before(from) {
			continue
		}
		var direction, peer string
		switch provider {
		case r.Native:
			direction, peer = "off", r.Provider
		case r.Provider:
			direction, peer = "onto", r.Native
		default:
			continue
		}
		announced := r.Mode == "inject"
		k := key{direction, peer, announced, r.Start.UnixNano() / int64(step)}
		m := groups[k]
		if m == nil {
			m = &Move{At: r.Start, Direction: direction, Peer: peer, Announced: announced}
			groups[k] = m
		}
		m.At = minTime(m.At, r.Start)
		m.Prefixes++
	}
	out := make([]Move, 0, len(groups))
	for _, m := range groups {
		out = append(out, *m)
	}
	slices.SortFunc(out, func(a, b Move) int {
		return cmp.Or(a.At.Compare(b.At), cmp.Compare(a.Direction, b.Direction), cmp.Compare(a.Peer, b.Peer))
	})
	return out
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
