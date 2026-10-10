package history

import (
	"cmp"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Destination buckets of the timeseries report (#129). Every bucket is a
// subset of "all", and better_50 is a subset of better_20.
const (
	BucketAll      = "all"
	BucketProblem  = "problem"
	BucketBetter20 = "better_20"
	BucketBetter50 = "better_50"
)

// Buckets lists the destination buckets in the order rows are written in
// for one day.
var Buckets = []string{BucketAll, BucketProblem, BucketBetter20, BucketBetter50}

// TimeSeriesRow is one UTC day of one bucket. Before is the native
// provider's average on the day and After the chosen provider's, over the
// prefixes in the bucket that day. Both come from the daily probe rollups,
// so the two lines are measurements of the two paths whether or not the
// improvement was announced.
type TimeSeriesRow struct {
	Day           string  `json:"day"`
	Bucket        string  `json:"bucket"`
	Prefixes      int     `json:"prefixes"`
	BeforeLossPct float64 `json:"before_loss_pct"`
	AfterLossPct  float64 `json:"after_loss_pct"`
	BeforeRTTMs   float64 `json:"before_rtt_ms"`
	AfterRTTMs    float64 `json:"after_rtt_ms"`
}

type dayKey struct {
	day      int64
	prefix   netip.Prefix
	provider string
}

type tsPair struct {
	day              int64
	prefix           netip.Prefix
	native, provider string
}

type tsAcc struct {
	prefixes       map[netip.Prefix]bool
	bl, al, br, ar mean
}

func (x *tsAcc) add(p netip.Prefix, n, c plugin.ProbeBucket) {
	if x.prefixes == nil {
		x.prefixes = map[netip.Prefix]bool{}
	}
	x.prefixes[p] = true
	x.bl.addN(n.LossSum, n.Measured)
	x.br.addN(n.RTTSumMs, n.Measured)
	x.al.addN(c.LossSum, c.Measured)
	x.ar.addN(c.RTTSumMs, c.Measured)
}

// better reports whether after is at least pct percent better (lower)
// than before. A before of zero cannot get better.
func better(before, after, pct float64) bool {
	return before > 0 && (before-after)*100 >= pct*before
}

// timeseries builds loss and RTT per UTC day, before (the native
// provider) and after (the chosen provider), for every improvement that
// overlaps the range. Each improvement is paired, per day it was active,
// with that day's rollup of its native and its chosen provider toward the
// prefix; a day with no measurement on either side is skipped.
//
//   - all: every such prefix and day.
//   - problem: improvements made for performance (the native path broke
//     the loss or latency thresholds), not for commit or cost.
//   - better_20, better_50: prefix-days on which the chosen path's loss or
//     RTT averaged at least 20% (50%) lower than the native path's.
//
// Daily rollups are the finest the store keeps, so a point is one day.
func (a *agg) timeseries(rep *Report) {
	rollup := make(map[dayKey]plugin.ProbeBucket, len(a.buckets))
	for _, b := range a.buckets {
		k := dayKey{b.Day.UTC().Unix(), b.Prefix, b.Provider}
		cur := rollup[k]
		if cur.Measured == 0 && cur.Probes == 0 {
			cur = b
		} else {
			cur.Probes += b.Probes
			cur.Failed += b.Failed
			cur.Measured += b.Measured
			cur.LossSum += b.LossSum
			cur.RTTSumMs += b.RTTSumMs
			cur.JitterSum += b.JitterSum
		}
		rollup[k] = cur
	}
	first := a.q.From.UTC().Truncate(24 * time.Hour)
	type cell struct {
		day    int64
		bucket string
	}
	cells := map[cell]*tsAcc{}
	seen := map[tsPair]bool{}
	for _, r := range a.imps {
		if r.Native == "" || r.Provider == "" || r.Native == r.Provider {
			continue
		}
		end := r.End
		if end.IsZero() || end.After(a.q.Now) {
			end = a.q.Now
		}
		startDay := r.Start.UTC().Truncate(24 * time.Hour)
		// A day counts when the improvement was active in it; the day it
		// started counts even if it ended in the same instant.
		d := startDay
		if d.Before(first) {
			d = first
		}
		for ; d.Before(a.q.To) && (d.Before(end) || d.Equal(startDay)); d = d.Add(24 * time.Hour) {
			pair := tsPair{d.Unix(), r.Prefix, r.Native, r.Provider}
			if seen[pair] {
				continue
			}
			n, ok := rollup[dayKey{d.Unix(), r.Prefix, r.Native}]
			c, ok2 := rollup[dayKey{d.Unix(), r.Prefix, r.Provider}]
			if !ok || !ok2 || n.Measured == 0 || c.Measured == 0 {
				continue
			}
			seen[pair] = true
			buckets := []string{BucketAll}
			if cause(r) == plugin.CausePerformance {
				buckets = append(buckets, BucketProblem)
			}
			nl, cl := n.LossSum/float64(n.Measured), c.LossSum/float64(c.Measured)
			nr, cr := n.RTTSumMs/float64(n.Measured), c.RTTSumMs/float64(c.Measured)
			if better(nl, cl, 20) || better(nr, cr, 20) {
				buckets = append(buckets, BucketBetter20)
			}
			if better(nl, cl, 50) || better(nr, cr, 50) {
				buckets = append(buckets, BucketBetter50)
			}
			for _, b := range buckets {
				k := cell{d.Unix(), b}
				if cells[k] == nil {
					cells[k] = &tsAcc{}
				}
				cells[k].add(r.Prefix, n, c)
			}
		}
	}
	keys := make([]cell, 0, len(cells))
	for k := range cells {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(x, y cell) int {
		if c := cmp.Compare(x.day, y.day); c != 0 {
			return c
		}
		return cmp.Compare(slices.Index(Buckets, x.bucket), slices.Index(Buckets, y.bucket))
	})
	rows := make([]TimeSeriesRow, 0, len(keys))
	rep.head = []string{"day", "bucket", "prefixes", "before_loss_pct", "after_loss_pct", "before_rtt_ms", "after_rtt_ms"}
	for _, k := range keys {
		x := cells[k]
		row := TimeSeriesRow{
			Day: time.Unix(k.day, 0).UTC().Format(time.DateOnly), Bucket: k.bucket, Prefixes: len(x.prefixes),
			BeforeLossPct: x.bl.val(), AfterLossPct: x.al.val(), BeforeRTTMs: x.br.val(), AfterRTTMs: x.ar.val(),
		}
		rows = append(rows, row)
		rep.lines = append(rep.lines, []string{row.Day, row.Bucket, strconv.Itoa(row.Prefixes),
			f(row.BeforeLossPct), f(row.AfterLossPct), f(row.BeforeRTTMs), f(row.AfterRTTMs)})
	}
	rep.Rows = rows
}
