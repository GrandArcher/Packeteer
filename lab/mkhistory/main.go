// Command mkhistory writes a small synthetic report history to a sqlite
// storage file, for the UI smoke test of the before/after graphs (#129):
//
//	mkhistory -o /tmp/pk/packeteer.db
//
// The days are the last few UTC days, so the default 7-day graph has
// points. Documentation prefixes and made-up provider names only; it
// reads and announces nothing.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/storage/sqlite"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const days = 5

// seed is `days` days ending today. lab-a is the native provider and lab-b
// the chosen one:
//
//	198.51.100.0/24 performance: 8% loss, 120 ms -> 0%, 40 ms (50% better)
//	203.0.113.0/24  performance: 0% loss, 100 ms -> 0%, 80 ms (20% better)
//	192.0.2.0/24    cost: 50 ms -> 49 ms (in "all" only)
func seed(now time.Time) plugin.HistoryBatch {
	today := now.UTC().Truncate(24 * time.Hour)
	pa := netip.MustParsePrefix("198.51.100.0/24")
	pb := netip.MustParsePrefix("203.0.113.0/24")
	pc := netip.MustParsePrefix("192.0.2.0/24")
	var b plugin.HistoryBatch
	bucket := func(day time.Time, p netip.Prefix, provider string, loss, rtt float64) {
		b.Buckets = append(b.Buckets, plugin.ProbeBucket{Day: day, Prefix: p, Provider: provider,
			Probes: 100, Measured: 100, LossSum: loss * 100, RTTSumMs: rtt * 100})
	}
	for i := range days {
		day := today.Add(-time.Duration(days-1-i) * 24 * time.Hour)
		bucket(day, pa, "lab-a", 8, 120)
		bucket(day, pa, "lab-b", 0, 40)
		bucket(day, pb, "lab-a", 0, 100)
		bucket(day, pb, "lab-b", 0, 80)
		bucket(day, pc, "lab-a", 0, 50)
		bucket(day, pc, "lab-b", 0, 49)
	}
	start := today.Add(-(days - 1) * 24 * time.Hour)
	end := today.Add(12 * time.Hour)
	for i, r := range []struct {
		p     netip.Prefix
		cause string
	}{{pa, plugin.CausePerformance}, {pb, plugin.CausePerformance}, {pc, plugin.CauseCost}} {
		b.Improvements = append(b.Improvements, plugin.ImprovementRecord{
			ID: fmt.Sprintf("seed-%d", i), Prefix: r.p, Provider: "lab-b", Native: "lab-a", Cause: r.cause,
			Mode: "observe", Start: start.Add(time.Hour), End: end,
		})
	}
	return b
}

func main() {
	out := flag.String("o", "", "sqlite file to write (absolute path)")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "usage: mkhistory -o FILE")
		os.Exit(2)
	}
	c, err := plugin.ConfigFromYAML("path: " + *out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkhistory:", err)
		os.Exit(1)
	}
	s, err := sqlite.New(c, plugin.Env{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkhistory:", err)
		os.Exit(1)
	}
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "mkhistory:", err)
		os.Exit(1)
	}
	if err := s.Write(ctx, seed(time.Now())); err != nil {
		fmt.Fprintln(os.Stderr, "mkhistory:", err)
		os.Exit(1)
	}
	if err := s.Stop(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "mkhistory:", err)
		os.Exit(1)
	}
}
