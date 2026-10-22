// Command mkhistory writes a small synthetic report history to a sqlite
// storage file, for the UI smoke test of the before/after graphs (#129):
//
//	mkhistory -o /tmp/pk/packeteer.db
//
// The days are the last few UTC days, so the default 7-day graph has
// points, plus the last 24 hours of per-provider probe samples for the
// Providers table and the Overview chart (#349). With -commit it writes
// instead the 95th-percentile samples and commit improvements for the
// Commit & Cost page smoke test (#174).
// Documentation prefixes and made-up provider names only; it reads and
// announces nothing.
package main

import (
	"context"
	"flag"
	"fmt"
	"math"
	"net/netip"
	"os"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/storage/sqlite"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const days = 5

// providerSeed is the last 24 hours of five-minute provider samples up to
// the current slot (#349), for the Providers table and the Overview latency
// chart. lab-a runs at 120 ms with 8% loss and lab-b at 40 ms with none. Both
// swing a little through the day so the lines are not flat, except in the
// last hour, so the 15-minute figures are exactly the base.
func providerSeed(now time.Time) []plugin.ProviderSample {
	last := now.UTC().Truncate(5 * time.Minute)
	var out []plugin.ProviderSample
	for at := last.Add(-24 * time.Hour); !at.After(last); at = at.Add(5 * time.Minute) {
		swing := math.Sin(2 * math.Pi * float64(at.Hour()*60+at.Minute()) / (24 * 60))
		if last.Sub(at) < time.Hour {
			swing = 0
		}
		for _, p := range []struct {
			name      string
			rtt, loss float64
		}{{"lab-a", 120 + 10*swing, 8}, {"lab-b", 40 + 4*swing, 0}} {
			out = append(out, plugin.ProviderSample{Provider: p.name, Slot: at, Probes: 20, Measured: 20,
				LossSum: p.loss * 20, RTTSumMs: p.rtt * 20, JitterSum: p.rtt / 10 * 20})
		}
	}
	return out
}

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

// commitDays of samples, one every five minutes, ending at the last full
// five-minute mark. lab-a runs under its 100 Mbps commit at first and
// ends the window over it even at night, so the open period's 95th is over
// the commit from its first sample; lab-b stays far under 200. Billing day 1, so a
// sample belongs to the UTC month it was taken in.
const commitDays = 30

func commitSeed(now time.Time) ([]plugin.UsageSample, plugin.HistoryBatch) {
	end := now.UTC().Truncate(5 * time.Minute)
	var samples []plugin.UsageSample
	for at := end.Add(-commitDays * 24 * time.Hour); !at.After(end); at = at.Add(5 * time.Minute) {
		start := time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC)
		age := float64(end.Sub(at)) / float64(commitDays*24*time.Hour)
		day := math.Max(0, math.Sin(2*math.Pi*float64(at.Hour()*60+at.Minute())/(24*60)))
		for _, p := range []struct {
			name string
			out  float64
		}{{"lab-a", 40 + 60*day + 70*(1-age)}, {"lab-b", 20 + 10*day}} {
			samples = append(samples, plugin.UsageSample{Provider: p.name, Host: "edge", Interface: "ether1",
				PeriodStart: start, PeriodEnd: start.AddDate(0, 1, 0), At: at, InBps: p.out * 2e5, OutBps: p.out * 1e6})
		}
	}
	var b plugin.HistoryBatch
	// Three prefixes taken off lab-a for commit while only recommending
	// (observe), and one move an earlier inject run announced. The two
	// observe moves are 4h apart so they never share a 2h point of the
	// 30-day range, whatever hour the seed runs.
	for i, r := range []struct {
		prefix string
		mode   string
		ago    time.Duration
	}{{"198.51.100.0/24", "observe", 50 * time.Hour}, {"203.0.113.0/24", "observe", 50 * time.Hour}, {"192.0.2.0/24", "observe", 46 * time.Hour}, {"198.51.100.0/24", "inject", 6 * 24 * time.Hour}} {
		b.Improvements = append(b.Improvements, plugin.ImprovementRecord{
			ID: fmt.Sprintf("commit-%d", i), Prefix: netip.MustParsePrefix(r.prefix), Provider: "lab-b", Native: "lab-a",
			Cause: plugin.CauseCommit, Mode: r.mode, Start: end.Add(-r.ago), End: end.Add(-r.ago + 3*time.Hour),
		})
	}
	return samples, b
}

func main() {
	out := flag.String("o", "", "sqlite file to write (absolute path)")
	commit := flag.Bool("commit", false, "write commit samples and commit improvements instead")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "usage: mkhistory [-commit] -o FILE")
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
	var batch plugin.HistoryBatch
	if *commit {
		var samples []plugin.UsageSample
		samples, batch = commitSeed(time.Now())
		if err := s.PutUsageSamples(ctx, samples); err != nil {
			fmt.Fprintln(os.Stderr, "mkhistory:", err)
			os.Exit(1)
		}
	} else {
		batch = seed(time.Now())
	}
	if err := s.Write(ctx, batch); err != nil {
		fmt.Fprintln(os.Stderr, "mkhistory:", err)
		os.Exit(1)
	}
	if !*commit {
		if err := s.PutProviderSamples(ctx, providerSeed(time.Now())); err != nil {
			fmt.Fprintln(os.Stderr, "mkhistory:", err)
			os.Exit(1)
		}
	}
	if err := s.Stop(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "mkhistory:", err)
		os.Exit(1)
	}
}
