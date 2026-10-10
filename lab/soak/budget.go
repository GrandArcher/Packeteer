package main

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Profile is one workload and the budgets it must stay inside.
type Profile struct {
	// Prefixes is the synthetic table size.
	Prefixes int `yaml:"prefixes"`
	// Duration is the soak phase, after the table is learned.
	Duration time.Duration `yaml:"duration"`
	// Warmup is the start of the soak left out of the growth baseline.
	Warmup time.Duration `yaml:"warmup"`
	// Sample is how often the process and the API are read.
	Sample time.Duration `yaml:"sample"`
	// FlowRate is IPFIX records per second.
	FlowRate int `yaml:"flow_rate"`
	// FlowHot is the size of the hot set half the records go to.
	FlowHot int `yaml:"flow_hot"`
	// FlowTopN is the flow source's top_n (probe targets from flows).
	FlowTopN int `yaml:"flow_top_n"`
	// StaticTargets is the number of static probe targets.
	StaticTargets int `yaml:"static_targets"`
	// Churn is prefixes withdrawn and announced again per minute.
	Churn int `yaml:"churn"`
	// RateLimitPPS is probe.rate_limit_pps in the generated config.
	// Zero uses the load-test default of 100000, which lets the fixed
	// prober finish the pr profile's targets. The opt-in rate profile
	// sets the operator default of 100 (#125).
	RateLimitPPS int     `yaml:"rate_limit_pps"`
	Budgets      Budgets `yaml:"budgets"`
}

// Budgets are the limits. Zero leaves a figure reported but unchecked.
type Budgets struct {
	LearnSeconds      float64 `yaml:"learn_seconds"`
	RSSPeakMB         float64 `yaml:"rss_peak_mb"`
	RSSGrowthMB       float64 `yaml:"rss_growth_mb"`
	RSSSlopeMB        float64 `yaml:"rss_slope_mb"`
	CPUAvgCores       float64 `yaml:"cpu_avg_cores"`
	Threads           int     `yaml:"threads"`
	UDPDropPct        float64 `yaml:"udp_drop_pct"`
	APIP99Ms          float64 `yaml:"api_p99_ms"`
	ReconvergeSecs    float64 `yaml:"reconverge_seconds"`
	ShutdownSeconds   float64 `yaml:"shutdown_seconds"`
	MinMeasured       int     `yaml:"min_measured"`
	MinActivePerHour  int     `yaml:"min_active_per_hour"`
	MinPassiveTracked int     `yaml:"min_passive_tracked"`
}

type budgetFile struct {
	Profiles map[string]Profile `yaml:"profiles"`
}

func loadProfile(path, name string) (Profile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var f budgetFile
	if err := dec.Decode(&f); err != nil {
		return Profile{}, fmt.Errorf("%s: %w", path, err)
	}
	p, ok := f.Profiles[name]
	if !ok {
		names := make([]string, 0, len(f.Profiles))
		for n := range f.Profiles {
			names = append(names, n)
		}
		slices.Sort(names)
		return Profile{}, fmt.Errorf("%s: no profile %q (have %s)", path, name, strings.Join(names, ", "))
	}
	return p, p.validate()
}

func (p Profile) validate() error {
	var errs []error
	if !newTable(p.Prefixes).valid() || p.Prefixes < v4Count+2 {
		errs = append(errs, fmt.Errorf("prefixes %d: want %d to %d", p.Prefixes, v4Count+2, v4Count+maxV6))
	}
	if p.Duration <= 0 || p.Sample <= 0 || p.Warmup < 0 || p.Warmup >= p.Duration {
		errs = append(errs, errors.New("duration and sample must be positive, warmup shorter than duration"))
	}
	if p.FlowRate < 0 || p.Churn < 0 || p.FlowTopN < 0 || p.StaticTargets < 0 || p.FlowHot < 0 {
		errs = append(errs, errors.New("rates and counts must not be negative"))
	}
	if p.StaticTargets > p.Prefixes {
		errs = append(errs, errors.New("static_targets exceeds prefixes"))
	}
	if p.Churn/60 > p.Prefixes/2 {
		errs = append(errs, errors.New("churn too large for the table"))
	}
	return errors.Join(errs...)
}

// Result is what one run measured.
type Result struct {
	Profile         string  `json:"profile"`
	Prefixes        int     `json:"prefixes"`
	DurationSeconds float64 `json:"duration_seconds"`
	FlowRecords     uint64  `json:"flow_records"`
	ChurnUpdates    uint64  `json:"churn_updates"`

	LearnSeconds    float64  `json:"learn_seconds"`
	LearnCPUCores   float64  `json:"learn_cpu_cores"`
	RSSPeakMB       float64  `json:"rss_peak_mb"`
	RSSBaselineMB   float64  `json:"rss_baseline_mb"`
	RSSEndMB        float64  `json:"rss_end_mb"`
	RSSGrowthMB     float64  `json:"rss_growth_mb"`
	RSSSlopeMB      float64  `json:"rss_slope_mb"`
	CPUAvgCores     float64  `json:"cpu_avg_cores"`
	Threads         int      `json:"threads"`
	UDPDropPct      float64  `json:"udp_drop_pct"`
	APIP99Ms        float64  `json:"api_p99_ms"`
	ReconvergeSecs  float64  `json:"reconverge_seconds"`
	ShutdownSeconds float64  `json:"shutdown_seconds"`
	Measured        int      `json:"measured"`
	ActivePerHour   float64  `json:"active_per_hour"`
	PassiveTracked  int      `json:"passive_tracked"`
	PacketeerRoutes int      `json:"packeteer_routes"`
	Failures        []string `json:"failures"`
}

// Check is one budget line.
type Check struct {
	Name  string
	Value float64
	Limit float64
	Min   bool // the value must be at least Limit
	Unit  string
}

func (c Check) Checked() bool { return c.Limit != 0 }

func (c Check) Pass() bool {
	if !c.Checked() {
		return true
	}
	if c.Min {
		return c.Value >= c.Limit
	}
	return c.Value <= c.Limit
}

// checks pairs every measured figure with its budget.
func checks(r Result, b Budgets) []Check {
	return []Check{
		{Name: "full table learned", Value: r.LearnSeconds, Limit: b.LearnSeconds, Unit: "s"},
		{Name: "peak RSS", Value: r.RSSPeakMB, Limit: b.RSSPeakMB, Unit: "MiB"},
		{Name: "RSS growth after warmup", Value: r.RSSGrowthMB, Limit: b.RSSGrowthMB, Unit: "MiB"},
		{Name: "RSS still rising, last third", Value: r.RSSSlopeMB, Limit: b.RSSSlopeMB, Unit: "MiB"},
		{Name: "average CPU during soak", Value: r.CPUAvgCores, Limit: b.CPUAvgCores, Unit: "cores"},
		{Name: "OS threads", Value: float64(r.Threads), Limit: float64(b.Threads)},
		{Name: "flow datagrams dropped", Value: r.UDPDropPct, Limit: b.UDPDropPct, Unit: "%"},
		{Name: "API p99 latency", Value: r.APIP99Ms, Limit: b.APIP99Ms, Unit: "ms"},
		{Name: "reconverge after churn", Value: r.ReconvergeSecs, Limit: b.ReconvergeSecs, Unit: "s"},
		{Name: "SIGTERM to exit", Value: r.ShutdownSeconds, Limit: b.ShutdownSeconds, Unit: "s"},
		{Name: "prefixes measured", Value: float64(r.Measured), Limit: float64(b.MinMeasured), Min: true},
		{Name: "active prefixes measured per hour", Value: r.ActivePerHour, Limit: float64(b.MinActivePerHour), Min: true},
		{Name: "passive prefixes tracked", Value: float64(r.PassiveTracked), Limit: float64(b.MinPassiveTracked), Min: true},
	}
}

// report renders the result as a Markdown table and says whether every
// budget and invariant held.
func report(r Result, b Budgets) (string, bool) {
	ok := len(r.Failures) == 0
	var s strings.Builder
	fmt.Fprintf(&s, "### Load and soak: profile `%s`\n\n", r.Profile)
	fmt.Fprintf(&s, "%d prefixes, %s soak, %d flow records, %d churn updates. Observe mode, stock image, mounted config.\n\n",
		r.Prefixes, time.Duration(r.DurationSeconds*float64(time.Second)).Round(time.Second), r.FlowRecords, r.ChurnUpdates)
	s.WriteString("| Check | Measured | Budget | |\n|---|---|---|---|\n")
	for _, c := range checks(r, b) {
		limit, mark := "-", "report"
		if c.Checked() {
			op := "≤"
			if c.Min {
				op = "≥"
			}
			limit = op + " " + num(c.Limit) + unit(c.Unit)
			mark = "ok"
			if !c.Pass() {
				mark = "**OVER**"
				ok = false
			}
		}
		fmt.Fprintf(&s, "| %s | %s%s | %s | %s |\n", c.Name, num(c.Value), unit(c.Unit), limit, mark)
	}
	fmt.Fprintf(&s, "\nLearn-phase CPU %s cores; RSS baseline %s MiB, end %s MiB; routes Packeteer sent the router: %d.\n",
		num(r.LearnCPUCores), num(r.RSSBaselineMB), num(r.RSSEndMB), r.PacketeerRoutes)
	for _, f := range r.Failures {
		fmt.Fprintf(&s, "\n- **FAIL**: %s", f)
	}
	if len(r.Failures) > 0 {
		s.WriteString("\n")
	}
	return s.String(), ok
}

func unit(u string) string {
	if u == "" {
		return ""
	}
	return " " + u
}

func num(v float64) string {
	switch {
	case v == math.Trunc(v) && math.Abs(v) < 1e15:
		return fmt.Sprintf("%.0f", v)
	case math.Abs(v) >= 100:
		return fmt.Sprintf("%.0f", v)
	case math.Abs(v) >= 1:
		return fmt.Sprintf("%.1f", v)
	default:
		return fmt.Sprintf("%.3f", v)
	}
}

// percentile returns the p-th percentile (0-100) of xs, nearest rank.
func percentile(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := slices.Clone(xs)
	slices.Sort(s)
	i := int(math.Ceil(p/100*float64(len(s)))) - 1
	return s[max(0, min(i, len(s)-1))]
}

// probePace is the prefix-commit counter and the passive-prefix estimate
// read from /metrics during a soak (#125).
type probePace struct {
	warm, end float64
	warmSet   bool
	passive   float64
}

// sample records one successful /metrics read. The first sample at or
// after warmup freezes the commit counter; later samples move the end.
func (p *probePace) sample(elapsed, warmup time.Duration, commits, tracked float64) {
	if !p.warmSet && elapsed >= warmup {
		p.warm = commits
		p.warmSet = true
	}
	p.end = commits
	p.passive = tracked
}

// perHour scales commits after the warmup boundary to one hour. A
// missing boundary counts from zero. A counter that went backwards
// counts as no progress. post is the soak after warmup; under a second
// it falls back to the whole soak, and under a second there too the
// rate is zero.
func (p probePace) perHour(durationSec, warmupSec float64) float64 {
	warm := 0.0
	if p.warmSet {
		warm = p.warm
	}
	delta := p.end - warm
	if delta < 0 {
		delta = 0
	}
	post := durationSec - warmupSec
	if post < 1 {
		post = durationSec
	}
	if post < 1 {
		return 0
	}
	return delta / post * 3600
}

// growth is the RSS level during warmup and the level over the second
// half of the samples after warmup. Both are medians.
//
// Go returns unused pages with MADV_DONTNEED, so RSS falls after a
// collection and climbs back as the heap refills. On a ~4.5 GiB heap
// that cycle is minutes wide. A tenth of the post-warmup samples (about
// 35s on the pr profile) can sit entirely in the valley or entirely on
// the refilled heap. Actions run 36902639588 measured that as 342 MiB
// of growth (4476 then 4818) while the end was inside the band of runs
// that passed and the warmup median was already 4619. The baseline is
// that warmup median. The end median covers the whole second half, so
// one spike does not set it. A leak is a second half above the warmup
// level. With no warmup samples the first half of post is the baseline.
func growth(warm, post []float64) (base, end float64) {
	if len(warm) == 0 && len(post) == 0 {
		return 0, 0
	}
	if len(post) == 0 {
		m := percentile(warm, 50)
		return m, m
	}
	if len(warm) == 0 {
		if len(post) < 2 {
			m := percentile(post, 50)
			return m, m
		}
		mid := len(post) / 2
		return percentile(post[:mid], 50), percentile(post[mid:], 50)
	}
	endPart := post
	if len(post) >= 2 {
		endPart = post[len(post)/2:]
	}
	return percentile(warm, 50), percentile(endPart, 50)
}

// minSlopeSamples is the fewest samples in the last third that give a
// slope. Below it the figure is 0 (reported, not a failure).
const minSlopeSamples = 8

// riseLastThird is how far RSS is still climbing at the end of the run,
// in MiB. It is the smaller of two figures, so both must show a climb:
//
//   - the Theil-Sen slope (the median of the slopes between every pair of
//     samples) over the last third, times the width of that third; and
//   - the median of the last sixth minus the median of the middle third.
//
// It is 0 when RSS is flat or falling.
//
// growth compares a baseline with the end, so it cannot say whether RSS
// has levelled off. A leak that arrives late, or a table that keeps
// refilling, can sit under the growth budget and still be climbing when
// the run stops. RSS also moves in steps: the collector hands pages back
// and the heap refills a block at a time. The median of pairwise slopes
// ignores one step at the very end (a single sample 300 MiB up). The
// second figure ignores a dip and refill inside the last third, which the
// slope alone reads as a climb: a heap that is back where the middle of
// the run already had it is not rising. A steady climb passes both.
func riseLastThird(rss []float64) float64 {
	n := len(rss)
	tail := rss[n*2/3:]
	if len(tail) < minSlopeSamples {
		return 0
	}
	slopes := make([]float64, 0, len(tail)*(len(tail)-1)/2)
	for i := range tail {
		for j := i + 1; j < len(tail); j++ {
			slopes = append(slopes, (tail[j]-tail[i])/float64(j-i))
		}
	}
	trend := percentile(slopes, 50) * float64(len(tail)-1)
	net := percentile(rss[n*5/6:], 50) - percentile(rss[n/3:n*2/3], 50)
	return max(0, min(trend, net))
}
