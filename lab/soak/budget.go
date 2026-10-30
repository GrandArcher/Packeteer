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
	// Prefixes is the synthetic table size. A real profile leaves it out:
	// the table is the dump's.
	Prefixes int `yaml:"prefixes"`
	// Real plays one peer's full view from a RIPE RIS or RouteViews MRT
	// dump given with -mrt, instead of the synthetic table (#342). It is
	// observe only, with no flows, churn or probe targets.
	Real bool `yaml:"real"`
	// Peers, on a real profile, plays that many peers' views of the dump
	// (the ones with the most routes), each on its own session and as its
	// own provider's next hop, so Packeteer holds that many different
	// paths per prefix (#103). Zero plays the largest peer once, or as
	// many times as sessions says.
	Peers int `yaml:"peers"`
	// ScaleTo, on a real profile, grows the dump's table to this many
	// prefixes with more-specifics of its own prefixes (#103). Zero keeps
	// the dump's size.
	ScaleTo int `yaml:"scale_to"`
	// Simulate, on a real profile, gives the learned table probe results
	// from the sim prober instead of none: a seeded delay and loss model
	// per provider, over the vip source's targets (#103). No packet is
	// sent, and every figure from it is simulated.
	Simulate bool `yaml:"simulate"`
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
	RateLimitPPS int `yaml:"rate_limit_pps"`
	// Sessions is how many edge routers the harness plays (#383), each
	// sending the whole table. Zero is one.
	Sessions int `yaml:"sessions"`
	// Inject runs Packeteer in inject mode with this max_improvements.
	// Zero runs observe.
	Inject int `yaml:"inject"`
	// FlapEvery closes one session this often, taking turns and never the
	// slow one; the router sends the whole table again when Packeteer
	// comes back. Zero does not flap.
	FlapEvery time.Duration `yaml:"flap_every"`
	// SlowPeerBPS makes the last session read Packeteer's messages at
	// this many bytes a second. Zero has no slow peer.
	SlowPeerBPS int `yaml:"slow_peer_bps"`
	// VIPTargets is the vip source's max_targets: prefixes whose AS path
	// holds a documentation ASN. Zero has no vip source.
	VIPTargets int `yaml:"vip_targets"`
	// OutageTargets is how many static targets lose every packet on
	// transit-a, so the outage source has an incident to find. Zero has
	// no outage source.
	OutageTargets int     `yaml:"outage_targets"`
	Budgets       Budgets `yaml:"budgets"`

	realPaths int      // set by useReal
	vipASNs   []uint32 // set by useReal on a simulated run
}

// sessions is the number of routers, at least one.
func (p Profile) sessions() int { return max(1, p.Sessions, p.Peers) }

// Budgets are the limits. Zero leaves a figure reported but unchecked.
//
// The four figures that grow with the table (learn time and the three RSS
// ones) are written per million prefixes in the file, so one number holds
// from a 1M to a 5M table (#217). loadProfile multiplies them by the
// profile's prefixes into the flat fields the checks read.
type Budgets struct {
	LearnSeconds float64 `yaml:"-"`
	RSSPeakMB    float64 `yaml:"-"`
	RSSGrowthMB  float64 `yaml:"-"`
	RSSSlopeMB   float64 `yaml:"-"`

	LearnSecondsPerM float64 `yaml:"learn_seconds_per_mprefix"`
	RSSPeakMBPerM    float64 `yaml:"rss_peak_mb_per_mprefix"`
	RSSGrowthMBPerM  float64 `yaml:"rss_growth_mb_per_mprefix"`
	RSSSlopeMBPerM   float64 `yaml:"rss_slope_mb_per_mprefix"`

	CPUAvgCores       float64 `yaml:"cpu_avg_cores"`
	Threads           int     `yaml:"threads"`
	UDPDropPct        float64 `yaml:"udp_drop_pct"`
	APIP99Ms          float64 `yaml:"api_p99_ms"`
	ReconvergeSecs    float64 `yaml:"reconverge_seconds"`
	ShutdownSeconds   float64 `yaml:"shutdown_seconds"`
	MinMeasured       int     `yaml:"min_measured"`
	MinActivePerHour  int     `yaml:"min_active_per_hour"`
	MinPassiveTracked int     `yaml:"min_passive_tracked"`
	// LoopGapSecs bounds the longest the decide loop went without an
	// evaluation and the probe loop without storing a prefix (#383).
	LoopGapSecs float64 `yaml:"loop_gap_seconds"`
}

// scaled fills the flat limits from the per-million ones for a table of n
// prefixes.
func (b Budgets) scaled(n int) Budgets {
	m := float64(n) / 1e6
	b.LearnSeconds = b.LearnSecondsPerM * m
	b.RSSPeakMB = b.RSSPeakMBPerM * m
	b.RSSGrowthMB = b.RSSGrowthMBPerM * m
	b.RSSSlopeMB = b.RSSSlopeMBPerM * m
	return b
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
	p.Budgets = p.Budgets.scaled(p.paths())
	return p, p.validate()
}

// multiply plays the table on n sessions (0 keeps the profile's), so
// Packeteer holds n paths per prefix, and rescales the budgets to the
// paths.
func (p *Profile) multiply(n int) error {
	// A profile that plays peers already has one session per view; 1 is
	// what lab/realtable.sh passes by default.
	if n == 0 || (p.Peers > 0 && n == 1) {
		return nil
	}
	p.Sessions = n
	p.Budgets = p.Budgets.scaled(p.paths())
	return p.validate()
}

// paths is the routes Packeteer holds: the dump's, once read, else the
// table size times the sessions.
func (p Profile) paths() int {
	if p.realPaths > 0 {
		return p.realPaths
	}
	return p.Prefixes * p.sessions()
}

// useReal sets the table size from a dump and rescales the budgets to the
// paths its views hold.
func (p *Profile) useReal(t *realSet) error {
	p.Prefixes = t.prefixes
	if len(t.views) == 1 {
		p.realPaths = t.prefixes * p.sessions()
	} else {
		p.realPaths = t.paths
	}
	p.Budgets = p.Budgets.scaled(p.paths())
	if !p.Simulate {
		return nil
	}
	var err error
	p.vipASNs, err = vipASNs(t, p.VIPTargets)
	return err
}

func (p Profile) validate() error {
	var errs []error
	switch {
	case p.Real:
		if p.Prefixes != 0 || p.Inject != 0 || p.StaticTargets != 0 || p.OutageTargets != 0 || p.Churn != 0 || p.FlowRate != 0 || (p.VIPTargets != 0 && !p.Simulate) {
			errs = append(errs, errors.New("real: prefixes come from the dump, and inject, static_targets, outage_targets, churn and flow_rate must be 0, and so must vip_targets without simulate (observe only)"))
		}
		if p.Simulate && p.VIPTargets == 0 {
			errs = append(errs, errors.New("simulate needs vip_targets: the sim prober answers for the targets the vip source names"))
		}
		if p.Peers < 0 || p.Peers > maxViews || (p.Peers > 0 && p.Sessions > 0) {
			errs = append(errs, fmt.Errorf("peers %d: want 0 to %d, and not together with sessions", p.Peers, maxViews))
		}
		if p.Simulate && p.Peers != maxViews {
			errs = append(errs, fmt.Errorf("simulate models %d providers with sessions: peers must be %d", maxViews, maxViews))
		}
		if p.ScaleTo < 0 {
			errs = append(errs, errors.New("scale_to must not be negative"))
		}
	case p.Peers != 0 || p.ScaleTo != 0 || p.Simulate:
		errs = append(errs, errors.New("peers, scale_to and simulate go with a real profile"))
	case !newTable(p.Prefixes).valid() || p.Prefixes < v4Count+2:
		errs = append(errs, fmt.Errorf("prefixes %d: want %d to %d", p.Prefixes, v4Count+2, v4Count+maxV6))
	}
	if p.Duration <= 0 || p.Sample <= 0 || p.Warmup < 0 || p.Warmup >= p.Duration {
		errs = append(errs, errors.New("duration and sample must be positive, warmup shorter than duration"))
	}
	if p.FlowRate < 0 || p.Churn < 0 || p.FlowTopN < 0 || p.StaticTargets < 0 || p.FlowHot < 0 {
		errs = append(errs, errors.New("rates and counts must not be negative"))
	}
	if b := p.Budgets; b.LearnSecondsPerM < 0 || b.RSSPeakMBPerM < 0 || b.RSSGrowthMBPerM < 0 || b.RSSSlopeMBPerM < 0 {
		errs = append(errs, errors.New("per-million budgets must not be negative"))
	}
	if !p.Real && p.StaticTargets > p.Prefixes {
		errs = append(errs, errors.New("static_targets exceeds prefixes"))
	}
	if !p.Real && p.Churn/60 > p.Prefixes/2 {
		errs = append(errs, errors.New("churn too large for the table"))
	}
	if p.Sessions < 0 || p.Sessions > maxSessions {
		errs = append(errs, fmt.Errorf("sessions %d: want 1 to %d", p.Sessions, maxSessions))
	}
	// One session flapping, or only a slow one, would take the whole view
	// down or leave no fast session to compare with.
	if (p.FlapEvery != 0 || p.SlowPeerBPS != 0) && p.Sessions < 2 {
		errs = append(errs, errors.New("flap_every and slow_peer_bps need at least 2 sessions"))
	}
	if p.FlapEvery < 0 || p.SlowPeerBPS < 0 || p.Inject < 0 || p.VIPTargets < 0 || p.OutageTargets < 0 || p.Budgets.LoopGapSecs < 0 {
		errs = append(errs, errors.New("flap_every, slow_peer_bps, inject, vip_targets, outage_targets and loop_gap_seconds must not be negative"))
	}
	if p.SlowPeerBPS > 0 && p.SlowPeerBPS < 512 {
		errs = append(errs, errors.New("slow_peer_bps below 512 cannot read a full UPDATE inside the hold time"))
	}
	if p.Inject > 10000 || p.VIPTargets > 100000 {
		errs = append(errs, errors.New("inject is at most 10000 (max_improvements) and vip_targets at most 100000"))
	}
	if p.OutageTargets > p.StaticTargets || (p.OutageTargets > 0 && p.OutageTargets < 3) {
		errs = append(errs, errors.New("outage_targets must be 3 (the outage source's min_prefixes) to static_targets"))
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

	LearnSeconds    float64 `json:"learn_seconds"`
	LearnCPUCores   float64 `json:"learn_cpu_cores"`
	RSSPeakMB       float64 `json:"rss_peak_mb"`
	RSSBaselineMB   float64 `json:"rss_baseline_mb"`
	RSSEndMB        float64 `json:"rss_end_mb"`
	RSSGrowthMB     float64 `json:"rss_growth_mb"`
	RSSSlopeMB      float64 `json:"rss_slope_mb"`
	CPUAvgCores     float64 `json:"cpu_avg_cores"`
	Threads         int     `json:"threads"`
	UDPDropPct      float64 `json:"udp_drop_pct"`
	APIP99Ms        float64 `json:"api_p99_ms"`
	ReconvergeSecs  float64 `json:"reconverge_seconds"`
	ShutdownSeconds float64 `json:"shutdown_seconds"`
	Measured        int     `json:"measured"`
	ActivePerHour   float64 `json:"active_per_hour"`
	PassiveTracked  int     `json:"passive_tracked"`
	PacketeerRoutes int     `json:"packeteer_routes"`

	// Multi-session and inject figures (#383).
	Mode              string  `json:"mode"`
	Sessions          int     `json:"sessions"`
	DecideMaxGapSecs  float64 `json:"decide_max_gap_seconds"`
	ProbeMaxGapSecs   float64 `json:"probe_max_gap_seconds"`
	LockWaitPerSec    float64 `json:"lock_wait_per_second"`
	LockWaitMaxPerSec float64 `json:"lock_wait_max_per_second"`
	Flaps             int     `json:"flaps"`
	ReconnectMaxSecs  float64 `json:"reconnect_max_seconds"`
	SessionDrops      int     `json:"session_drops"`
	MaxSilenceMs      float64 `json:"max_silence_ms"`
	WithdrawChecks    int     `json:"withdraw_checks"`
	WithdrawP50Ms     float64 `json:"withdraw_p50_ms"`
	WithdrawP99Ms     float64 `json:"withdraw_p99_ms"`
	WithdrawMaxMs     float64 `json:"withdraw_max_ms"`
	SlowWithdrawMaxMs float64 `json:"slow_withdraw_max_ms"`
	SlowWithdrawLate  int     `json:"slow_withdraw_late"`
	InjectedPeak      int     `json:"injected_peak"`
	InjectedEnd       int     `json:"injected_end"`
	RoutesAtClose     int     `json:"routes_at_close"`
	SlowAtClose       int     `json:"slow_routes_at_close"`
	OutageEvents      int     `json:"outage_events"`

	// Simulated is set when the probe results are the sim prober's model
	// and not measurements (#103).
	Simulated bool `json:"simulated"`

	// Table describes a real table (#342), counts only. Nil on synthetic
	// runs.
	Table *TableInfo `json:"table,omitempty"`

	Failures []string `json:"failures"`
}

// TableInfo is what a real dump held: counts, never a prefix or an AS.
type TableInfo struct {
	Peers   int `json:"peers"` // peers in the dump with routes
	Views   int `json:"views"` // peers played, one session each
	IPv4    int `json:"ipv4"`  // distinct prefixes over the views
	IPv6    int `json:"ipv6"`
	Sets    int `json:"sets"`    // distinct attribute sets
	Skipped int `json:"skipped"` // routes left out: malformed
	Derived int `json:"derived"` // prefixes added by scale_to
	Paths   int `json:"paths"`   // routes over the views
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

// checks pairs every measured figure with its budget. The inject and
// multi-session rows appear only on runs that have them.
func checks(r Result, b Budgets) []Check {
	cs := []Check{
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
		{Name: simulated(r, "prefixes measured"), Value: float64(r.Measured), Limit: float64(b.MinMeasured), Min: true},
		{Name: simulated(r, "active prefixes measured per hour"), Value: r.ActivePerHour, Limit: float64(b.MinActivePerHour), Min: true},
		{Name: "passive prefixes tracked", Value: float64(r.PassiveTracked), Limit: float64(b.MinPassiveTracked), Min: true},
		{Name: "decide loop, longest gap", Value: r.DecideMaxGapSecs, Limit: b.LoopGapSecs, Unit: "s"},
		{Name: "probe loop, longest gap", Value: r.ProbeMaxGapSecs, Limit: b.LoopGapSecs, Unit: "s"},
		{Name: "lock wait, average", Value: r.LockWaitPerSec, Unit: "s/s"},
		{Name: "lock wait, worst sample", Value: r.LockWaitMaxPerSec, Unit: "s/s"},
	}
	if r.Sessions > 1 {
		cs = append(cs,
			Check{Name: "longest silence on a fast session", Value: r.MaxSilenceMs, Unit: "ms"},
			Check{Name: "flap to session back, longest", Value: r.ReconnectMaxSecs, Unit: "s"})
	}
	if r.Mode == "inject" {
		cs = append(cs,
			Check{Name: "withdraw latency p50, fast sessions", Value: r.WithdrawP50Ms, Unit: "ms"},
			Check{Name: "withdraw latency p99, fast sessions", Value: r.WithdrawP99Ms, Unit: "ms"},
			Check{Name: "withdraw latency max, fast sessions", Value: r.WithdrawMaxMs, Unit: "ms"},
			Check{Name: "withdraw latency max, slow session", Value: r.SlowWithdrawMaxMs, Unit: "ms"})
	}
	return cs
}

// simulated marks a figure that comes from probe results, so a simulated
// run never shows one as measured (#103).
func simulated(r Result, name string) string {
	if r.Simulated {
		return name + " (SIMULATED)"
	}
	return name
}

// report renders the result as a Markdown table and says whether every
// budget and invariant held.
func report(r Result, b Budgets) (string, bool) {
	ok := len(r.Failures) == 0
	var s strings.Builder
	fmt.Fprintf(&s, "### Load and soak: profile `%s`\n\n", r.Profile)
	fmt.Fprintf(&s, "%d prefixes on %d session(s), %s soak, %d flow records, %d churn updates. %s mode, stock image, mounted config.\n\n",
		r.Prefixes, max(1, r.Sessions), time.Duration(r.DurationSeconds*float64(time.Second)).Round(time.Second), r.FlowRecords, r.ChurnUpdates, modeName(r.Mode))
	if r.Simulated {
		s.WriteString("**Probe results are SIMULATED**: the sim prober answers from a seeded delay and loss model per provider, sends no packet, and no real address is probed. Rows marked SIMULATED are not measurements of any network. The learned table, memory, CPU, and API figures are measured.\n\n")
	}
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
	fmt.Fprintf(&s, "\nLearn-phase CPU %s cores; RSS baseline %s MiB, end %s MiB; routes Packeteer sent the routers: %d.\n",
		num(r.LearnCPUCores), num(r.RSSBaselineMB), num(r.RSSEndMB), r.PacketeerRoutes)
	if r.Sessions > 1 {
		fmt.Fprintf(&s, "Flaps %d; sessions dropped without a flap %d.\n", r.Flaps, r.SessionDrops)
	}
	if r.Mode == "inject" {
		fmt.Fprintf(&s, "Withdraw checks %d (slow session late %d); most routes on one session %d, %d at the end; still held when the sessions closed on SIGTERM: %d on fast sessions, %d on the slow one; outage incidents %d.\n",
			r.WithdrawChecks, r.SlowWithdrawLate, r.InjectedPeak, r.InjectedEnd, r.RoutesAtClose, r.SlowAtClose, r.OutageEvents)
	}
	if t := r.Table; t != nil {
		fmt.Fprintf(&s, "Real table: %d of the dump's %d peers played, %d IPv4 and %d IPv6 prefixes in %d attribute sets (%.1f prefixes per set), %d paths, %d prefixes added by scale_to, %d skipped.\n",
			max(1, t.Views), t.Peers, t.IPv4, t.IPv6, t.Sets, float64(t.IPv4+t.IPv6)/float64(max(1, t.Sets)), t.Paths, t.Derived, t.Skipped)
	}
	for _, f := range r.Failures {
		fmt.Fprintf(&s, "\n- **FAIL**: %s", f)
	}
	if len(r.Failures) > 0 {
		s.WriteString("\n")
	}
	return s.String(), ok
}

func modeName(m string) string {
	if m == "inject" {
		return "Inject"
	}
	return "Observe"
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
