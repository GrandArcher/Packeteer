package history

import (
	"cmp"
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Report names.
const (
	ReportSummary      = "summary"
	ReportImprovements = "improvements"
	ReportCauses       = "causes"
	ReportPerformance  = "performance"
	ReportProviders    = "providers"
	ReportPrefixes     = "prefixes"
	ReportASNs         = "asns"
	ReportCountries    = "countries"
	ReportProbes       = "probes"
	ReportSavings      = "savings"
)

// Reports lists every report name with a one-line description.
var Reports = []struct {
	Name    string `json:"name"`
	Summary string `json:"summary"`
}{
	{ReportSummary, "Totals: improvements by cause, active now, average loss and latency before and after, probes, estimated savings."},
	{ReportImprovements, "Every improvement that overlaps the range, newest first."},
	{ReportCauses, "Improvements started per UTC day, by cause (performance, commit, cost)."},
	{ReportPerformance, "Loss and latency before (native) and after (chosen provider), by cause."},
	{ReportProviders, "Provider efficiency: measured loss, latency, failures, and improvements onto and off each provider."},
	{ReportPrefixes, "Top prefixes by problems, volume, or loss."},
	{ReportASNs, "Top origin ASNs by problems, volume, or loss."},
	{ReportCountries, "Top countries by problems, volume, or loss (needs a rules policy with geoip_db)."},
	{ReportProbes, "Probes per UTC day."},
	{ReportSavings, "Estimated cost savings per improvement between priced providers."},
}

// Known reports whether name is a report.
func Known(name string) bool {
	for _, r := range Reports {
		if r.Name == name {
			return true
		}
	}
	return false
}

// HoursPerMonth converts a monthly price per Mbps into an hourly accrual.
// Savings accrue as est_savings × hours / HoursPerMonth.
const HoursPerMonth = 730

// Sort keys for the top-N reports.
const (
	SortProblems = "problems"
	SortVolume   = "volume"
	SortLoss     = "loss"
)

// Limits for row counts.
const (
	DefaultLimit = 20
	MaxLimit     = 10000
)

// Query selects a report.
type Query struct {
	Name string
	From time.Time
	To   time.Time
	// Now bounds open improvements. It defaults to To.
	Now   time.Time
	Limit int
	Sort  string
}

// Report is one report's rows. Rows is a typed slice for JSON; CSV writes
// the same rows with a header.
type Report struct {
	Name  string    `json:"report"`
	From  time.Time `json:"from"`
	To    time.Time `json:"to"`
	Rows  any       `json:"rows"`
	head  []string
	lines [][]string
}

// CSV writes the report as comma-separated values with a header row.
func (r Report) CSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(r.head); err != nil {
		return err
	}
	if err := cw.WriteAll(r.lines); err != nil {
		return err
	}
	cw.Flush()
	return cw.Error()
}

// Build aggregates h into the named report. It is pure: the same history
// and query always give the same rows.
func Build(h plugin.History, q Query) (Report, error) {
	if q.Now.IsZero() || q.Now.After(q.To) {
		q.Now = q.To
	}
	if q.Limit <= 0 {
		q.Limit = DefaultLimit
		if q.Name == ReportImprovements || q.Name == ReportSavings {
			q.Limit = 100
		}
	}
	if q.Limit > MaxLimit {
		q.Limit = MaxLimit
	}
	if q.Sort == "" {
		q.Sort = SortProblems
	}
	switch q.Sort {
	case SortProblems, SortVolume, SortLoss:
	default:
		return Report{}, fmt.Errorf("sort %q is invalid (want problems, volume, loss)", q.Sort)
	}
	a := newAgg(h, q)
	rep := Report{Name: q.Name, From: q.From.UTC(), To: q.To.UTC()}
	switch q.Name {
	case ReportSummary:
		a.summary(&rep)
	case ReportImprovements:
		a.improvements(&rep)
	case ReportCauses:
		a.causes(&rep)
	case ReportPerformance:
		a.performance(&rep)
	case ReportProviders:
		a.providers(&rep)
	case ReportPrefixes:
		a.prefixes(&rep)
	case ReportASNs:
		a.groups(&rep, "asn")
	case ReportCountries:
		a.groups(&rep, "country")
	case ReportProbes:
		a.probes(&rep)
	case ReportSavings:
		a.savings(&rep)
	default:
		return Report{}, fmt.Errorf("unknown report %q", q.Name)
	}
	return rep, nil
}

type agg struct {
	q       Query
	buckets []plugin.ProbeBucket
	imps    []plugin.ImprovementRecord
	info    map[netip.Prefix]plugin.PrefixInfo
}

func newAgg(h plugin.History, q Query) *agg {
	a := &agg{q: q, info: map[netip.Prefix]plugin.PrefixInfo{}}
	for _, b := range h.Buckets {
		if !b.Day.Before(q.From.UTC().Truncate(24*time.Hour)) && b.Day.Before(q.To) {
			a.buckets = append(a.buckets, b)
		}
	}
	for _, r := range h.Improvements {
		if r.Start.Before(q.To) && (r.End.IsZero() || !r.End.Before(q.From)) {
			a.imps = append(a.imps, r)
		}
	}
	for _, p := range h.Prefixes {
		a.info[p.Prefix] = p
	}
	return a
}

// started reports whether r started inside the range.
func (a *agg) started(r plugin.ImprovementRecord) bool {
	return !r.Start.Before(a.q.From) && r.Start.Before(a.q.To)
}

// hours is how long r was active inside the range.
func (a *agg) hours(r plugin.ImprovementRecord) float64 {
	start, end := r.Start, r.End
	if end.IsZero() || end.After(a.q.Now) {
		end = a.q.Now
	}
	if start.Before(a.q.From) {
		start = a.q.From
	}
	if end.After(a.q.To) {
		end = a.q.To
	}
	if !end.After(start) {
		return 0
	}
	return end.Sub(start).Hours()
}

// activeAt reports whether r was active at t.
func activeAt(r plugin.ImprovementRecord, t time.Time) bool {
	return !r.Start.After(t) && (r.End.IsZero() || r.End.After(t))
}

func cause(r plugin.ImprovementRecord) string {
	if r.Cause == "" {
		return plugin.CausePerformance
	}
	return r.Cause
}

// mean is a running average.
type mean struct {
	sum float64
	n   int
}

func (m *mean) add(v float64)         { m.sum += v; m.n++ }
func (m *mean) addN(s float64, n int) { m.sum += s; m.n += n }
func (m mean) val() float64 {
	if m.n == 0 {
		return 0
	}
	return round(m.sum / float64(m.n))
}

func round(v float64) float64 { return math.Round(v*1000) / 1000 }

func f(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// ---- summary ----

// SummaryRow is the single row of the summary report.
type SummaryRow struct {
	Improvements      int     `json:"improvements"`
	Performance       int     `json:"performance"`
	Commit            int     `json:"commit"`
	Cost              int     `json:"cost"`
	Active            int     `json:"active"`
	SteeredHours      float64 `json:"steered_hours"`
	BeforeLossPct     float64 `json:"before_loss_pct"`
	AfterLossPct      float64 `json:"after_loss_pct"`
	BeforeRTTMs       float64 `json:"before_rtt_ms"`
	AfterRTTMs        float64 `json:"after_rtt_ms"`
	Probes            int     `json:"probes"`
	FailedProbes      int     `json:"failed_probes"`
	Prefixes          int     `json:"prefixes"`
	EstSavingsRate    float64 `json:"est_savings_rate"`
	EstSavingsAccrued float64 `json:"est_savings_accrued"`
}

func (a *agg) summary(rep *Report) {
	var s SummaryRow
	var bl, al, br, ar mean
	for _, r := range a.imps {
		s.SteeredHours += a.hours(r)
		s.EstSavingsAccrued += r.EstSavings * a.hours(r) / HoursPerMonth
		if activeAt(r, a.q.Now) {
			s.Active++
			s.EstSavingsRate += r.EstSavings
		}
		if !a.started(r) {
			continue
		}
		s.Improvements++
		switch cause(r) {
		case plugin.CauseCommit:
			s.Commit++
		case plugin.CauseCost:
			s.Cost++
		default:
			s.Performance++
		}
		if r.HasBefore && r.HasAfter {
			bl.add(r.BeforeLoss)
			al.add(r.AfterLoss)
			br.add(r.BeforeRTT)
			ar.add(r.AfterRTT)
		}
	}
	seen := map[netip.Prefix]bool{}
	for _, b := range a.buckets {
		s.Probes += b.Probes
		s.FailedProbes += b.Failed
		seen[b.Prefix] = true
	}
	s.Prefixes = len(seen)
	s.BeforeLossPct, s.AfterLossPct, s.BeforeRTTMs, s.AfterRTTMs = bl.val(), al.val(), br.val(), ar.val()
	s.SteeredHours, s.EstSavingsRate, s.EstSavingsAccrued = round(s.SteeredHours), round(s.EstSavingsRate), round(s.EstSavingsAccrued)
	rep.Rows = []SummaryRow{s}
	rep.head = []string{"improvements", "performance", "commit", "cost", "active", "steered_hours", "before_loss_pct", "after_loss_pct",
		"before_rtt_ms", "after_rtt_ms", "probes", "failed_probes", "prefixes", "est_savings_rate", "est_savings_accrued"}
	rep.lines = [][]string{{
		strconv.Itoa(s.Improvements), strconv.Itoa(s.Performance), strconv.Itoa(s.Commit), strconv.Itoa(s.Cost), strconv.Itoa(s.Active),
		f(s.SteeredHours), f(s.BeforeLossPct), f(s.AfterLossPct), f(s.BeforeRTTMs), f(s.AfterRTTMs),
		strconv.Itoa(s.Probes), strconv.Itoa(s.FailedProbes), strconv.Itoa(s.Prefixes), f(s.EstSavingsRate), f(s.EstSavingsAccrued),
	}}
}

// ---- improvements ----

// ImprovementRow is one improvement.
type ImprovementRow struct {
	Prefix        string    `json:"prefix"`
	Provider      string    `json:"provider"`
	Native        string    `json:"native"`
	Cause         string    `json:"cause"`
	Reason        string    `json:"reason,omitempty"`
	Mode          string    `json:"mode,omitempty"`
	Start         time.Time `json:"start"`
	End           time.Time `json:"end,omitzero"`
	EndReason     string    `json:"end_reason,omitempty"`
	Hours         float64   `json:"hours"`
	BeforeLossPct *float64  `json:"before_loss_pct,omitempty"`
	AfterLossPct  *float64  `json:"after_loss_pct,omitempty"`
	BeforeRTTMs   *float64  `json:"before_rtt_ms,omitempty"`
	AfterRTTMs    *float64  `json:"after_rtt_ms,omitempty"`
	OriginASN     uint32    `json:"origin_asn,omitempty"`
	Country       string    `json:"country,omitempty"`
	VolumeMbps    float64   `json:"volume_mbps,omitempty"`
	CostDelta     float64   `json:"cost_delta,omitempty"`
	EstSavings    float64   `json:"est_savings,omitempty"`
}

func opt(ok bool, v float64) *float64 {
	if !ok {
		return nil
	}
	return &v
}

func optS(v *float64) string {
	if v == nil {
		return ""
	}
	return f(*v)
}

func (a *agg) improvements(rep *Report) {
	imps := slices.Clone(a.imps)
	slices.SortFunc(imps, func(x, y plugin.ImprovementRecord) int {
		if c := y.Start.Compare(x.Start); c != 0 {
			return c
		}
		return cmp.Compare(x.ID, y.ID)
	})
	if len(imps) > a.q.Limit {
		imps = imps[:a.q.Limit]
	}
	rows := make([]ImprovementRow, 0, len(imps))
	rep.head = []string{"prefix", "provider", "native", "cause", "reason", "mode", "start", "end", "end_reason", "hours",
		"before_loss_pct", "after_loss_pct", "before_rtt_ms", "after_rtt_ms", "origin_asn", "country", "volume_mbps", "cost_delta", "est_savings"}
	for _, r := range imps {
		row := ImprovementRow{
			Prefix: r.Prefix.String(), Provider: r.Provider, Native: r.Native, Cause: cause(r), Reason: r.Reason, Mode: r.Mode,
			Start: r.Start.UTC(), EndReason: r.EndReason, Hours: round(a.hours(r)),
			BeforeLossPct: opt(r.HasBefore, r.BeforeLoss), BeforeRTTMs: opt(r.HasBefore, r.BeforeRTT),
			AfterLossPct: opt(r.HasAfter, r.AfterLoss), AfterRTTMs: opt(r.HasAfter, r.AfterRTT),
			OriginASN: r.OriginASN, Country: r.Country, VolumeMbps: r.VolumeMbps, CostDelta: r.CostDelta, EstSavings: r.EstSavings,
		}
		if !r.End.IsZero() {
			row.End = r.End.UTC()
		}
		rows = append(rows, row)
		asn := ""
		if r.OriginASN != 0 {
			asn = strconv.FormatUint(uint64(r.OriginASN), 10)
		}
		rep.lines = append(rep.lines, []string{row.Prefix, row.Provider, row.Native, row.Cause, row.Reason, row.Mode, ts(row.Start), ts(row.End),
			row.EndReason, f(row.Hours), optS(row.BeforeLossPct), optS(row.AfterLossPct), optS(row.BeforeRTTMs), optS(row.AfterRTTMs),
			asn, row.Country, f(row.VolumeMbps), f(row.CostDelta), f(row.EstSavings)})
	}
	rep.Rows = rows
}

// ---- causes ----

// CauseRow is improvements started on one UTC day.
type CauseRow struct {
	Day         string `json:"day"`
	Performance int    `json:"performance"`
	Commit      int    `json:"commit"`
	Cost        int    `json:"cost"`
	Total       int    `json:"total"`
}

func (a *agg) causes(rep *Report) {
	byDay := map[string]*CauseRow{}
	for _, r := range a.imps {
		if !a.started(r) {
			continue
		}
		d := r.Start.UTC().Format(time.DateOnly)
		row := byDay[d]
		if row == nil {
			row = &CauseRow{Day: d}
			byDay[d] = row
		}
		switch cause(r) {
		case plugin.CauseCommit:
			row.Commit++
		case plugin.CauseCost:
			row.Cost++
		default:
			row.Performance++
		}
		row.Total++
	}
	rows := make([]CauseRow, 0, len(byDay))
	for _, r := range byDay {
		rows = append(rows, *r)
	}
	slices.SortFunc(rows, func(x, y CauseRow) int { return cmp.Compare(x.Day, y.Day) })
	rep.Rows = rows
	rep.head = []string{"day", "performance", "commit", "cost", "total"}
	for _, r := range rows {
		rep.lines = append(rep.lines, []string{r.Day, strconv.Itoa(r.Performance), strconv.Itoa(r.Commit), strconv.Itoa(r.Cost), strconv.Itoa(r.Total)})
	}
}

// ---- performance ----

// PerformanceRow is before/after averages for one cause ("all" totals).
type PerformanceRow struct {
	Cause         string  `json:"cause"`
	Improvements  int     `json:"improvements"`
	BeforeLossPct float64 `json:"before_loss_pct"`
	AfterLossPct  float64 `json:"after_loss_pct"`
	LossReduced   float64 `json:"loss_reduced_pct"`
	BeforeRTTMs   float64 `json:"before_rtt_ms"`
	AfterRTTMs    float64 `json:"after_rtt_ms"`
	RTTReducedMs  float64 `json:"rtt_reduced_ms"`
}

func (a *agg) performance(rep *Report) {
	type acc struct{ bl, al, br, ar mean }
	by := map[string]*acc{}
	all := &acc{}
	for _, r := range a.imps {
		if !a.started(r) || !r.HasBefore || !r.HasAfter {
			continue
		}
		c := cause(r)
		if by[c] == nil {
			by[c] = &acc{}
		}
		for _, x := range []*acc{by[c], all} {
			x.bl.add(r.BeforeLoss)
			x.al.add(r.AfterLoss)
			x.br.add(r.BeforeRTT)
			x.ar.add(r.AfterRTT)
		}
	}
	row := func(name string, x *acc) PerformanceRow {
		return PerformanceRow{
			Cause: name, Improvements: x.bl.n,
			BeforeLossPct: x.bl.val(), AfterLossPct: x.al.val(), LossReduced: round(x.bl.val() - x.al.val()),
			BeforeRTTMs: x.br.val(), AfterRTTMs: x.ar.val(), RTTReducedMs: round(x.br.val() - x.ar.val()),
		}
	}
	var rows []PerformanceRow
	for _, c := range []string{plugin.CausePerformance, plugin.CauseCommit, plugin.CauseCost} {
		if x := by[c]; x != nil {
			rows = append(rows, row(c, x))
		}
	}
	rows = append(rows, row("all", all))
	rep.Rows = rows
	rep.head = []string{"cause", "improvements", "before_loss_pct", "after_loss_pct", "loss_reduced_pct", "before_rtt_ms", "after_rtt_ms", "rtt_reduced_ms"}
	for _, r := range rows {
		rep.lines = append(rep.lines, []string{r.Cause, strconv.Itoa(r.Improvements), f(r.BeforeLossPct), f(r.AfterLossPct), f(r.LossReduced),
			f(r.BeforeRTTMs), f(r.AfterRTTMs), f(r.RTTReducedMs)})
	}
}

// ---- providers ----

// ProviderRow is one provider's efficiency over the range.
type ProviderRow struct {
	Provider         string  `json:"provider"`
	Probes           int     `json:"probes"`
	FailedPct        float64 `json:"failed_pct"`
	AvgLossPct       float64 `json:"avg_loss_pct"`
	AvgRTTMs         float64 `json:"avg_rtt_ms"`
	AvgJitterMs      float64 `json:"avg_jitter_ms"`
	ImprovementsTo   int     `json:"improvements_to"`
	ImprovementsFrom int     `json:"improvements_from"`
	SteeredHours     float64 `json:"steered_hours"`
}

func (a *agg) providers(rep *Report) {
	type acc struct {
		probes, failed int
		loss, rtt, jit mean
		to, from       int
		hours          float64
	}
	by := map[string]*acc{}
	get := func(name string) *acc {
		if by[name] == nil {
			by[name] = &acc{}
		}
		return by[name]
	}
	for _, b := range a.buckets {
		x := get(b.Provider)
		x.probes += b.Probes
		x.failed += b.Failed
		x.loss.addN(b.LossSum, b.Measured)
		x.rtt.addN(b.RTTSumMs, b.Measured)
		x.jit.addN(b.JitterSum, b.Measured)
	}
	for _, r := range a.imps {
		if r.Provider != "" {
			get(r.Provider).hours += a.hours(r)
		}
		if !a.started(r) {
			continue
		}
		if r.Provider != "" {
			get(r.Provider).to++
		}
		if r.Native != "" {
			get(r.Native).from++
		}
	}
	rows := make([]ProviderRow, 0, len(by))
	for name, x := range by {
		fp := 0.0
		if x.probes > 0 {
			fp = round(100 * float64(x.failed) / float64(x.probes))
		}
		rows = append(rows, ProviderRow{
			Provider: name, Probes: x.probes, FailedPct: fp, AvgLossPct: x.loss.val(), AvgRTTMs: x.rtt.val(), AvgJitterMs: x.jit.val(),
			ImprovementsTo: x.to, ImprovementsFrom: x.from, SteeredHours: round(x.hours),
		})
	}
	slices.SortFunc(rows, func(x, y ProviderRow) int { return cmp.Compare(x.Provider, y.Provider) })
	rep.Rows = rows
	rep.head = []string{"provider", "probes", "failed_pct", "avg_loss_pct", "avg_rtt_ms", "avg_jitter_ms", "improvements_to", "improvements_from", "steered_hours"}
	for _, r := range rows {
		rep.lines = append(rep.lines, []string{r.Provider, strconv.Itoa(r.Probes), f(r.FailedPct), f(r.AvgLossPct), f(r.AvgRTTMs), f(r.AvgJitterMs),
			strconv.Itoa(r.ImprovementsTo), strconv.Itoa(r.ImprovementsFrom), f(r.SteeredHours)})
	}
}

// ---- prefixes, ASNs, countries ----

type prefixAcc struct {
	prefix    netip.Prefix
	asn       uint32
	country   string
	volume    float64
	probes    int
	loss, rtt mean
	imps      int
	hours     float64
}

func (a *agg) perPrefix() map[netip.Prefix]*prefixAcc {
	by := map[netip.Prefix]*prefixAcc{}
	get := func(p netip.Prefix) *prefixAcc {
		x := by[p]
		if x == nil {
			x = &prefixAcc{prefix: p}
			if info, ok := a.info[p]; ok {
				x.asn, x.country, x.volume = info.OriginASN, info.Country, info.VolumeMbps
			}
			by[p] = x
		}
		return x
	}
	for _, b := range a.buckets {
		x := get(b.Prefix)
		x.probes += b.Probes
		x.loss.addN(b.LossSum, b.Measured)
		x.rtt.addN(b.RTTSumMs, b.Measured)
	}
	for _, r := range a.imps {
		x := get(r.Prefix)
		x.hours += a.hours(r)
		if x.asn == 0 {
			x.asn = r.OriginASN
		}
		if x.country == "" {
			x.country = r.Country
		}
		if x.volume == 0 {
			x.volume = r.VolumeMbps
		}
		if a.started(r) {
			x.imps++
		}
	}
	return by
}

// topCompare orders rows for sort: problems (improvements, then loss),
// volume, or loss. Ties break by key.
func topCompare(sort string, ai, bi int, al, bl, av, bv float64) int {
	switch sort {
	case SortVolume:
		if c := cmp.Compare(bv, av); c != 0 {
			return c
		}
		return cmp.Compare(bl, al)
	case SortLoss:
		if c := cmp.Compare(bl, al); c != 0 {
			return c
		}
		return cmp.Compare(bi, ai)
	default:
		if c := cmp.Compare(bi, ai); c != 0 {
			return c
		}
		return cmp.Compare(bl, al)
	}
}

// PrefixRow is one prefix in the top-prefixes report.
type PrefixRow struct {
	Prefix       string  `json:"prefix"`
	OriginASN    uint32  `json:"origin_asn,omitempty"`
	Country      string  `json:"country,omitempty"`
	VolumeMbps   float64 `json:"volume_mbps"`
	Probes       int     `json:"probes"`
	AvgLossPct   float64 `json:"avg_loss_pct"`
	AvgRTTMs     float64 `json:"avg_rtt_ms"`
	Improvements int     `json:"improvements"`
	SteeredHours float64 `json:"steered_hours"`
}

func (a *agg) prefixes(rep *Report) {
	var rows []PrefixRow
	for _, x := range a.perPrefix() {
		rows = append(rows, PrefixRow{
			Prefix: x.prefix.String(), OriginASN: x.asn, Country: x.country, VolumeMbps: round(x.volume), Probes: x.probes,
			AvgLossPct: x.loss.val(), AvgRTTMs: x.rtt.val(), Improvements: x.imps, SteeredHours: round(x.hours),
		})
	}
	slices.SortFunc(rows, func(x, y PrefixRow) int {
		if c := topCompare(a.q.Sort, x.Improvements, y.Improvements, x.AvgLossPct, y.AvgLossPct, x.VolumeMbps, y.VolumeMbps); c != 0 {
			return c
		}
		return cmp.Compare(x.Prefix, y.Prefix)
	})
	if len(rows) > a.q.Limit {
		rows = rows[:a.q.Limit]
	}
	if rows == nil {
		rows = []PrefixRow{}
	}
	rep.Rows = rows
	rep.head = []string{"prefix", "origin_asn", "country", "volume_mbps", "probes", "avg_loss_pct", "avg_rtt_ms", "improvements", "steered_hours"}
	for _, r := range rows {
		asn := ""
		if r.OriginASN != 0 {
			asn = strconv.FormatUint(uint64(r.OriginASN), 10)
		}
		rep.lines = append(rep.lines, []string{r.Prefix, asn, r.Country, f(r.VolumeMbps), strconv.Itoa(r.Probes), f(r.AvgLossPct), f(r.AvgRTTMs),
			strconv.Itoa(r.Improvements), f(r.SteeredHours)})
	}
}

// GroupRow is one origin ASN or country.
type GroupRow struct {
	Key          string  `json:"key"`
	Prefixes     int     `json:"prefixes"`
	VolumeMbps   float64 `json:"volume_mbps"`
	Probes       int     `json:"probes"`
	AvgLossPct   float64 `json:"avg_loss_pct"`
	AvgRTTMs     float64 `json:"avg_rtt_ms"`
	Improvements int     `json:"improvements"`
	SteeredHours float64 `json:"steered_hours"`
}

// groups aggregates prefixes by origin ASN or country. Prefixes with no
// ASN or no country are left out.
func (a *agg) groups(rep *Report, by string) {
	type acc struct {
		prefixes  int
		volume    float64
		probes    int
		loss, rtt mean
		imps      int
		hours     float64
	}
	m := map[string]*acc{}
	for _, x := range a.perPrefix() {
		key := x.country
		if by == "asn" {
			key = ""
			if x.asn != 0 {
				key = strconv.FormatUint(uint64(x.asn), 10)
			}
		}
		if key == "" {
			continue
		}
		g := m[key]
		if g == nil {
			g = &acc{}
			m[key] = g
		}
		g.prefixes++
		g.volume += x.volume
		g.probes += x.probes
		g.loss.addN(x.loss.sum, x.loss.n)
		g.rtt.addN(x.rtt.sum, x.rtt.n)
		g.imps += x.imps
		g.hours += x.hours
	}
	rows := make([]GroupRow, 0, len(m))
	for k, g := range m {
		rows = append(rows, GroupRow{Key: k, Prefixes: g.prefixes, VolumeMbps: round(g.volume), Probes: g.probes,
			AvgLossPct: g.loss.val(), AvgRTTMs: g.rtt.val(), Improvements: g.imps, SteeredHours: round(g.hours)})
	}
	slices.SortFunc(rows, func(x, y GroupRow) int {
		if c := topCompare(a.q.Sort, x.Improvements, y.Improvements, x.AvgLossPct, y.AvgLossPct, x.VolumeMbps, y.VolumeMbps); c != 0 {
			return c
		}
		return cmp.Compare(x.Key, y.Key)
	})
	if len(rows) > a.q.Limit {
		rows = rows[:a.q.Limit]
	}
	rep.Rows = rows
	key := "country"
	if by == "asn" {
		key = "origin_asn"
	}
	rep.head = []string{key, "prefixes", "volume_mbps", "probes", "avg_loss_pct", "avg_rtt_ms", "improvements", "steered_hours"}
	for _, r := range rows {
		rep.lines = append(rep.lines, []string{r.Key, strconv.Itoa(r.Prefixes), f(r.VolumeMbps), strconv.Itoa(r.Probes), f(r.AvgLossPct),
			f(r.AvgRTTMs), strconv.Itoa(r.Improvements), f(r.SteeredHours)})
	}
}

// ---- probes ----

// ProbeDayRow is probe volume on one UTC day.
type ProbeDayRow struct {
	Day        string  `json:"day"`
	Probes     int     `json:"probes"`
	Failed     int     `json:"failed"`
	Prefixes   int     `json:"prefixes"`
	AvgLossPct float64 `json:"avg_loss_pct"`
	AvgRTTMs   float64 `json:"avg_rtt_ms"`
}

func (a *agg) probes(rep *Report) {
	type acc struct {
		probes, failed int
		prefixes       map[netip.Prefix]bool
		loss, rtt      mean
	}
	m := map[string]*acc{}
	for _, b := range a.buckets {
		d := b.Day.UTC().Format(time.DateOnly)
		x := m[d]
		if x == nil {
			x = &acc{prefixes: map[netip.Prefix]bool{}}
			m[d] = x
		}
		x.probes += b.Probes
		x.failed += b.Failed
		x.prefixes[b.Prefix] = true
		x.loss.addN(b.LossSum, b.Measured)
		x.rtt.addN(b.RTTSumMs, b.Measured)
	}
	rows := make([]ProbeDayRow, 0, len(m))
	for d, x := range m {
		rows = append(rows, ProbeDayRow{Day: d, Probes: x.probes, Failed: x.failed, Prefixes: len(x.prefixes), AvgLossPct: x.loss.val(), AvgRTTMs: x.rtt.val()})
	}
	slices.SortFunc(rows, func(x, y ProbeDayRow) int { return cmp.Compare(x.Day, y.Day) })
	rep.Rows = rows
	rep.head = []string{"day", "probes", "failed", "prefixes", "avg_loss_pct", "avg_rtt_ms"}
	for _, r := range rows {
		rep.lines = append(rep.lines, []string{r.Day, strconv.Itoa(r.Probes), strconv.Itoa(r.Failed), strconv.Itoa(r.Prefixes), f(r.AvgLossPct), f(r.AvgRTTMs)})
	}
}

// ---- savings ----

// SavingsRow is one priced improvement. EstSavings is the monthly rate
// (cost_delta × volume); Accrued is that rate over the hours inside the
// range, divided by HoursPerMonth. Negative values are extra spend.
type SavingsRow struct {
	Prefix     string    `json:"prefix"`
	Native     string    `json:"native"`
	Provider   string    `json:"provider"`
	Cause      string    `json:"cause"`
	Start      time.Time `json:"start"`
	End        time.Time `json:"end,omitzero"`
	CostDelta  float64   `json:"cost_delta"`
	VolumeMbps float64   `json:"volume_mbps"`
	EstSavings float64   `json:"est_savings"`
	Hours      float64   `json:"hours"`
	Accrued    float64   `json:"accrued"`
}

func (a *agg) savings(rep *Report) {
	var rows []SavingsRow
	for _, r := range a.imps {
		if r.CostDelta == 0 && r.EstSavings == 0 {
			continue
		}
		h := a.hours(r)
		row := SavingsRow{Prefix: r.Prefix.String(), Native: r.Native, Provider: r.Provider, Cause: cause(r), Start: r.Start.UTC(),
			CostDelta: r.CostDelta, VolumeMbps: r.VolumeMbps, EstSavings: r.EstSavings, Hours: round(h), Accrued: round(r.EstSavings * h / HoursPerMonth)}
		if !r.End.IsZero() {
			row.End = r.End.UTC()
		}
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(x, y SavingsRow) int {
		if c := cmp.Compare(y.Accrued, x.Accrued); c != 0 {
			return c
		}
		if c := cmp.Compare(x.Prefix, y.Prefix); c != 0 {
			return c
		}
		return x.Start.Compare(y.Start)
	})
	if len(rows) > a.q.Limit {
		rows = rows[:a.q.Limit]
	}
	if rows == nil {
		rows = []SavingsRow{}
	}
	rep.Rows = rows
	rep.head = []string{"prefix", "native", "provider", "cause", "start", "end", "cost_delta", "volume_mbps", "est_savings", "hours", "accrued"}
	for _, r := range rows {
		rep.lines = append(rep.lines, []string{r.Prefix, r.Native, r.Provider, r.Cause, ts(r.Start), ts(r.End), f(r.CostDelta), f(r.VolumeMbps),
			f(r.EstSavings), f(r.Hours), f(r.Accrued)})
	}
}
