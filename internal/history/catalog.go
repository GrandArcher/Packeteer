package history

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Report categories, in the order the page lists them.
const (
	CategoryOverview     = "Overview"
	CategoryImprovements = "Improvements"
	CategoryPerformance  = "Performance"
	CategoryTraffic      = "Traffic"
	CategoryCost         = "Cost"
	CategoryProtection   = "Protection"
)

// Filter names a report may accept (#178). The query parameters have the
// same names.
const (
	FilterProvider  = "provider"
	FilterASN       = "asn"
	FilterPrefix    = "prefix"
	FilterCause     = "cause"
	FilterIPVersion = "ip_version"
)

// Column types. They decide how a sort compares two cells.
const (
	TypeText   = "text"
	TypeNumber = "number"
	TypeTime   = "time"
	TypePrefix = "prefix"
)

// Column is one column of a report: Key is the JSON field of a row, Label
// the human name, and Unit what a number is counted in.
type Column struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Unit  string `json:"unit,omitempty"`
	Type  string `json:"type"`
	// csv replaces Key in the CSV header where the two have always differed.
	csv string
}

func (c Column) header() string {
	if c.csv != "" {
		return c.csv
	}
	return c.Key
}

// Def describes a report: what it is, how to find it, and which filters and
// columns it has. Filters apply to the rows before they are built, so the
// page, CSV, XLSX, and widgets see the same rows.
type Def struct {
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Summary  string   `json:"summary"`
	Filters  []string `json:"filters"`
	Columns  []Column `json:"columns"`
	// DefaultDays is the range when a request names none; 0 means 7.
	DefaultDays int `json:"default_days,omitempty"`
	// Limited reports are cut to the row limit after sorting; the others
	// have one row per day, provider, or cause and are never cut.
	Limited bool `json:"limited"`
}

func num(key, label, unit string) Column {
	return Column{Key: key, Label: label, Unit: unit, Type: TypeNumber}
}
func txt(key, label string) Column  { return Column{Key: key, Label: label, Type: TypeText} }
func when(key, label string) Column { return Column{Key: key, Label: label, Type: TypeTime} }

// Filters are all the filter parameters. Which of them a report takes is in
// its Def.
var Filters = []string{FilterProvider, FilterASN, FilterPrefix, FilterCause, FilterIPVersion}

var (
	noCause      = []string{FilterProvider, FilterASN, FilterPrefix, FilterIPVersion}
	noProvider   = []string{FilterASN, FilterPrefix, FilterCause, FilterIPVersion}
	prefixFilter = []string{FilterPrefix, FilterIPVersion}
	// The scorecard ranks providers against each other, so a provider
	// filter would rank a subset.
	noProviderOrCause = []string{FilterASN, FilterPrefix, FilterIPVersion}
)

// Reports lists every report in catalog order.
var Reports = []Def{
	{Name: ReportSummary, Category: CategoryOverview, Filters: noCause,
		Summary: "Totals: improvements by cause, active now, average loss and latency before and after, probes, estimated savings.",
		Columns: []Column{
			num("improvements", "Improvements", ""), num("performance", "Performance", ""), num("commit", "Commit", ""), num("cost", "Cost", ""),
			num("active", "Active now", ""), num("steered_hours", "Steered", "h"),
			num("before_loss_pct", "Loss before", "%"), num("after_loss_pct", "Loss after", "%"),
			num("before_rtt_ms", "RTT before", "ms"), num("after_rtt_ms", "RTT after", "ms"),
			num("probes", "Probes", ""), num("failed_probes", "Failed probes", ""), num("prefixes", "Prefixes", ""),
			num("est_savings_rate", "Est. savings rate", "per month"), num("est_savings_accrued", "Est. savings accrued", ""),
		}},
	{Name: ReportImprovements, Category: CategoryImprovements, Filters: Filters, Limited: true,
		Summary: "Every improvement that overlaps the range, newest first.",
		Columns: []Column{
			{Key: "prefix", Label: "Prefix", Type: TypePrefix}, txt("provider", "Chosen provider"), txt("native", "Native provider"), txt("cause", "Cause"),
			txt("reason", "Reason"), txt("mode", "Mode"), when("start", "Start"), when("end", "End"), txt("end_reason", "End reason"),
			num("hours", "Active", "h"), num("before_loss_pct", "Loss before", "%"), num("after_loss_pct", "Loss after", "%"),
			num("before_rtt_ms", "RTT before", "ms"), num("after_rtt_ms", "RTT after", "ms"), num("origin_asn", "Origin AS", ""),
			txt("country", "Country"), num("volume_mbps", "Volume", "Mbps"), num("cost_delta", "Cost delta", "per Mbps"),
			num("est_savings", "Est. savings", "per month"),
		}},
	{Name: ReportExchanges, Category: CategoryImprovements, Filters: Filters,
		Summary: "Improvements onto each Internet exchange peer: started, active now, prefixes, Mbps moved, and hours steered.",
		Columns: []Column{
			txt("exchange", "Exchange"), txt("peer", "Peer"), num("improvements", "Improvements", ""), num("active", "Active now", ""),
			num("prefixes", "Prefixes", ""), num("volume_mbps", "Moved", "Mbps"), num("steered_hours", "Steered", "h"),
		}},
	{Name: ReportCauses, Category: CategoryImprovements, Filters: Filters,
		Summary: "Improvements started per UTC day, by cause (performance, commit, cost).",
		Columns: []Column{
			txt("day", "Day (UTC)"), num("performance", "Performance", ""), num("commit", "Commit", ""), num("cost", "Cost", ""), num("total", "Total", ""),
		}},
	{Name: ReportPerformance, Category: CategoryPerformance, Filters: Filters,
		Summary: "Loss and latency before (native) and after (chosen provider), by cause.",
		Columns: []Column{
			txt("cause", "Cause"), num("improvements", "Improvements", ""), num("before_loss_pct", "Loss before", "%"), num("after_loss_pct", "Loss after", "%"),
			num("loss_reduced_pct", "Loss reduced", "%"), num("before_rtt_ms", "RTT before", "ms"), num("after_rtt_ms", "RTT after", "ms"),
			num("rtt_reduced_ms", "RTT reduced", "ms"),
		}},
	{Name: ReportTimeSeries, Category: CategoryPerformance, Filters: noProvider,
		Summary: "Loss and latency per UTC day, before (native) and after (chosen provider), for all, problem, 20%-better, and 50%-better destinations. Not cut by limit.",
		Columns: []Column{
			txt("day", "Day (UTC)"), txt("bucket", "Destinations"), num("prefixes", "Prefixes", ""),
			num("before_loss_pct", "Loss before", "%"), num("after_loss_pct", "Loss after", "%"),
			num("before_rtt_ms", "RTT before", "ms"), num("after_rtt_ms", "RTT after", "ms"),
		}},
	{Name: ReportProviders, Category: CategoryPerformance, Filters: noCause,
		Summary: "Provider efficiency: measured loss, latency, failures, and improvements onto and off each provider.",
		Columns: []Column{
			txt("provider", "Provider"), num("probes", "Probes", ""), num("failed_pct", "Failed", "%"), num("avg_loss_pct", "Avg loss", "%"),
			num("avg_rtt_ms", "Avg RTT", "ms"), num("avg_jitter_ms", "Avg jitter", "ms"), num("improvements_to", "Improvements onto", ""),
			num("improvements_from", "Improvements off", ""), num("steered_hours", "Steered", "h"),
		}},
	{Name: ReportProbes, Category: CategoryPerformance, Filters: noCause,
		Summary: "Probes per UTC day.",
		Columns: []Column{
			txt("day", "Day (UTC)"), num("probes", "Probes", ""), num("failed", "Failed", ""), num("prefixes", "Prefixes", ""),
			num("avg_loss_pct", "Avg loss", "%"), num("avg_rtt_ms", "Avg RTT", "ms"),
		}},
	{Name: ReportProbeASNs, Category: CategoryPerformance, Filters: noCause, Limited: true,
		Summary: "Probes per destination origin ASN per UTC day, newest day and most probed ASN first. Prefixes with no learned origin are left out.",
		Columns: []Column{
			txt("day", "Day (UTC)"), num("origin_asn", "Origin AS", ""), num("prefixes", "Prefixes", ""), num("probes", "Probes", ""), num("failed", "Failed", ""),
		}},
	{Name: ReportScorecard, Category: CategoryPerformance, Filters: noProviderOrCause, Limited: true, DefaultDays: 30,
		Summary: "Provider scorecard: loss, latency, and jitter percentiles per provider and destination origin ASN, weighted by flow volume, with the providers ranked per ASN.",
		Columns: []Column{
			txt("provider", "Provider"), num("origin_asn", "Origin AS", ""), num("rank", "Rank", ""), num("prefixes", "Prefixes", ""), num("probes", "Probes", ""),
			num("failed_pct", "Failed", "%"), num("volume_mbps", "Volume", "Mbps"), txt("weighting", "Weighting"),
			num("loss_p50_pct", "Loss p50", "%"), num("loss_p95_pct", "Loss p95", "%"), num("rtt_p50_ms", "RTT p50", "ms"), num("rtt_p95_ms", "RTT p95", "ms"),
			num("jitter_p50_ms", "Jitter p50", "ms"), num("jitter_p95_ms", "Jitter p95", "ms"),
		}},
	{Name: ReportPrefixes, Category: CategoryTraffic, Filters: noCause, Limited: true,
		Summary: "Top prefixes by problems, volume, or loss.",
		Columns: []Column{
			{Key: "prefix", Label: "Prefix", Type: TypePrefix}, num("origin_asn", "Origin AS", ""), txt("country", "Country"), num("volume_mbps", "Volume", "Mbps"),
			num("probes", "Probes", ""), num("avg_loss_pct", "Avg loss", "%"), num("avg_rtt_ms", "Avg RTT", "ms"),
			num("improvements", "Improvements", ""), num("steered_hours", "Steered", "h"),
		}},
	{Name: ReportASNs, Category: CategoryTraffic, Filters: noCause, Limited: true,
		Summary: "Top origin ASNs by problems, volume, or loss.",
		Columns: []Column{
			{Key: "key", Label: "Origin AS", Type: TypeNumber, csv: "origin_asn"}, num("prefixes", "Prefixes", ""), num("volume_mbps", "Volume", "Mbps"),
			num("probes", "Probes", ""), num("avg_loss_pct", "Avg loss", "%"), num("avg_rtt_ms", "Avg RTT", "ms"),
			num("improvements", "Improvements", ""), num("steered_hours", "Steered", "h"),
		}},
	{Name: ReportCountries, Category: CategoryTraffic, Filters: noCause, Limited: true,
		Summary: "Top countries by problems, volume, or loss (needs a rules policy with geoip_db).",
		Columns: []Column{
			{Key: "key", Label: "Country", Type: TypeText, csv: "country"}, num("prefixes", "Prefixes", ""), num("volume_mbps", "Volume", "Mbps"),
			num("probes", "Probes", ""), num("avg_loss_pct", "Avg loss", "%"), num("avg_rtt_ms", "Avg RTT", "ms"),
			num("improvements", "Improvements", ""), num("steered_hours", "Steered", "h"),
		}},
	{Name: ReportSavings, Category: CategoryCost, Filters: Filters, Limited: true,
		Summary: "Estimated cost savings per improvement between priced providers.",
		Columns: []Column{
			{Key: "prefix", Label: "Prefix", Type: TypePrefix}, txt("native", "Native provider"), txt("provider", "Chosen provider"), txt("cause", "Cause"),
			when("start", "Start"), when("end", "End"), num("cost_delta", "Cost delta", "per Mbps"), num("volume_mbps", "Volume", "Mbps"),
			num("est_savings", "Est. savings", "per month"), num("hours", "Active", "h"), num("accrued", "Accrued", ""),
		}},
	{Name: ReportMitigations, Category: CategoryProtection, Filters: prefixFilter, Limited: true,
		Summary: "Threat mitigation history: every RTBH, redirect, and FlowSpec rule that overlaps the range, newest first.",
		Columns: []Column{
			txt("id", "ID"), {Key: "prefix", Label: "Prefix", Type: TypePrefix}, txt("action", "Action"), txt("target", "Target"), txt("match", "Match"),
			txt("source_countries", "Source countries"), num("rate_mbps", "Rate", "Mbps"), num("routes", "Routes", ""), txt("reason", "Reason"), txt("mode", "Mode"),
			when("created", "Created"), when("expires", "Expires"), when("announced", "Announced"), when("end", "End"), txt("end_reason", "End reason"),
			num("announced_hours", "On the wire", "h"),
		}},
	{Name: ReportAnomalies, Category: CategoryProtection, Filters: prefixFilter, Limited: true,
		Summary: "Traffic anomaly history: every detected anomaly that overlaps the range, the rule that matched, and the mitigation added, newest first.",
		Columns: []Column{
			txt("id", "ID"), {Key: "prefix", Label: "Prefix", Type: TypePrefix}, txt("protocol", "Protocol"), num("peak_mbps", "Peak", "Mbps"),
			num("baseline_mbps", "Baseline", "Mbps"), txt("reason", "Reason"), txt("rule", "Rule"), txt("mitigation", "Mitigation"), txt("action", "Action"),
			when("start", "Start"), when("end", "End"), txt("end_reason", "End reason"), num("minutes", "Lasted", "min"),
		}},
}

// Lookup returns the definition of the named report.
func Lookup(name string) (Def, bool) {
	i := slices.IndexFunc(Reports, func(d Def) bool { return d.Name == name })
	if i < 0 {
		return Def{}, false
	}
	return Reports[i], true
}

// Known reports whether name is a report.
func Known(name string) bool {
	_, ok := Lookup(name)
	return ok
}

func (d Def) column(key string) (int, bool) {
	i := slices.IndexFunc(d.Columns, func(c Column) bool { return c.Key == key })
	return i, i >= 0
}

// Sort orders of a column sort.
const (
	OrderAsc  = "asc"
	OrderDesc = "desc"
)

var causes = []string{plugin.CausePerformance, plugin.CauseCommit, plugin.CauseCost, plugin.CauseStatic}

// Validate checks q against its report: the sort key and order, the cause,
// and that every filter set is one the report supports. Build calls it, so
// no caller can ask for a filter that would be silently ignored.
func (q Query) Validate() error {
	d, ok := Lookup(q.Name)
	if !ok {
		return fmt.Errorf("unknown report %q", q.Name)
	}
	set := map[string]bool{
		FilterProvider: q.Provider != "", FilterASN: q.ASN != 0, FilterPrefix: q.Prefix.IsValid(),
		FilterCause: q.Cause != "", FilterIPVersion: q.IPVersion != 0,
	}
	for _, name := range Filters {
		if set[name] && !slices.Contains(d.Filters, name) {
			return fmt.Errorf("the %s report has no %s filter (it takes %s)", d.Name, name, strings.Join(d.Filters, ", "))
		}
	}
	if q.Limit != 0 && !d.Limited {
		return fmt.Errorf("the %s report is never cut, so it takes no limit", d.Name)
	}
	if q.Cause != "" && !slices.Contains(causes, q.Cause) {
		return fmt.Errorf("cause must be one of %s", strings.Join(causes, ", "))
	}
	if q.IPVersion != 0 && q.IPVersion != 4 && q.IPVersion != 6 {
		return fmt.Errorf("ip_version must be 4 or 6")
	}
	_, isColumn := d.column(q.Sort)
	// Only the top-N reports pick their rows by problems, volume, or loss;
	// the others would ignore those keys.
	topN := d.Name == ReportPrefixes || d.Name == ReportASNs || d.Name == ReportCountries
	switch {
	case q.Sort == "" || isColumn:
	case topN && (q.Sort == SortProblems || q.Sort == SortVolume || q.Sort == SortLoss):
	default:
		keys := make([]string, len(d.Columns))
		for i, c := range d.Columns {
			keys[i] = c.Key
		}
		if topN {
			return fmt.Errorf("sort %q is invalid (want %s, %s, %s, or a column: %s)", q.Sort, SortProblems, SortVolume, SortLoss, strings.Join(keys, ", "))
		}
		return fmt.Errorf("sort %q is invalid (want a column: %s)", q.Sort, strings.Join(keys, ", "))
	}
	switch q.Order {
	case "":
	case OrderAsc, OrderDesc:
		if !isColumn {
			return fmt.Errorf("order needs sort=<column>")
		}
	default:
		return fmt.Errorf("order must be %s or %s", OrderAsc, OrderDesc)
	}
	return nil
}

// matchPrefix applies the prefix and ip_version filters.
func (q Query) matchPrefix(p netip.Prefix) bool {
	if q.Prefix.IsValid() && p != q.Prefix {
		return false
	}
	switch q.IPVersion {
	case 4:
		return p.Addr().Unmap().Is4()
	case 6:
		return !p.Addr().Unmap().Is4()
	}
	return true
}
