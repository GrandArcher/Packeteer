package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/internal/netpfx"
)

// ReportSource builds reports from stored history. Nil when no storage
// plugin is configured.
type ReportSource interface {
	Report(ctx context.Context, q history.Query) (history.Report, error)
	Prefix(ctx context.Context, p netip.Prefix, q history.Query) (history.PrefixHistory, error)
	Search(ctx context.Context, q history.SearchQuery) (history.SearchResult, error)
}

// Report range bounds.
const (
	DefaultReportDays = 7
	MaxReportDays     = 3660
)

func (s *Server) handleReportList(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	writeJSON(w, http.StatusOK, struct {
		meta
		Enabled bool `json:"enabled"`
		Reports any  `json:"reports"`
	}{meta: snap.meta(), Enabled: s.reports != nil, Reports: history.Reports})
}

// parseTime accepts RFC 3339 or a UTC date (2006-01-02).
func parseTime(v string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse(time.DateOnly, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is not RFC 3339 or YYYY-MM-DD", v)
	}
	return t.UTC(), nil
}

// reportParams are the query parameters every report takes besides its
// filters.
var reportParams = []string{"days", "from", "to", "limit", "sort", "order", "format"}

// reportQuery reads the range, limit, sort, and filters. The default range
// is the last DefaultReportDays days, or the report's own default. An
// unknown parameter is an error, so a misspelled filter cannot return
// unfiltered rows.
func reportQuery(r *http.Request, name string, now time.Time) (history.Query, error) {
	return reportQueryValues(r.URL.Query(), name, now)
}

func reportQueryValues(v url.Values, name string, now time.Time) (history.Query, error) {
	q := history.Query{Name: name, To: now.UTC(), Sort: v.Get("sort"), Order: v.Get("order")}
	if name != "" {
		for k := range v {
			if !slices.Contains(reportParams, k) && !slices.Contains(history.Filters, k) {
				return q, fmt.Errorf("unknown parameter %q", k)
			}
		}
	}
	if s := v.Get("to"); s != "" {
		t, err := parseTime(s)
		if err != nil {
			return q, fmt.Errorf("to: %w", err)
		}
		q.To = t
	}
	days := DefaultReportDays
	if d, ok := history.Lookup(name); ok && d.DefaultDays > 0 {
		days = d.DefaultDays
	}
	if s := v.Get("days"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > MaxReportDays {
			return q, fmt.Errorf("days must be 1-%d", MaxReportDays)
		}
		days = n
	}
	q.From = q.To.Add(-time.Duration(days) * 24 * time.Hour)
	if s := v.Get("from"); s != "" {
		if v.Get("days") != "" {
			return q, fmt.Errorf("set from or days, not both")
		}
		t, err := parseTime(s)
		if err != nil {
			return q, fmt.Errorf("from: %w", err)
		}
		q.From = t
	}
	if !q.From.Before(q.To) {
		return q, fmt.Errorf("from must be before to")
	}
	if q.To.Sub(q.From) > MaxReportDays*24*time.Hour {
		return q, fmt.Errorf("range is longer than %d days", MaxReportDays)
	}
	if s := v.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > history.MaxLimit {
			return q, fmt.Errorf("limit must be 1-%d", history.MaxLimit)
		}
		q.Limit = n
	}
	q.Now = now.UTC()
	// The prefix history call has no report name and its own prefix.
	if name == "" {
		return q, nil
	}
	if s := v.Get(history.FilterPrefix); s != "" {
		p, err := netip.ParsePrefix(s)
		if err != nil || p != p.Masked() {
			return q, fmt.Errorf("prefix must be a network in CIDR form, such as 192.0.2.0/24")
		}
		q.Prefix = p
	}
	if s := v.Get(history.FilterASN); s != "" {
		n, ok := netpfx.ParseASN(s)
		if !ok {
			return q, fmt.Errorf("asn must be an AS number such as 64500")
		}
		q.ASN = n
	}
	if q.Provider = v.Get(history.FilterProvider); !validText(q.Provider, 100) {
		return q, fmt.Errorf("provider must be one line of at most 100 bytes")
	}
	q.Cause = v.Get(history.FilterCause)
	if s := v.Get(history.FilterIPVersion); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			return q, fmt.Errorf("ip_version must be 4 or 6")
		}
		q.IPVersion = n
	}
	return q, q.Validate()
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !history.Known(name) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown report " + strconv.Quote(name)})
		return
	}
	if s.reports == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "history storage is not configured (set storage.type: sqlite)"})
		return
	}
	format := r.URL.Query().Get("format")
	if format != "" && format != "json" && format != "csv" && format != "xlsx" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "format must be json, csv, or xlsx"})
		return
	}
	q, err := reportQuery(r, name, time.Now())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	rep, err := s.reports.Report(ctx, q)
	if err != nil {
		s.log.Warn("report", "name", name, "err", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if format == "csv" || format == "xlsx" {
		contentType, write := "text/csv; charset=utf-8", rep.CSV
		if format == "xlsx" {
			contentType, write = history.XLSXContentType, rep.XLSX
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="packeteer-%s-%s-%s.%s"`,
			name, q.From.Format("20060102T150405Z"), q.To.Format("20060102T150405Z"), format))
		w.WriteHeader(http.StatusOK)
		if err := write(w); err != nil {
			s.log.Warn("report export", "name", name, "format", format, "err", err)
		}
		return
	}
	snap := s.snapshot()
	writeJSON(w, http.StatusOK, struct {
		meta
		history.Report
	}{meta: snap.meta(), Report: rep})
}

// handlePrefixHistory serves one prefix's stored probe rollups and
// improvements for the prefix page (#179). Without a storage plugin it
// answers enabled: false so the page can say so. It reads only.
func (s *Server) handlePrefixHistory(w http.ResponseWriter, r *http.Request) {
	p, err := netip.ParsePrefix(r.URL.Query().Get("prefix"))
	if err != nil || p != p.Masked() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "prefix must be a network in CIDR form, such as 192.0.2.0/24"})
		return
	}
	snap := s.snapshot()
	if s.reports == nil {
		writeJSON(w, http.StatusOK, struct {
			meta
			Enabled bool   `json:"enabled"`
			Prefix  string `json:"prefix"`
		}{meta: snap.meta(), Prefix: p.String()})
		return
	}
	q, err := reportQuery(r, "", time.Now())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	h, err := s.reports.Prefix(ctx, p, q)
	if err != nil {
		s.log.Warn("prefix history", "prefix", p, "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "history store unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, struct {
		meta
		Enabled bool `json:"enabled"`
		history.PrefixHistory
	}{meta: snap.meta(), Enabled: true, PrefixHistory: h})
}
