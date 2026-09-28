package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/GrandArcher/Packeteer/internal/history"
)

// ReportSource builds reports from stored history. Nil when no storage
// plugin is configured.
type ReportSource interface {
	Report(ctx context.Context, q history.Query) (history.Report, error)
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

// reportQuery reads from, to, days, limit, and sort. The default range is
// the last DefaultReportDays days.
func reportQuery(r *http.Request, name string, now time.Time) (history.Query, error) {
	q := history.Query{Name: name, To: now.UTC(), Sort: r.URL.Query().Get("sort")}
	v := r.URL.Query()
	if s := v.Get("to"); s != "" {
		t, err := parseTime(s)
		if err != nil {
			return q, fmt.Errorf("to: %w", err)
		}
		q.To = t
	}
	days := DefaultReportDays
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
	return q, nil
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
	if format != "" && format != "json" && format != "csv" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "format must be json or csv"})
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
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="packeteer-%s-%s-%s.csv"`,
			name, q.From.Format("20060102T150405Z"), q.To.Format("20060102T150405Z")))
		w.WriteHeader(http.StatusOK)
		if err := rep.CSV(w); err != nil {
			s.log.Warn("report csv", "name", name, "err", err)
		}
		return
	}
	snap := s.snapshot()
	writeJSON(w, http.StatusOK, struct {
		meta
		history.Report
	}{meta: snap.meta(), Report: rep})
}
