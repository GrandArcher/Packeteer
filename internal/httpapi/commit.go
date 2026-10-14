package httpapi

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/GrandArcher/Packeteer/internal/commitview"
	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// UsageReader reads the persisted 95th-percentile samples (#127). Nil when
// the storage plugin does not keep them.
type UsageReader interface {
	UsageSamples(ctx context.Context, q plugin.UsageSampleQuery) ([]plugin.UsageSample, error)
}

// commitProvider is one telemetry binding: the figures of /api/telemetry,
// the billable 95th as commit control reads it (absent without a stored
// sample or a positive commit), the drawn points, and the commit moves.
// Points is empty when no sample is stored; Moves when nothing moved or
// history is off.
type commitProvider struct {
	Telemetry
	BillableMbps *float64           `json:"billable_mbps,omitempty"`
	Points       []commitview.Point `json:"points"`
	Moves        []commitview.Move  `json:"moves"`
}

// handleCommit serves the Commit & Cost page (#174). Read-only.
func (s *Server) handleCommit(w http.ResponseWriter, r *http.Request) {
	days := 7
	if v := r.URL.Query().Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if _, ok := commitview.Steps[n]; err != nil || !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "days must be 1, 7, or 30"})
			return
		}
		days = n
	}
	step := commitview.Steps[days]
	snap := s.snapshot()
	m := snap.meta()
	to := m.GeneratedAt
	from := to.Add(-time.Duration(days) * 24 * time.Hour)

	var moves []history.ImprovementRow
	var movesTruncated bool
	if s.reports != nil {
		rep, err := s.reports.Report(r.Context(), history.Query{Name: history.ReportImprovements, From: from, To: to, Now: to, Cause: plugin.CauseCommit, Limit: history.MaxLimit})
		if err != nil {
			s.log.Warn("commit page: improvements", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot read the improvement history"})
			return
		}
		moves, _ = rep.Rows.([]history.ImprovementRow)
		movesTruncated = rep.Total > len(moves)
	}
	out := make([]commitProvider, 0, len(snap.Telemetry))
	for _, t := range snap.Telemetry {
		row := commitProvider{Telemetry: t, Points: []commitview.Point{}, Moves: commitview.Moves(moves, t.Provider, from, step)}
		u := plugin.Usage{Samples: t.Samples, CommitMbps: t.CommitMbps, Single: t.UsageMbps != nil, OutMbps95: t.OutMbps95}
		if t.UsageMbps != nil {
			u.UsageMbps = *t.UsageMbps
		}
		if v, ok := u.BillableMbps(); ok {
			row.BillableMbps = &v
		}
		if s.usage != nil && t.Host != "" && t.Interface != "" {
			samples, err := s.usageSamples(r.Context(), t, from, to)
			if err != nil {
				s.log.Warn("commit page: usage samples", "provider", t.Provider, "err", err)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot read the stored samples"})
				return
			}
			row.Points = commitview.Series(plugin.PercentileMode(t.Percentile), samples, from, step)
		}
		out = append(out, row)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	writeJSON(w, http.StatusOK, struct {
		meta
		Days        int              `json:"days"`
		From        time.Time        `json:"from"`
		To          time.Time        `json:"to"`
		StepSeconds int              `json:"step_seconds"`
		Samples     bool             `json:"samples_stored"`
		Moves       bool             `json:"moves_recorded"`
		Truncated   bool             `json:"moves_truncated,omitempty"`
		Providers   []commitProvider `json:"providers"`
	}{m, days, from, to, int(step / time.Second), s.usage != nil, s.reports != nil, movesTruncated, out})
}

// usageSamples returns the binding's samples in [from, to] and, when the
// range starts inside a billing period, the earlier samples of that period,
// because the running 95th counts the whole period.
func (s *Server) usageSamples(ctx context.Context, t Telemetry, from, to time.Time) ([]plugin.UsageSample, error) {
	q := plugin.UsageSampleQuery{Provider: t.Provider, Host: t.Host, Interface: t.Interface, From: from, To: to.Add(time.Millisecond)}
	in, err := s.usage.UsageSamples(ctx, q)
	if err != nil || len(in) == 0 || !in[0].PeriodStart.Before(from) {
		return in, err
	}
	q.From, q.To = in[0].PeriodStart, from
	before, err := s.usage.UsageSamples(ctx, q)
	return append(before, in...), err
}
