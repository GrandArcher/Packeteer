package httpapi

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/fieldreport"
	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// shareValueDays is the range of the value totals in a field report.
const shareValueDays = 30

// handleShareReport serves the redacted field-report summary (#625) for the
// Settings page and `packeteer report --share`. It returns the text; the
// client shows it and the operator decides whether to keep it. It reads
// state only and sends nothing anywhere.
func (s *Server) handleShareReport(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, map[string]string{
		"filename": fieldreport.FileName,
		"report":   fieldreport.Render(s.shareInput(ctx)),
	})
}

func (s *Server) shareInput(ctx context.Context) fieldreport.Input {
	snap := s.snapshot()
	o := s.overview()
	in := fieldreport.Input{Version: snap.Version, Mode: snap.Mode, Facts: s.setup.Load().Report}
	for _, h := range o.Setup {
		// A provider hint id ends in the provider's name.
		id := h.ID
		if strings.HasPrefix(id, "provider-") {
			id = "provider"
		}
		in.Checklist = append(in.Checklist, fieldreport.Item{ID: id, Level: h.Level})
	}
	if s.events != nil {
		if evs, err := s.events.Query(ctx, plugin.EventQuery{Limit: fieldreport.EventWindow}); err == nil {
			in.Events = countEvents(evs)
		} else {
			s.log.Warn("field report events", "err", err)
		}
	}
	if s.reports != nil {
		in.ValueDays = shareValueDays
		if v, ok := s.shareValue(ctx); ok {
			in.Value = v
		}
	}
	return in
}

// shareValue reads the total rows of the value report. ok is false when the
// report failed, which the summary words as not available.
func (s *Server) shareValue(ctx context.Context) ([]fieldreport.Value, bool) {
	now := time.Now()
	rep, err := s.reports.Report(ctx, history.Query{Name: history.ReportValue, From: now.AddDate(0, 0, -shareValueDays), To: now})
	if err != nil {
		s.log.Warn("field report value", "err", err)
		return nil, false
	}
	rows, _ := rep.Rows.([]history.ValueRow)
	out := []fieldreport.Value{}
	for _, row := range rows {
		if row.Scope != history.ValueTotal {
			continue
		}
		out = append(out, fieldreport.Value{Basis: row.Basis, Improvements: row.Improvements, Measured: row.Measured,
			SteeredHours: row.SteeredHours, LossAvoidedPct: row.LossAvoided, RTTAvoidedMs: row.RTTAvoidedMs})
	}
	return out, true
}

func countEvents(evs []plugin.Event) *fieldreport.Events {
	out := &fieldreport.Events{Total: len(evs), Kinds: map[string]int{}}
	for _, e := range evs {
		switch e.Severity {
		case plugin.SeverityWarning:
			out.Warning++
		case plugin.SeverityCritical:
			out.Critical++
		default:
			continue
		}
		out.Kinds[e.Kind]++
	}
	return out
}
