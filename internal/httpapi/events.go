package httpapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Bounds for GET /api/events.
const (
	defaultEventRows = 200
	maxEventRows     = 1000
	maxEventText     = 200
)

// eventRow is one event as the Events page shows it.
type eventRow struct {
	plugin.Event
	Source string `json:"source"`
}

// handleEvents lists recent controller events (#173), newest first. It
// reads the event log and nothing else.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if s.events == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "the event log is off"})
		return
	}
	var q plugin.EventQuery
	var ok bool
	if q.Limit, q.From, q.To, ok = parseRowsAndRange(w, r, defaultEventRows, maxEventRows); !ok {
		return
	}
	v := r.URL.Query()
	if sev := v.Get("severity"); sev != "" {
		if _, ok := plugin.SeverityRank(plugin.Severity(sev)); !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "severity must be info, warning, or critical"})
			return
		}
		q.MinSeverity = plugin.Severity(sev)
	}
	if q.Text = v.Get("q"); len(q.Text) > maxEventText {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "q must be at most " + strconv.Itoa(maxEventText) + " bytes"})
		return
	}
	evs, err := s.events.Query(r.Context(), q)
	if err != nil {
		s.log.Error("event read", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "event store unavailable"})
		return
	}
	rows := make([]eventRow, len(evs))
	for i, e := range evs {
		rows[i] = eventRow{Event: e, Source: e.Source()}
	}
	body := map[string]any{"events": rows, "stored": s.events.Stored(), "now": time.Now().UTC()}
	if !s.events.Stored() {
		body["since"] = s.events.Started().UTC()
	}
	writeJSON(w, http.StatusOK, body)
}
