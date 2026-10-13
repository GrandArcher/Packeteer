package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// MaintenanceControl lists maintenance windows and opens or closes
// on-demand ones. A window only excludes providers from improvements; it
// cannot add or announce a route.
type MaintenanceControl interface {
	Active(now time.Time) []plugin.MaintenanceWindow
	// Windows lists the one-off and on-demand windows not yet started and
	// those that have ended.
	Windows(now time.Time) (upcoming, finished []plugin.MaintenanceWindow)
	// CanOpen is false when no policy accepts on-demand windows.
	CanOpen() bool
	Open(providers []string, start, end time.Time, reason string, now time.Time) (plugin.MaintenanceWindow, error)
	Close(id string) bool
}

type maintenanceRequest struct {
	Providers []string `json:"providers"`
	// Duration opens a window now. Start and end (RFC 3339) open one at a
	// chosen time. Set one form or the other.
	Duration string `json:"duration"`
	Start    string `json:"start"`
	End      string `json:"end"`
	Reason   string `json:"reason"`
}

// MaintenanceList is the answer to GET /api/maintenance. Windows are the
// ones open now; Upcoming and Finished are the others (#177).
type MaintenanceList struct {
	meta
	Configured bool                       `json:"configured"`
	OnDemand   bool                       `json:"on_demand"`
	Windows    []plugin.MaintenanceWindow `json:"windows"`
	Upcoming   []plugin.MaintenanceWindow `json:"upcoming"`
	Finished   []plugin.MaintenanceWindow `json:"finished"`
}

func (s *Server) handleMaintenance(w http.ResponseWriter, _ *http.Request) {
	body := MaintenanceList{meta: s.snapshot().meta(), Windows: []plugin.MaintenanceWindow{}, Upcoming: []plugin.MaintenanceWindow{}, Finished: []plugin.MaintenanceWindow{}}
	if s.maint != nil {
		body.Configured = true
		body.OnDemand = s.maint.CanOpen() && s.writesEnabled()
		now := time.Now()
		body.Windows = nz(s.maint.Active(now))
		up, fin := s.maint.Windows(now)
		body.Upcoming, body.Finished = nz(up), nz(fin)
	}
	writeJSON(w, http.StatusOK, body)
}

// writable rejects a change unless basic auth is on, a maintenance policy
// takes on-demand windows, and (for POST) the body is JSON. A cross-site
// form cannot send application/json without a CORS preflight, which this
// server never grants.
func (s *Server) writable(w http.ResponseWriter, r *http.Request, needJSON bool) bool {
	if !s.writesEnabled() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "on-demand maintenance requires auth (auth.enabled) or PACKETEER_HTTP_USER and PACKETEER_HTTP_PASSWORD"})
		return false
	}
	if s.maint == nil || !s.maint.CanOpen() {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no maintenance policy configured"})
		return false
	}
	if needJSON {
		mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mt != "application/json" {
			writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "content type must be application/json"})
			return false
		}
	}
	return true
}

func (s *Server) handleMaintenanceOpen(w http.ResponseWriter, r *http.Request) {
	if !s.writable(w, r, true) {
		return
	}
	var req maintenanceRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body: " + err.Error()})
		return
	}
	now := time.Now()
	start, end, err := req.span(now)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	detail := "providers=" + strings.Join(req.Providers, ",") + " start=" + start.UTC().Format(time.RFC3339) + " end=" + end.UTC().Format(time.RFC3339)
	noteAudit(r, "", detail)
	win, err := s.maint.Open(req.Providers, start, end, req.Reason, now)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	noteAudit(r, win.ID, detail)
	writeJSON(w, http.StatusCreated, win)
}

// span turns the request into a window: a duration from now, or an
// explicit start and end.
func (m maintenanceRequest) span(now time.Time) (start, end time.Time, err error) {
	switch {
	case m.Duration != "" && (m.Start != "" || m.End != ""):
		return start, end, errors.New("set duration, or start and end, not both")
	case m.Duration != "":
		d, err := time.ParseDuration(m.Duration)
		if err != nil {
			return start, end, fmt.Errorf("duration: %w", err)
		}
		return now, now.Add(d), nil
	case m.Start == "" || m.End == "":
		return start, end, errors.New("set duration, or both start and end")
	}
	if start, err = time.Parse(time.RFC3339, m.Start); err != nil {
		return start, end, fmt.Errorf("start: %w", err)
	}
	if end, err = time.Parse(time.RFC3339, m.End); err != nil {
		return start, end, fmt.Errorf("end: %w", err)
	}
	return start, end, nil
}

func (s *Server) handleMaintenanceClose(w http.ResponseWriter, r *http.Request) {
	if !s.writable(w, r, false) {
		return
	}
	if !s.maint.Close(r.PathValue("id")) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no open on-demand window with that id"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
