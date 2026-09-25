package httpapi

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// MaintenanceControl lists maintenance windows and opens or closes
// on-demand ones. A window only excludes providers from improvements; it
// cannot add or announce a route.
type MaintenanceControl interface {
	Active(now time.Time) []plugin.MaintenanceWindow
	// CanOpen is false when no policy accepts on-demand windows.
	CanOpen() bool
	Open(providers []string, d time.Duration, reason string, now time.Time) (plugin.MaintenanceWindow, error)
	Close(id string) bool
}

type maintenanceRequest struct {
	Providers []string `json:"providers"`
	Duration  string   `json:"duration"`
	Reason    string   `json:"reason"`
}

func (s *Server) handleMaintenance(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	body := struct {
		meta
		Configured bool                       `json:"configured"`
		OnDemand   bool                       `json:"on_demand"`
		Windows    []plugin.MaintenanceWindow `json:"windows"`
	}{meta: snap.meta(), Windows: []plugin.MaintenanceWindow{}}
	if s.maint != nil {
		body.Configured = true
		body.OnDemand = s.maint.CanOpen() && s.user != ""
		body.Windows = nz(s.maint.Active(time.Now()))
	}
	writeJSON(w, http.StatusOK, body)
}

// writable rejects a change unless basic auth is on, a maintenance policy
// takes on-demand windows, and (for POST) the body is JSON. A cross-site
// form cannot send application/json without a CORS preflight, which this
// server never grants.
func (s *Server) writable(w http.ResponseWriter, r *http.Request, needJSON bool) bool {
	if s.user == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "on-demand maintenance requires PACKETEER_HTTP_USER and PACKETEER_HTTP_PASSWORD"})
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
	d, err := time.ParseDuration(req.Duration)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "duration: " + err.Error()})
		return
	}
	win, err := s.maint.Open(req.Providers, d, req.Reason, time.Now())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, win)
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
