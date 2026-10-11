package httpapi

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/leakwatch"
)

// LeakControl is the leak watch (#199) as the API sees it: its state, and
// the operator's release of a held prefix.
type LeakControl interface {
	Status() leakwatch.Status
	Clear(netip.Prefix) bool
}

// handleLeaks serves the leak watch: its sources, and the prefixes held
// out because a route for them was seen outside the AS.
func (s *Server) handleLeaks(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	body := struct {
		meta
		Enabled  bool `json:"enabled"`
		Writable bool `json:"writable"`
		leakwatch.Status
	}{meta: snap.meta(), Status: leakwatch.Status{State: "unknown", Sources: []leakwatch.SourceStatus{}, Leaks: []leakwatch.Leak{}}}
	if s.leaks != nil {
		body.Enabled = true
		body.Writable = s.writesEnabled()
		body.Status = s.leaks.Status()
	}
	writeJSON(w, http.StatusOK, body)
}

// handleLeakClear releases a held prefix. It announces nothing itself: the
// next decision round may steer the prefix again, and a route still
// visible outside the AS is held again at its next sighting.
func (s *Server) handleLeakClear(w http.ResponseWriter, r *http.Request) {
	if !s.writesEnabled() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "clearing a leak requires auth (auth.enabled) or PACKETEER_HTTP_USER and PACKETEER_HTTP_PASSWORD"})
		return
	}
	if s.leaks == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "leak_watch is not enabled"})
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "content type must be application/json"})
		return
	}
	var req struct {
		Prefix string `json:"prefix"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body: " + err.Error()})
		return
	}
	p, err := netip.ParsePrefix(req.Prefix)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "prefix: " + err.Error()})
		return
	}
	if !s.leaks.Clear(p) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "that prefix is not held"})
		return
	}
	noteAudit(r, p.Masked().String(), "leak hold cleared")
	s.log.Info("leak hold cleared through the API", "prefix", p.Masked(), "remote", r.RemoteAddr)
	w.WriteHeader(http.StatusNoContent)
}

// LeakMetrics renders the leak watch gauges.
func LeakMetrics(st leakwatch.Status) []byte {
	var b strings.Builder
	writeGauge(&b, "packeteer_leaks_held", "Prefixes held out because a route for them was seen outside the AS.", sample{value: float64(len(st.Leaks))})
	var up []sample
	for _, src := range st.Sources {
		up = append(up, sample{labels: []lbl{{"source", src.Name}}, value: boolFloat(src.Healthy)})
	}
	writeGauge(&b, "packeteer_leak_source_up", "1 while a leak source is delivering. 0 means unknown, not clean.", up...)
	writeGauge(&b, "packeteer_leak_sightings_dropped", "Sightings dropped because the leak watch queue was full.", sample{value: float64(st.Dropped)})
	return []byte(b.String())
}
