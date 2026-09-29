package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"time"

	"github.com/GrandArcher/Packeteer/internal/mitigation"
)

// MitigationControl lists, adds, and removes threat mitigation rules
// (#28). The controller checks the mitigation allowlist, max_rules, the
// TTL bounds, and the catalog; only inject announces, and only a prefix in
// the learned RIB.
type MitigationControl interface {
	Status() mitigation.Status
	Add(mitigation.Request) (mitigation.Rule, error)
	Remove(id string) bool
}

type mitigationRequest struct {
	Prefix string `json:"prefix"`
	Action string `json:"action"`
	Target string `json:"target"`
	TTL    string `json:"ttl"`
	Reason string `json:"reason"`
}

func (s *Server) handleMitigations(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	body := struct {
		meta
		Enabled bool `json:"enabled"`
		// Writable is true when rules can be added (basic auth is on).
		Writable bool `json:"writable"`
		mitigation.Status
	}{meta: snap.meta(), Status: (*mitigation.Controller)(nil).Status()}
	if s.mitigation != nil {
		body.Enabled = true
		body.Writable = s.user != ""
		body.Status = s.mitigation.Status()
	}
	writeJSON(w, http.StatusOK, body)
}

// mitigationWritable rejects a change unless basic auth is on, mitigation
// is configured, and (for POST) the body is JSON. A cross-site form cannot
// send application/json without a CORS preflight, which this server never
// grants.
func (s *Server) mitigationWritable(w http.ResponseWriter, r *http.Request, needJSON bool) bool {
	if s.user == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "mitigation rules require PACKETEER_HTTP_USER and PACKETEER_HTTP_PASSWORD"})
		return false
	}
	if s.mitigation == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "mitigation is not configured"})
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

func (s *Server) handleMitigationAdd(w http.ResponseWriter, r *http.Request) {
	if !s.mitigationWritable(w, r, true) {
		return
	}
	var req mitigationRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
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
	var ttl time.Duration
	if req.TTL != "" {
		if ttl, err = time.ParseDuration(req.TTL); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ttl: " + err.Error()})
			return
		}
	}
	rule, err := s.mitigation.Add(mitigation.Request{Prefix: p, Action: req.Action, Target: req.Target, TTL: ttl, Reason: req.Reason})
	switch {
	case errors.Is(err, mitigation.ErrFull):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	case err != nil:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.log.Info("mitigation rule added through the API", "id", rule.ID, "prefix", rule.Prefix, "action", rule.Action, "target", rule.Target, "remote", r.RemoteAddr)
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) handleMitigationRemove(w http.ResponseWriter, r *http.Request) {
	if !s.mitigationWritable(w, r, false) {
		return
	}
	if !s.mitigation.Remove(r.PathValue("id")) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no mitigation rule with that id"})
		return
	}
	s.log.Info("mitigation rule removed through the API", "id", r.PathValue("id"), "remote", r.RemoteAddr)
	w.WriteHeader(http.StatusNoContent)
}
