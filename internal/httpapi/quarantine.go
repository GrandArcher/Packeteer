package httpapi

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"sort"
	"time"

	"github.com/GrandArcher/Packeteer/internal/policy"
)

// QuarantineControl is the flap quarantine's release handle (#228). The
// list itself comes from the snapshot.
type QuarantineControl interface {
	Release(netip.Prefix) bool
}

// Quarantine is a prefix parked on its native path after changing its
// chosen provider too often.
type Quarantine struct {
	Prefix  string    `json:"prefix"`
	Since   time.Time `json:"since"`
	Until   time.Time `json:"until"`
	Flips   int       `json:"flips"`
	Strikes int       `json:"strikes"`
}

func assembleQuarantine(in []policy.Quarantine) []Quarantine {
	out := make([]Quarantine, 0, len(in))
	for _, q := range in {
		if q.Prefix.IsValid() {
			out = append(out, Quarantine{Prefix: q.Prefix.String(), Since: q.Since, Until: q.Until, Flips: q.Flips, Strikes: q.Strikes})
		}
	}
	sort.Slice(out, func(i, j int) bool { return lessPrefix(out[i].Prefix, out[j].Prefix) < 0 })
	return out
}

// handleQuarantine lists the quarantined prefixes.
func (s *Server) handleQuarantine(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	writeJSON(w, http.StatusOK, struct {
		meta
		Writable    bool         `json:"writable"`
		Quarantined []Quarantine `json:"quarantined"`
	}{meta: snap.meta(), Writable: s.writesEnabled(), Quarantined: nz(snap.Quarantined)})
}

// handleQuarantineRelease ends one quarantine. It announces nothing: the
// next decision round treats the prefix as usual, and a prefix that flips
// again is parked again for longer.
func (s *Server) handleQuarantineRelease(w http.ResponseWriter, r *http.Request) {
	if !s.writesEnabled() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "releasing a quarantine requires auth (auth.enabled) or PACKETEER_HTTP_USER and PACKETEER_HTTP_PASSWORD"})
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
	ctl, _ := s.quarantine.Load().(QuarantineControl)
	if ctl == nil || !ctl.Release(p) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "that prefix is not quarantined"})
		return
	}
	noteAudit(r, p.Masked().String(), "flap quarantine released")
	s.log.Info("flap quarantine released through the API", "prefix", p.Masked(), "remote", r.RemoteAddr)
	w.WriteHeader(http.StatusNoContent)
}
