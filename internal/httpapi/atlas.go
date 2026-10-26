package httpapi

import (
	"errors"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/GrandArcher/Packeteer/internal/atlas"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// AtlasLocal is one provider's local measurement of the prefix, shown
// beside the Atlas results as the evidence of #202.
type AtlasLocal struct {
	Provider   string  `json:"provider"`
	Target     string  `json:"target,omitempty"`
	OK         bool    `json:"ok"`
	LossPct    float64 `json:"loss_pct"`
	RTTAvgMs   float64 `json:"rtt_avg_ms"`
	Confidence string  `json:"confidence"`
}

// AtlasView is the answer to GET /api/atlas.
type AtlasView struct {
	State  string        `json:"state"`
	Status *atlas.Status `json:"status,omitempty"`
	// Target is the test address Atlas probes are pointed at: the address
	// Packeteer measures for the prefix. Empty when it measures none.
	Target       string         `json:"target,omitempty"`
	Local        []AtlasLocal   `json:"local,omitempty"`
	Measurements []atlas.Record `json:"measurements"`
	// CanMeasure is true when POST /api/atlas/measure is open: the
	// integration has a key, the prefix has a test address, and the server
	// has auth and the caller is an operator.
	CanMeasure bool `json:"can_measure"`
}

// atlasTarget returns the prefix's test address and its local rows from
// the snapshot.
func atlasTarget(snap Snapshot, p netip.Prefix) (netip.Addr, []AtlasLocal) {
	var rows []atlas.LocalRow
	var local []AtlasLocal
	for _, pr := range snap.Probes {
		if pr.Prefix != p.String() {
			continue
		}
		local = append(local, AtlasLocal{Provider: pr.Provider, Target: pr.Target, OK: pr.OK, LossPct: pr.LossPct, RTTAvgMs: pr.RTTAvgMs, Confidence: pr.Confidence.Level})
		a, _ := netip.ParseAddr(pr.Target)
		rows = append(rows, atlas.LocalRow{Provider: pr.Provider, Target: a, Answered: pr.Received > 0})
	}
	addr, _ := atlas.TestAddr(rows, "")
	return addr, local
}

// handleAtlas answers the RIPE Atlas panel on the prefix page (#213). It
// reads stored results and makes no request to Atlas. With the integration
// off it answers state "off" with no data.
func (s *Server) handleAtlas(w http.ResponseWriter, r *http.Request) {
	st := s.atlas.State()
	if st == atlas.StateOff {
		writeJSON(w, http.StatusOK, AtlasView{State: st, Measurements: []atlas.Record{}})
		return
	}
	v := r.URL.Query().Get("prefix")
	p, err := netip.ParsePrefix(v)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "prefix " + strconv.Quote(v) + " is not a CIDR"})
		return
	}
	p = p.Masked()
	status := s.atlas.Status()
	addr, local := atlasTarget(s.snapshot(), p)
	out := AtlasView{State: st, Status: &status, Local: local, Measurements: s.atlas.Records(p)}
	if out.Measurements == nil {
		out.Measurements = []atlas.Record{}
	}
	if addr.IsValid() {
		out.Target = addr.String()
	}
	out.CanMeasure = s.atlas.Active() && atlas.PublicTarget(addr) && s.writesEnabled() &&
		principalFrom(r.Context()).Role.Allows(plugin.RoleOperator)
	writeJSON(w, http.StatusOK, out)
}

type atlasMeasureRequest struct {
	Prefix string `json:"prefix"`
	Type   string `json:"type"`
}

// handleAtlasMeasure creates one on-demand measurement (#213). It spends
// the operator's credits, so it needs a signed-in operator and obeys the
// same caps as every other measurement. The target is always a test
// address Packeteer already measures for the prefix, never one the caller
// names.
func (s *Server) handleAtlasMeasure(w http.ResponseWriter, r *http.Request) {
	if !s.writesEnabled() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "Atlas measurements spend credits and require auth (auth.enabled) or PACKETEER_HTTP_USER and PACKETEER_HTTP_PASSWORD"})
		return
	}
	var req atlasMeasureRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	p, err := netip.ParsePrefix(req.Prefix)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "prefix " + strconv.Quote(req.Prefix) + " is not a CIDR"})
		return
	}
	p = p.Masked()
	switch s.atlas.State() {
	case atlas.StateOff:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": atlas.ErrOff.Error()})
		return
	case atlas.StateNoKey:
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": atlas.ErrNoKey.Error()})
		return
	}
	addr, _ := atlasTarget(s.snapshot(), p)
	if !addr.IsValid() {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Packeteer measures no test address for " + p.String()})
		return
	}
	rec, err := s.atlas.Measure(r.Context(), atlas.Request{Prefix: p, Target: addr, Type: req.Type, Trigger: atlas.TriggerManual})
	if err != nil {
		status := http.StatusBadGateway
		switch {
		case errors.Is(err, atlas.ErrBadType), errors.Is(err, atlas.ErrPublic):
			status = http.StatusBadRequest
		case errors.Is(err, atlas.ErrCapCredit), errors.Is(err, atlas.ErrCapHour), errors.Is(err, atlas.ErrBalance):
			status = http.StatusTooManyRequests
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	noteAudit(r, p.String(), "RIPE Atlas "+rec.Type+" measurement "+strconv.Itoa(rec.ID)+" from "+strconv.Itoa(rec.Requested)+" probes, about "+strconv.Itoa(rec.Credits)+" credits")
	writeJSON(w, http.StatusOK, rec)
}
