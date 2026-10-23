package httpapi

import (
	"net/http"
	"net/netip"
	"time"

	"github.com/GrandArcher/Packeteer/internal/policy"
)

// Explainer returns the latest decision for a prefix with its gate list and
// when it was made, from one evaluation (#201). *policy.Engine implements it.
type Explainer interface {
	Explain(netip.Prefix) (policy.Decision, policy.Explain, time.Time, bool)
}

// SetExplainer installs the decision explanations behind
// GET /api/decisions/{prefix}. It is stored after New, once the decision
// engine exists.
func (s *Server) SetExplainer(e Explainer) {
	if s == nil {
		return
	}
	s.explainer.Store(e)
}

// handleDecisionExplain serves the latest decision for one prefix with the
// checks it passed through and the measurements behind them. It reads only.
func (s *Server) handleDecisionExplain(w http.ResponseWriter, r *http.Request) {
	p, err := netip.ParsePrefix(r.PathValue("prefix"))
	if err != nil || p != p.Masked() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "prefix must be a network in CIDR form, such as 192.0.2.0/24"})
		return
	}
	snap := s.snapshot()
	ex, _ := s.explainer.Load().(Explainer)
	if ex == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no decision engine is running"})
		return
	}
	d, why, decidedAt, ok := ex.Explain(p)
	rows := assembleDecisions(snap.Mode, []policy.Decision{d})
	if !ok || len(rows) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no decision for " + p.String() + ": Packeteer is not measuring it now"})
		return
	}
	body := struct {
		meta
		DecidedAt *time.Time `json:"decided_at,omitempty"`
		Decision
		Explain policy.Explain `json:"explain"`
	}{meta: snap.meta(), Decision: rows[0], Explain: why}
	if !decidedAt.IsZero() {
		t := decidedAt.UTC()
		body.DecidedAt = &t
	}
	writeJSON(w, http.StatusOK, body)
}
