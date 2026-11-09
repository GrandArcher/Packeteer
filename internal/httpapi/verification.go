package httpapi

import (
	"net/http"

	"github.com/GrandArcher/Packeteer/internal/verify"
)

// handleVerification serves the steer checks of #305: each outbound
// improvement and inbound steer as pending, verified, partial, not moved,
// or unknown. It is read-only. With verify off, enabled is false and the
// list is empty.
func (s *Server) handleVerification(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	var results []verify.Result
	if s.verification != nil {
		results = s.verification()
	}
	writeJSON(w, http.StatusOK, struct {
		meta
		Enabled bool            `json:"enabled"`
		Results []verify.Result `json:"results"`
	}{meta: snap.meta(), Enabled: s.verification != nil, Results: nz(results)})
}
