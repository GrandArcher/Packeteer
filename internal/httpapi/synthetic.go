package httpapi

import (
	"net/http"

	"github.com/GrandArcher/Packeteer/internal/nonbgp"
)

// handleSynthetic serves the non-BGP mode (#300): the prefixes learned from
// flow data, each labeled synthetic, the announced prefix that bounds it,
// and the static route that carries it when it is steered. It is read-only.
// With the mode off, enabled is false and the list is empty.
func (s *Server) handleSynthetic(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	body := struct {
		meta
		Enabled bool `json:"enabled"`
		nonbgp.Status
	}{meta: snap.meta(), Status: nonbgp.Status{Routes: []nonbgp.RouteStatus{}}}
	if s.synthetic != nil {
		body.Enabled = true
		body.Status = s.synthetic()
	}
	writeJSON(w, http.StatusOK, body)
}
