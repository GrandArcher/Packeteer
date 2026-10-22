package httpapi

import (
	"net/http"
	"net/netip"
	"strconv"

	"github.com/GrandArcher/Packeteer/internal/ringlg"
)

// handleRingLG answers the "Seen from NLNOG RING" panel (#283) for one
// prefix. With ring_lg off it returns state "off" and makes no request.
// The answer is display only: nothing reads it back into a decision.
func (s *Server) handleRingLG(w http.ResponseWriter, r *http.Request) {
	if !s.ringLG.Enabled() {
		writeJSON(w, http.StatusOK, ringlg.Result{State: ringlg.StateOff})
		return
	}
	v := r.URL.Query().Get("prefix")
	p, err := netip.ParsePrefix(v)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "prefix " + strconv.Quote(v) + " is not a CIDR"})
		return
	}
	writeJSON(w, http.StatusOK, s.ringLG.Lookup(r.Context(), p))
}
