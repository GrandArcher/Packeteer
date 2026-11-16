package httpapi

import (
	"net/http"

	"github.com/GrandArcher/Packeteer/internal/exchange"
)

// handleExchangePotentialPeers serves the potential-peers report (#154):
// destination origin ASNs ranked by flow bytes, with whether an exchange
// shows the AS and whether its prefixes have a path through an exchange LAN
// today, as JSON or CSV. ?class= keeps one class. Read-only: no session is
// opened and nothing is announced. Each row carries the PeeringDB network
// name when the cached lookup has one (#629); that never triggers a fetch.
func (s *Server) handleExchangePotentialPeers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format, limit, ok := exchangeReportParams(w, q)
	if !ok {
		return
	}
	class := q.Get("class")
	if class != "" && !exchange.ValidPotentialClass(class) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "class must be route_server, bilateral, unknown, or absent"})
		return
	}
	m := s.exMembers.Load()
	if m == nil || m.PotentialPeers == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no exchanges are configured"})
		return
	}
	rep := m.PotentialPeers(class, limit)
	if names := s.networkNames(); len(names) > 0 {
		rows := make([]exchange.PotentialRow, len(rep.Rows))
		copy(rows, rep.Rows)
		for i := range rows {
			rows[i].Name = names[rows[i].ASN]
		}
		rep.Rows = rows
	}
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="packeteer-potential-peers.csv"`)
		w.WriteHeader(http.StatusOK)
		if err := rep.WriteCSV(w); err != nil {
			s.log.Warn("potential peers export", "err", err)
		}
		return
	}
	writeJSON(w, http.StatusOK, struct {
		meta
		exchange.PotentialPeers
	}{meta: s.snapshot().meta(), PotentialPeers: rep})
}
