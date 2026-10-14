package httpapi

import (
	"net/http"
	"strconv"

	"github.com/GrandArcher/Packeteer/internal/exchange"
)

// handleExchangeOffload serves the transit-to-exchange offload report
// (#152): prefixes that leave through a transit while a configured
// exchange peer advertises the exact prefix, by bytes, as JSON or CSV.
// Read-only: nothing is steered by it.
func (s *Server) handleExchangeOffload(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := q.Get("format")
	if format != "" && format != "json" && format != "csv" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "format must be json or csv"})
		return
	}
	limit := defaultExchangeRows
	if format == "csv" {
		limit = maxExchangeRows
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxExchangeRows {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be 1 to " + strconv.Itoa(maxExchangeRows)})
			return
		}
		limit = n
	}
	m := s.exMembers.Load()
	if m == nil || m.Offload == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no exchanges are configured"})
		return
	}
	rep := m.Offload(limit)
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="packeteer-exchange-offload.csv"`)
		w.WriteHeader(http.StatusOK)
		if err := rep.WriteCSV(w); err != nil {
			s.log.Warn("offload export", "err", err)
		}
		return
	}
	writeJSON(w, http.StatusOK, struct {
		meta
		exchange.Offload
	}{meta: s.snapshot().meta(), Offload: rep})
}
