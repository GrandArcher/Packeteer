package httpapi

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/GrandArcher/Packeteer/internal/exchange"
)

// handleExchangeOffload serves the transit-to-exchange offload report
// (#152): prefixes that leave through a transit while a configured
// exchange peer advertises the exact prefix, by bytes, as JSON or CSV.
// Read-only: nothing is steered by it.
func (s *Server) handleExchangeOffload(w http.ResponseWriter, r *http.Request) {
	format, limit, ok := exchangeReportParams(w, r.URL.Query())
	if !ok {
		return
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

// exchangeReportParams reads format (json or csv) and limit of an exchange
// report. The CSV defaults to the maximum rows. It writes the 400 itself.
func exchangeReportParams(w http.ResponseWriter, q url.Values) (format string, limit int, ok bool) {
	format = q.Get("format")
	if format != "" && format != "json" && format != "csv" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "format must be json or csv"})
		return "", 0, false
	}
	limit = defaultExchangeRows
	if format == "csv" {
		limit = maxExchangeRows
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxExchangeRows {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be 1 to " + strconv.Itoa(maxExchangeRows)})
			return "", 0, false
		}
		limit = n
	}
	return format, limit, true
}
