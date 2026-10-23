package httpapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/herd"
)

// HerdSource is what the ops API reads from herd (#260). It reads the herd
// store and the signing code; it never announces and never feeds Decide.
type HerdSource interface {
	Status(ctx context.Context) herd.NodeStatus
	Vantages(ctx context.Context, rawQuery string) (herd.VantageView, error)
	// Preview is the status code and signed body a puller would get for a
	// records request with this raw query.
	Preview(rawQuery string) (int, []byte)
	// PreviewStatus is the signed status document a puller would get.
	PreviewStatus() []byte
	// The dashboard views (#296). A herd.QueryError is a request the caller
	// can fix.
	Overview(ctx context.Context) (herd.Overview, error)
	Events(ctx context.Context, rawQuery string) (herd.Events, error)
	Mesh(ctx context.Context, rawQuery string) (herd.Mesh, error)
	Monitor(ctx context.Context, rawQuery string) (herd.Monitor, error)
	Map(ctx context.Context, rawQuery string) (herd.Map, error)
	Search(ctx context.Context, rawQuery string) (herd.Search, error)
}

type herdHolder struct{ src HerdSource }

// SetHerd installs herd (#260). Nil leaves the herd endpoints reporting
// that herd is off.
func (s *Server) SetHerd(src HerdSource) {
	if s == nil || src == nil {
		return
	}
	s.herd.Store(&herdHolder{src})
}

func (s *Server) herdSource() HerdSource {
	if h, _ := s.herd.Load().(*herdHolder); h != nil {
		return h.src
	}
	return nil
}

func (s *Server) handleHerd(w http.ResponseWriter, r *http.Request) {
	src := s.herdSource()
	if src == nil {
		writeJSON(w, http.StatusOK, struct {
			meta
			Enabled bool `json:"enabled"`
		}{meta: s.snapshot().meta()})
		return
	}
	writeJSON(w, http.StatusOK, struct {
		meta
		herd.NodeStatus
	}{meta: s.snapshot().meta(), NodeStatus: src.Status(r.Context())})
}

// handleHerdVantages serves records per vantage, never merged. A query must
// name an origin_asn or a prefix.
func (s *Server) handleHerdVantages(w http.ResponseWriter, r *http.Request) {
	src := s.herdSource()
	if src == nil {
		writeJSON(w, http.StatusOK, struct {
			meta
			herd.VantageView
		}{meta: s.snapshot().meta(), VantageView: herd.VantageView{Vantages: []herd.Vantage{}}})
		return
	}
	v, err := src.Vantages(r.Context(), r.URL.RawQuery)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, struct {
		meta
		herd.VantageView
	}{meta: s.snapshot().meta(), VantageView: v})
}

// handleHerdPreview writes the exact bytes a puller would receive: the
// status document for ?doc=status, otherwise the records response for the
// query. Same code as the pull API.
func (s *Server) handleHerdPreview(w http.ResponseWriter, r *http.Request) {
	src := s.herdSource()
	if src == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "herd is off"})
		return
	}
	code, body := http.StatusOK, []byte(nil)
	if r.URL.Query().Get("doc") == "status" {
		body = src.PreviewStatus()
	} else {
		code, body = src.Preview(r.URL.RawQuery)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// HerdMetrics renders the herd counters: tripped limits by limit and peer,
// the hand-off queue, and the store against its budgets.
func HerdMetrics(st herd.NodeStatus) []byte {
	var b strings.Builder
	var trips []sample
	for _, t := range st.Limits {
		l := []lbl{{"limit", t.Limit}}
		if t.Peer != "" {
			l = append(l, lbl{"peer", t.Peer})
		}
		trips = append(trips, sample{labels: l, value: float64(t.Count)})
	}
	writeCounter(&b, "packeteer_herd_limit_trips_total", "Times a herd limit refused or cut something, by limit and peer.", trips...)
	writeCounter(&b, "packeteer_herd_records_dropped_total", "Probe results herd dropped because its queue was full.", sample{value: float64(st.Queue.Dropped)})
	writeCounter(&b, "packeteer_herd_records_stored_total", "Herd records written from probe rounds.", sample{value: float64(st.Queue.Stored)})
	writeCounter(&b, "packeteer_herd_restarts_total", "Times a herd goroutine panicked and was restarted.", sample{value: float64(st.Queue.Restarts)})
	writeGauge(&b, "packeteer_herd_store_bytes", "Herd record bytes stored, by class.",
		sample{labels: []lbl{{"class", "local"}}, value: float64(st.Store.LocalBytes)},
		sample{labels: []lbl{{"class", "pulled"}}, value: float64(st.Store.PulledBytes)})
	writeGauge(&b, "packeteer_herd_store_budget_bytes", "Herd record byte budget, by class.",
		sample{labels: []lbl{{"class", "local"}}, value: float64(st.Store.LocalBudget)},
		sample{labels: []lbl{{"class", "pulled"}}, value: float64(st.Store.PulledBudget)})
	writeGauge(&b, "packeteer_herd_store_records", "Herd records stored, by class.",
		sample{labels: []lbl{{"class", "local"}}, value: float64(st.Store.LocalRecords)},
		sample{labels: []lbl{{"class", "pulled"}}, value: float64(st.Store.PulledRecords)})
	var peers []sample
	for _, p := range st.Peers {
		peers = append(peers, sample{labels: []lbl{{"peer", p.KeyID}}, value: boolFloat(p.Failures == 0 && !p.LastOK.IsZero())})
	}
	writeGauge(&b, "packeteer_herd_peer_up", "1 when the peer has been pulled and has no failures since.", peers...)
	return []byte(b.String())
}
