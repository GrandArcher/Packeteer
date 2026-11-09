package httpapi

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/probe"
)

// ReorderFlow is one train of a reordering measurement (#224): one
// 5-tuple, so one ECMP member.
type ReorderFlow struct {
	Flow        int     `json:"flow"`
	Sent        int     `json:"sent"`
	Received    int     `json:"received"`
	Reordered   int     `json:"reordered"`
	RatioPct    float64 `json:"ratio_pct"`
	Extent      int     `json:"extent"`
	NReordering int     `json:"n_reordering"`
	Error       string  `json:"error,omitempty"`
}

// Reorder is the latest reordering measurement of one provider path
// toward one responder: the RFC 4737 reordered ratio, extent, and
// n-reordering of the worst flow, and every flow. Estimate marks an icmp
// responder, whose replies the far end may reorder; estimates are never
// an input to a decision.
type Reorder struct {
	Provider  string        `json:"provider"`
	Responder string        `json:"responder"`
	Port      uint16        `json:"port,omitempty"`
	Type      string        `json:"type"`
	Estimate  bool          `json:"estimate"`
	OK        bool          `json:"ok"`
	Worst     ReorderFlow   `json:"worst"`
	WorstFlow int           `json:"worst_flow,omitempty"`
	Flows     []ReorderFlow `json:"flows"`
	Error     string        `json:"error,omitempty"`
	Time      time.Time     `json:"time"`
}

// ProviderReorder is the provider's headline reading on /api/providers:
// the worst flow of its controlled responders, or, with only estimates,
// the worst estimate.
type ProviderReorder struct {
	RatioPct    float64   `json:"ratio_pct"`
	Extent      int       `json:"extent"`
	NReordering int       `json:"n_reordering"`
	Estimate    bool      `json:"estimate"`
	Responder   string    `json:"responder"`
	Time        time.Time `json:"time"`
}

func reorderFlow(f probe.FlowReorder) ReorderFlow {
	return ReorderFlow{Flow: f.Flow, Sent: f.Sent, Received: f.Received, Reordered: f.Reordered,
		RatioPct: jsonFloat(f.RatioPct), Extent: f.Extent, NReordering: f.NReordering, Error: f.Err}
}

func assembleReorder(rs []probe.ReorderResult) []Reorder {
	out := make([]Reorder, 0, len(rs))
	for _, r := range rs {
		row := Reorder{
			Provider: r.Provider, Responder: r.Responder.String(), Port: r.Port, Type: r.Type, Estimate: r.Estimate,
			OK: r.OK(), WorstFlow: r.WorstFlow, Error: r.Err, Time: r.Time,
			Worst: reorderFlow(probe.FlowReorder{Flow: r.WorstFlow, ReorderStats: r.Worst}),
		}
		for _, f := range r.Flows {
			row.Flows = append(row.Flows, reorderFlow(f))
		}
		row.Flows = nz(row.Flows)
		out = append(out, row)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		return out[i].Responder < out[j].Responder
	})
	return out
}

// providerReorder picks each provider's headline reading. A controlled
// (twamp) reading beats an estimate; among readings of one kind the
// highest ratio wins.
func providerReorder(rows []Reorder) map[string]*ProviderReorder {
	out := map[string]*ProviderReorder{}
	for _, r := range rows {
		if !r.OK {
			continue
		}
		cur := out[r.Provider]
		switch {
		case cur == nil:
		case cur.Estimate && !r.Estimate:
		case cur.Estimate == r.Estimate && r.Worst.RatioPct > cur.RatioPct:
		default:
			continue
		}
		out[r.Provider] = &ProviderReorder{RatioPct: r.Worst.RatioPct, Extent: r.Worst.Extent, NReordering: r.Worst.NReordering,
			Estimate: r.Estimate, Responder: r.Responder, Time: r.Time}
	}
	return out
}

// handleReorder serves the reordering measurements (#224). Read-only.
func (s *Server) handleReorder(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	writeJSON(w, http.StatusOK, struct {
		meta
		Configured bool      `json:"configured"`
		Reorder    []Reorder `json:"reorder"`
	}{meta: snap.meta(), Configured: snap.ReorderConfigured, Reorder: nz(snap.Reorder)})
}

// reorderMetrics writes the per-flow RFC 4737 gauges and a success gauge
// per provider and responder.
func reorderMetrics(b *strings.Builder, rows []Reorder) {
	var ratio, extent, nre, ok []sample
	for _, r := range rows {
		base := []lbl{{"provider", r.Provider}, {"responder", r.Responder}, {"type", r.Type}, {"estimate", boolText(r.Estimate)}}
		ok = append(ok, sample{labels: base, value: boolFloat(r.OK)})
		for _, f := range r.Flows {
			if f.Error != "" || f.Received == 0 {
				continue
			}
			l := append(append([]lbl{}, base...), lbl{"flow", strconv.Itoa(f.Flow)})
			ratio = append(ratio, sample{labels: l, value: clamp01(f.RatioPct / 100)})
			extent = append(extent, sample{labels: l, value: float64(f.Extent)})
			nre = append(nre, sample{labels: l, value: float64(f.NReordering)})
		}
	}
	writeGauge(b, "packeteer_reorder_success", "1 if the latest reordering measurement toward the responder got a reply (#224). estimate is true for an icmp responder.", ok...)
	writeGauge(b, "packeteer_reorder_ratio", "RFC 4737 reordered ratio of the latest train, from 0 to 1, per flow (one 5-tuple).", ratio...)
	writeGauge(b, "packeteer_reorder_extent", "Largest RFC 4737 reordering extent in the latest train, in arrival positions, per flow.", extent...)
	writeGauge(b, "packeteer_reorder_n", "Largest RFC 4737 n-reordering degree in the latest train, per flow.", nre...)
}
