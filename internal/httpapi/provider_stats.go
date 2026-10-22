package httpapi

import (
	"net/http"
	"sort"
	"time"

	"github.com/GrandArcher/Packeteer/internal/provseries"
)

// ProviderStats is where the Providers page and the Overview latency chart
// read per-provider measurements. Series is the last day of probe results.
// Traffic returns each provider's current Mbps and whether any flow source
// reports volume at all; it may be nil. Both only read.
type ProviderStats struct {
	Series  func() []provseries.Stat
	Traffic func() (mbps map[string]float64, flow bool)
}

// SetProviderStats installs the reads behind GET /api/providers/stats. It
// may be called after New, once the decision engine and the RIB view exist.
func (s *Server) SetProviderStats(p ProviderStats) {
	if s == nil {
		return
	}
	s.provStats.Store(&p)
}

// StatWindow is one window of a provider's figures: the median of its
// five-minute slots. With no probe in the window, slots is 0 and every
// figure is absent. rtt_ms and jitter_ms are absent too when nothing in the
// window answered; a path that never replies has no latency.
type StatWindow struct {
	Slots    int      `json:"slots"`
	LossPct  *float64 `json:"loss_pct,omitempty"`
	RTTMs    *float64 `json:"rtt_ms,omitempty"`
	JitterMs *float64 `json:"jitter_ms,omitempty"`
}

// StatPoint is one hour of a provider's probes, for the charts. rtt_ms is
// absent for an hour in which nothing answered.
type StatPoint struct {
	Time    time.Time `json:"t"`
	LossPct float64   `json:"loss_pct"`
	RTTMs   *float64  `json:"rtt_ms,omitempty"`
}

// ProviderStat is one provider's measured latency, loss, and jitter over
// the last 15 minutes and the last 24 hours, its hourly points, and, when
// a flow source reports volume, the Mbps leaving through it.
type ProviderStat struct {
	Provider string      `json:"provider"`
	Last15m  StatWindow  `json:"last_15m"`
	Last24h  StatWindow  `json:"last_24h"`
	Points   []StatPoint `json:"points"`
	Mbps     *float64    `json:"mbps,omitempty"`
}

func statWindow(w provseries.Window) StatWindow {
	out := StatWindow{Slots: w.Slots}
	if w.Slots == 0 {
		return out
	}
	loss := w.LossPct
	out.LossPct = &loss
	if w.HasRTT {
		rtt, jit := w.RTTMs, w.JitterMs
		out.RTTMs, out.JitterMs = &rtt, &jit
	}
	return out
}

func providerStats(stats []provseries.Stat, mbps map[string]float64, flow bool) []ProviderStat {
	out := make([]ProviderStat, 0, len(stats))
	for _, st := range stats {
		row := ProviderStat{Provider: st.Provider, Last15m: statWindow(st.Last15m), Last24h: statWindow(st.Last24h), Points: make([]StatPoint, 0, len(st.Points))}
		for _, p := range st.Points {
			pt := StatPoint{Time: p.At, LossPct: p.LossPct}
			if p.HasRTT {
				rtt := p.RTTMs
				pt.RTTMs = &rtt
			}
			row.Points = append(row.Points, pt)
		}
		out = append(out, row)
	}
	if !flow {
		return out
	}
	have := map[string]bool{}
	for i := range out {
		v := mbps[out[i].Provider]
		out[i].Mbps = &v
		have[out[i].Provider] = true
	}
	// A provider with no measurement yet can still carry traffic.
	var extra []string
	for name := range mbps {
		if !have[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		v := mbps[name]
		out = append(out, ProviderStat{Provider: name, Points: []StatPoint{}, Mbps: &v})
	}
	return out
}

// handleProviderStats serves GET /api/providers/stats.
func (s *Server) handleProviderStats(w http.ResponseWriter, _ *http.Request) {
	var stats []provseries.Stat
	var mbps map[string]float64
	var flow bool
	if p := s.provStats.Load(); p != nil {
		if p.Series != nil {
			stats = p.Series()
		}
		if p.Traffic != nil {
			mbps, flow = p.Traffic()
		}
	}
	writeJSON(w, http.StatusOK, struct {
		meta
		// Flow is true when a flow source reports volume. Without one the
		// page says there is no flow data.
		Flow      bool           `json:"flow"`
		Providers []ProviderStat `json:"providers"`
	}{meta: s.snapshot().meta(), Flow: flow, Providers: providerStats(stats, mbps, flow)})
}
