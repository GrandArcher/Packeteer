package httpapi

import (
	"net/http"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/anomaly"
)

// handleAnomalies serves traffic anomaly detection (#33): open anomalies,
// the rules that turn them into mitigation rules, and the feed. It is
// read-only; mitigation rules the detector added are also on
// /api/mitigations.
func (s *Server) handleAnomalies(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	body := struct {
		meta
		Enabled bool `json:"enabled"`
		anomaly.Status
	}{meta: snap.meta(), Status: anomaly.Status{Rules: []anomaly.Rule{}, Anomalies: []anomaly.Anomaly{}, Feed: []anomaly.Change{}}}
	if s.anomaly != nil {
		body.Enabled = true
		body.Status = s.anomaly()
	}
	writeJSON(w, http.StatusOK, body)
}

// AnomalyMetrics renders traffic anomaly detection (#33) gauges.
func AnomalyMetrics(st anomaly.Status) []byte {
	var b strings.Builder
	writeGauge(&b, "packeteer_anomalies_active", "Open traffic anomalies.", sample{value: float64(len(st.Anomalies))})
	writeGauge(&b, "packeteer_anomaly_mitigating", "Open anomalies with a mitigation rule the detector added.", sample{value: float64(st.Mitigating)})
	writeGauge(&b, "packeteer_anomaly_baselines", "Destination prefix and protocol keys with a learned baseline.", sample{value: float64(st.Tracked)})
	writeGauge(&b, "packeteer_anomaly_actions_last_hour", "Mitigation rules the detector added in the last hour (capped by max_actions_per_hour).",
		sample{value: float64(st.ActionsLastHour)})
	return []byte(b.String())
}
