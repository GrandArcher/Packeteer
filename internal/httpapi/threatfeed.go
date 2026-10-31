package httpapi

import (
	"net/http"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/threatfeed"
)

// handleThreatFeeds serves threat-intelligence feed ingest (#134): each
// feed's last fetch, the rules, and the listed networks they acted on. It
// is read-only; the mitigation rules the feeds added are also on
// /api/mitigations.
func (s *Server) handleThreatFeeds(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	body := struct {
		meta
		Enabled bool `json:"enabled"`
		threatfeed.Status
	}{meta: snap.meta(), Status: threatfeed.Status{Feeds: []threatfeed.FeedStatus{}, Rules: []threatfeed.Rule{}, Proposals: []threatfeed.Proposal{}}}
	if s.threatFeeds != nil {
		body.Enabled = true
		body.Status = s.threatFeeds()
	}
	writeJSON(w, http.StatusOK, body)
}

// ThreatFeedMetrics renders threat feed (#134) gauges.
func ThreatFeedMetrics(st threatfeed.Status) []byte {
	var b strings.Builder
	var up, entries []sample
	for _, f := range st.Feeds {
		l := []lbl{{"feed", f.Name}}
		up = append(up, sample{labels: l, value: boolFloat(!f.LastSuccess.IsZero() && f.Error == "")})
		entries = append(entries, sample{labels: l, value: float64(f.Entries)})
	}
	writeGauge(&b, "packeteer_threat_feed_up", "1 when the feed's last fetch succeeded.", up...)
	writeGauge(&b, "packeteer_threat_feed_entries", "Networks the feed listed at its last successful fetch.", entries...)
	writeGauge(&b, "packeteer_threat_feed_mitigations", "Mitigation rules the threat feeds hold (capped by max_active).", sample{value: float64(st.Held)})
	return []byte(b.String())
}
