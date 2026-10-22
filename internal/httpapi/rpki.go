package httpapi

import (
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// SetRPKIStatus installs the health of the rpki.sources for /metrics
// (#200).
func (s *Server) SetRPKIStatus(fn func() []plugin.RPKIStatus) {
	if s == nil || fn == nil {
		return
	}
	s.rpkiStatus.Store(fn)
}

// RPKIMetrics renders the RPKI source gauges. A source that never
// completed a fetch has no cache age sample.
func RPKIMetrics(sources []plugin.RPKIStatus, now time.Time) []byte {
	var up, vrps, age []sample
	for _, st := range sources {
		l := []lbl{{"source", st.Source}}
		up = append(up, sample{labels: l, value: boolFloat(st.Up)})
		vrps = append(vrps, sample{labels: l, value: float64(st.VRPs)})
		if !st.Updated.IsZero() {
			age = append(age, sample{labels: l, value: now.Sub(st.Updated).Seconds()})
		}
	}
	var b strings.Builder
	writeGauge(&b, "packeteer_rpki_source_up", "1 while the RPKI source's session or last fetch is up.", up...)
	writeGauge(&b, "packeteer_rpki_vrps", "Validated ROA payloads in the RPKI source's cache.", vrps...)
	writeGauge(&b, "packeteer_rpki_cache_age_seconds", "Seconds since the RPKI source's data was fetched. Lookups are unknown past its staleness.", age...)
	return []byte(b.String())
}
