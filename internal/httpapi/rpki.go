package httpapi

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
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

// SetRPKIDisplay installs the lookup that may ask rpki.display_fallback
// (#200). Only /api/prefixes, which the prefix card reads, uses it, and only
// for the paths on the page it returns, so /metrics and the rest of the API
// never send a prefix to the fallback's outside service.
func (s *Server) SetRPKIDisplay(fn func(netip.Prefix, uint32) plugin.RPKIAnswer) {
	if s == nil || fn == nil {
		return
	}
	s.rpkiDisplay.Store(fn)
}

// labelDisplay asks the display lookup for each learned path in rows that
// the sources left unknown. The rows share their paths with the snapshot,
// so each row gets its own copy before a label changes.
func (s *Server) labelDisplay(rows []Prefix) {
	fn, _ := s.rpkiDisplay.Load().(func(netip.Prefix, uint32) plugin.RPKIAnswer)
	if fn == nil {
		return
	}
	for i := range rows {
		p, err := netip.ParsePrefix(rows[i].Prefix)
		if err != nil {
			continue
		}
		paths := slices.Clone(rows[i].Paths)
		for j := range paths {
			lp := &paths[j]
			origin := netpfx.LastAS(lp.ASPath)
			if lp.RPKI != string(plugin.RPKIUnknown) || origin == 0 {
				continue
			}
			if a := fn(p.Masked(), origin); a.State != plugin.RPKIUnknown {
				lp.RPKI, lp.RPKISource, lp.RPKIUpdated = string(a.State), a.Source, ptrTime(a.Updated)
			}
		}
		rows[i].Paths = paths
	}
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
	writeGauge(&b, "packeteer_rpki_cache_age_seconds", "Age of the RPKI source's data: since the last RTR sync or fetch, or a json document's generated time. Lookups are unknown past its staleness.", age...)
	return []byte(b.String())
}
