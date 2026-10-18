package httpapi

import (
	"net/http"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/federation"
)

// SetIXPSites installs the multi-site fabric health view (#167). The
// function is called on each request. It reads the federation peers'
// last snapshots; it must not fetch or announce.
func (s *Server) SetIXPSites(fn func() federation.IXPSitesView) {
	if s == nil {
		return
	}
	s.ixpSites.Store(fn)
}

func (s *Server) ixpSitesView() (federation.IXPSitesView, bool) {
	fn, _ := s.ixpSites.Load().(func() federation.IXPSitesView)
	if fn == nil {
		return federation.IXPSitesView{}, false
	}
	return fn(), true
}

func (s *Server) handleIXPSites(w http.ResponseWriter, _ *http.Request) {
	v, _ := s.ixpSitesView()
	if v.Sites == nil {
		v.Sites = []federation.SiteHealth{}
	}
	if v.Links == nil {
		v.Links = []federation.SiteLink{}
	}
	if v.Incidents == nil {
		v.Incidents = []federation.SiteIncident{}
	}
	writeJSON(w, http.StatusOK, struct {
		meta
		federation.IXPSitesView
	}{meta: s.snapshot().meta(), IXPSitesView: v})
}

// IXPSitesMetrics renders the sites view (#167): whether each site's
// snapshot is fresh, the incidents open at it, and the core links' loss
// and RTT. A link that could not be probed makes no loss or RTT series.
func IXPSitesMetrics(v federation.IXPSitesView) []byte {
	if !v.Enabled {
		return nil
	}
	incidents := map[string]int{}
	for _, in := range v.Incidents {
		incidents[in.Site]++
	}
	var up, inc, rtt, loss []sample
	for _, st := range v.Sites {
		l := []lbl{{"site", st.Name}}
		up = append(up, sample{labels: l, value: boolFloat(st.Fresh)})
		inc = append(inc, sample{labels: l, value: float64(incidents[st.Name])})
	}
	for _, l := range v.Links {
		if l.Error != "" {
			continue
		}
		lb := []lbl{{"site", l.Site}, {"peer", l.Peer}, {"link", l.Name}}
		rtt = append(rtt, sample{labels: lb, value: l.RTTMs})
		loss = append(loss, sample{labels: lb, value: l.LossPct})
	}
	var b strings.Builder
	writeGauge(&b, "packeteer_ixp_site_up", "1 when the site's federation snapshot is fresh.", up...)
	writeGauge(&b, "packeteer_ixp_site_incidents", "Fabric, vantage, route-server, core, and site incidents open at the site.", inc...)
	writeGauge(&b, "packeteer_ixp_core_rtt_ms", "Round-trip time over a core link from the site to its peer in the latest core round.", rtt...)
	writeGauge(&b, "packeteer_ixp_core_loss_pct", "Packet loss percent over a core link from the site to its peer in the latest core round.", loss...)
	return []byte(b.String())
}
