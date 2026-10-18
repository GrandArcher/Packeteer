package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// SetIXPMembers installs the read-only IX-F member list (#161). The
// function is called on each request. It must not fetch or announce.
func (s *Server) SetIXPMembers(fn func() plugin.MemberView) {
	if s == nil {
		return
	}
	s.ixpMembers.Store(fn)
}

func (s *Server) ixpMemberView() (plugin.MemberView, bool) {
	fn, _ := s.ixpMembers.Load().(func() plugin.MemberView)
	if fn == nil {
		return plugin.MemberView{}, false
	}
	return fn(), true
}

func (s *Server) handleIXPMembers(w http.ResponseWriter, _ *http.Request) {
	v, ok := s.ixpMemberView()
	if !ok {
		v = plugin.MemberView{}
	}
	if v.IXPs == nil {
		v.IXPs = []plugin.IXPSite{}
	}
	if v.Members == nil {
		v.Members = []plugin.IXPMember{}
	}
	writeJSON(w, http.StatusOK, struct {
		meta
		plugin.MemberView
	}{meta: s.snapshot().meta(), MemberView: v})
}

// SetIXPFabric installs the fabric probe view (#162). The function is
// called on each request. It must not fetch or announce.
func (s *Server) SetIXPFabric(fn func() plugin.FabricView) {
	if s == nil {
		return
	}
	s.ixpFabric.Store(fn)
}

func (s *Server) ixpFabricView() (plugin.FabricView, bool) {
	fn, _ := s.ixpFabric.Load().(func() plugin.FabricView)
	if fn == nil {
		return plugin.FabricView{}, false
	}
	return fn(), true
}

func (s *Server) handleIXPProbes(w http.ResponseWriter, _ *http.Request) {
	v, ok := s.ixpFabricView()
	if !ok {
		v = plugin.FabricView{}
	}
	if v.Vantages == nil {
		v.Vantages = []plugin.FabricVantageStatus{}
	}
	if v.Samples == nil {
		v.Samples = []plugin.FabricSample{}
	}
	writeJSON(w, http.StatusOK, struct {
		meta
		plugin.FabricView
	}{meta: s.snapshot().meta(), FabricView: v})
}

// IXPMemberMetrics renders the IX-F import. member and address gauges are
// zero while the list is stale; age and key expiry stay.
func IXPMemberMetrics(v plugin.MemberView, now time.Time) []byte {
	if !v.Configured {
		return nil
	}
	var b strings.Builder
	members, addrs := v.MemberCount, v.AddressCount
	if v.Stale {
		members, addrs = 0, 0
	}
	up := v.Error == "" && !v.Stale && !v.Fetched.IsZero()
	writeGauge(&b, "packeteer_ixp_members", "Members in the latest IX-F import. Zero when the list is stale.",
		sample{value: float64(members)})
	writeGauge(&b, "packeteer_ixp_member_addresses", "LAN addresses in the latest IX-F import. Zero when the list is stale.",
		sample{value: float64(addrs)})
	writeGauge(&b, "packeteer_ixp_member_import_up", "1 when the latest IX-F import succeeded and the list is not stale.",
		sample{value: boolFloat(up)})
	if !v.Fetched.IsZero() {
		age := now.Sub(v.Fetched).Seconds()
		if age < 0 {
			age = 0
		}
		writeGauge(&b, "packeteer_ixp_member_import_age_seconds", "Seconds since the last successful IX-F import.",
			sample{value: age})
	}
	if !v.KeyExpires.IsZero() {
		writeGauge(&b, "packeteer_ixp_api_key_expiry_seconds", "Unix time when the IXP Manager API key stops working.",
			sample{value: float64(v.KeyExpires.Unix())})
	}
	return []byte(b.String())
}

// IXPFabricMetrics renders the fabric prober. Targets and the
// past-tolerance count are zero while the member list is stale; age stays.
// There is no per-member series.
func IXPFabricMetrics(v plugin.FabricView, now time.Time) []byte {
	if !v.Configured {
		return nil
	}
	up := !v.Stale && !v.Round.IsZero()
	targets, opt, past := v.Targets, v.OptOut, 0
	if v.Stale {
		targets, opt, past = 0, 0, 0
		up = false
	} else {
		for _, s := range v.Samples {
			if s.PastTolerance {
				past++
			}
		}
		for _, st := range v.Vantages {
			if !st.Up {
				up = false
			}
		}
	}
	var b strings.Builder
	writeGauge(&b, "packeteer_ixp_fabric_up", "1 when the latest fabric round used a fresh member list and every vantage could probe.",
		sample{value: boolFloat(up)})
	writeGauge(&b, "packeteer_ixp_fabric_targets", "Member LAN addresses probed in the latest fabric round. Zero when the member list is stale.",
		sample{value: float64(targets)})
	writeGauge(&b, "packeteer_ixp_fabric_opt_out", "Member LAN addresses not probed because Can Ping did not allow them. Zero when the member list is stale.",
		sample{value: float64(opt)})
	writeGauge(&b, "packeteer_ixp_fabric_past_tolerance", "Probes at or past the ping warning (busy-host when that host is busy). Zero when the member list is stale.",
		sample{value: float64(past)})
	if !v.Round.IsZero() {
		age := now.Sub(v.Round).Seconds()
		if age < 0 {
			age = 0
		}
		writeGauge(&b, "packeteer_ixp_fabric_age_seconds", "Seconds since the latest fabric round.",
			sample{value: age})
	}
	return []byte(b.String())
}

// routeServerSource is the Birdseye watch (#164): the latest poll and one
// session's history. Neither fetches.
type routeServerSource struct {
	view    func() plugin.RouteServerView
	history func(server, session string) ([]plugin.RouteServerSample, bool)
}

// SetIXPRouteServers installs the route-server reads (#164). Both
// functions are called on each request. They must not fetch or announce.
func (s *Server) SetIXPRouteServers(view func() plugin.RouteServerView, history func(server, session string) ([]plugin.RouteServerSample, bool)) {
	if s == nil {
		return
	}
	s.ixpRouteServers.Store(&routeServerSource{view: view, history: history})
}

func (s *Server) ixpRouteServerSource() (*routeServerSource, bool) {
	src, _ := s.ixpRouteServers.Load().(*routeServerSource)
	return src, src != nil
}

func (s *Server) handleIXPRouteServers(w http.ResponseWriter, _ *http.Request) {
	var v plugin.RouteServerView
	if src, ok := s.ixpRouteServerSource(); ok {
		v = src.view()
	}
	if v.Servers == nil {
		v.Servers = []plugin.RouteServerStatus{}
	}
	if v.Sessions == nil {
		v.Sessions = []plugin.RouteServerSession{}
	}
	writeJSON(w, http.StatusOK, struct {
		meta
		plugin.RouteServerView
	}{meta: s.snapshot().meta(), RouteServerView: v})
}

func (s *Server) handleIXPRouteServerHistory(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	server, session := q.Get("server"), q.Get("session")
	if server == "" || session == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "server and session are required"})
		return
	}
	src, ok := s.ixpRouteServerSource()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "route servers are not configured"})
		return
	}
	samples, found := src.history(server, session)
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no history for that server and session"})
		return
	}
	writeJSON(w, http.StatusOK, struct {
		meta
		Server  string                     `json:"server"`
		Session string                     `json:"session"`
		Samples []plugin.RouteServerSample `json:"samples"`
	}{meta: s.snapshot().meta(), Server: server, Session: session, Samples: samples})
}

// IXPRouteServerMetrics renders the route-server watch. A stale server
// counts as down and shows no sessions. There is no per-member series.
func IXPRouteServerMetrics(v plugin.RouteServerView, now time.Time) []byte {
	if !v.Configured {
		return nil
	}
	up, newest := len(v.Servers) > 0, time.Time{}
	for _, s := range v.Servers {
		if !s.Up {
			up = false
		}
		if s.Polled.After(newest) {
			newest = s.Polled
		}
	}
	var established, down, filtered int
	for _, s := range v.Sessions {
		if s.Established {
			established++
		} else {
			down++
		}
		filtered += s.Filtered
	}
	var b strings.Builder
	writeGauge(&b, "packeteer_ixp_rs_up", "1 when the latest Birdseye poll succeeded on every route server.",
		sample{value: boolFloat(up)})
	writeGauge(&b, "packeteer_ixp_rs_sessions_established", "Member sessions in the Established state on fresh route servers.",
		sample{value: float64(established)})
	writeGauge(&b, "packeteer_ixp_rs_sessions_down", "Member sessions not Established on fresh route servers.",
		sample{value: float64(down)})
	writeGauge(&b, "packeteer_ixp_rs_filtered_routes", "Routes tagged rs-asn:1101:x across fresh route servers.",
		sample{value: float64(filtered)})
	if !newest.IsZero() {
		age := now.Sub(newest).Seconds()
		if age < 0 {
			age = 0
		}
		writeGauge(&b, "packeteer_ixp_rs_age_seconds", "Seconds since the latest Birdseye poll on any route server.",
			sample{value: age})
	}
	return []byte(b.String())
}
