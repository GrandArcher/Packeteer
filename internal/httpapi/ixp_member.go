package httpapi

import (
	"cmp"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// IXPMemberPage is the body of GET /api/ixp/members/{asn} (#166): one member's
// connections from the IX-F list, its latest fabric samples by vantage, and
// its route-server sessions. The history of a session is
// GET /api/ixp/routeservers/history. Every part comes from the views the
// other ixp endpoints serve; nothing is fetched and nothing is announced.
type IXPMemberPage struct {
	meta
	ASN         uint32                      `json:"asn"`
	Name        string                      `json:"name,omitempty"`
	ManagerLink string                      `json:"ixp_manager_url,omitempty"`
	Connections []plugin.IXPConnection      `json:"connections"`
	Fabric      IXPMemberFabric             `json:"fabric"`
	Sessions    []plugin.RouteServerSession `json:"route_server_sessions"`
}

type IXPMemberFabric struct {
	Configured bool                  `json:"configured"`
	Stale      bool                  `json:"stale"`
	Round      *time.Time            `json:"round,omitempty"`
	Samples    []plugin.FabricSample `json:"samples"`
}

// ixpManagerLink is IXP Manager's admin search for the ASN. The IX-F
// export does not carry IXP Manager's customer id, and the search page
// lists the customer with its own link. The URL is for the operator's
// browser; Packeteer never requests it.
func ixpManagerLink(base string, asn uint32) string {
	if base == "" {
		return ""
	}
	return base + "/admin/search?search=AS" + strconv.FormatUint(uint64(asn), 10)
}

func parseASN(s string) (uint32, bool) {
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err == nil && n > 0
}

func (s *Server) handleIXPMember(w http.ResponseWriter, r *http.Request) {
	asn, ok := parseASN(r.PathValue("asn"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "asn must be a number from 1 to 4294967295"})
		return
	}
	body := IXPMemberPage{
		meta: s.snapshot().meta(), ASN: asn,
		Connections: []plugin.IXPConnection{},
		Fabric:      IXPMemberFabric{Samples: []plugin.FabricSample{}},
		Sessions:    []plugin.RouteServerSession{},
	}
	known := false
	if mv, ok := s.ixpMemberView(); ok {
		for _, m := range mv.Members {
			if m.ASN != asn {
				continue
			}
			known, body.Name = true, m.Name
			body.Connections = append(body.Connections, m.Connections...)
			body.ManagerLink = ixpManagerLink(mv.ManagerURL, asn)
		}
	}
	if fv, ok := s.ixpFabricView(); ok && fv.Configured {
		body.Fabric.Configured, body.Fabric.Stale = true, fv.Stale
		if !fv.Round.IsZero() {
			round := fv.Round
			body.Fabric.Round = &round
		}
		for _, sm := range fv.Samples {
			if sm.ASN == asn {
				body.Fabric.Samples = append(body.Fabric.Samples, sm)
			}
		}
		slices.SortFunc(body.Fabric.Samples, func(a, b plugin.FabricSample) int {
			return cmp.Or(cmp.Compare(a.Vantage, b.Vantage), cmp.Compare(a.Address, b.Address))
		})
	}
	if src, ok := s.ixpRouteServerSource(); ok {
		for _, ss := range src.view().Sessions {
			if ss.ASN != asn {
				continue
			}
			body.Sessions = append(body.Sessions, ss)
			if body.Name == "" {
				body.Name = ss.Name
			}
		}
		slices.SortFunc(body.Sessions, func(a, b plugin.RouteServerSession) int {
			return cmp.Or(cmp.Compare(a.Server, b.Server), cmp.Compare(a.Session, b.Session))
		})
	}
	if !known && len(body.Sessions) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no IXP member with that ASN"})
		return
	}
	writeJSON(w, http.StatusOK, body)
}

// IXPMemberFabricMetrics renders the latest fabric round per member (#166):
// loss, RTT, and jitter by ASN, VLAN id, vantage, and address family. A
// member with several addresses in one VLAN and family shows the worst of
// them, so a series never repeats. A probe error is not a measurement and
// a stale member list has no round, so neither makes a series. The series
// count is members x vantages x families.
func IXPMemberFabricMetrics(v plugin.FabricView) []byte {
	if !v.Configured || v.Stale {
		return nil
	}
	var rtt, loss, jitter []sample
	for _, w := range plugin.WorstFabricPaths(v.Samples) {
		l := []lbl{{"asn", strconv.FormatUint(uint64(w.ASN), 10)}, {"vlan", strconv.Itoa(w.VLANID)}, {"vantage", w.Vantage}, {"family", w.Family}}
		rtt = append(rtt, sample{labels: l, value: w.RTTMs})
		loss = append(loss, sample{labels: l, value: w.LossPct})
		jitter = append(jitter, sample{labels: l, value: w.JitterMs})
	}
	var b strings.Builder
	writeGauge(&b, "packeteer_ixp_member_rtt_ms", "Round-trip time to the member's LAN address in the latest fabric round, worst address per VLAN and family.", rtt...)
	writeGauge(&b, "packeteer_ixp_member_loss_pct", "Packet loss percent to the member's LAN address in the latest fabric round, worst address per VLAN and family.", loss...)
	writeGauge(&b, "packeteer_ixp_member_jitter_ms", "Jitter to the member's LAN address in the latest fabric round, worst address per VLAN and family.", jitter...)
	return []byte(b.String())
}
