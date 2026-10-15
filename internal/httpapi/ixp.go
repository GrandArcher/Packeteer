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
