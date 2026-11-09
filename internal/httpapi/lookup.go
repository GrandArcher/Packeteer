package httpapi

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// SetLookup installs the read-only PeeringDB / IX-F directory (#153). The
// function is called on each request. It must not fetch or announce.
func (s *Server) SetLookup(fn func() plugin.LookupView) {
	if s == nil {
		return
	}
	s.lookup.Store(fn)
}

func (s *Server) lookupView() (plugin.LookupView, bool) {
	fn, _ := s.lookup.Load().(func() plugin.LookupView)
	if fn == nil {
		return plugin.LookupView{}, false
	}
	return fn(), true
}

// handleLookup serves the cached directory. ?asn= keeps one network and
// its memberships; an ASN the directory does not hold gives empty lists.
func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	v, _ := s.lookupView()
	if raw := r.URL.Query().Get("asn"); raw != "" {
		asn, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(raw), "AS"), 10, 32)
		if err != nil || asn == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "asn must be a number from 1 to 4294967295"})
			return
		}
		v = filterLookup(v, uint32(asn))
	}
	if v.Exchanges == nil {
		v.Exchanges = []plugin.LookupExchange{}
	}
	if v.Networks == nil {
		v.Networks = []plugin.LookupNetwork{}
	}
	if v.Memberships == nil {
		v.Memberships = []plugin.LookupMembership{}
	}
	writeJSON(w, http.StatusOK, struct {
		meta
		plugin.LookupView
	}{meta: s.snapshot().meta(), LookupView: v})
}

// filterLookup copies v keeping the rows of one ASN. The counts stay the
// size of the whole directory.
func filterLookup(v plugin.LookupView, asn uint32) plugin.LookupView {
	nets := []plugin.LookupNetwork{}
	for _, n := range v.Networks {
		if n.ASN == asn {
			nets = append(nets, n)
		}
	}
	mems := []plugin.LookupMembership{}
	for _, m := range v.Memberships {
		if m.ASN == asn {
			mems = append(mems, m)
		}
	}
	v.Networks, v.Memberships = nets, mems
	return v
}

// LookupMetrics renders the directory cache. Counts are zero while the
// cache is stale; age stays.
func LookupMetrics(v plugin.LookupView, now time.Time) []byte {
	if !v.Configured {
		return nil
	}
	var b strings.Builder
	nets, mems := v.NetworkCount, v.MembershipCount
	if v.Stale {
		nets, mems = 0, 0
	}
	up := v.Error == "" && !v.Stale && !v.Fetched.IsZero()
	writeGauge(&b, "packeteer_lookup_networks", "Networks in the PeeringDB cache. Zero when the cache is stale.",
		sample{value: float64(nets)})
	writeGauge(&b, "packeteer_lookup_memberships", "LAN attachments at the configured exchanges in the PeeringDB cache. Zero when the cache is stale.",
		sample{value: float64(mems)})
	writeGauge(&b, "packeteer_lookup_up", "1 when the latest PeeringDB refresh succeeded and the cache is not stale.",
		sample{value: boolFloat(up)})
	if !v.Fetched.IsZero() {
		age := now.Sub(v.Fetched).Seconds()
		if age < 0 {
			age = 0
		}
		writeGauge(&b, "packeteer_lookup_age_seconds", "Seconds since the last successful PeeringDB refresh.",
			sample{value: age})
	}
	return []byte(b.String())
}
