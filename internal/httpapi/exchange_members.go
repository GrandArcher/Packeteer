package httpapi

import (
	"net/http"
	"net/netip"
	"strconv"

	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/rib"
)

const (
	defaultMemberPrefixes = 100
	maxMemberPrefixes     = 1000
)

// ExchangeMembers is what the member comparison reads beyond the snapshot
// (#156): the recorded counts and the prefixes of one class. Prefixes is
// nil without a RIB view.
type ExchangeMembers struct {
	History  *exchange.History
	Prefixes func(nh netip.Addr, class string, limit int) ([]netip.Prefix, int)
}

// SetExchangeMembers attaches the member comparison reads. It may be
// called after New, once the RIB view exists.
func (s *Server) SetExchangeMembers(m ExchangeMembers) {
	if s == nil {
		return
	}
	s.exMembers.Store(&m)
}

// memberDetail is the answer of GET /api/exchanges/member.
type memberDetail struct {
	meta
	Exchange     string                `json:"exchange"`
	NextHop      string                `json:"next_hop"`
	Availability exchange.Availability `json:"availability"`
	History      []exchange.Sample     `json:"history"`
	// Class, Prefixes, and PrefixesTotal are set when ?class= is given.
	// Prefixes is cut at ?limit=; PrefixesTotal is the full count, and is
	// present (also as 0) whenever a class was asked for.
	Class         string   `json:"class,omitempty"`
	Prefixes      []string `json:"prefixes,omitempty"`
	PrefixesTotal *int     `json:"prefixes_total,omitempty"`
}

// handleExchangeMember compares one member's route server and bilateral
// prefixes (#156). The member must be a configured peer of the named
// exchange: only a peer's paths are classified. Read-only.
func (s *Server) handleExchangeMember(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	nh, err := netip.ParseAddr(q.Get("next_hop"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "next_hop must be an IP address"})
		return
	}
	nh = nh.Unmap()
	class := q.Get("class")
	switch class {
	case "", rib.AvailRouteServerOnly, rib.AvailBilateralOnly, rib.AvailBoth:
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "class must be route_server_only, bilateral_only, or both"})
		return
	}
	limit := defaultMemberPrefixes
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxMemberPrefixes {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be 1 to " + strconv.Itoa(maxMemberPrefixes)})
			return
		}
		limit = n
	}
	snap := s.snapshot()
	out := memberDetail{meta: snap.meta(), Exchange: q.Get("exchange"), NextHop: nh.String(), History: []exchange.Sample{}}
	found := false
	for _, ex := range snap.Exchanges {
		if ex.Name != out.Exchange {
			continue
		}
		for _, p := range ex.Peers {
			if p.NextHop == out.NextHop {
				out.Availability, found = p.Availability, true
			}
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such member on that exchange"})
		return
	}
	if m := s.exMembers.Load(); m != nil {
		if m.History != nil {
			out.History = m.History.Series(out.Exchange, nh)
		}
		if class != "" && m.Prefixes != nil {
			ps, total := m.Prefixes(nh, class, limit)
			out.Class, out.PrefixesTotal = class, &total
			for _, p := range ps {
				out.Prefixes = append(out.Prefixes, p.String())
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}
