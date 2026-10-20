package httpapi

import (
	"cmp"
	"context"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/time/rate"

	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/internal/rib"
)

// Global search (#172). One read-only endpoint over the measured
// prefixes, the learned RIB, the current improvements, and (when a
// storage plugin is set) stored improvements and probe rollups. It
// changes nothing and announces nothing.
const (
	// searchLimit caps every list in the answer. A total beside each list
	// counts every match.
	searchLimit = 25
	// searchDays is how far back stored history is searched.
	searchDays = 90
	// searchASNs caps the AS numbers an AS-name search follows into rows.
	searchASNs    = 10
	maxSearchLen  = 64
	searchTimeout = 10 * time.Second
	// A caller gets searchBurst searches at once, then one per
	// searchEvery. searchCallers bounds the callers tracked.
	searchBurst   = 10
	searchEvery   = 500 * time.Millisecond
	searchCallers = 1024
)

// SearchRIB finds learned routes without copying the table. *rib.View
// implements it.
type SearchRIB interface {
	Find(keep func(rib.Route) bool, before func(a, b rib.Route) bool, limit int) ([]rib.Route, int)
}

// SetSearchRIB attaches the learned RIB view the search reads. It may be
// called after New, once the view exists. Without it the RIB list is empty.
func (s *Server) SetSearchRIB(r SearchRIB) {
	if s == nil {
		return
	}
	s.searchRIB.Store(&r)
}

// Search kinds.
const (
	kindPrefix = "prefix"
	kindASN    = "asn"
	kindName   = "name"
)

type searchTerm struct {
	kind   string
	prefix netip.Prefix
	asn    uint32
	name   string
}

var (
	asnPattern  = regexp.MustCompile(`^(?i:as)?[0-9]{1,10}$`)
	namePattern = regexp.MustCompile(`^[\p{L}\p{N} ._,&()'-]+$`)
)

const searchInputHint = "q must be a prefix such as 192.0.2.0/24, an address, an AS number such as AS64510, or an AS name of 2-64 bytes of letters, digits, spaces, or . _ , & ( ) ' -"

// parseSearch classifies the query. Anything else is refused, so a
// search term never carries control characters or markup into a log or
// a link.
func parseSearch(raw string) (searchTerm, bool) {
	q := strings.TrimSpace(raw)
	if q == "" || len(q) > maxSearchLen {
		return searchTerm{}, false
	}
	if p, err := netip.ParsePrefix(q); err == nil && !p.Addr().Is4In6() && p.Addr().Zone() == "" {
		return searchTerm{kind: kindPrefix, prefix: p.Masked()}, true
	}
	if a, err := netip.ParseAddr(q); err == nil && a.Zone() == "" {
		a = a.Unmap()
		return searchTerm{kind: kindPrefix, prefix: netip.PrefixFrom(a, a.BitLen())}, true
	}
	if asnPattern.MatchString(q) {
		n, ok := netpfx.ParseASN(q)
		if !ok {
			return searchTerm{}, false
		}
		return searchTerm{kind: kindASN, asn: n}, true
	}
	if len(q) >= 2 && namePattern.MatchString(q) && strings.IndexFunc(q, unicode.IsLetter) >= 0 {
		return searchTerm{kind: kindName, name: q}, true
	}
	return searchTerm{}, false
}

// matcher decides whether a row belongs to the answer: its prefix is
// related to the searched prefix, or one of its origin ASes is followed.
type matcher struct {
	prefix netip.Prefix // zero unless the query is a prefix
	asns   []uint32
}

// match returns the row's relation to the searched prefix, which is empty
// for a row that matched by origin only, and whether it matched.
func (m matcher) match(p netip.Prefix, origins ...uint32) (string, bool) {
	return netpfx.Match(m.prefix, m.asns, p, origins...)
}

// searchGroup is one list of the answer: at most searchLimit rows and
// the number that matched.
type searchGroup[T any] struct {
	Total int `json:"total"`
	Rows  []T `json:"rows"`
}

func group[T any](rows []T, total int) searchGroup[T] {
	return searchGroup[T]{Total: total, Rows: nz(rows)}
}

// SearchASN is an AS the query named or an AS whose name matched. Name and
// Source are set when Packeteer knows the name: Source is "provider" for
// an exchange peer in the config, or "whois" for a lookup made with the
// whois tool.
type SearchASN struct {
	ASN    uint32 `json:"asn"`
	Name   string `json:"name,omitempty"`
	Source string `json:"source,omitempty"`
}

// SearchMeasured is a prefix Packeteer probes now.
type SearchMeasured struct {
	Prefix      string    `json:"prefix"`
	Relation    string    `json:"relation,omitempty"`
	OriginASN   uint32    `json:"origin_asn,omitempty"`
	Current     string    `json:"current,omitempty"`
	Recommended string    `json:"recommended,omitempty"`
	InRIB       bool      `json:"in_rib"`
	Probed      time.Time `json:"probed,omitzero"`
}

// SearchRoute is a route in the learned RIB view.
type SearchRoute struct {
	Prefix    string    `json:"prefix"`
	Relation  string    `json:"relation,omitempty"`
	OriginASN uint32    `json:"origin_asn,omitempty"`
	NextHop   string    `json:"next_hop,omitempty"`
	Provider  string    `json:"provider,omitempty"`
	Since     time.Time `json:"since,omitzero"`
}

// SearchImprovement is a current improvement: a recommendation in observe
// and suggest, and a steer that is announced only in inject.
type SearchImprovement struct {
	Prefix    string    `json:"prefix"`
	Relation  string    `json:"relation,omitempty"`
	OriginASN uint32    `json:"origin_asn,omitempty"`
	Provider  string    `json:"provider"`
	Native    string    `json:"native,omitempty"`
	Cause     string    `json:"cause,omitempty"`
	Since     time.Time `json:"since,omitzero"`
}

// SearchHistory says whether stored history was searched. Note explains
// why it was not.
type SearchHistory struct {
	Enabled bool   `json:"enabled"`
	Days    int    `json:"days,omitempty"`
	Note    string `json:"note,omitempty"`
}

// SearchResponse is the body of GET /api/search. Improvements and Rollups
// are stored history; the other lists are live.
type SearchResponse struct {
	meta
	Query           string                                 `json:"query"`
	Kind            string                                 `json:"kind"`
	Limit           int                                    `json:"limit"`
	History         SearchHistory                          `json:"history"`
	ASNs            searchGroup[SearchASN]                 `json:"asns"`
	Measured        searchGroup[SearchMeasured]            `json:"measured"`
	RIB             searchGroup[SearchRoute]               `json:"rib"`
	Recommendations searchGroup[SearchImprovement]         `json:"recommendations"`
	Improvements    searchGroup[history.SearchImprovement] `json:"improvements"`
	Rollups         searchGroup[history.SearchRollup]      `json:"rollups"`
}

// searchLimiters is a token bucket per caller, so one client cannot use
// the history store up for the rest.
type searchLimiters struct {
	mu sync.Mutex
	by map[string]*rate.Limiter
}

func (l *searchLimiters) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	lim := l.by[key]
	if lim == nil {
		if len(l.by) >= searchCallers {
			// Forget callers that have their whole burst back: they are idle.
			for k, v := range l.by {
				if v.Tokens() >= searchBurst {
					delete(l.by, k)
				}
			}
			if len(l.by) >= searchCallers {
				return false
			}
		}
		if l.by == nil {
			l.by = map[string]*rate.Limiter{}
		}
		lim = rate.NewLimiter(rate.Every(searchEvery), searchBurst)
		l.by[key] = lim
	}
	return lim.Allow()
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	key := p.User
	if key == "" {
		key = remoteString(r)
	}
	if !s.searches.allow(key) {
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many searches; try again shortly"})
		return
	}
	raw := r.URL.Query().Get("q")
	term, ok := parseSearch(raw)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": searchInputHint})
		return
	}
	snap := s.snapshot()
	asns := s.searchASNs(term, snap.Providers)
	m := matcher{}
	if term.kind == kindPrefix {
		m.prefix = term.prefix
	}
	for _, a := range asns[:min(len(asns), searchASNs)] {
		m.asns = append(m.asns, a.ASN)
	}

	res := SearchResponse{
		meta: snap.meta(), Query: strings.TrimSpace(raw), Kind: term.kind, Limit: searchLimit,
		ASNs: group(asns[:min(len(asns), searchLimit)], len(asns)),
	}
	res.Measured = searchMeasured(snap.Prefixes, m)
	res.Recommendations = searchImprovements(snap, m)
	res.RIB = s.searchRoutes(m)
	res.History = s.searchHistory(r.Context(), m, &res)
	writeJSON(w, http.StatusOK, res)
}

// searchASNs lists the ASes a query is about. An AS number is itself, with
// its name when one is known; a name is every known name that contains it.
func (s *Server) searchASNs(term searchTerm, providers []Provider) []SearchASN {
	known := map[uint32]SearchASN{}
	for _, pr := range providers {
		if pr.PeerASN != 0 {
			known[pr.PeerASN] = SearchASN{ASN: pr.PeerASN, Name: pr.Name, Source: "provider"}
		}
		if pr.ASN != 0 {
			known[pr.ASN] = SearchASN{ASN: pr.ASN, Name: pr.Name, Source: "provider"}
		}
	}
	for asn, name := range s.tools.ASNames() {
		known[asn] = SearchASN{ASN: asn, Name: name, Source: "whois"}
	}
	switch term.kind {
	case kindASN:
		if a, ok := known[term.asn]; ok {
			return []SearchASN{a}
		}
		return []SearchASN{{ASN: term.asn}}
	case kindName:
		want := strings.ToLower(term.name)
		var out []SearchASN
		for _, a := range known {
			if strings.Contains(strings.ToLower(a.Name), want) {
				out = append(out, a)
			}
		}
		slices.SortFunc(out, func(x, y SearchASN) int { return cmp.Compare(x.ASN, y.ASN) })
		return out
	}
	return nil
}

func searchMeasured(rows []Prefix, m matcher) searchGroup[SearchMeasured] {
	var out []SearchMeasured
	for i := range rows {
		row := &rows[i]
		p, err := netip.ParsePrefix(row.Prefix)
		if err != nil {
			continue
		}
		rel, ok := m.match(p, pathOrigins(row)...)
		if !ok {
			continue
		}
		sm := SearchMeasured{Prefix: row.Prefix, Relation: rel, OriginASN: originASN(row), Current: row.Current, Recommended: row.Recommended, InRIB: row.InRIB}
		for _, pr := range row.Probes {
			if pr.Time.After(sm.Probed) {
				sm.Probed = pr.Time.UTC()
			}
		}
		out = append(out, sm)
	}
	slices.SortFunc(out, func(x, y SearchMeasured) int {
		return cmp.Or(y.Probed.Compare(x.Probed), cmp.Compare(x.Prefix, y.Prefix))
	})
	total := len(out)
	return group(out[:min(total, searchLimit)], total)
}

// pathOrigins are the origins of every learned path: any of them may be a
// followed AS, as /api/prefixes?asn= has it.
func pathOrigins(row *Prefix) []uint32 {
	var out []uint32
	for _, lp := range row.Paths {
		if o := netpfx.LastAS(lp.ASPath); o != 0 {
			out = append(out, o)
		}
	}
	return out
}

// originASN is the origin of the first learned path that has one, the
// same origin the ASN map groups by.
func originASN(row *Prefix) uint32 {
	for i := range row.Paths {
		if o := netpfx.LastAS(row.Paths[i].ASPath); o != 0 {
			return o
		}
	}
	return 0
}

func searchImprovements(snap Snapshot, m matcher) searchGroup[SearchImprovement] {
	rows := make(map[string]*Prefix, len(snap.Prefixes))
	for i := range snap.Prefixes {
		rows[snap.Prefixes[i].Prefix] = &snap.Prefixes[i]
	}
	var out []SearchImprovement
	for _, im := range snap.Improvements {
		p, err := netip.ParsePrefix(im.Prefix)
		if err != nil {
			continue
		}
		row := rows[im.Prefix]
		var origins []uint32
		var first uint32
		if row != nil {
			origins, first = pathOrigins(row), originASN(row)
		}
		if rel, ok := m.match(p, origins...); ok {
			out = append(out, SearchImprovement{Prefix: im.Prefix, Relation: rel, OriginASN: first,
				Provider: im.Provider, Native: im.Native, Cause: im.Cause, Since: im.Since.UTC()})
		}
	}
	slices.SortFunc(out, func(x, y SearchImprovement) int {
		return cmp.Or(y.Since.Compare(x.Since), cmp.Compare(x.Prefix, y.Prefix))
	})
	total := len(out)
	return group(out[:min(total, searchLimit)], total)
}

func (s *Server) searchRoutes(m matcher) searchGroup[SearchRoute] {
	var src SearchRIB
	if p := s.searchRIB.Load(); p != nil {
		src = *p
	}
	if src == nil {
		return group[SearchRoute](nil, 0)
	}
	origin := func(r rib.Route) uint32 { return netpfx.LastAS(r.ASPath) }
	routes, total := src.Find(func(r rib.Route) bool {
		_, ok := m.match(r.Prefix, origin(r))
		return ok
	}, func(a, b rib.Route) bool {
		return a.Age.After(b.Age) || (a.Age.Equal(b.Age) && netpfx.Less(a.Prefix, b.Prefix))
	}, searchLimit)
	out := make([]SearchRoute, 0, len(routes))
	for _, r := range routes {
		rel, _ := m.match(r.Prefix)
		sr := SearchRoute{Prefix: r.Prefix.String(), Relation: rel, OriginASN: origin(r), Provider: r.Provider, Since: r.Age.UTC()}
		if r.NextHop.IsValid() {
			sr.NextHop = r.NextHop.String()
		}
		out = append(out, sr)
	}
	return group(out, total)
}

// searchHistory fills the stored lists of res and says how it went.
func (s *Server) searchHistory(ctx context.Context, m matcher, res *SearchResponse) SearchHistory {
	res.Improvements = group[history.SearchImprovement](nil, 0)
	res.Rollups = group[history.SearchRollup](nil, 0)
	if s.reports == nil {
		return SearchHistory{Note: "History is off (no storage plugin is configured), so only live data was searched."}
	}
	now := time.Now().UTC()
	ctx, cancel := context.WithTimeout(ctx, searchTimeout)
	defer cancel()
	hq := history.SearchQuery{Prefix: m.prefix, ASNs: m.asns, From: now.AddDate(0, 0, -searchDays), To: now, Limit: searchLimit}
	got, err := s.reports.Search(ctx, hq)
	if err != nil {
		s.log.Warn("search history", "err", err)
		return SearchHistory{Enabled: true, Days: searchDays, Note: "The history store did not answer, so only live data is shown."}
	}
	res.Improvements = group(got.Improvements, got.ImprovementsTotal)
	res.Rollups = group(got.Rollups, got.RollupsTotal)
	return SearchHistory{Enabled: true, Days: searchDays}
}
