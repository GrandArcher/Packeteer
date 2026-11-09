package httpapi

import (
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
)

// The measured-prefix list is served in pages (#183), so a table of 100k
// prefixes costs one page per request. A request with no paging
// parameters gets the first defaultPrefixLimit rows.
const (
	defaultPrefixLimit = 100
	maxPrefixLimit     = 500
	// asnMapNodes and asnSitePrefixes bound the ASN map in the same
	// response. Count on a site and asn_total are the full numbers.
	asnMapNodes     = 100
	asnSitePrefixes = 8
)

// prefixQuery is the filter, order, and window of one /api/prefixes call.
type prefixQuery struct {
	prefix   string
	provider string
	asn      uint32
	differs  bool
	sort     string
	offset   int
	limit    int
}

func parsePrefixQuery(v url.Values) (prefixQuery, error) {
	q := prefixQuery{
		prefix:   strings.TrimSpace(v.Get("prefix")),
		provider: strings.TrimSpace(v.Get("provider")),
		sort:     "prefix",
		limit:    defaultPrefixLimit,
	}
	if s := v.Get("sort"); s != "" {
		switch s {
		case "prefix", "gain", "loss", "rtt":
			q.sort = s
		default:
			return q, fmt.Errorf("sort must be prefix, gain, loss, or rtt")
		}
	}
	if s := strings.TrimSpace(v.Get("asn")); s != "" {
		n, ok := netpfx.ParseASN(s)
		if !ok {
			return q, fmt.Errorf("asn must be an AS number such as 64500")
		}
		q.asn = n
	}
	if s := v.Get("differs"); s != "" {
		b, err := strconv.ParseBool(s)
		if err != nil {
			return q, fmt.Errorf("differs must be true or false")
		}
		q.differs = b
	}
	if s := v.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > maxPrefixLimit {
			return q, fmt.Errorf("limit must be 1-%d", maxPrefixLimit)
		}
		q.limit = n
	}
	if s := v.Get("offset"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return q, fmt.Errorf("offset must be 0 or more")
		}
		q.offset = n
	}
	return q, nil
}

// match reports whether a row passes every filter. A prefix filter that is
// a CIDR matches that prefix exactly; any other text matches as a
// substring of the prefix. The provider filter is an exact name (any
// case) of a probed, current, or recommended provider.
func (q prefixQuery) match(row *Prefix, want *netip.Prefix) bool {
	if q.differs && !(row.Current != "" && row.Recommended != "" && row.Recommended != row.Current) {
		return false
	}
	if want != nil {
		if row.Prefix != want.String() && row.Prefix != want.Masked().String() {
			return false
		}
	} else if q.prefix != "" && !strings.Contains(strings.ToLower(row.Prefix), strings.ToLower(q.prefix)) {
		return false
	}
	if q.provider != "" && !rowHasProvider(row, q.provider) {
		return false
	}
	if q.asn != 0 && !rowHasOrigin(row, q.asn) {
		return false
	}
	return true
}

func rowHasProvider(row *Prefix, name string) bool {
	if strings.EqualFold(row.Current, name) || strings.EqualFold(row.Recommended, name) {
		return true
	}
	for i := range row.Probes {
		if strings.EqualFold(row.Probes[i].Provider, name) {
			return true
		}
	}
	return false
}

// rowHasOrigin uses the last AS of a learned path, as the ASN map does.
func rowHasOrigin(row *Prefix, asn uint32) bool {
	for i := range row.Paths {
		if netpfx.LastAS(row.Paths[i].ASPath) == asn {
			return true
		}
	}
	return false
}

// worse orders by a measurement, highest first, rows without one last.
func worse(a, b *float64) bool {
	if a == nil || b == nil {
		return a != nil
	}
	return *a > *b
}

// page returns the rows of one page and the number of rows that matched.
// rows are in prefix order, and every other order keeps it for ties, so a
// page is stable between requests while the data is.
func (q prefixQuery) page(rows []Prefix) ([]Prefix, int) {
	var want *netip.Prefix
	if p, err := netip.ParsePrefix(q.prefix); err == nil {
		want = &p
	}
	idx := make([]int, 0, len(rows))
	for i := range rows {
		if q.match(&rows[i], want) {
			idx = append(idx, i)
		}
	}
	switch q.sort {
	case "gain":
		sort.SliceStable(idx, func(a, b int) bool { return rows[idx[a]].Gain > rows[idx[b]].Gain })
	case "loss":
		sort.SliceStable(idx, func(a, b int) bool {
			return worse(rows[idx[a]].ExitLossPct, rows[idx[b]].ExitLossPct)
		})
	case "rtt":
		sort.SliceStable(idx, func(a, b int) bool {
			return worse(rows[idx[a]].ExitRTTMs, rows[idx[b]].ExitRTTMs)
		})
	}
	total := len(idx)
	if q.offset >= total {
		return []Prefix{}, total
	}
	end := min(q.offset+q.limit, total)
	out := make([]Prefix, 0, end-q.offset)
	for _, i := range idx[q.offset:end] {
		out = append(out, rows[i])
	}
	return out, total
}

// boundASNMap is the ASN map as the API serves it: the first asnMapNodes
// origin ASNs, or only the requested one, with at most asnSitePrefixes
// prefixes listed per site. The snapshot is not changed.
func boundASNMap(nodes []ASNNode, only uint32) ([]ASNNode, int) {
	var picked []ASNNode
	for _, n := range nodes {
		if only == 0 || n.ASN == only {
			picked = append(picked, n)
		}
	}
	total := len(picked)
	if total > asnMapNodes {
		picked = picked[:asnMapNodes]
	}
	out := make([]ASNNode, 0, len(picked))
	for _, n := range picked {
		sites := make([]ASNSite, len(n.Sites))
		for i, s := range n.Sites {
			if len(s.Prefixes) > asnSitePrefixes {
				s.Prefixes = s.Prefixes[:asnSitePrefixes:asnSitePrefixes]
			}
			sites[i] = s
		}
		out = append(out, ASNNode{ASN: n.ASN, Sites: sites})
	}
	return out, total
}

// PrefixPage is the body of GET /api/prefixes. Total is the number of rows
// that matched and Measured the number before filtering.
type PrefixPage struct {
	meta
	Prefixes []Prefix  `json:"prefixes"`
	Total    int       `json:"total"`
	Measured int       `json:"measured"`
	Offset   int       `json:"offset"`
	Limit    int       `json:"limit"`
	ASNMap   []ASNNode `json:"asn_map"`
	ASNTotal int       `json:"asn_total"`
}

// handlePrefixes serves the measured prefixes, one page at a time. Query:
// prefix, asn, provider, differs, sort (prefix, gain, loss, rtt), limit,
// offset.
func (s *Server) handlePrefixes(w http.ResponseWriter, r *http.Request) {
	q, err := parsePrefixQuery(r.URL.Query())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	snap := s.snapshot()
	rows, total := q.page(snap.Prefixes)
	s.labelDisplay(rows)
	nodes, asnTotal := boundASNMap(snap.ASNMap, q.asn)
	writeJSON(w, http.StatusOK, PrefixPage{
		meta: snap.meta(), Prefixes: rows, Total: total, Measured: len(snap.Prefixes),
		Offset: q.offset, Limit: q.limit, ASNMap: nodes, ASNTotal: asnTotal,
	})
}
