package httpapi

import (
	"net/http"
	"net/netip"
	"strconv"

	"github.com/GrandArcher/Packeteer/internal/linkout"
)

// maxLinkoutObjects bounds one request: a page of prefixes plus the ASNs
// on it.
const maxLinkoutObjects = 300

// handleLinkouts builds the "open in" links (#211) for the prefixes and
// ASNs named in the query, so the page never builds a URL itself. It reads
// no table and makes no request to any of the sites. An object that
// linkouts.hide_internal covers gets an empty list.
func (s *Server) handleLinkouts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	prefixes, asns := q["prefix"], q["asn"]
	if len(prefixes)+len(asns) > maxLinkoutObjects {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at most " + strconv.Itoa(maxLinkoutObjects) + " prefix and asn values per request"})
		return
	}
	body := struct {
		Prefix map[string][]linkout.Link `json:"prefix"`
		ASN    map[string][]linkout.Link `json:"asn"`
	}{Prefix: map[string][]linkout.Link{}, ASN: map[string][]linkout.Link{}}
	for _, v := range prefixes {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "prefix " + strconv.Quote(v) + " is not a CIDR"})
			return
		}
		body.Prefix[v] = s.linkouts.Prefix(p)
	}
	for _, v := range asns {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil || n == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "asn " + strconv.Quote(v) + " is not an AS number"})
			return
		}
		body.ASN[v] = s.linkouts.ASN(uint32(n))
	}
	writeJSON(w, http.StatusOK, body)
}
