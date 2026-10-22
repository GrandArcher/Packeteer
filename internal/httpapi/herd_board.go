package httpapi

import (
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/GrandArcher/Packeteer/internal/herd"
	"github.com/GrandArcher/Packeteer/internal/outside"
)

// HerdOutside is the outside intelligence on the herd dashboard (#296).
// Its sections are display only and are never mixed into herd data.
type HerdOutside interface {
	IDs() []string
	Sections(t outside.Target, now time.Time) []outside.Section
}

type outsideHolder struct{ src HerdOutside }

// SetHerdOutside installs the enabled outside sources. Nil or never called
// leaves the dashboard with herd data only.
func (s *Server) SetHerdOutside(src HerdOutside) {
	if s == nil || src == nil {
		return
	}
	s.outside.Store(&outsideHolder{src})
}

func (s *Server) herdOutside() HerdOutside {
	if h, _ := s.outside.Load().(*outsideHolder); h != nil {
		return h.src
	}
	return nil
}

// serveHerdView writes one dashboard view. With herd off it writes off, an
// empty view with enabled false.
func serveHerdView[T any](s *Server, w http.ResponseWriter, off T, call func(HerdSource) (T, error)) {
	src := s.herdSource()
	if src == nil {
		writeJSON(w, http.StatusOK, off)
		return
	}
	v, err := call(src)
	var qe herd.QueryError
	switch {
	case errors.As(err, &qe):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": qe.Error()})
	case err != nil:
		s.log.Error("herd dashboard", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "herd store unavailable"})
	default:
		writeJSON(w, http.StatusOK, v)
	}
}

func (s *Server) handleHerdOverview(w http.ResponseWriter, r *http.Request) {
	serveHerdView(s, w, herd.Overview{Members: []herd.MemberRow{}, Countries: []string{}}, func(h HerdSource) (herd.Overview, error) { return h.Overview(r.Context()) })
}

func (s *Server) handleHerdEvents(w http.ResponseWriter, r *http.Request) {
	serveHerdView(s, w, herd.Events{Events: []herd.EventRow{}}, func(h HerdSource) (herd.Events, error) { return h.Events(r.Context(), r.URL.RawQuery) })
}

func (s *Server) handleHerdMesh(w http.ResponseWriter, r *http.Request) {
	serveHerdView(s, w, herd.Mesh{Targets: []herd.Target{}, Rows: []herd.MeshRow{}}, func(h HerdSource) (herd.Mesh, error) { return h.Mesh(r.Context(), r.URL.RawQuery) })
}

func (s *Server) handleHerdMonitor(w http.ResponseWriter, r *http.Request) {
	serveHerdView(s, w, herd.Monitor{Series: []herd.Series{}, Paths: []herd.PathTrack{}}, func(h HerdSource) (herd.Monitor, error) { return h.Monitor(r.Context(), r.URL.RawQuery) })
}

func (s *Server) handleHerdMap(w http.ResponseWriter, r *http.Request) {
	serveHerdView(s, w, herd.Map{Countries: []herd.Country{}}, func(h HerdSource) (herd.Map, error) { return h.Map(r.Context(), r.URL.RawQuery) })
}

func (s *Server) handleHerdSearch(w http.ResponseWriter, r *http.Request) {
	serveHerdView(s, w, herd.Search{Hits: []herd.Hit{}}, func(h HerdSource) (herd.Search, error) { return h.Search(r.Context(), r.URL.RawQuery) })
}

// handleHerdOutside serves the enabled outside sources for the prefix and
// origin_asn in the query. With none enabled, sources and sections are
// empty and the page shows herd data only.
func (s *Server) handleHerdOutside(w http.ResponseWriter, r *http.Request) {
	body := struct {
		Sources  []string          `json:"sources"`
		Sections []outside.Section `json:"sections"`
	}{Sources: []string{}, Sections: []outside.Section{}}
	src := s.herdOutside()
	if src == nil {
		writeJSON(w, http.StatusOK, body)
		return
	}
	var t outside.Target
	q := r.URL.Query()
	for k := range q {
		if k != "prefix" && k != "origin_asn" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown parameter " + strconv.Quote(k)})
			return
		}
	}
	if v := q.Get("prefix"); v != "" {
		p, err := netip.ParsePrefix(v)
		if err != nil || p != p.Masked() {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "prefix " + strconv.Quote(v)})
			return
		}
		t.Prefix = p
	}
	if v := q.Get("origin_asn"); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil || n == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "origin_asn " + strconv.Quote(v) + " is not an ASN"})
			return
		}
		t.ASN = uint32(n)
	}
	body.Sources, body.Sections = src.IDs(), src.Sections(t, time.Now())
	writeJSON(w, http.StatusOK, body)
}
