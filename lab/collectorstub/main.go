// Command collectorstub is the in-lab stand-in for the public route
// collectors of lab/e2e-origin-agreement.sh (#671), and for the VRP document
// Packeteer validates against. One role per process:
//
//	ris        GET /ris?prefix=P       the origins "RIS" sees for exactly P
//	routeviews GET /routeviews?prefix=P  the same for "RouteViews"
//	vrp        GET /json                the lab ROAs in Routinator's JSON form
//
// Every answer is fixed data about documentation prefixes and documentation
// ASNs. It dials nothing. Every request is recorded at /_lab/state so the
// script can check what reached it. It listens on :8080.
//
// Usage: collectorstub -role ris|routeviews|vrp
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// origins is what each collector sees, by the exact prefix. A prefix that is
// not listed is not announced as far as that collector can tell.
//
//   - 198.51.100.0/25: both see AS64500, the origin transit-a announces
//     (agreement).
//   - 203.0.113.0/25: transit-a announces AS64501, RIS agrees, RouteViews
//     lists AS64511 only (disagreement).
//   - 203.0.113.128/25: neither sees it (empty).
var origins = map[string]map[netip.Prefix][]uint32{
	"ris": {
		netip.MustParsePrefix("198.51.100.0/25"): {64500},
		netip.MustParsePrefix("203.0.113.0/25"):  {64501},
	},
	"routeviews": {
		netip.MustParsePrefix("198.51.100.0/25"): {64500, 64510},
		netip.MustParsePrefix("203.0.113.0/25"):  {64511},
	},
}

// Request is one recorded request.
type Request struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Prefix string `json:"prefix,omitempty"`
	Status int    `json:"status"`
}

// State is what /_lab/state returns.
type State struct {
	Role     string    `json:"role"`
	Requests []Request `json:"requests"`
}

type stub struct {
	role string
	now  func() time.Time

	mu   sync.Mutex
	reqs []Request
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *stub) record(r *http.Request, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = append(s.reqs, Request{Method: r.Method, Path: r.URL.Path, Prefix: r.URL.Query().Get("prefix"), Status: status})
}

// handler serves the role's endpoint and the lab state.
func (s *stub) handler() http.Handler {
	mux := http.NewServeMux()
	serve := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			if r.Method != http.MethodGet {
				http.Error(sw, "GET only", http.StatusMethodNotAllowed)
			} else {
				h(sw, r)
			}
			s.record(r, sw.status)
		}
	}
	if s.role == "vrp" {
		// 198.51.100.0/24 and 203.0.113.0/24 allow up to /24, so the /25s
		// transit-a announces are invalid, and nothing covers them.
		mux.HandleFunc("/json", serve(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{
				"metadata": map[string]any{"generated": s.now().Unix()},
				"roas": []map[string]any{
					{"asn": "AS64500", "prefix": "198.51.100.0/24", "maxLength": 24, "ta": "lab"},
					{"asn": "AS64501", "prefix": "203.0.113.0/24", "maxLength": 24, "ta": "lab"},
				},
			})
		}))
	} else {
		mux.HandleFunc("/"+s.role, serve(func(w http.ResponseWriter, r *http.Request) {
			p, err := netip.ParsePrefix(r.URL.Query().Get("prefix"))
			if err != nil {
				http.Error(w, "bad prefix", http.StatusBadRequest)
				return
			}
			got := origins[s.role][p.Masked()]
			if got == nil {
				got = []uint32{}
			}
			writeJSON(w, http.StatusOK, map[string]any{"prefix": p.Masked().String(), "origins": got})
		}))
	}
	mux.HandleFunc("/_lab/state", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		writeJSON(w, http.StatusOK, State{Role: s.role, Requests: slices.Clone(s.reqs)})
	})
	return mux
}

func main() {
	role := flag.String("role", "", "ris, routeviews, or vrp")
	flag.Parse()
	if *role != "ris" && *role != "routeviews" && *role != "vrp" {
		log.Fatal("collectorstub: -role must be ris, routeviews, or vrp")
	}
	s := &stub{role: *role, now: time.Now}
	srv := &http.Server{Addr: ":8080", Handler: s.handler(), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
