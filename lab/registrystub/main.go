// Command registrystub is the in-lab registry stand-in for lab/e2e-registry.sh
// (#657): a whois IRR (RIPE dialect), the RIPE database REST API, PeeringDB,
// and a VRP JSON document, all answering from fixed data about documentation
// prefixes and documentation ASNs. It dials nothing and holds no real
// registry data. Writes are accepted only with the lab credentials, which
// come from the environment, and every request is recorded without its
// credentials so the script can check what reached the stand-in.
//
// It listens on :43 (whois), :8443 (https: RIPE REST under /ripe, PeeringDB
// under /peeringdb) and :8323 (http: VRP JSON at /json, lab state at
// /_lab/state).
//
// Usage: registrystub -cert FILE -key FILE
package main

import (
	"bufio"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Environment variables holding the credentials the stand-in accepts.
const (
	ripeUserEnv     = "STUB_RIPE_USER"
	ripePasswordEnv = "STUB_RIPE_PASSWORD"
	pdbKeyEnv       = "STUB_PEERINGDB_API_KEY"
)

// maxBody bounds a request body.
const maxBody = 1 << 20

type attr struct{ Name, Value string }

// object is one RPSL object, in attribute order.
type object []attr

func (o object) get(name string) string {
	for _, a := range o {
		if a.Name == name {
			return a.Value
		}
	}
	return ""
}

// key is the REST key of a route object: the prefix and the origin.
func (o object) key() string { return o.get(o[0].Name) + o.get("origin") }

func (o object) text() string {
	var b strings.Builder
	for _, a := range o {
		fmt.Fprintf(&b, "%-15s %s\n", a.Name+":", a.Value)
	}
	return b.String()
}

func route(prefix string, origin int, descr string) object {
	return object{{"route", prefix}, {"descr", descr}, {"origin", "AS" + strconv.Itoa(origin)}, {"mnt-by", "MAINT-LAB"}, {"source", "TEST"}}
}

// Request is one recorded request. Authorized is true when the request
// carried the credentials this stand-in accepts.
type Request struct {
	Service    string `json:"service"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Authorized bool   `json:"authorized"`
	Status     int    `json:"status"`
}

// State is what GET /_lab/state returns.
type State struct {
	Requests []Request                 `json:"requests"`
	Routes   []string                  `json:"routes"`
	PDB      map[string]map[string]any `json:"peeringdb"`
}

type stub struct {
	ripeUser, ripePass, pdbKey string
	now                        func() time.Time

	mu     sync.Mutex
	routes []object
	// pdb holds the records by "class/id".
	pdb  map[string]map[string]any
	reqs []Request
}

// newStub returns the stand-in with the lab data. The announced prefixes in
// the lab are 203.0.113.0/24 and 203.0.113.128/25, both from AS64501.
func newStub(getenv func(string) string, now func() time.Time) *stub {
	return &stub{
		ripeUser: getenv(ripeUserEnv), ripePass: getenv(ripePasswordEnv), pdbKey: getenv(pdbKeyEnv), now: now,
		// 203.0.113.128/25 has no object (missing); 192.0.2.0/24 is no
		// longer announced (stale).
		routes: []object{
			route("203.0.113.0/24", 64501, "lab registered"),
			route("192.0.2.0/24", 64501, "lab stale"),
		},
		pdb: map[string]map[string]any{
			// Two prefixes are announced and PeeringDB says one.
			"net/1": {"id": 1, "asn": 64501, "name": "Lab Net", "info_prefixes4": 1, "info_prefixes6": 0},
			// The lab config says 10000 Mbps on this port.
			"netixlan/11": {"id": 11, "ix_id": 7, "asn": 64501, "ipaddr4": "198.51.100.130", "ipaddr6": nil, "speed": 1000},
		},
	}
}

func (s *stub) record(service string, r *http.Request, authorized bool, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = append(s.reqs, Request{Service: service, Method: r.Method, Path: r.URL.Path, Authorized: authorized, Status: status})
}

// statusWriter keeps the status for the request record.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// wrap records the request after the handler ran. The handler returns
// whether the request carried the lab credentials.
func (s *stub) wrap(service string, h func(w http.ResponseWriter, r *http.Request) bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		authorized := h(sw, r)
		s.record(service, r, authorized, sw.status)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func equal(a, b string) bool {
	return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// httpsHandler serves the RIPE REST API under /ripe and PeeringDB under
// /peeringdb.
func (s *stub) httpsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ripe/test/", s.wrap("ripe", s.ripe))
	mux.HandleFunc("/peeringdb/api/", s.wrap("peeringdb", s.peeringdb))
	return mux
}

// httpHandler serves the VRP JSON and the lab state.
func (s *stub) httpHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/json", s.wrap("vrp", func(w http.ResponseWriter, r *http.Request) bool {
		// 203.0.113.0/24 allows up to /24, so the announced /25 is invalid.
		// Nothing covers 192.0.2.0/24.
		writeJSON(w, http.StatusOK, map[string]any{
			"metadata": map[string]any{"generated": s.now().Unix()},
			"roas":     []map[string]any{{"asn": "AS64501", "prefix": "203.0.113.0/24", "maxLength": 24, "ta": "lab"}},
		})
		return false
	}))
	mux.HandleFunc("/_lab/state", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.state())
	})
	return mux
}

func (s *stub) state() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := State{Requests: slices.Clone(s.reqs), Routes: []string{}, PDB: map[string]map[string]any{}}
	for _, o := range s.routes {
		st.Routes = append(st.Routes, o.text())
	}
	for k, v := range s.pdb {
		st.PDB[k] = v
	}
	return st
}

// ripe is POST /ripe/test/route (create), GET and DELETE /ripe/test/route/KEY.
// Writes need the basic-auth lab account.
func (s *stub) ripe(w http.ResponseWriter, r *http.Request) bool {
	class, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/ripe/test/"), "/")
	if class != "route" {
		http.NotFound(w, r)
		return false
	}
	user, pass, ok := r.BasicAuth()
	authorized := ok && equal(s.ripeUser, user) && equal(s.ripePass, pass)
	if r.Method != http.MethodGet && !authorized {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.Method {
	case http.MethodGet:
		i := s.find(key)
		if i < 0 {
			writeJSON(w, http.StatusNotFound, map[string]any{})
			return authorized
		}
		attrs := make([]map[string]string, 0, len(s.routes[i]))
		for _, a := range s.routes[i] {
			attrs = append(attrs, map[string]string{"name": a.Name, "value": a.Value})
		}
		writeJSON(w, http.StatusOK, map[string]any{"objects": map[string]any{"object": []any{map[string]any{
			"source": map[string]string{"id": "TEST"}, "attributes": map[string]any{"attribute": attrs}}}}})
	case http.MethodDelete:
		i := s.find(key)
		if i < 0 {
			writeJSON(w, http.StatusNotFound, map[string]any{})
			return authorized
		}
		s.routes = slices.Delete(s.routes, i, i+1)
		writeJSON(w, http.StatusOK, map[string]any{})
	case http.MethodPost:
		var doc struct {
			Objects struct {
				Object []struct {
					Attributes struct {
						Attribute []struct{ Name, Value string } `json:"attribute"`
					} `json:"attributes"`
				} `json:"object"`
			} `json:"objects"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&doc); err != nil || len(doc.Objects.Object) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return authorized
		}
		var o object
		for _, a := range doc.Objects.Object[0].Attributes.Attribute {
			o = append(o, attr(a))
		}
		if len(o) == 0 || o[0].Name != "route" || o.get("source") != "TEST" || s.find(o.key()) >= 0 {
			w.WriteHeader(http.StatusBadRequest)
			return authorized
		}
		s.routes = append(s.routes, o)
		writeJSON(w, http.StatusCreated, map[string]any{})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
	return authorized
}

// find is the index of the route object with key, or -1. The caller holds mu.
func (s *stub) find(key string) int {
	return slices.IndexFunc(s.routes, func(o object) bool { return o.key() == key })
}

// peeringdb answers the reads the registry source makes and accepts a PUT
// of a net or netixlan record with the lab API key. Every other list is
// empty: the lookup block, which the lab needs only for the exchange id,
// reads ix, org and other networks from here too, never from the internet.
func (s *stub) peeringdb(w http.ResponseWriter, r *http.Request) bool {
	authorized := equal(s.pdbKey, strings.TrimPrefix(r.Header.Get("Authorization"), "Api-Key "))
	rest := strings.TrimPrefix(r.URL.Path, "/peeringdb/api/")
	class, id, detail := strings.Cut(rest, "/")
	data := func(v ...any) bool {
		writeJSON(w, http.StatusOK, map[string]any{"data": append([]any{}, v...)})
		return authorized
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if detail {
		rec, ok := s.pdb[class+"/"+id]
		switch {
		case !ok:
			writeJSON(w, http.StatusNotFound, map[string]any{})
		case r.Method == http.MethodPut:
			if !authorized {
				w.WriteHeader(http.StatusUnauthorized)
				return false
			}
			var body map[string]any
			if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return authorized
			}
			for k, v := range body {
				rec[k] = v
			}
			return data(rec)
		case r.Method == http.MethodGet:
			return data(rec)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return authorized
	}
	q := r.URL.Query()
	switch {
	case class == "net" && q.Get("asn") == "64501":
		return data(s.pdb["net/1"])
	case class == "netixlan" && q.Get("asn") == "64501":
		return data(s.pdb["netixlan/11"])
	case class == "netfac" && q.Get("local_asn") == "64501":
		return data(map[string]any{"id": 21, "local_asn": 64501, "fac_id": 3})
	case class == "poc" && q.Get("net_id") == "1":
		return data(map[string]any{"id": 31, "role": "NOC", "updated": s.now().UTC().Format(time.RFC3339)})
	case slices.Contains([]string{"ix", "net", "netixlan", "netfac", "org", "poc"}, class):
		return data()
	}
	http.NotFound(w, r)
	return authorized
}

// serveWhois answers RIPE-dialect queries, one per connection, and closes.
func (s *stub) serveWhois(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			line, err := bufio.NewReader(io.LimitReader(c, 4096)).ReadString('\n')
			if err != nil {
				return
			}
			_, _ = io.WriteString(c, s.whois(strings.TrimSpace(line)))
		}()
	}
}

// whois answers "-r -s TEST [-B] [-x] [-i origin] -T route,route6 KEY": an
// inverse origin query lists every object of that origin, any other KEY is a
// prefix matched exactly.
func (s *stub) whois(query string) string {
	f := strings.Fields(query)
	var key string
	origin := false
	for i := 0; i < len(f); i++ {
		switch f[i] {
		case "-s", "-T":
			i++
		case "-i":
			origin = true
			i++
		case "-r", "-B", "-x":
		default:
			key = f[i]
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = append(s.reqs, Request{Service: "whois", Method: "QUERY", Path: query, Status: 200})
	var b strings.Builder
	b.WriteString("% Lab IRR stand-in. Documentation data only.\n\n")
	n := 0
	for _, o := range s.routes {
		if (origin && o.get("origin") == key) || (!origin && o.get("route") == key) {
			b.WriteString(o.text() + "\n")
			n++
		}
	}
	if n == 0 {
		return "%ERROR:101: no entries found\n"
	}
	return b.String()
}

func main() {
	cert := flag.String("cert", "", "TLS certificate for the https listener")
	keyFile := flag.String("key", "", "TLS key for the https listener")
	flag.Parse()
	if *cert == "" || *keyFile == "" {
		log.Fatal("registrystub: -cert and -key are required")
	}
	pair, err := tls.LoadX509KeyPair(*cert, *keyFile)
	if err != nil {
		log.Fatal(err)
	}
	s := newStub(os.Getenv, time.Now)
	ln, err := net.Listen("tcp", ":43")
	if err != nil {
		log.Fatal(err)
	}
	go s.serveWhois(ln)
	go func() {
		srv := &http.Server{Addr: ":8443", Handler: s.httpsHandler(), TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}}, ReadHeaderTimeout: 10 * time.Second}
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}()
	srv := &http.Server{Addr: ":8323", Handler: s.httpHandler(), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
