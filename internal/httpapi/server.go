// Package httpapi is Packeteer's ops surface: health, Prometheus metrics, a
// JSON API, and an embedded dashboard. It does not announce routes. The
// only write is opening or closing an on-demand maintenance window, which
// can only exclude providers, and it requires basic auth.
package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// Options configure the server. User and Password must both be set or both
// be empty. When both are set, every route requires HTTP basic auth.
type Options struct {
	Addr     string
	User     string
	Password string
	Snapshot func() Snapshot
	Logger   *slog.Logger
	// Maintenance is nil when no maintenance policy is configured.
	Maintenance MaintenanceControl
}

// Server is an HTTP server. Handler serves the routes without listening,
// which is what tests use. Start binds Addr.
type Server struct {
	addr     string
	user     string
	password string
	snap     func() Snapshot
	maint    MaintenanceControl
	log      *slog.Logger
	handler  http.Handler
	http     *http.Server
	ln       net.Listener
}

// New validates auth and builds the handler. It does not listen.
func New(opt Options) (*Server, error) {
	if (opt.User == "") != (opt.Password == "") {
		return nil, errors.New("http: basic auth requires both user and password")
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	s := &Server{addr: opt.Addr, user: opt.User, password: opt.Password, snap: opt.Snapshot, maint: opt.Maintenance, log: opt.Logger}
	s.handler = s.routes()
	return s, nil
}

// Handler is the read-only API and dashboard.
func (s *Server) Handler() http.Handler { return s.handler }

// Addr is the bound address after Start, or the configured address before.
func (s *Server) Addr() string {
	if s.ln != nil {
		return s.ln.Addr().String()
	}
	return s.addr
}

// Start listens and serves until Shutdown. A bind error is returned to
// the caller; later serve errors are logged.
func (s *Server) Start() error {
	if s.addr == "" {
		return errors.New("http: listen address is empty")
	}
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("http: listen %s: %w", s.addr, err)
	}
	s.ln = ln
	s.http = &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	go func() {
		err := s.http.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("http server", "err", err)
		}
	}()
	s.log.Info("http listening", "addr", ln.Addr().String(), "auth", s.authMode())
	return nil
}

// Shutdown stops the listener and waits for in-flight requests.
func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || s.http == nil {
		return nil
	}
	return s.http.Shutdown(ctx)
}

func (s *Server) authMode() string {
	if s.user == "" {
		return "off"
	}
	return "basic"
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /api/providers", s.handleProviders)
	mux.HandleFunc("GET /api/probes", s.handleProbes)
	mux.HandleFunc("GET /api/prefixes", s.handlePrefixes)
	mux.HandleFunc("GET /api/decisions", s.handleDecisions)
	mux.HandleFunc("GET /api/improvements", s.handleImprovements)
	mux.HandleFunc("GET /api/telemetry", s.handleTelemetry)
	mux.HandleFunc("GET /api/maintenance", s.handleMaintenance)
	mux.HandleFunc("POST /api/maintenance", s.handleMaintenanceOpen)
	mux.HandleFunc("DELETE /api/maintenance/{id}", s.handleMaintenanceClose)
	mux.Handle("GET /", http.FileServer(http.FS(webRoot)))

	var h http.Handler = mux
	if s.user != "" {
		h = s.withAuth(h)
	}
	return withSecurityHeaders(h)
}

func (s *Server) snapshot() Snapshot {
	if s.snap == nil {
		return Snapshot{}
	}
	out := s.snap()
	out.zeroNil()
	return out
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": snap.Version})
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	status := http.StatusOK
	name := "ready"
	if !snap.Ready() {
		status = http.StatusServiceUnavailable
		name = "not_ready"
	}
	writeJSON(w, status, map[string]any{
		"status":         name,
		"ready":          snap.Ready(),
		"bgp_configured": snap.BGPConfigured,
		"rib_ready":      snap.RIBReady,
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(Metrics(s.snapshot()))
}

func (s *Server) handleProviders(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	writeJSON(w, http.StatusOK, struct {
		meta
		Providers []Provider `json:"providers"`
		BGP       bgpBody    `json:"bgp"`
	}{
		meta:      snap.meta(),
		Providers: nz(snap.Providers),
		BGP:       bgpBody{Configured: snap.BGPConfigured, Ready: snap.RIBReady, Peers: nz(snap.Peers)},
	})
}

func (s *Server) handleProbes(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	writeJSON(w, http.StatusOK, struct {
		meta
		Probes []Probe `json:"probes"`
	}{meta: snap.meta(), Probes: nz(snap.Probes)})
}

func (s *Server) handlePrefixes(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	writeJSON(w, http.StatusOK, struct {
		meta
		Prefixes []Prefix `json:"prefixes"`
	}{meta: snap.meta(), Prefixes: nz(snap.Prefixes)})
}

func (s *Server) handleDecisions(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	body := struct {
		meta
		DecidedAt *time.Time `json:"decided_at,omitempty"`
		Decisions []Decision `json:"decisions"`
	}{meta: snap.meta(), Decisions: nz(snap.Decisions)}
	if !snap.DecidedAt.IsZero() {
		t := snap.DecidedAt.UTC()
		body.DecidedAt = &t
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) handleImprovements(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	writeJSON(w, http.StatusOK, struct {
		meta
		Improvements []Improvement `json:"improvements"`
	}{meta: snap.meta(), Improvements: nz(snap.Improvements)})
}

func (s *Server) handleTelemetry(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	writeJSON(w, http.StatusOK, struct {
		meta
		Telemetry []Telemetry `json:"telemetry"`
	}{meta: snap.meta(), Telemetry: nz(snap.Telemetry)})
}

type meta struct {
	Version     string    `json:"version"`
	Mode        string    `json:"mode"`
	Ready       bool      `json:"ready"`
	GeneratedAt time.Time `json:"generated_at"`
}

func (s Snapshot) meta() meta {
	at := s.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	return meta{Version: s.Version, Mode: s.Mode, Ready: s.Ready(), GeneratedAt: at.UTC()}
}

type bgpBody struct {
	Configured bool   `json:"configured"`
	Ready      bool   `json:"ready"`
	Peers      []Peer `json:"peers"`
}

func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			user, pass = "", ""
		}
		// Both compares always run. SHA-256 makes the cost independent of
		// the secret length, which ConstantTimeCompare does not.
		matchUser := secretEqual(user, s.user)
		matchPass := secretEqual(pass, s.password)
		if !ok || !matchUser || !matchPass {
			w.Header().Set("WWW-Authenticate", `Basic realm="packeteer"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func secretEqual(got, want string) bool {
	a := sha256.Sum256([]byte(got))
	b := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

func withSecurityHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Robots-Tag", "noindex")
		h.Set("Content-Security-Policy", csp)
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func nz[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

var webRoot = func() fs.FS {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err)
	}
	return sub
}()
