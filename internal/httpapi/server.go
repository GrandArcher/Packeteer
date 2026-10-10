// Package httpapi is Packeteer's ops surface: health, Prometheus metrics, a
// JSON API, history reports (JSON and CSV), read-only troubleshooting tools
// (looking glass, on-demand probe, traceroute, whois), and an embedded
// dashboard. It does not announce routes itself. The writes are opening
// or closing an on-demand maintenance window, which can only exclude
// providers, and adding or removing a threat mitigation rule (#28), which
// the mitigation controller checks and announces only in inject, plus
// users and API tokens when auth is on (#32). Every change needs a
// signed-in operator (or the basic-auth account) and is audited; see
// access.go.
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
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/GrandArcher/Packeteer/internal/anomaly"
	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/federation"
	"github.com/GrandArcher/Packeteer/internal/inbound"
	"github.com/GrandArcher/Packeteer/internal/troubleshoot"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Options configure the server. User and Password must both be set or both
// be empty. When both are set, every route requires HTTP basic auth. Auth
// replaces them with users, roles, and tokens (#32); the two are exclusive.
type Options struct {
	Addr     string
	User     string
	Password string
	// Auth is role-based access (#32). Nil keeps the basic-auth account.
	Auth *auth.Service
	// Audit records changes. Nil records nothing.
	Audit *auth.Auditor
	// AllowFrom restricts client addresses (http.allow_from). Empty
	// allows any.
	AllowFrom []netip.Prefix
	Snapshot  func() Snapshot
	Logger    *slog.Logger
	// Maintenance is nil when no maintenance policy is configured.
	Maintenance MaintenanceControl
	// Reports is nil when no storage plugin is configured.
	Reports ReportSource
	// Tools are the read-only troubleshooting tools. Nil disables them.
	Tools *troubleshoot.Tools
	// Inbound reads inbound commit control. Nil means it is not configured.
	Inbound func() inbound.Status
	// Mitigation is threat mitigation (#28). Nil means it is not
	// configured.
	Mitigation MitigationControl
	// Anomaly is traffic anomaly detection (#33). Nil means it is not
	// configured.
	Anomaly func() anomaly.Status
	// Federation is the central view of every instance (#30). Nil means
	// the instance runs standalone.
	Federation func() federation.Status
	// HA is the active/standby elector's view (#31). Nil means a single
	// instance, always active.
	HA func() plugin.ElectorStatus
	// ConfigEditor is the validated config editor (#34). Nil when
	// http.config_editor is off.
	ConfigEditor ConfigEditor
	// Dashboards keeps custom dashboards (#34). Nil when the storage
	// plugin does not keep them.
	Dashboards plugin.DashboardStore
	// Subscriptions is the report subscription scheduler (#34). Nil when
	// none are configured.
	Subscriptions Subscriptions
	// Setup describes the loaded config for the dashboard's first-run
	// checklist (#49).
	Setup Setup
}

// Server is an HTTP server. Handler serves the routes without listening,
// which is what tests use. Start binds Addr.
type Server struct {
	addr       string
	user       string
	password   string
	auth       *auth.Service
	audit      *auth.Auditor
	allowFrom  []netip.Prefix
	snap       func() Snapshot
	maint      MaintenanceControl
	reports    ReportSource
	tools      *troubleshoot.Tools
	inbound    func() inbound.Status
	mitigation MitigationControl
	anomaly    func() anomaly.Status
	federation func() federation.Status
	ha         func() plugin.ElectorStatus
	editor     ConfigEditor
	dashboards plugin.DashboardStore
	subs       Subscriptions
	setup      atomic.Pointer[Setup]
	// suggest lists next hops the operator may accept as a draft provider
	// row (#102). Nil means there is nothing to suggest. It must not write
	// config or announce.
	suggest atomic.Value
	// apply, when set, applies a file that was just written and whose
	// every change can run online (#128). Nil leaves the file for a
	// restart or SIGHUP. It may be stored after New, once the reloader
	// exists. The function returns the keys it applied, a refusal that
	// left the running config in place, or a fatal error after the BGP
	// speaker changed.
	apply   atomic.Value
	log     *slog.Logger
	handler http.Handler
	http    *http.Server
	ln      net.Listener
}

// SetSetup replaces the facts the overview's setup checklist reads. An
// online reload calls it when the cap or the sources change.
func (s *Server) SetSetup(st Setup) {
	if s == nil {
		return
	}
	s.setup.Store(&st)
}

// New validates auth and builds the handler. It does not listen.
func New(opt Options) (*Server, error) {
	if (opt.User == "") != (opt.Password == "") {
		return nil, errors.New("http: basic auth requires both user and password")
	}
	if opt.Auth != nil && opt.User != "" {
		return nil, errors.New("http: auth replaces PACKETEER_HTTP_USER and PACKETEER_HTTP_PASSWORD; unset them")
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	s := &Server{addr: opt.Addr, user: opt.User, password: opt.Password, auth: opt.Auth, audit: opt.Audit, allowFrom: opt.AllowFrom, snap: opt.Snapshot, maint: opt.Maintenance, reports: opt.Reports, tools: opt.Tools, inbound: opt.Inbound, mitigation: opt.Mitigation, anomaly: opt.Anomaly, federation: opt.Federation, ha: opt.HA,
		editor: opt.ConfigEditor, dashboards: opt.Dashboards, subs: opt.Subscriptions, log: opt.Logger}
	setup := opt.Setup
	s.setup.Store(&setup)
	s.handler = s.routes()
	return s, nil
}

// OnlineApplier applies the config file just written when every change
// can run online. applied are the keys now running. refused means the
// running config was left as it was. fatal means the BGP speaker changed
// and the process must stop, which withdraws.
type OnlineApplier func(ctx context.Context) (applied []string, refused, fatal error)

// SetOnlineApply installs the reload used after a fully online PUT
// /api/config (#128). It may be called after New.
func (s *Server) SetOnlineApply(fn OnlineApplier) {
	if s == nil {
		return
	}
	if fn == nil {
		s.apply.Store(OnlineApplier(nil))
		return
	}
	s.apply.Store(fn)
}

// SetSuggestions installs the read-only next-hop suggestions (#102).
// The function must not write config, probe, or announce. It may be
// called after New, once the RIB view exists.
func (s *Server) SetSuggestions(fn func() []Suggestion) {
	if s == nil {
		return
	}
	s.suggest.Store(fn)
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

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	for _, rt := range s.routeTable() {
		mux.Handle(rt.pattern, s.guard(rt))
	}
	var h http.Handler = mux
	if s.user != "" {
		h = s.withAuth(h)
	}
	// Browsers may not send a cross-origin change (Sec-Fetch-Site or
	// Origin), whatever the credentials.
	h = http.NewCrossOriginProtection().Handler(h)
	return withSecurityHeaders(withAllowFrom(s.allowFrom, h))
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
	if s.mitigation != nil {
		_, _ = w.Write(MitigationMetrics(s.mitigation.Status()))
	}
	if s.anomaly != nil {
		_, _ = w.Write(AnomalyMetrics(s.anomaly()))
	}
	if s.ha != nil {
		_, _ = w.Write(HAMetrics(s.ha()))
	}
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
		Prefixes []Prefix  `json:"prefixes"`
		ASNMap   []ASNNode `json:"asn_map"`
	}{meta: snap.meta(), Prefixes: nz(snap.Prefixes), ASNMap: nz(snap.ASNMap)})
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

// handleExchanges serves Internet exchange statistics (#27): per peer,
// the prefixes seen through its next hop, probe health, and improvements,
// and next hops on the peering LAN that are not configured peers.
func (s *Server) handleExchanges(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	writeJSON(w, http.StatusOK, struct {
		meta
		Exchanges []exchange.Stats `json:"exchanges"`
	}{meta: snap.meta(), Exchanges: nz(snap.Exchanges)})
}

// handleHA serves the active/standby view (#31). Without an elector the
// instance is standalone and always active. It is read-only.
func (s *Server) handleHA(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	st := plugin.ElectorStatus{Role: plugin.RoleActive, Eligible: true, Detail: "single instance (no ha configured)"}
	enabled := s.ha != nil
	if enabled {
		st = s.ha()
	}
	writeJSON(w, http.StatusOK, struct {
		meta
		HAEnabled bool `json:"ha_enabled"`
		plugin.ElectorStatus
	}{meta: snap.meta(), HAEnabled: enabled, ElectorStatus: st})
}

// handleFederation serves the central view (#30): this instance's
// published snapshot, every peer's latest snapshot and freshness, and the
// global commits. It is read-only.
func (s *Server) handleFederation(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	st := federation.Status{Peers: []federation.PeerView{}, GlobalCommit: []federation.CommitStatus{}}
	if s.federation != nil {
		st = s.federation()
	}
	writeJSON(w, http.StatusOK, struct {
		meta
		federation.Status
	}{meta: snap.meta(), Status: st})
}

// handleInbound serves inbound optimization: the steers (announced in
// inject, suggested in observe and suggest), the routes on the wire, and
// providers over commit that were not steered.
func (s *Server) handleInbound(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	st := inbound.Status{Prefixes: []string{}, Steers: []inbound.Steer{}, Announced: []inbound.Route{}, Blocked: []inbound.Blocked{}}
	if s.inbound != nil {
		st = s.inbound()
	}
	// meta.mode is the top-level mode; inbound has its own.
	writeJSON(w, http.StatusOK, struct {
		meta
		Enabled     bool              `json:"enabled"`
		InboundMode string            `json:"inbound_mode,omitempty"`
		Prefixes    []string          `json:"prefixes"`
		Steers      []inbound.Steer   `json:"steers"`
		Announced   []inbound.Route   `json:"announced"`
		Blocked     []inbound.Blocked `json:"blocked"`
		Evaluated   *time.Time        `json:"evaluated,omitempty"`
	}{meta: snap.meta(), Enabled: s.inbound != nil, InboundMode: st.Mode, Prefixes: nz(st.Prefixes),
		Steers: nz(st.Steers), Announced: nz(st.Announced), Blocked: nz(st.Blocked), Evaluated: evaluatedAt(st.Evaluated)})
}

func evaluatedAt(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
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
