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
	"bytes"
	"context"
	"crypto/rand"
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
	"strings"
	"sync/atomic"
	"time"

	"github.com/GrandArcher/Packeteer/internal/anomaly"
	"github.com/GrandArcher/Packeteer/internal/atlas"
	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/eventlog"
	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/export"
	"github.com/GrandArcher/Packeteer/internal/federation"
	"github.com/GrandArcher/Packeteer/internal/inbound"
	"github.com/GrandArcher/Packeteer/internal/linkout"
	"github.com/GrandArcher/Packeteer/internal/ringlg"
	"github.com/GrandArcher/Packeteer/internal/troubleshoot"
	"github.com/GrandArcher/Packeteer/internal/verify"
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
	// Events keeps recent events for GET /api/events (#173). Nil makes
	// that endpoint answer 404.
	Events *eventlog.Log
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
	// Verification lists the steer checks (#305). Nil means verify is off.
	Verification func() []verify.Result
	// Mitigation is threat mitigation (#28). Nil means it is not
	// configured.
	Mitigation MitigationControl
	// Anomaly is traffic anomaly detection (#33). Nil means it is not
	// configured.
	Anomaly func() anomaly.Status
	// Leaks is the leak watch (#199). Nil means it is not enabled.
	Leaks LeakControl
	// Federation is the central view of every instance (#30). Nil means
	// the instance runs standalone.
	Federation func() federation.Status
	// FederationPush pushes config sections to the federation peers
	// (#137). Nil when federation or the config editor is off.
	FederationPush FederationPusher
	// HA is the active/standby elector's view (#31). Nil means a single
	// instance, always active.
	HA func() plugin.ElectorStatus
	// Export reports exporter delivery counts (#207). Nil means no
	// exporter is configured and /metrics has no packeteer_export_* series.
	Export func() []export.Stat
	// ConfigEditor is the validated config editor (#34). Nil when
	// http.config_editor is off.
	ConfigEditor ConfigEditor
	// FirstRun is the persisted first-run setup state (#416). Nil unless
	// the config editor is on only because setup is pending.
	FirstRun FirstRun
	// Dashboards keeps custom dashboards (#34). Nil when the storage
	// plugin does not keep them.
	Dashboards plugin.DashboardStore
	// Subscriptions is the report subscription scheduler (#34). Nil when
	// none are configured.
	Subscriptions Subscriptions
	// Setup describes the loaded config for the dashboard's first-run
	// checklist (#49).
	Setup Setup
	// Upgrade is the version check, upgrade, and rollback (#196). Nil when
	// upgrade.enabled is off.
	Upgrade UpgradeControl
	// Linkouts builds the "open in" links (#211). Nil uses the defaults.
	Linkouts *linkout.Set
	// RingLG answers the NLNOG RING panel (#283). Nil or disabled is off.
	RingLG *ringlg.Client
	// Atlas answers the RIPE Atlas panel and on-demand measurements
	// (#213). Nil or disabled is off.
	Atlas *atlas.Client
	// Usage reads the persisted 95th-percentile samples for the Commit &
	// Cost page (#174). Nil when the storage plugin keeps none.
	Usage UsageReader
	// System reads the configured plugins and their latest results for
	// the System page (#184). Nil lists only what the snapshot knows.
	System func() SystemFacts
}

// Server is an HTTP server. Handler serves the routes without listening,
// which is what tests use. Start binds Addr.
type Server struct {
	addr         string
	user         string
	password     string
	auth         *auth.Service
	audit        *auth.Auditor
	events       *eventlog.Log
	allowFrom    []netip.Prefix
	snap         func() Snapshot
	maint        MaintenanceControl
	reports      ReportSource
	tools        *troubleshoot.Tools
	inbound      func() inbound.Status
	verification func() []verify.Result
	mitigation   MitigationControl
	anomaly      func() anomaly.Status
	leaks        LeakControl
	federation   func() federation.Status
	fedPush      FederationPusher
	ha           func() plugin.ElectorStatus
	export       func() []export.Stat
	editor       ConfigEditor
	firstRun     FirstRun
	dashboards   plugin.DashboardStore
	subs         Subscriptions
	upgrade      UpgradeControl
	linkouts     *linkout.Set
	ringLG       *ringlg.Client
	atlas        *atlas.Client
	sysFacts     func() SystemFacts
	usage        UsageReader
	setup        atomic.Pointer[Setup]
	// suggest lists next hops the operator may accept as a draft provider
	// row (#102). Nil means there is nothing to suggest. It must not write
	// config or announce.
	suggest atomic.Value
	// searchRIB is the learned RIB the global search reads (#172). Nil
	// until SetSearchRIB.
	searchRIB atomic.Pointer[SearchRIB]
	searches  searchLimiters
	// provStats is the per-provider measurement read (GET
	// /api/providers/stats). Nil until SetProviderStats. It never announces.
	provStats atomic.Pointer[ProviderStats]
	// preflight is the onboarding checks (#221). Nil until SetPreflight.
	// Running them sends TTL-limited probes only; they never announce.
	preflight atomic.Pointer[PreflightControl]
	// blast is the blast-radius preview (#227). Nil until SetBlast.
	blast atomic.Pointer[BlastControl]
	// blastKey signs preview tokens; a restart invalidates them.
	blastKey [32]byte
	blastNow func() time.Time
	// whatIf replays stored decision rounds (#204). Nil until SetWhatIf.
	whatIf atomic.Pointer[WhatIfControl]
	// exMembers is the member comparison of the exchange view (#156). Nil
	// until SetExchangeMembers.
	exMembers atomic.Pointer[ExchangeMembers]
	// ixpMembers is the IX-F import (#161). Nil until SetIXPMembers.
	// Read at request time. It never announces.
	ixpMembers atomic.Value
	// ixpFabric is the fabric prober (#162). Nil until SetIXPFabric.
	// Read at request time. It never announces.
	ixpFabric atomic.Value
	// lookup is the PeeringDB / IX-F directory (#153). Nil until SetLookup.
	// Read at request time. It never announces.
	lookup atomic.Value
	// ixpRouteServers is the Birdseye watch (#164). Nil until
	// SetIXPRouteServers. Read at request time. It never announces.
	ixpRouteServers atomic.Value
	// ixpCorrelation is the fabric incident correlator (#163). Nil until
	// SetIXPCorrelation. Read at request time. It never announces.
	ixpCorrelation atomic.Value
	// herd is opt-in measurement sharing (#260). Nil until SetHerd. It
	// never announces and never feeds a decision.
	herd atomic.Value
	// outside is the herd dashboard's outside sources (#296). Nil until
	// SetHerdOutside.
	outside atomic.Value
	// ixpSites is the multi-site fabric health view (#167). Nil until
	// SetIXPSites. Read at request time. It never announces.
	ixpSites atomic.Value
	// explainer is the decision explanations (#201). Nil until
	// SetExplainer.
	explainer atomic.Value
	// quarantine releases a flap-quarantined prefix (#228). Nil until
	// SetQuarantine.
	quarantine atomic.Value
	// candidates is the Protection form's prefix picker (#131).
	candidates atomic.Value
	// rpkiStatus is the health of the rpki.sources (#200). Nil until
	// SetRPKIStatus.
	rpkiStatus atomic.Value
	// rpkiDisplay is the learned-path lookup with the display fallback
	// (#200). Nil until SetRPKIDisplay.
	rpkiDisplay atomic.Value
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

	// writeTimeout bounds a request from the end of its headers to the last
	// byte written, so a client that stops reading cannot hold a connection.
	writeTimeout time.Duration
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
	s := &Server{addr: opt.Addr, user: opt.User, password: opt.Password, auth: opt.Auth, audit: opt.Audit, events: opt.Events, allowFrom: opt.AllowFrom, snap: opt.Snapshot, maint: opt.Maintenance, reports: opt.Reports, tools: opt.Tools, inbound: opt.Inbound, verification: opt.Verification, mitigation: opt.Mitigation, anomaly: opt.Anomaly, leaks: opt.Leaks, federation: opt.Federation, fedPush: opt.FederationPush, ha: opt.HA, export: opt.Export,
		editor: opt.ConfigEditor, firstRun: opt.FirstRun, dashboards: opt.Dashboards, subs: opt.Subscriptions, upgrade: opt.Upgrade, log: opt.Logger}
	setup := opt.Setup
	s.setup.Store(&setup)
	_, _ = rand.Read(s.blastKey[:])
	s.blastNow = time.Now
	s.linkouts = opt.Linkouts
	s.ringLG = opt.RingLG
	s.atlas = opt.Atlas
	s.sysFacts = opt.System
	s.usage = opt.Usage
	if s.linkouts == nil {
		s.linkouts = linkout.New(linkout.Config{})
	}
	s.writeTimeout = writeTimeout
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

// SetQuarantine installs the release handle for the flap quarantine
// (#228). It is stored after New, once the decision engine exists.
func (s *Server) SetQuarantine(c QuarantineControl) {
	if s == nil {
		return
	}
	s.quarantine.Store(c)
}

// writeTimeout outlasts the slowest handler, an on-demand tool bounded by
// toolTimeout, plus time to send its output. No endpoint streams a
// response.
const writeTimeout = toolTimeout + 30*time.Second

// Handler is the read-only API and dashboard.
func (s *Server) Handler() http.Handler { return s.handler }

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
		WriteTimeout:      s.writeTimeout,
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

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(s.metricsText(r.Context()))
}

// MetricSamples is every series GET /metrics renders now, for the metrics
// export stream (#287).
func (s *Server) MetricSamples(ctx context.Context) []plugin.MetricSample {
	return parseMetrics(s.metricsText(ctx))
}

func (s *Server) metricsText(ctx context.Context) []byte {
	var w bytes.Buffer
	_, _ = w.Write(Metrics(s.snapshot()))
	_, _ = w.Write(RuntimeMetrics())
	if s.mitigation != nil {
		_, _ = w.Write(MitigationMetrics(s.mitigation.Status()))
	}
	if s.anomaly != nil {
		_, _ = w.Write(AnomalyMetrics(s.anomaly()))
	}
	if s.leaks != nil {
		_, _ = w.Write(LeakMetrics(s.leaks.Status()))
	}
	if fn, _ := s.rpkiStatus.Load().(func() []plugin.RPKIStatus); fn != nil {
		_, _ = w.Write(RPKIMetrics(fn(), time.Now()))
	}
	if s.ha != nil {
		_, _ = w.Write(HAMetrics(s.ha()))
	}
	if s.export != nil {
		_, _ = w.Write(ExportMetrics(s.export()))
	}
	if p := s.preflightControl(); p != nil {
		if rep, ok := p.Latest(); ok {
			_, _ = w.Write(PreflightMetrics(rep))
		}
	}
	if v, ok := s.lookupView(); ok && v.Configured {
		_, _ = w.Write(LookupMetrics(v, time.Now()))
	}
	if v, ok := s.ixpMemberView(); ok && v.Configured {
		_, _ = w.Write(IXPMemberMetrics(v, time.Now()))
	}
	if v, ok := s.ixpFabricView(); ok && v.Configured {
		_, _ = w.Write(IXPFabricMetrics(v, time.Now()))
		_, _ = w.Write(IXPMemberFabricMetrics(v))
	}
	if src, ok := s.ixpRouteServerSource(); ok {
		_, _ = w.Write(IXPRouteServerMetrics(src.view(), time.Now()))
	}
	if v, ok := s.ixpCorrelationView(); ok && v.Configured {
		_, _ = w.Write(IXPCorrelationMetrics(v))
	}
	if v, ok := s.ixpSitesView(); ok {
		_, _ = w.Write(IXPSitesMetrics(v))
	}
	if src := s.herdSource(); src != nil {
		_, _ = w.Write(HerdMetrics(src.Status(ctx)))
	}
	return w.Bytes()
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
	imps := withASNames(snap.Improvements, snap.Providers, s.tools.ASNames())
	writeJSON(w, http.StatusOK, struct {
		meta
		Improvements []Improvement `json:"improvements"`
	}{meta: snap.meta(), Improvements: imps})
}

// withASNames returns a copy of imps with each origin AS named: a name an
// earlier whois lookup returned, else the provider that uses that AS.
func withASNames(imps []Improvement, providers []Provider, whois map[uint32]string) []Improvement {
	out := make([]Improvement, len(imps))
	copy(out, imps)
	for i := range out {
		if name := whois[out[i].ASN]; name != "" {
			out[i].ASName = name
			continue
		}
		for _, pr := range providers {
			if out[i].ASN != 0 && (pr.ASN == out[i].ASN || pr.PeerASN == out[i].ASN) {
				out[i].ASName = pr.Name
				break
			}
		}
	}
	return out
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
		// PushEnabled tells the dashboard that an admin can push settings.
		PushEnabled bool `json:"push_enabled"`
	}{meta: snap.meta(), Status: st, PushEnabled: s.fedPush != nil && s.writesEnabled()})
}

// FederationPusher pushes the named config sections of this instance's
// file to the named federation peers (all peers when none are named) and
// reports each peer's answer (#137).
type FederationPusher func(ctx context.Context, sections, peers []string) (federation.PushReport, error)

type fedPushRequest struct {
	Sections []string `json:"sections"`
	Peers    []string `json:"peers"`
}

// handleFederationPush sends this instance's thresholds or policies to
// the peers. Each peer validates them like a local PUT /api/config and
// applies them online; one that refuses reports why. It is admin only and
// audited here and on each peer. It never pushes mode, the allowlist, or
// the announcer, and it announces nothing.
func (s *Server) handleFederationPush(w http.ResponseWriter, r *http.Request) {
	if s.fedPush == nil || !s.writesEnabled() {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "settings push needs federation, http.config_editor, and auth or basic auth"})
		return
	}
	var req fedPushRequest
	if !decodeLarge(w, r, &req, 1<<14) {
		return
	}
	rep, err := s.fedPush(r.Context(), req.Sections, req.Peers)
	if err != nil {
		noteAudit(r, "federation", "settings push refused: "+err.Error())
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var detail []string
	for _, p := range rep.Peers {
		detail = append(detail, p.Peer+"="+p.Status)
	}
	noteAudit(r, "federation", "push "+strings.Join(rep.Sections, ",")+" to "+strings.Join(detail, " "))
	writeJSON(w, http.StatusOK, rep)
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
