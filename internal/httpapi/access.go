package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Access control (#32). Every route has a minimum role. With auth
// configured (Options.Auth), a request is authenticated (password,
// token, or SSO session) and must hold that role; without it the server
// keeps the single basic-auth account, which may do everything. Every
// request with an unsafe method, and every denied one, is written to the
// audit log. http.allow_from restricts client addresses in both modes.

// route is one endpoint and the lowest role that may call it. An empty
// role is public: health checks, the sign-in endpoints, and the sign-in
// page with the files it loads (signin.js, shell.js, app.css, logo.png).
// The logo is also the favicon, so it has to load before a session.
type route struct {
	pattern string
	role    plugin.Role
	h       http.HandlerFunc
}

// routeTable is every endpoint the server serves. Tests walk it so that
// every endpoint has an authorization check.
func (s *Server) routeTable() []route {
	const (
		public   = plugin.Role("")
		viewer   = plugin.RoleViewer
		operator = plugin.RoleOperator
		admin    = plugin.RoleAdmin
	)
	files := http.FileServer(http.FS(webRoot))
	return []route{
		{"GET /healthz", public, s.handleHealth},
		{"GET /readyz", public, s.handleReady},
		{"GET /metrics", viewer, s.handleMetrics},
		{"GET /api/overview", viewer, s.handleOverview},
		{"GET /api/system", viewer, s.handleSystem},
		{"GET /api/search", viewer, s.handleSearch},
		{"GET /api/providers", viewer, s.handleProviders},
		{"GET /api/probes", viewer, s.handleProbes},
		{"GET /api/prefixes", viewer, s.handlePrefixes},
		{"GET /api/prefixes/history", viewer, s.handlePrefixHistory},
		{"GET /api/decisions", viewer, s.handleDecisions},
		{"GET /api/improvements", viewer, s.handleImprovements},
		{"GET /api/telemetry", viewer, s.handleTelemetry},
		{"GET /api/commit", viewer, s.handleCommit},
		{"GET /api/inbound", viewer, s.handleInbound},
		{"GET /api/exchanges", viewer, s.handleExchanges},
		{"GET /api/exchanges/member", viewer, s.handleExchangeMember},
		{"GET /api/exchanges/offload", viewer, s.handleExchangeOffload},
		{"GET /api/exchanges/potential-peers", viewer, s.handleExchangePotentialPeers},
		{"GET /api/ixp/members", viewer, s.handleIXPMembers},
		{"GET /api/ixp/probes", viewer, s.handleIXPProbes},
		{"GET /api/ixp/routeservers", viewer, s.handleIXPRouteServers},
		{"GET /api/ixp/routeservers/history", viewer, s.handleIXPRouteServerHistory},
		{"GET /api/linkouts", viewer, s.handleLinkouts},
		{"GET /api/federation", viewer, s.handleFederation},
		{"GET /api/ha", viewer, s.handleHA},
		{"GET /api/reports", viewer, s.handleReportList},
		{"GET /api/reports/{name}", viewer, s.handleReport},
		{"GET /api/maintenance", viewer, s.handleMaintenance},
		{"POST /api/maintenance", operator, s.handleMaintenanceOpen},
		{"DELETE /api/maintenance/{id}", operator, s.handleMaintenanceClose},
		{"GET /api/mitigations", viewer, s.handleMitigations},
		{"GET /api/mitigations/candidates", viewer, s.handleMitigationCandidates},
		{"POST /api/mitigations", operator, s.handleMitigationAdd},
		{"DELETE /api/mitigations/{id}", operator, s.handleMitigationRemove},
		{"GET /api/anomalies", viewer, s.handleAnomalies},
		{"GET /api/quarantine", viewer, s.handleQuarantine},
		{"POST /api/quarantine/release", operator, s.handleQuarantineRelease},
		{"GET /api/leaks", viewer, s.handleLeaks},
		{"POST /api/leaks/clear", operator, s.handleLeakClear},
		{"GET /api/troubleshoot", viewer, s.handleToolStatus},
		{"GET /api/troubleshoot/lookingglass", viewer, s.handleLookingGlass},
		{"POST /api/troubleshoot/probe", operator, s.handleToolProbe},
		{"POST /api/troubleshoot/optimize", operator, s.handleToolOptimize},
		{"POST /api/troubleshoot/traceroute", operator, s.handleToolTrace},
		{"POST /api/troubleshoot/whois", operator, s.handleToolWhois},
		{"GET /api/me", viewer, s.handleMe},
		{"GET /api/tokens", viewer, s.handleTokens},
		{"POST /api/tokens", viewer, s.handleTokenCreate},
		{"DELETE /api/tokens/{id}", viewer, s.handleTokenRevoke},
		{"GET /api/users", admin, s.handleUsers},
		{"POST /api/users", admin, s.handleUserCreate},
		{"PATCH /api/users/{name}", admin, s.handleUserUpdate},
		{"DELETE /api/users/{name}", admin, s.handleUserDelete},
		{"GET /api/events", viewer, s.handleEvents},
		{"GET /api/audit", admin, s.handleAudit},
		{"GET /api/config", admin, s.handleConfig},
		{"POST /api/config/validate", admin, s.handleConfigValidate},
		{"PUT /api/config", admin, s.handleConfigSave},
		{"POST /api/config/wizard", admin, s.handleWizard},
		{"POST /api/config/form", admin, s.handleConfigForm},
		{"GET /api/config/suggestions", admin, s.handleSuggestions},
		{"GET /api/upgrade", admin, s.handleUpgrade},
		{"POST /api/upgrade/check", admin, s.handleUpgradeCheck},
		{"POST /api/upgrade/apply", admin, s.handleUpgradeApply},
		{"POST /api/upgrade/rollback", admin, s.handleUpgradeRollback},
		{"GET /api/dashboards", viewer, s.handleDashboards},
		{"PUT /api/dashboards/{name}", viewer, s.handleDashboardPut},
		{"DELETE /api/dashboards/{name}", viewer, s.handleDashboardDelete},
		{"GET /api/subscriptions", viewer, s.handleSubscriptions},
		{"POST /api/subscriptions/{name}/send", operator, s.handleSubscriptionSend},
		{"GET /auth/login", public, s.handleLogin},
		{"GET /auth/callback", public, s.handleCallback},
		{"GET /auth/signin", public, s.handleSigninInfo},
		{"POST /auth/signin", public, s.handleSignin},
		{"POST /auth/logout", public, s.handleLogout},
		{"GET /signin.html", public, serveFile("signin.html")},
		{"GET /signin.js", public, serveFile("signin.js")},
		{"GET /shell.js", public, serveFile("shell.js")},
		{"GET /app.css", public, serveFile("app.css")},
		{"GET /logo.png", public, serveFile("logo.png")},
		{"GET /prefix/", viewer, serveFile("prefix.html")},
		{"GET /", viewer, files.ServeHTTP},
	}
}

// methodNone marks the anonymous caller when neither auth nor basic
// auth is on.
const methodNone = "none"

type principalKey struct{}
type noteKey struct{}

// auditNote lets a handler name what it changed.
type auditNote struct {
	target string
	detail string
}

func principalFrom(ctx context.Context) auth.Principal {
	p, _ := ctx.Value(principalKey{}).(auth.Principal)
	return p
}

// noteAudit sets the target and detail of the request's audit record.
func noteAudit(r *http.Request, target, detail string) {
	if n, ok := r.Context().Value(noteKey{}).(*auditNote); ok {
		n.target, n.detail = target, detail
	}
}

func unsafeMethod(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// guard authenticates and authorizes one route, then audits it.
func (s *Server) guard(rt route) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := s.authorize(w, r, rt)
		if !ok {
			return
		}
		ctx := context.WithValue(r.Context(), principalKey{}, p)
		if !unsafeMethod(r.Method) || rt.role == "" {
			rt.h(w, r.WithContext(ctx))
			return
		}
		note := &auditNote{target: r.PathValue("id")}
		if n := r.PathValue("name"); n != "" {
			note.target = n
		}
		rec := &statusRecorder{ResponseWriter: w}
		rt.h(rec, r.WithContext(context.WithValue(ctx, noteKey{}, note)))
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		// With no auth at all the caller is anonymous: a refused request
		// changed nothing, and recording it would let anyone who reaches
		// the port fill the log.
		if p.Method == methodNone && rec.status >= 400 {
			return
		}
		s.record(r, p, rt.pattern, note.target, note.detail, rec.status)
	})
}

func (s *Server) record(r *http.Request, p auth.Principal, action, target, detail string, status int) {
	if s.audit == nil {
		return
	}
	result := auth.ResultOK
	switch {
	case status == http.StatusForbidden || status == http.StatusUnauthorized:
		result = auth.ResultDenied
	case status >= 400:
		result = auth.ResultFailed
	}
	actor := p.User
	if actor == "" {
		actor = "anonymous"
	}
	s.audit.Record(r.Context(), plugin.AuditRecord{
		Actor: actor, Role: p.Role, Method: p.Method, Remote: remoteString(r), Action: action,
		Target: target, Result: result, Status: status, Detail: detail,
	})
}

func remoteString(r *http.Request) string {
	if a := auth.RemoteIP(r); a.IsValid() {
		return a.String()
	}
	return ""
}

// authorize returns the caller, or writes the refusal.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, rt route) (auth.Principal, bool) {
	if s.auth == nil {
		// Without auth, the one basic-auth account (checked by withAuth
		// for every route) may do everything; the write handlers still
		// refuse changes when basic auth is off.
		if s.user != "" {
			return auth.Principal{User: s.user, Role: plugin.RoleAdmin, Method: auth.MethodBasic}, true
		}
		return auth.Principal{Method: methodNone}, true
	}
	if rt.role == "" {
		return auth.Principal{}, true
	}
	p, err := s.auth.Authenticate(r)
	switch {
	case err == nil:
	case errors.Is(err, auth.ErrThrottled):
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": err.Error()})
		return p, false
	case errors.Is(err, auth.ErrUnavailable):
		s.log.Error("http auth: user store", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "user store unavailable"})
		return p, false
	default:
		if errors.Is(err, auth.ErrNoCredentials) && r.Method == http.MethodGet && cookieUsable(r) &&
			!strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/metrics" {
			http.Redirect(w, r, "/signin.html", http.StatusFound)
			return p, false
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="packeteer"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return p, false
	}
	if !p.Role.Allows(rt.role) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: needs role " + string(rt.role)})
		// Denied changes are audited; denied reads are not.
		if unsafeMethod(r.Method) {
			s.record(r, p, rt.pattern, "", "role "+string(p.Role)+" below "+string(rt.role), http.StatusForbidden)
		}
		return p, false
	}
	return p, true
}

// cookieUsable reports whether the browser will keep the Secure session
// cookie: the request came over TLS (directly or through a proxy that
// says so) or the page is on localhost. Elsewhere a redirect to the
// sign-in page would loop, so the basic-auth prompt stays.
func cookieUsable(r *http.Request) bool {
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && ip.IsLoopback()
}

// withAllowFrom refuses clients outside http.allow_from.
func withAllowFrom(allow []netip.Prefix, next http.Handler) http.Handler {
	if len(allow) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := auth.RemoteIP(r)
		for _, p := range allow {
			if ip.IsValid() && p.Contains(ip) {
				next.ServeHTTP(w, r)
				return
			}
		}
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: client address not allowed"})
	})
}

func (s *Server) authMode() string {
	switch {
	case s.auth != nil:
		return "rbac"
	case s.user != "":
		return "basic"
	}
	return "off"
}

// writesEnabled is false when neither auth nor basic auth is on: then
// nobody may change anything through the API.
func (s *Server) writesEnabled() bool { return s.auth != nil || s.user != "" }

func (s *Server) needAuth(w http.ResponseWriter) bool {
	if s.auth == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "users and tokens need auth (auth.enabled and a storage plugin)"})
		return false
	}
	return true
}

func writeAuthError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, auth.ErrInvalid):
		status = http.StatusBadRequest
	case errors.Is(err, auth.ErrExists), errors.Is(err, auth.ErrLastAdmin):
		status = http.StatusConflict
	case errors.Is(err, auth.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, auth.ErrForbidden):
		status = http.StatusForbidden
	case errors.Is(err, auth.ErrUnavailable):
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// decodeJSON reads a small JSON body with no unknown fields.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "content type must be application/json"})
		return false
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body: " + err.Error()})
		return false
	}
	return true
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	writeJSON(w, http.StatusOK, struct {
		Auth string `json:"auth"`
		SSO  bool   `json:"sso"`
		auth.Principal
	}{Auth: s.authMode(), SSO: s.auth.SSOEnabled(), Principal: p})
}

// ---- Users (admin) ----

type userRequest struct {
	Name     string      `json:"name"`
	Role     plugin.Role `json:"role"`
	Password string      `json:"password"`
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if !s.needAuth(w) {
		return
	}
	us, err := s.auth.Users(r.Context())
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": us})
}

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	if !s.needAuth(w) {
		return
	}
	var req userRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	noteAudit(r, req.Name, "role="+string(req.Role))
	u, err := s.auth.CreateUser(r.Context(), req.Name, req.Role, req.Password)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

func (s *Server) handleUserUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.needAuth(w) {
		return
	}
	var up auth.UserUpdate
	if !decodeJSON(w, r, &up) {
		return
	}
	var changed []string
	if up.Role != nil {
		changed = append(changed, "role="+string(*up.Role))
	}
	if up.Password != nil {
		changed = append(changed, "password")
	}
	if up.Disabled != nil {
		changed = append(changed, "disabled="+strconv.FormatBool(*up.Disabled))
	}
	name := r.PathValue("name")
	noteAudit(r, name, strings.Join(changed, " "))
	u, err := s.auth.UpdateUser(r.Context(), name, up)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	if !s.needAuth(w) {
		return
	}
	if err := s.auth.DeleteUser(r.Context(), r.PathValue("name")); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Tokens (own; admin sees all) ----

type tokenRequest struct {
	Name string      `json:"name"`
	Role plugin.Role `json:"role"`
	TTL  string      `json:"ttl"`
}

func (s *Server) handleTokens(w http.ResponseWriter, r *http.Request) {
	if !s.needAuth(w) {
		return
	}
	ts, err := s.auth.Tokens(r.Context(), principalFrom(r.Context()))
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": ts})
}

func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	if !s.needAuth(w) {
		return
	}
	var req tokenRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	var ttl time.Duration
	if req.TTL != "" {
		d, err := time.ParseDuration(req.TTL)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ttl: " + err.Error()})
			return
		}
		ttl = d
	}
	t, secret, err := s.auth.CreateToken(r.Context(), principalFrom(r.Context()), req.Name, req.Role, ttl)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	// The secret is never written to the audit log.
	noteAudit(r, t.ID, "name="+t.Name+" role="+string(t.Role)+" expires="+t.Expires.Format(time.RFC3339))
	writeJSON(w, http.StatusCreated, struct {
		auth.TokenView
		Token string `json:"token"`
	}{TokenView: t, Token: secret})
}

func (s *Server) handleTokenRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.needAuth(w) {
		return
	}
	t, err := s.auth.RevokeToken(r.Context(), principalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		writeAuthError(w, err)
		return
	}
	noteAudit(r, t.ID, "user="+t.User+" name="+t.Name)
	w.WriteHeader(http.StatusNoContent)
}

// ---- Audit log (admin) ----

const maxAuditRows = 1000

// parseRowsAndRange reads limit (1..max) and the RFC 3339 from and to of
// a list request. On a bad value it writes the 400 and returns false.
func parseRowsAndRange(w http.ResponseWriter, r *http.Request, def, max int) (limit int, from, to time.Time, ok bool) {
	v := r.URL.Query()
	limit = def
	if l := v.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > max {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be 1-" + strconv.Itoa(max)})
			return 0, from, to, false
		}
		limit = n
	}
	for key, dst := range map[string]*time.Time{"from": &from, "to": &to} {
		if t := v.Get(key); t != "" {
			at, err := time.Parse(time.RFC3339, t)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": key + ": want RFC 3339"})
				return 0, from, to, false
			}
			*dst = at
		}
	}
	return limit, from, to, true
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if !s.audit.Stored() {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": auth.ErrNoAuditStore.Error()})
		return
	}
	q := plugin.AuditQuery{Limit: 100}
	var ok bool
	if q.Limit, q.From, q.To, ok = parseRowsAndRange(w, r, q.Limit, maxAuditRows); !ok {
		return
	}
	recs, err := s.audit.Query(r.Context(), q)
	if err != nil {
		s.log.Error("audit read", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": nz(recs)})
}

// ---- Single sign-on ----

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.auth.SSOEnabled() {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": auth.ErrNoSSO.Error()})
		return
	}
	if err := s.auth.BeginLogin(w, r); err != nil {
		s.log.Warn("sso sign-in", "err", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "single sign-on unavailable"})
	}
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if !s.auth.SSOEnabled() {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": auth.ErrNoSSO.Error()})
		return
	}
	p, who, err := s.auth.FinishLogin(w, r)
	if err != nil {
		s.log.Warn("sso sign-in refused", "user", who, "err", err)
		s.record(r, auth.Principal{User: who, Method: auth.MethodSSO}, "auth.login", who, err.Error(), http.StatusUnauthorized)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "sign-in refused: " + err.Error()})
		return
	}
	s.record(r, p, "auth.login", p.User, "", http.StatusFound)
	http.Redirect(w, r, "/", http.StatusFound)
}

// serveFile serves one embedded file. The route's role decides who may read it.
func serveFile(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { http.ServeFileFS(w, r, webRoot, name) }
}

// handleSigninInfo tells the sign-in page whether to offer single sign-on
// and which mode to show in the banner. The page cannot read
// /api/overview before a user is signed in.
func (s *Server) handleSigninInfo(w http.ResponseWriter, _ *http.Request) {
	if s.auth == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "sign-in needs auth (auth.enabled and a storage plugin)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sso": s.auth.SSOEnabled(), "mode": s.snapshot().Mode})
}

type signinRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

// handleSignin signs a local user in and sets the session cookie. A wrong
// name or password is one answer for both. Failures are audited with the
// attempted name when it is a valid user name (an admin may read it); the
// password is never logged or audited.
func (s *Server) handleSignin(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "sign-in needs auth (auth.enabled and a storage plugin)"})
		return
	}
	var req signinRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	p, err := s.auth.SignIn(w, r, req.Name, req.Password)
	switch {
	case err == nil:
		s.record(r, p, "auth.login", p.User, "", http.StatusOK)
		writeJSON(w, http.StatusOK, map[string]any{"user": p.User, "role": p.Role})
	case errors.Is(err, auth.ErrThrottled):
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": err.Error()})
	case errors.Is(err, auth.ErrBadCredentials):
		target := ""
		if auth.ValidUserName(req.Name) {
			target = req.Name
		}
		s.record(r, auth.Principal{Method: auth.MethodPassword}, "auth.login", target, "invalid credentials", http.StatusUnauthorized)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid user name or password"})
	default:
		s.log.Error("sign-in", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "sign-in unavailable"})
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if p, ok := s.auth.Logout(w, r); ok {
		s.record(r, p, "auth.logout", p.User, "", http.StatusNoContent)
	}
	w.WriteHeader(http.StatusNoContent)
}
