package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
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
// role is public: health checks and the SSO sign-in endpoints.
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
		{"GET /api/providers", viewer, s.handleProviders},
		{"GET /api/probes", viewer, s.handleProbes},
		{"GET /api/prefixes", viewer, s.handlePrefixes},
		{"GET /api/decisions", viewer, s.handleDecisions},
		{"GET /api/improvements", viewer, s.handleImprovements},
		{"GET /api/telemetry", viewer, s.handleTelemetry},
		{"GET /api/inbound", viewer, s.handleInbound},
		{"GET /api/exchanges", viewer, s.handleExchanges},
		{"GET /api/federation", viewer, s.handleFederation},
		{"GET /api/ha", viewer, s.handleHA},
		{"GET /api/reports", viewer, s.handleReportList},
		{"GET /api/reports/{name}", viewer, s.handleReport},
		{"GET /api/maintenance", viewer, s.handleMaintenance},
		{"POST /api/maintenance", operator, s.handleMaintenanceOpen},
		{"DELETE /api/maintenance/{id}", operator, s.handleMaintenanceClose},
		{"GET /api/mitigations", viewer, s.handleMitigations},
		{"POST /api/mitigations", operator, s.handleMitigationAdd},
		{"DELETE /api/mitigations/{id}", operator, s.handleMitigationRemove},
		{"GET /api/anomalies", viewer, s.handleAnomalies},
		{"GET /api/troubleshoot", viewer, s.handleToolStatus},
		{"GET /api/troubleshoot/lookingglass", viewer, s.handleLookingGlass},
		{"POST /api/troubleshoot/probe", operator, s.handleToolProbe},
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
		{"GET /api/audit", admin, s.handleAudit},
		{"GET /api/config", admin, s.handleConfig},
		{"POST /api/config/validate", admin, s.handleConfigValidate},
		{"PUT /api/config", admin, s.handleConfigSave},
		{"POST /api/config/wizard", admin, s.handleWizard},
		{"GET /api/dashboards", viewer, s.handleDashboards},
		{"PUT /api/dashboards/{name}", viewer, s.handleDashboardPut},
		{"DELETE /api/dashboards/{name}", viewer, s.handleDashboardDelete},
		{"GET /api/subscriptions", viewer, s.handleSubscriptions},
		{"POST /api/subscriptions/{name}/send", operator, s.handleSubscriptionSend},
		{"GET /auth/login", public, s.handleLogin},
		{"GET /auth/callback", public, s.handleCallback},
		{"POST /auth/logout", public, s.handleLogout},
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
		if errors.Is(err, auth.ErrNoCredentials) && r.Method == http.MethodGet && s.auth.SSOEnabled() &&
			!strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/metrics" {
			http.Redirect(w, r, "/auth/login", http.StatusFound)
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

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if !s.audit.Stored() {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": auth.ErrNoAuditStore.Error()})
		return
	}
	q := plugin.AuditQuery{Limit: 100}
	v := r.URL.Query()
	if l := v.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > maxAuditRows {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be 1-" + strconv.Itoa(maxAuditRows)})
			return
		}
		q.Limit = n
	}
	for key, dst := range map[string]*time.Time{"from": &q.From, "to": &q.To} {
		if t := v.Get(key); t != "" {
			at, err := time.Parse(time.RFC3339, t)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": key + ": want RFC 3339"})
				return
			}
			*dst = at
		}
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

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if user, ok := s.auth.Logout(w, r); ok {
		s.record(r, auth.Principal{User: user, Method: auth.MethodSSO}, "auth.logout", user, "", http.StatusNoContent)
	}
	w.WriteHeader(http.StatusNoContent)
}
