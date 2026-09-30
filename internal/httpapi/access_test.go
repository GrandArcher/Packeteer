package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/auth/authtest"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func init() { auth.SetHashIterations(1000) }

// rbacEnv is a server with auth on, one user and one token per role, and
// an audit log that also feeds a fake notifier.
type rbacEnv struct {
	h      http.Handler
	srv    *Server
	svc    *auth.Service
	store  *authtest.Store
	events []plugin.Event
	tokens map[plugin.Role]string
	maint  *fakeMaint
}

func newRBAC(t *testing.T, sso plugin.SSO, allow ...string) *rbacEnv {
	t.Helper()
	e := &rbacEnv{store: authtest.New(), tokens: map[plugin.Role]string{}, maint: &fakeMaint{canOpen: true}}
	svc, err := auth.New(auth.Options{Users: e.store, SSO: sso})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	var prefixes []netip.Prefix
	for _, a := range allow {
		prefixes = append(prefixes, netip.MustParsePrefix(a))
	}
	srv, err := New(Options{
		Auth: svc, Audit: auth.NewAuditor(e.store, func(ev plugin.Event) { e.events = append(e.events, ev) }, nil), AllowFrom: prefixes,
		Maintenance: e.maint, Mitigation: newMitControl(t), Snapshot: func() Snapshot { return Assemble(sampleInput()) },
	})
	if err != nil {
		t.Fatal(err)
	}
	e.srv, e.h = srv, srv.Handler()
	ctx := context.Background()
	for _, r := range []plugin.Role{plugin.RoleViewer, plugin.RoleOperator, plugin.RoleAdmin} {
		name := string(r) + "-user"
		if _, err := svc.CreateUser(ctx, name, r, name+"-password"); err != nil {
			t.Fatal(err)
		}
		_, tok, err := svc.CreateToken(ctx, auth.Principal{User: name, Role: r, Method: auth.MethodPassword}, "test", r, 0)
		if err != nil {
			t.Fatal(err)
		}
		e.tokens[r] = tok
	}
	return e
}

func (e *rbacEnv) do(method, path, token, body string, mod ...func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, m := range mod {
		m(req)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func routePath(pattern string) (method, path string) {
	method, path, _ = strings.Cut(pattern, " ")
	path = strings.NewReplacer("{id}", "x", "{name}", "nobody").Replace(path)
	if path == "/api/troubleshoot/lookingglass" {
		path += "?prefix=198.51.100.0/24"
	}
	return method, path
}

func needsRole(rec *httptest.ResponseRecorder) bool {
	return rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), "needs role")
}

// TestAuthzEveryEndpoint walks the route table: every endpoint refuses
// an anonymous caller and a bad token (unless public), refuses each role
// below its minimum, and admits its minimum role and above. Denied
// changes are audited.
func TestAuthzEveryEndpoint(t *testing.T) {
	e := newRBAC(t, nil)
	roles := []plugin.Role{plugin.RoleViewer, plugin.RoleOperator, plugin.RoleAdmin}
	rt := e.srv.routeTable()
	if len(rt) < 39 {
		t.Fatalf("route table has %d routes", len(rt))
	}
	for i, r := range rt {
		method, path := routePath(r.pattern)
		// Bad tokens count toward the per-address throttle: one address
		// per route keeps each under the limit.
		badFrom := func(req *http.Request) { req.RemoteAddr = fmt.Sprintf("203.0.113.%d:1", i+1) }
		body := ""
		if method == http.MethodPost || method == http.MethodPatch {
			body = "{}"
		}
		t.Run(r.pattern, func(t *testing.T) {
			anon := e.do(method, path, "", body)
			bad := e.do(method, path, "pkt_0123456789abcdef_"+strings.Repeat("A", 43), body, badFrom)
			if r.role == "" {
				if anon.Code == http.StatusUnauthorized || needsRole(anon) {
					t.Fatalf("public route refused anonymous: %d %s", anon.Code, anon.Body)
				}
				return
			}
			if anon.Code != http.StatusUnauthorized || !strings.Contains(anon.Header().Get("WWW-Authenticate"), "Basic") {
				t.Fatalf("anonymous: %d %s", anon.Code, anon.Body)
			}
			if bad.Code != http.StatusUnauthorized {
				t.Fatalf("bad token: %d", bad.Code)
			}
			for _, role := range roles {
				before := len(e.store.Records())
				rec := e.do(method, path, e.tokens[role], body)
				allowed := role.Allows(r.role)
				switch {
				case allowed && (rec.Code == http.StatusUnauthorized || needsRole(rec)):
					t.Errorf("%s refused: %d %s", role, rec.Code, rec.Body)
				case !allowed && !needsRole(rec):
					t.Errorf("%s admitted: %d %s", role, rec.Code, rec.Body)
				}
				recs := e.store.Records()
				if unsafeMethod(method) {
					if len(recs) != before+1 {
						t.Fatalf("%s: %d audit records for a change, want 1", role, len(recs)-before)
					}
					last := recs[len(recs)-1]
					if last.Actor != string(role)+"-user" || last.Action != r.pattern || last.Method != auth.MethodToken {
						t.Errorf("%s: audit %+v", role, last)
					}
					if !allowed && last.Result != auth.ResultDenied {
						t.Errorf("%s: denied change audited as %s", role, last.Result)
					}
				} else if len(recs) != before {
					t.Errorf("%s: a read was audited", role)
				}
			}
		})
	}
}

func TestAuthUsersTokensAuditAPI(t *testing.T) {
	e := newRBAC(t, nil)
	admin, op, viewer := e.tokens[plugin.RoleAdmin], e.tokens[plugin.RoleOperator], e.tokens[plugin.RoleViewer]

	// An admin creates a user; the password is never returned.
	rec := e.do("POST", "/api/users", admin, `{"name":"alice","role":"operator","password":"alice-password-1"}`)
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), "alice-password-1") || strings.Contains(rec.Body.String(), "pbkdf2") {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("POST", "/api/users", admin, `{"name":"alice","role":"operator","password":"alice-password-1"}`); rec.Code != http.StatusConflict {
		t.Fatalf("dup: %d", rec.Code)
	}
	if rec := e.do("POST", "/api/users", admin, `{"name":"bob","role":"root","password":"bob-password-12"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad role: %d", rec.Code)
	}
	if rec := e.do("POST", "/api/users", admin, `{"name":"bob","role":"viewer","password":"bob-password-12","extra":1}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", rec.Code)
	}
	// alice signs in with her password and opens a maintenance window.
	rec = e.do("POST", "/api/maintenance", "", `{"providers":["transit-a"],"duration":"30m","reason":"fiber work"}`,
		func(r *http.Request) { r.SetBasicAuth("alice", "alice-password-1") })
	if rec.Code != http.StatusCreated {
		t.Fatalf("alice maintenance: %d %s", rec.Code, rec.Body)
	}
	// /api/me reflects the caller.
	var me struct {
		Auth, User, Method string
		Role               plugin.Role
	}
	rec = e.do("GET", "/api/me", "", "", func(r *http.Request) { r.SetBasicAuth("alice", "alice-password-1") })
	_ = json.Unmarshal(rec.Body.Bytes(), &me)
	if me.Auth != "rbac" || me.User != "alice" || me.Role != plugin.RoleOperator || me.Method != auth.MethodPassword {
		t.Fatalf("me: %s", rec.Body)
	}
	// alice mints a viewer token; its secret is shown once and not audited.
	rec = e.do("POST", "/api/tokens", "", `{"name":"grafana","role":"viewer","ttl":"24h"}`, func(r *http.Request) { r.SetBasicAuth("alice", "alice-password-1") })
	var tok struct {
		ID, Token string
		Role      plugin.Role
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	if rec.Code != http.StatusCreated || !strings.HasPrefix(tok.Token, "pkt_") || tok.Role != plugin.RoleViewer {
		t.Fatalf("token: %d %s", rec.Code, rec.Body)
	}
	for _, r := range e.store.Records() {
		if strings.Contains(r.Detail+r.Target, tok.Token) {
			t.Fatal("token secret in the audit log")
		}
	}
	// The viewer token reads but cannot change.
	if rec := e.do("GET", "/api/providers", tok.Token, ""); rec.Code != http.StatusOK {
		t.Fatalf("viewer read: %d", rec.Code)
	}
	if rec := e.do("POST", "/api/maintenance", tok.Token, `{"providers":["transit-a"],"duration":"30m"}`); !needsRole(rec) {
		t.Fatalf("viewer write: %d", rec.Code)
	}
	// A token cannot mint tokens, nor a token above its user.
	if rec := e.do("POST", "/api/tokens", tok.Token, `{"name":"again"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("token minted: %d", rec.Code)
	}
	if rec := e.do("POST", "/api/tokens", "", `{"name":"up","role":"admin"}`, func(r *http.Request) { r.SetBasicAuth("alice", "alice-password-1") }); rec.Code != http.StatusForbidden {
		t.Fatalf("escalation: %d", rec.Code)
	}
	// Tokens are private to their user; admins see all.
	var list struct{ Tokens []auth.TokenView }
	rec = e.do("GET", "/api/tokens", viewer, "")
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Tokens) != 1 || list.Tokens[0].User != "viewer-user" {
		t.Fatalf("viewer tokens: %s", rec.Body)
	}
	rec = e.do("GET", "/api/tokens", admin, "")
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Tokens) != 4 {
		t.Fatalf("admin tokens: %s", rec.Body)
	}
	if rec := e.do("DELETE", "/api/tokens/"+tok.ID, op, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("revoke other's: %d", rec.Code)
	}
	if rec := e.do("DELETE", "/api/tokens/"+tok.ID, admin, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("admin revoke: %d", rec.Code)
	}
	if rec := e.do("GET", "/api/providers", tok.Token, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token: %d", rec.Code)
	}
	// Demote, disable, and delete through the API; the last admin stays.
	if rec := e.do("PATCH", "/api/users/alice", admin, `{"role":"viewer"}`); rec.Code != http.StatusOK {
		t.Fatalf("demote: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("POST", "/api/maintenance", "", `{"providers":["transit-a"],"duration":"30m"}`, func(r *http.Request) { r.SetBasicAuth("alice", "alice-password-1") }); !needsRole(rec) {
		t.Fatalf("demoted alice wrote: %d", rec.Code)
	}
	if rec := e.do("PATCH", "/api/users/alice", admin, `{"disabled":true}`); rec.Code != http.StatusOK {
		t.Fatalf("disable: %d", rec.Code)
	}
	if rec := e.do("GET", "/api/providers", "", "", func(r *http.Request) { r.SetBasicAuth("alice", "alice-password-1") }); rec.Code != http.StatusUnauthorized {
		t.Fatalf("disabled alice read: %d", rec.Code)
	}
	if rec := e.do("DELETE", "/api/users/alice", admin, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec := e.do("PATCH", "/api/users/admin-user", admin, `{"role":"viewer"}`); rec.Code != http.StatusConflict {
		t.Fatalf("last admin demoted: %d", rec.Code)
	}
	if rec := e.do("DELETE", "/api/users/ghost", admin, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("ghost: %d", rec.Code)
	}
	var users struct{ Users []auth.UserView }
	rec = e.do("GET", "/api/users", admin, "")
	_ = json.Unmarshal(rec.Body.Bytes(), &users)
	if len(users.Users) != 3 || strings.Contains(rec.Body.String(), "pbkdf2") {
		t.Fatalf("users: %s", rec.Body)
	}

	// The audit log has every change, with who, and each went to the
	// notifiers as audit.recorded.
	var audit struct{ Records []plugin.AuditRecord }
	rec = e.do("GET", "/api/audit?limit=1000", admin, "")
	_ = json.Unmarshal(rec.Body.Bytes(), &audit)
	if rec.Code != http.StatusOK || len(audit.Records) == 0 {
		t.Fatalf("audit: %d %s", rec.Code, rec.Body)
	}
	find := func(action, actor, result string) plugin.AuditRecord {
		for _, r := range audit.Records {
			if r.Action == action && r.Actor == actor && r.Result == result {
				return r
			}
		}
		t.Fatalf("no audit record %s by %s (%s) in %+v", action, actor, result, audit.Records)
		return plugin.AuditRecord{}
	}
	if r := find("POST /api/maintenance", "alice", auth.ResultOK); r.Target != "api-1" || !strings.Contains(r.Detail, "transit-a") || r.Remote != "192.0.2.1" {
		t.Fatalf("maintenance record: %+v", r)
	}
	find("POST /api/maintenance", "alice", auth.ResultDenied)
	find("POST /api/users", "admin-user", auth.ResultOK)
	find("PATCH /api/users/{name}", "admin-user", auth.ResultOK)
	find("DELETE /api/users/{name}", "admin-user", auth.ResultOK)
	find("PATCH /api/users/{name}", "admin-user", auth.ResultFailed)
	find("DELETE /api/tokens/{id}", "admin-user", auth.ResultOK)
	if len(e.events) != len(e.store.Records()) {
		t.Fatalf("%d events for %d audit records", len(e.events), len(e.store.Records()))
	}
	for _, ev := range e.events {
		if ev.Kind != plugin.EventAudit || ev.Fields["actor"] == "" || ev.Fields["action"] == "" {
			t.Fatalf("event: %+v", ev)
		}
	}
	if rec := e.do("GET", "/api/audit?limit=0", admin, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad limit: %d", rec.Code)
	}
	if rec := e.do("GET", "/api/audit?from=yesterday", admin, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad from: %d", rec.Code)
	}
}

func TestAuthAllowFromAndCrossOrigin(t *testing.T) {
	e := newRBAC(t, nil, "198.51.100.0/24")
	// httptest requests come from 192.0.2.1: outside the list, even for
	// health checks and with valid credentials.
	for _, p := range []string{"/healthz", "/api/providers"} {
		if rec := e.do("GET", p, e.tokens[plugin.RoleAdmin], ""); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "address") {
			t.Fatalf("%s outside allow_from: %d %s", p, rec.Code, rec.Body)
		}
	}
	inside := func(r *http.Request) { r.RemoteAddr = "198.51.100.20:5000" }
	if rec := e.do("GET", "/api/providers", e.tokens[plugin.RoleViewer], "", inside); rec.Code != http.StatusOK {
		t.Fatalf("inside: %d", rec.Code)
	}
	// A browser's cross-site change is refused whatever the credentials.
	rec := e.do("POST", "/api/maintenance", e.tokens[plugin.RoleAdmin], `{"providers":["transit-a"],"duration":"30m"}`, inside,
		func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") })
	if rec.Code != http.StatusForbidden || len(e.maint.opened) != 0 {
		t.Fatalf("cross-site: %d %v", rec.Code, e.maint.opened)
	}
	// The same over allow_from on the legacy basic-auth server.
	s, err := New(Options{User: "ops", Password: "secret", AllowFrom: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/healthz", nil)
	req.RemoteAddr = "[2001:db8::5]:443"
	req.SetBasicAuth("ops", "secret")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("legacy inside: %d", rr.Code)
	}
}

func TestAuthThrottleAndStoreDown(t *testing.T) {
	e := newRBAC(t, nil)
	for i := 0; i < 10; i++ {
		e.do("GET", "/api/providers", "", "", func(r *http.Request) { r.SetBasicAuth("viewer-user", "wrong-password!") })
	}
	if rec := e.do("GET", "/api/providers", e.tokens[plugin.RoleViewer], ""); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("throttle: %d", rec.Code)
	}
	e2 := newRBAC(t, nil)
	e2.store.Fail = true
	if rec := e2.do("GET", "/api/providers", e2.tokens[plugin.RoleViewer], ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("store down: %d", rec.Code)
	}
	// Health checks do not need the store.
	if rec := e2.do("GET", "/healthz", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("healthz with store down: %d", rec.Code)
	}
}

type testSSO struct {
	plugin.Base
	id plugin.SSOIdentity
}

func (f *testSSO) AuthURL(_ context.Context, state, _, _ string) (string, error) {
	return "https://idp.example.net/authorize?state=" + url.QueryEscape(state), nil
}

func (f *testSSO) Exchange(context.Context, string, string, string) (plugin.SSOIdentity, error) {
	return f.id, nil
}

func TestAuthSSOFlow(t *testing.T) {
	sso := &testSSO{id: plugin.SSOIdentity{User: "noc@example.net", Role: plugin.RoleOperator}}
	e := newRBAC(t, sso)
	// A browser without a session is sent to sign in; the API is not.
	if rec := e.do("GET", "/", "", ""); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/auth/login" {
		t.Fatalf("dashboard: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if rec := e.do("GET", "/api/providers", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("api: %d", rec.Code)
	}
	rec := e.do("GET", "/auth/login", "", "")
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "https://idp.example.net/authorize") {
		t.Fatalf("login: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	var state *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.StateCookie {
			state = c
		}
	}
	rec = e.do("GET", "/auth/callback?code=c&state="+url.QueryEscape(state.Value), "", "", func(r *http.Request) { r.AddCookie(state) })
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("callback: %d %s", rec.Code, rec.Body)
	}
	var sess *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.SessionCookie && c.Value != "" {
			sess = c
		}
	}
	withSess := func(r *http.Request) { r.AddCookie(sess) }
	if rec := e.do("GET", "/api/me", "", "", withSess); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"method":"sso"`) {
		t.Fatalf("me: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("POST", "/api/maintenance", "", `{"providers":["transit-a"],"duration":"30m"}`, withSess); rec.Code != http.StatusCreated {
		t.Fatalf("sso operator write: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("GET", "/api/users", "", "", withSess); !needsRole(rec) {
		t.Fatalf("sso operator read users: %d", rec.Code)
	}
	// Replaying the callback fails and is audited.
	if rec := e.do("GET", "/auth/callback?code=c&state="+url.QueryEscape(state.Value), "", "", func(r *http.Request) { r.AddCookie(state) }); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay: %d", rec.Code)
	}
	if rec := e.do("POST", "/auth/logout", "", "", withSess); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", rec.Code)
	}
	if rec := e.do("GET", "/api/me", "", "", withSess); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after logout: %d", rec.Code)
	}
	var login, failed, logout bool
	for _, r := range e.store.Records() {
		switch {
		case r.Action == "auth.login" && r.Result == auth.ResultOK && r.Actor == "noc@example.net" && r.Role == plugin.RoleOperator:
			login = true
		case r.Action == "auth.login" && r.Result == auth.ResultDenied:
			failed = true
		case r.Action == "auth.logout" && r.Actor == "noc@example.net":
			logout = true
		}
	}
	if !login || !failed || !logout {
		t.Fatalf("sso audit: login %v failed %v logout %v: %+v", login, failed, logout, e.store.Records())
	}
}

// TestLegacyModeUnchanged: without auth, the basic-auth account behaves as
// before, users and tokens are not served, and changes are still audited.
func TestLegacyModeUnchanged(t *testing.T) {
	if _, err := New(Options{User: "ops", Password: "secret", Auth: &auth.Service{}}); err == nil {
		t.Fatal("auth and basic auth together accepted")
	}
	store := authtest.New()
	m := &fakeMaint{canOpen: true}
	s, err := New(Options{User: "ops", Password: "secret", Maintenance: m, Audit: auth.NewAuditor(store, nil, nil),
		Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	if rec := mdo(h, "POST", "/api/maintenance", "application/json", `{"providers":["transit-a"],"duration":"30m"}`, true); rec.Code != http.StatusCreated {
		t.Fatalf("basic write: %d", rec.Code)
	}
	recs := store.Records()
	if len(recs) != 1 || recs[0].Actor != "ops" || recs[0].Method != auth.MethodBasic || recs[0].Target != "api-1" {
		t.Fatalf("legacy audit: %+v", recs)
	}
	for _, p := range []string{"/api/users", "/api/tokens"} {
		if rec := mdo(h, "GET", p, "", "", true); rec.Code != http.StatusNotFound {
			t.Fatalf("%s without auth: %d", p, rec.Code)
		}
	}
	if rec := mdo(h, "GET", "/api/audit", "", "", true); rec.Code != http.StatusOK {
		t.Fatalf("legacy audit read: %d", rec.Code)
	}
	if rec := mdo(h, "GET", "/api/me", "", "", true); !strings.Contains(rec.Body.String(), `"auth":"basic"`) {
		t.Fatalf("legacy me: %s", rec.Body)
	}
	if rec := mdo(h, "GET", "/auth/login", "", "", true); rec.Code != http.StatusNotFound {
		t.Fatalf("legacy login: %d", rec.Code)
	}
	// No auth at all: reads open, writes refused (unchanged rollback mode).
	open, _ := New(Options{Maintenance: m, Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if rec := mdo(open.Handler(), "GET", "/api/providers", "", "", false); rec.Code != http.StatusOK {
		t.Fatalf("open read: %d", rec.Code)
	}
	if rec := mdo(open.Handler(), "POST", "/api/maintenance", "application/json", `{"providers":["transit-a"],"duration":"30m"}`, false); rec.Code != http.StatusForbidden {
		t.Fatalf("open write: %d", rec.Code)
	}
	// Anonymous refusals are not audited (nothing changed); anonymous
	// tool runs, which succeed, are.
	openStore := authtest.New()
	open2, _ := New(Options{Maintenance: m, Audit: auth.NewAuditor(openStore, nil, nil)})
	mdo(open2.Handler(), "POST", "/api/maintenance", "application/json", `{"providers":["transit-a"],"duration":"30m"}`, false)
	mdo(open2.Handler(), "POST", "/api/users", "application/json", `{}`, false)
	if recs := openStore.Records(); len(recs) != 0 {
		t.Fatalf("anonymous refusals audited: %+v", recs)
	}
}
