package httpapi

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/auth/authtest"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const signinPassword = "correct-horse-battery"

func (e *rbacEnv) signin(name, password string, mod ...func(*http.Request)) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]string{"name": name, "password": password})
	return e.do("POST", "/auth/signin", "", string(b), mod...)
}

func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.SessionCookie && c.Value != "" {
			return c
		}
	}
	return nil
}

func withCookie(c *http.Cookie) func(*http.Request) { return func(r *http.Request) { r.AddCookie(c) } }

func TestSigninPage(t *testing.T) {
	e := newRBAC(t, nil)
	// The page and the files it loads need no sign-in. The logo is one of
	// them: the favicon is requested before a session exists.
	for path, want := range map[string]string{
		"/signin.html": `id="signin-form"`,
		"/signin.js":   "/auth/signin",
		"/shell.js":    "shellRenderBanner",
		"/app.css":     ".signin-form",
	} {
		rec := e.do("GET", path, "", "")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s: %d, missing %q", path, rec.Code, want)
		}
	}
	page := e.do("GET", "/signin.html", "", "").Body.String()
	for _, want := range []string{`id="banner"`, `<label>User name `, `<label>Password `, `type="password"`, `autocomplete="current-password"`, `src="/signin.js"`, `rel="icon" href="/logo.png"`, `alt="Packeteer logo"`, `src="/logo.png"`} {
		if !strings.Contains(page, want) {
			t.Errorf("signin.html missing %s", want)
		}
	}
	if b, f := strings.Index(page, `id="banner"`), strings.Index(page, `<form`); b < 0 || b > f {
		t.Error("signin.html mode banner is not before the form")
	}
	if strings.Contains(page, "http://") || strings.Contains(page, "https://") || strings.Contains(page, "<script>") {
		t.Error("signin.html loads something that is not same-origin")
	}
	// Everything else still needs a user, and a script gets 401, not a page.
	if rec := e.do("GET", "/", "", "", overTLS); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/signin.html" {
		t.Fatalf("page without session: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if rec := e.do("GET", "/settings.html", "", "", overTLS); rec.Code != http.StatusFound {
		t.Fatalf("settings without session: %d", rec.Code)
	}
	for _, p := range []string{"/api/overview", "/metrics"} {
		if rec := e.do("GET", p, "", ""); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("WWW-Authenticate"), "Basic") {
			t.Fatalf("%s without credentials: %d", p, rec.Code)
		}
	}
	rec := e.do("GET", "/auth/signin", "", "")
	var info struct {
		SSO  bool
		Mode string
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &info)
	if rec.Code != http.StatusOK || info.SSO || info.Mode != "observe" {
		t.Fatalf("signin info: %d %s", rec.Code, rec.Body)
	}
	sso := newRBAC(t, &testSSO{})
	if rec := sso.do("GET", "/auth/signin", "", ""); !strings.Contains(rec.Body.String(), `"sso":true`) {
		t.Fatalf("signin info with sso: %s", rec.Body)
	}
}

func TestSigninFlow(t *testing.T) {
	e := newRBAC(t, nil)
	ctx := t.Context()
	if _, err := e.svc.CreateUser(ctx, "alice", plugin.RoleOperator, signinPassword); err != nil {
		t.Fatal(err)
	}
	// A wrong password and an unknown user get the same answer and are audited.
	for _, name := range []string{"alice", "ghost"} {
		rec := e.signin(name, "wrong-password-xx")
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != "" || sessionCookie(t, rec) != nil ||
			!strings.Contains(rec.Body.String(), "invalid user name or password") {
			t.Fatalf("bad sign-in %s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := e.do("POST", "/auth/signin", "", "not json"); rec.Code != http.StatusUnsupportedMediaType && rec.Code != http.StatusBadRequest {
		t.Fatalf("garbage body: %d", rec.Code)
	}
	if rec := e.signin("alice", signinPassword, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site sign-in: %d", rec.Code)
	}

	rec := e.signin("alice", signinPassword)
	c := sessionCookie(t, rec)
	if rec.Code != http.StatusOK || c == nil || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("sign-in: %d %s %+v", rec.Code, rec.Body, c)
	}
	if strings.Contains(rec.Body.String(), signinPassword) || strings.Contains(rec.Body.String(), "pbkdf2") {
		t.Fatalf("sign-in body leaks: %s", rec.Body)
	}

	// With the cookie alone: browse, see who is signed in, use the role.
	in := withCookie(c)
	var me struct {
		Auth, User, Method string
		Role               plugin.Role
		Session            bool
	}
	rec = e.do("GET", "/api/me", "", "", in)
	_ = json.Unmarshal(rec.Body.Bytes(), &me)
	if rec.Code != http.StatusOK || me.Auth != "rbac" || me.User != "alice" || me.Role != plugin.RoleOperator || me.Method != auth.MethodPassword || !me.Session {
		t.Fatalf("me: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("GET", "/", "", "", in); rec.Code != http.StatusOK {
		t.Fatalf("dashboard with session: %d", rec.Code)
	}
	if rec := e.do("GET", "/api/providers", "", "", in); rec.Code != http.StatusOK {
		t.Fatalf("api with session: %d", rec.Code)
	}
	if rec := e.do("POST", "/api/maintenance", "", `{"providers":["transit-a"],"duration":"30m"}`, in); rec.Code != http.StatusCreated {
		t.Fatalf("operator write with session: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("GET", "/api/users", "", "", in); !needsRole(rec) {
		t.Fatalf("operator session read users: %d", rec.Code)
	}

	// Basic auth and tokens are unchanged next to the session.
	basicAuth := func(r *http.Request) { r.SetBasicAuth("alice", signinPassword) }
	if rec := e.do("GET", "/api/me", "", "", basicAuth); !strings.Contains(rec.Body.String(), `"method":"password"`) || strings.Contains(rec.Body.String(), `"session"`) {
		t.Fatalf("basic auth: %s", rec.Body)
	}
	if rec := e.do("GET", "/api/me", e.tokens[plugin.RoleViewer], ""); rec.Code != http.StatusOK {
		t.Fatalf("token: %d", rec.Code)
	}

	// Sign out: the server forgets the session, so the cookie is dead.
	rec = e.do("POST", "/auth/logout", "", "", in)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", rec.Code)
	}
	for _, cc := range rec.Result().Cookies() {
		if cc.Name != auth.SessionCookie || cc.MaxAge >= 0 {
			t.Fatalf("logout cookie: %+v", cc)
		}
	}
	if rec := e.do("GET", "/api/me", "", "", in); rec.Code != http.StatusUnauthorized {
		t.Fatalf("api after sign-out: %d", rec.Code)
	}
	if rec := e.do("GET", "/", "", "", in, overTLS); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/signin.html" {
		t.Fatalf("page after sign-out: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if rec := e.do("POST", "/api/maintenance", "", `{"providers":["transit-a"],"duration":"30m"}`, in); rec.Code != http.StatusUnauthorized {
		t.Fatalf("write after sign-out: %d", rec.Code)
	}

	// Audit: two failures, one sign-in, one sign-out; no secret anywhere.
	var failed, ok, out int
	for _, r := range e.store.Records() {
		b, _ := json.Marshal(r)
		if bytes.Contains(b, []byte(signinPassword)) || bytes.Contains(b, []byte("wrong-password-xx")) {
			t.Fatalf("audit record holds a password: %s", b)
		}
		switch {
		case r.Action == "auth.login" && r.Result == auth.ResultDenied && r.Method == auth.MethodPassword && r.Remote == "192.0.2.1":
			failed++
			if r.Target != "alice" && r.Target != "ghost" {
				t.Errorf("failed sign-in target %q", r.Target)
			}
		case r.Action == "auth.login" && r.Result == auth.ResultOK && r.Actor == "alice" && r.Role == plugin.RoleOperator && r.Method == auth.MethodPassword:
			ok++
		case r.Action == "auth.logout" && r.Actor == "alice" && r.Result == auth.ResultOK && r.Method == auth.MethodPassword:
			out++
		}
	}
	if failed != 2 || ok != 1 || out != 1 {
		t.Fatalf("audit: failed %d, ok %d, out %d: %+v", failed, ok, out, e.store.Records())
	}
}

// TestSigninLockoutAndLogs: ten failures through the form lock the
// address out for basic auth too, and neither the log nor the audit
// record holds the password that was tried.
func TestSigninLockoutAndLogs(t *testing.T) {
	var logs bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	store := authtest.New()
	svc, err := auth.New(auth.Options{Users: store, Logger: lg})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateUser(t.Context(), "alice", plugin.RoleViewer, signinPassword); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Auth: svc, Audit: auth.NewAuditor(store, nil, lg), Logger: lg, Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if err != nil {
		t.Fatal(err)
	}
	e := &rbacEnv{h: srv.Handler(), srv: srv, svc: svc, store: store}
	const secret = "hunter2-hunter2-hunter2"
	for i := range 10 {
		if rec := e.signin("alice", secret); rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d", i, rec.Code)
		}
	}
	// Locked: the right password is refused, by the form and by basic auth.
	if rec := e.signin("alice", signinPassword); rec.Code != http.StatusTooManyRequests || sessionCookie(t, rec) != nil {
		t.Fatalf("locked form: %d", rec.Code)
	}
	if rec := e.do("GET", "/api/me", "", "", func(r *http.Request) { r.SetBasicAuth("alice", signinPassword) }); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("locked basic auth: %d", rec.Code)
	}
	// Another address is not locked.
	other := func(r *http.Request) { r.RemoteAddr = "192.0.2.77:1" }
	if rec := e.signin("alice", signinPassword, other); rec.Code != http.StatusOK {
		t.Fatalf("other address: %d", rec.Code)
	}
	if !strings.Contains(logs.String(), "throttling") {
		t.Fatalf("lockout not logged: %s", logs.String())
	}
	for _, p := range []string{secret, signinPassword} {
		if strings.Contains(logs.String(), p) {
			t.Fatalf("log holds a password: %s", logs.String())
		}
		for _, r := range store.Records() {
			if b, _ := json.Marshal(r); bytes.Contains(b, []byte(p)) {
				t.Fatalf("audit holds a password: %s", b)
			}
		}
	}
}

// TestSigninNeedsAuth: without auth there are no sessions to start.
func TestSigninNeedsAuth(t *testing.T) {
	s, err := New(Options{User: "ops", Password: "secret", Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	if rec := mdo(h, "GET", "/auth/signin", "", "", true); rec.Code != http.StatusNotFound {
		t.Fatalf("info: %d", rec.Code)
	}
	if rec := mdo(h, "POST", "/auth/signin", "application/json", `{"name":"ops","password":"secret"}`, true); rec.Code != http.StatusNotFound {
		t.Fatalf("post: %d", rec.Code)
	}
}

// A browser on plain http to a LAN address drops the Secure cookie, so a
// redirect to the sign-in page would loop: it keeps the basic-auth prompt.
func TestPageRedirectNeedsUsableCookie(t *testing.T) {
	e := newRBAC(t, nil)
	host := func(h string) func(*http.Request) { return func(r *http.Request) { r.Host = h } }
	proxied := func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "https") }
	for name, tc := range map[string]struct {
		mod      func(*http.Request)
		redirect bool
	}{
		"plain http, LAN address": {host("192.0.2.10:8080"), false},
		"plain http, name":        {host("packeteer.example.net"), false},
		"tls":                     {overTLS, true},
		"proxy says https":        {proxied, true},
		"localhost":               {host("localhost:8080"), true},
		"loopback v4":             {host("127.0.0.1:8080"), true},
		"loopback v6":             {host("[::1]:8080"), true},
	} {
		rec := e.do("GET", "/", "", "", tc.mod)
		if tc.redirect {
			if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/signin.html" {
				t.Errorf("%s: %d %s, want redirect", name, rec.Code, rec.Header().Get("Location"))
			}
			continue
		}
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("WWW-Authenticate"), "Basic") {
			t.Errorf("%s: %d %q, want 401 with a basic-auth challenge", name, rec.Code, rec.Header().Get("WWW-Authenticate"))
		}
	}
}
