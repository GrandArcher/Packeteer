package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/auth/authtest"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestMain(m *testing.M) {
	SetHashIterations(1000)
	m.Run()
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newSvc(t *testing.T, sso plugin.SSO) (*Service, *authtest.Store, *clock) {
	t.Helper()
	st := authtest.New()
	c := &clock{t: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	s, err := New(Options{Users: st, SSO: sso, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	return s, st, c
}

func req(remote string, mod func(*http.Request)) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/providers", nil)
	r.RemoteAddr = remote
	if mod != nil {
		mod(r)
	}
	return r
}

func basic(u, p string) func(*http.Request) { return func(r *http.Request) { r.SetBasicAuth(u, p) } }
func bearer(tok string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
}

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(h, "correct horse battery") || VerifyPassword(h, "correct horse batterY") {
		t.Fatal("verify")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Fatal("salt not random")
	}
	for _, bad := range []string{"", "x$1$a$b", "pbkdf2-sha256$0$AAAA$AAAA", "pbkdf2-sha256$abc$AAAA$AAAA", "pbkdf2-sha256$1000$!!$AAAA"} {
		if VerifyPassword(bad, "anything") {
			t.Errorf("malformed %q matched", bad)
		}
	}
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("short password hashed")
	}
}

func TestOptions(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("no store accepted")
	}
	for _, o := range []Options{{SessionTTL: time.Minute}, {SessionTTL: 30 * 24 * time.Hour}, {TokenTTL: time.Minute}, {TokenTTL: 400 * 24 * time.Hour}} {
		o.Users = authtest.New()
		if _, err := New(o); err == nil {
			t.Errorf("%+v accepted", o)
		}
	}
}

func TestPasswordAuthAndThrottle(t *testing.T) {
	s, _, c := newSvc(t, nil)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "noc", plugin.RoleOperator, "operator-password"); err != nil {
		t.Fatal(err)
	}
	p, err := s.Authenticate(req("192.0.2.5:1000", basic("noc", "operator-password")))
	if err != nil || p.User != "noc" || p.Role != plugin.RoleOperator || p.Method != MethodPassword {
		t.Fatalf("auth: %+v %v", p, err)
	}
	// Cached: still checked against the hash on a different password.
	if _, err := s.Authenticate(req("192.0.2.5:1000", basic("noc", "operator-passwor"))); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	for _, m := range []func(*http.Request){basic("nobody", "operator-password"), bearer("pkt_nope"), func(r *http.Request) { r.Header.Set("Authorization", "Digest x") }} {
		if _, err := s.Authenticate(req("192.0.2.5:1000", m)); !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("bad credential: %v", err)
		}
	}
	if _, err := s.Authenticate(req("192.0.2.5:1000", nil)); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("none: %v", err)
	}
	// Ten failures from one address throttle it, even with the right
	// password; another address is not affected.
	for i := 0; i < failLimit; i++ {
		_, _ = s.Authenticate(req("198.51.100.7:1", basic("noc", "guess-guess-guess")))
	}
	if _, err := s.Authenticate(req("198.51.100.7:1", basic("noc", "operator-password"))); !errors.Is(err, ErrThrottled) {
		t.Fatalf("throttle: %v", err)
	}
	if _, err := s.Authenticate(req("198.51.100.8:1", basic("noc", "operator-password"))); err != nil {
		t.Fatalf("other address throttled: %v", err)
	}
	c.add(failWindow)
	if _, err := s.Authenticate(req("198.51.100.7:1", basic("noc", "operator-password"))); err != nil {
		t.Fatalf("after window: %v", err)
	}
	// Disabled users and a password change take effect at once.
	d := true
	if _, err := s.UpdateUser(ctx, "noc", UserUpdate{Disabled: &d}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(req("192.0.2.5:1000", basic("noc", "operator-password"))); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("disabled: %v", err)
	}
	d = false
	pw := "a-new-long-password"
	if _, err := s.UpdateUser(ctx, "noc", UserUpdate{Disabled: &d, Password: &pw}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(req("192.0.2.5:1000", basic("noc", "operator-password"))); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("old password: %v", err)
	}
	if _, err := s.Authenticate(req("192.0.2.5:1000", basic("noc", pw))); err != nil {
		t.Fatalf("new password: %v", err)
	}
}

func TestStoreDown(t *testing.T) {
	s, st, _ := newSvc(t, nil)
	st.Fail = true
	if _, err := s.Authenticate(req("192.0.2.5:1", basic("noc", "operator-password"))); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("store down: %v", err)
	}
}

func TestTokens(t *testing.T) {
	s, _, c := newSvc(t, nil)
	ctx := context.Background()
	_, _ = s.CreateUser(ctx, "root", plugin.RoleAdmin, "admin-password-1")
	_, _ = s.CreateUser(ctx, "ops", plugin.RoleOperator, "operator-password")
	ops := Principal{User: "ops", Role: plugin.RoleOperator, Method: MethodPassword}
	admin := Principal{User: "root", Role: plugin.RoleAdmin, Method: MethodPassword}

	if _, _, err := s.CreateToken(ctx, ops, "x", plugin.RoleAdmin, 0); !errors.Is(err, ErrForbidden) {
		t.Fatalf("escalation: %v", err)
	}
	for _, bad := range []struct {
		name string
		role plugin.Role
		ttl  time.Duration
	}{{"", "", 0}, {"x", "root", 0}, {"x", "", time.Second}, {"x", "", 2 * MaxTokenTTL}, {"bad\nname", "", 0}} {
		if _, _, err := s.CreateToken(ctx, ops, bad.name, bad.role, bad.ttl); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	tv, secret, err := s.CreateToken(ctx, ops, "grafana", plugin.RoleViewer, time.Hour)
	if err != nil || !strings.HasPrefix(secret, "pkt_"+tv.ID+"_") || tv.Role != plugin.RoleViewer {
		t.Fatalf("create: %+v %q %v", tv, secret, err)
	}
	p, err := s.Authenticate(req("192.0.2.5:1", bearer(secret)))
	if err != nil || p.User != "ops" || p.Role != plugin.RoleViewer || p.Method != MethodToken || p.TokenID != tv.ID {
		t.Fatalf("bearer: %+v %v", p, err)
	}
	// A token cannot mint tokens.
	if _, _, err := s.CreateToken(ctx, p, "again", "", 0); !errors.Is(err, ErrForbidden) {
		t.Fatalf("token minted a token: %v", err)
	}
	// Tampered secret.
	if _, err := s.Authenticate(req("192.0.2.5:1", bearer(secret[:len(secret)-1]+"A"))); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("tampered: %v", err)
	}
	// The token's role follows a demoted user.
	tv2, sec2, _ := s.CreateToken(ctx, ops, "ops-script", "", time.Hour)
	if tv2.Role != plugin.RoleOperator {
		t.Fatalf("default role: %+v", tv2)
	}
	viewer := plugin.RoleViewer
	if _, err := s.UpdateUser(ctx, "ops", UserUpdate{Role: &viewer}); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Authenticate(req("192.0.2.5:1", bearer(sec2))); p.Role != plugin.RoleViewer {
		t.Fatalf("demoted token role: %+v", p)
	}
	// Listing: own only; admin all.
	if ts, _ := s.Tokens(ctx, ops); len(ts) != 2 {
		t.Fatalf("own tokens: %+v", ts)
	}
	adminTok, _, _ := s.CreateToken(ctx, admin, "admin-script", "", 0)
	if ts, _ := s.Tokens(ctx, ops); len(ts) != 2 {
		t.Fatalf("ops sees admin tokens: %+v", ts)
	}
	if ts, _ := s.Tokens(ctx, admin); len(ts) != 3 {
		t.Fatalf("admin tokens: %+v", ts)
	}
	if !adminTok.Expires.Equal(c.now().Add(DefaultTokenTTL)) {
		t.Fatalf("default ttl: %s", adminTok.Expires)
	}
	// Revoke: not someone else's (unless admin).
	if _, err := s.RevokeToken(ctx, ops, adminTok.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoke other: %v", err)
	}
	if _, err := s.RevokeToken(ctx, admin, tv2.ID); err != nil {
		t.Fatalf("admin revoke: %v", err)
	}
	if _, err := s.Authenticate(req("192.0.2.5:1", bearer(sec2))); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("revoked token works: %v", err)
	}
	// Expiry.
	c.add(time.Hour)
	if _, err := s.Authenticate(req("192.0.2.5:1", bearer(secret))); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("expired token works: %v", err)
	}
	// Deleting the user kills the rest.
	_, sec3, _ := s.CreateToken(ctx, ops, "late", "", time.Hour)
	if err := s.DeleteUser(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(req("192.0.2.5:1", bearer(sec3))); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("deleted user's token works: %v", err)
	}
	// Per-user cap.
	for i := 0; i < MaxTokensPerUser-1; i++ {
		if _, _, err := s.CreateToken(ctx, admin, "t", "", 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.CreateToken(ctx, admin, "t", "", 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cap: %v", err)
	}
}

func TestUsersAndLastAdmin(t *testing.T) {
	s, _, _ := newSvc(t, nil)
	ctx := context.Background()
	if ok, err := s.Bootstrap(ctx, "", "bootstrap-password"); !ok || err != nil {
		t.Fatalf("bootstrap: %v %v", ok, err)
	}
	if ok, err := s.Bootstrap(ctx, "", "another-password"); ok || err != nil {
		t.Fatalf("bootstrap twice: %v %v", ok, err)
	}
	if _, err := s.Authenticate(req("192.0.2.5:1", basic("admin", "bootstrap-password"))); err != nil {
		t.Fatalf("bootstrap password replaced: %v", err)
	}
	for _, bad := range []struct {
		name string
		role plugin.Role
		pw   string
	}{{"", plugin.RoleViewer, "long-enough-pw"}, {"-x", plugin.RoleViewer, "long-enough-pw"}, {"a b", plugin.RoleViewer, "long-enough-pw"}, {"ok", "root", "long-enough-pw"}, {"ok", plugin.RoleViewer, "short"}} {
		if _, err := s.CreateUser(ctx, bad.name, bad.role, bad.pw); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	if _, err := s.CreateUser(ctx, "admin", plugin.RoleViewer, "long-enough-pw"); !errors.Is(err, ErrExists) {
		t.Fatalf("dup: %v", err)
	}
	op := plugin.RoleOperator
	yes := true
	if _, err := s.UpdateUser(ctx, "admin", UserUpdate{Role: &op}); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote last admin: %v", err)
	}
	if _, err := s.UpdateUser(ctx, "admin", UserUpdate{Disabled: &yes}); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disable last admin: %v", err)
	}
	if err := s.DeleteUser(ctx, "admin"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete last admin: %v", err)
	}
	if _, err := s.UpdateUser(ctx, "admin", UserUpdate{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty update: %v", err)
	}
	if _, err := s.UpdateUser(ctx, "ghost", UserUpdate{Disabled: &yes}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ghost: %v", err)
	}
	_, _ = s.CreateUser(ctx, "second", plugin.RoleAdmin, "second-admin-pw")
	if err := s.DeleteUser(ctx, "admin"); err != nil {
		t.Fatalf("delete with another admin: %v", err)
	}
	us, _ := s.Users(ctx)
	if len(us) != 1 || us[0].Name != "second" {
		t.Fatalf("users: %+v", us)
	}
}

// fakeSSO stands in for an identity provider.
type fakeSSO struct {
	plugin.Base
	id  plugin.SSOIdentity
	err error
	got struct{ code, nonce, verifier string }
	url struct{ state, nonce, verifier string }
}

func (f *fakeSSO) AuthURL(_ context.Context, state, nonce, verifier string) (string, error) {
	f.url.state, f.url.nonce, f.url.verifier = state, nonce, verifier
	return "https://idp.example.net/authorize?state=" + url.QueryEscape(state), nil
}

func (f *fakeSSO) Exchange(_ context.Context, code, nonce, verifier string) (plugin.SSOIdentity, error) {
	f.got.code, f.got.nonce, f.got.verifier = code, nonce, verifier
	return f.id, f.err
}

// ssoLogin runs BeginLogin and FinishLogin like a browser would.
func ssoLogin(t *testing.T, s *Service, mutate func(cb *http.Request)) (Principal, *http.Cookie, error) {
	t.Helper()
	w := httptest.NewRecorder()
	if err := s.BeginLogin(w, httptest.NewRequest(http.MethodGet, "/auth/login", nil)); err != nil {
		t.Fatal(err)
	}
	var state *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == StateCookie {
			state = c
		}
	}
	if w.Code != http.StatusFound || state == nil || !state.HttpOnly || !state.Secure {
		t.Fatalf("begin: %d %+v", w.Code, state)
	}
	cb := httptest.NewRequest(http.MethodGet, "/auth/callback?code=c0de&state="+url.QueryEscape(state.Value), nil)
	cb.AddCookie(state)
	if mutate != nil {
		mutate(cb)
	}
	w = httptest.NewRecorder()
	p, _, err := s.FinishLogin(w, cb)
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookie && c.Value != "" {
			return p, c, err
		}
	}
	return p, nil, err
}

func TestSSO(t *testing.T) {
	sso := &fakeSSO{id: plugin.SSOIdentity{User: "noc@example.net", Subject: "s1", Role: plugin.RoleOperator}}
	s, st, c := newSvc(t, sso)
	ctx := context.Background()
	p, cookie, err := ssoLogin(t, s, nil)
	if err != nil || cookie == nil || p.Role != plugin.RoleOperator || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("login: %+v %+v %v", p, cookie, err)
	}
	if sso.got.code != "c0de" || sso.got.nonce != sso.url.nonce || sso.got.verifier != sso.url.verifier || len(sso.url.verifier) < 43 {
		t.Fatalf("exchange args: %+v %+v", sso.got, sso.url)
	}
	u, ok, _ := st.User(ctx, "noc@example.net")
	if !ok || u.Source != plugin.UserSSO || u.Role != plugin.RoleOperator || u.PasswordHash != "" {
		t.Fatalf("stored: %+v", u)
	}
	got, err := s.Authenticate(req("192.0.2.5:1", func(r *http.Request) { r.AddCookie(cookie) }))
	if err != nil || got.User != "noc@example.net" || got.Method != MethodSSO {
		t.Fatalf("session: %+v %v", got, err)
	}
	// An SSO user cannot use a password, nor have role or password set.
	if _, err := s.Authenticate(req("192.0.2.5:1", basic("noc@example.net", ""))); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("sso user by password: %v", err)
	}
	pw := "some-password-x"
	if _, err := s.UpdateUser(ctx, "noc@example.net", UserUpdate{Password: &pw}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("sso password: %v", err)
	}
	// Disabling ends the session and refuses the next sign-in.
	yes := true
	if _, err := s.UpdateUser(ctx, "noc@example.net", UserUpdate{Disabled: &yes}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(req("192.0.2.5:1", func(r *http.Request) { r.AddCookie(cookie) })); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("disabled session: %v", err)
	}
	if _, _, err := ssoLogin(t, s, nil); err == nil {
		t.Fatal("disabled user signed in")
	}
	// A local user with the same name is not taken over.
	_, _ = s.CreateUser(ctx, "local-admin", plugin.RoleAdmin, "local-admin-pw")
	sso.id.User = "local-admin"
	if _, _, err := ssoLogin(t, s, nil); err == nil {
		t.Fatal("sso took over a local user")
	}
	// State mismatch, provider error, and an exchange failure.
	sso.id.User = "other@example.net"
	if _, _, err := ssoLogin(t, s, func(cb *http.Request) { cb.URL.RawQuery = "code=c0de&state=forged" }); err == nil {
		t.Fatal("forged state accepted")
	}
	if _, _, err := ssoLogin(t, s, func(cb *http.Request) { cb.URL.RawQuery = "error=access_denied" }); err == nil {
		t.Fatal("provider error accepted")
	}
	sso.err = errors.New("bad id token")
	if _, _, err := ssoLogin(t, s, nil); err == nil {
		t.Fatal("exchange failure accepted")
	}
	sso.err = nil
	// Session expiry and logout.
	_, cookie, err = ssoLogin(t, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.add(DefaultSessionTTL)
	if _, err := s.Authenticate(req("192.0.2.5:1", func(r *http.Request) { r.AddCookie(cookie) })); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("expired session: %v", err)
	}
	_, cookie, _ = ssoLogin(t, s, nil)
	lr := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	lr.AddCookie(cookie)
	if user, ok := s.Logout(httptest.NewRecorder(), lr); !ok || user != "other@example.net" {
		t.Fatalf("logout: %q %v", user, ok)
	}
	if _, err := s.Authenticate(req("192.0.2.5:1", func(r *http.Request) { r.AddCookie(cookie) })); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("after logout: %v", err)
	}
	// SSO sessions cannot be replayed after the state was used once.
	if err := s.BeginLogin(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/login", nil)); err != nil {
		t.Fatal(err)
	}
	noSSO, _, _ := newSvc(t, nil)
	if err := noSSO.BeginLogin(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/login", nil)); !errors.Is(err, ErrNoSSO) {
		t.Fatalf("no sso: %v", err)
	}
}

func TestAuditor(t *testing.T) {
	st := authtest.New()
	var events []plugin.Event
	a := NewAuditor(st, func(e plugin.Event) { events = append(events, e) }, nil)
	r := a.Record(context.Background(), plugin.AuditRecord{Actor: "noc", Role: plugin.RoleOperator, Method: MethodPassword, Action: "POST /api/maintenance",
		Target: "api-1", Status: 201, Remote: "192.0.2.5"})
	if r.ID == "" || r.Time.IsZero() || r.Result != ResultOK {
		t.Fatalf("record: %+v", r)
	}
	recs, err := a.Query(context.Background(), plugin.AuditQuery{})
	if err != nil || len(recs) != 1 || recs[0].ID != r.ID {
		t.Fatalf("query: %+v %v", recs, err)
	}
	if len(events) != 1 || events[0].Kind != plugin.EventAudit || events[0].Fields["actor"] != "noc" || events[0].Fields["target"] != "api-1" ||
		events[0].Fields["status"] != "201" || !strings.Contains(events[0].Message, "POST /api/maintenance") {
		t.Fatalf("event: %+v", events)
	}
	// A failing store does not block the record or the event.
	st.Fail = true
	a.Record(context.Background(), plugin.AuditRecord{Actor: "x", Action: "y"})
	if len(events) != 2 {
		t.Fatal("event lost on store failure")
	}
	var nilA *Auditor
	nilA.Record(context.Background(), plugin.AuditRecord{})
	if _, err := NewAuditor(nil, nil, nil).Query(context.Background(), plugin.AuditQuery{}); !errors.Is(err, ErrNoAuditStore) {
		t.Fatalf("no store: %v", err)
	}
}
