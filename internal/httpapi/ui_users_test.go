package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// asUser calls the API the way the Admin and Tokens pages do: a signed-in
// user's request with a JSON body. Basic auth stands in for the session
// cookie; both resolve to the same password principal.
func (e *uiEnv) asUser(t *testing.T, user, method, path string, body any) (*httptest.ResponseRecorder, string) {
	t.Helper()
	var rd *strings.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = strings.NewReader(string(raw))
	} else {
		rd = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.SetBasicAuth(user, user+"-password")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec, rec.Body.String()
}

// audited finds a record by who, what, and result; detail "*" matches any.
func (e *uiEnv) audited(action, actor, target, detail, result string) (plugin.AuditRecord, bool) {
	for _, r := range e.store.Records() {
		if r.Action == action && r.Actor == actor && r.Target == target && r.Result == result && (detail == "*" || r.Detail == detail) {
			return r, true
		}
	}
	return plugin.AuditRecord{}, false
}

// TestUsersPage drives the calls the Admin page makes (#175) against the
// real API with auth on: add, change role, reset password, disable, enable,
// delete. Each is audited with its actor, a viewer is refused, and a
// password never reaches the audit log.
func TestUsersPage(t *testing.T) {
	e := newUI(t)
	const admin, viewer = "admin-user", "viewer-user"

	js := mustWeb(t, "web/admin.js")
	for _, want := range []string{
		`api("GET", "/api/users")`, `api("POST", "/api/users", {name: name, role: role, password: pw})`,
		`{role: sel.value}`, `{password: pw}`, `{disabled: !u.disabled}`, `"DELETE", userPath(u.name)`,
		`u.source !== "local"`, `me.role !== "admin"`, `Confirm delete`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("admin.js missing %q", want)
		}
	}
	for _, bad := range []string{"localStorage", "sessionStorage", "document.cookie"} {
		if strings.Contains(js, bad) {
			t.Errorf("admin.js uses %s", bad)
		}
	}

	rec, body := e.asUser(t, admin, "POST", "/api/users", map[string]string{"name": "noc1", "role": "viewer", "password": "first-password-1"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("add: %d %s", rec.Code, body)
	}
	rec, body = e.asUser(t, admin, "GET", "/api/users", nil)
	var list struct {
		Users []struct{ Name, Role, Source string }
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	found := false
	for _, u := range list.Users {
		if u.Name == "noc1" && u.Role == "viewer" && u.Source == plugin.UserLocal {
			found = true
		}
	}
	if !found || strings.Contains(body, "first-password-1") || strings.Contains(strings.ToLower(body), "hash") {
		t.Fatalf("list: %s", body)
	}

	if rec, body = e.asUser(t, admin, "PATCH", "/api/users/noc1", map[string]string{"role": "operator"}); rec.Code != http.StatusOK || !strings.Contains(body, `"operator"`) {
		t.Fatalf("role: %d %s", rec.Code, body)
	}
	if rec, body = e.asUser(t, admin, "PATCH", "/api/users/noc1", map[string]string{"password": "second-password-2"}); rec.Code != http.StatusOK {
		t.Fatalf("password: %d %s", rec.Code, body)
	}
	req := httptest.NewRequest("GET", "/api/me", nil)
	req.SetBasicAuth("noc1", "first-password-1")
	old := httptest.NewRecorder()
	e.h.ServeHTTP(old, req)
	req = httptest.NewRequest("GET", "/api/me", nil)
	req.SetBasicAuth("noc1", "second-password-2")
	fresh := httptest.NewRecorder()
	e.h.ServeHTTP(fresh, req)
	if old.Code != http.StatusUnauthorized || fresh.Code != http.StatusOK || !strings.Contains(fresh.Body.String(), `"role":"operator"`) {
		t.Fatalf("reset: old=%d new=%d %s", old.Code, fresh.Code, fresh.Body)
	}
	if rec, _ = e.asUser(t, admin, "PATCH", "/api/users/noc1", map[string]bool{"disabled": true}); rec.Code != http.StatusOK {
		t.Fatalf("disable: %d", rec.Code)
	}
	req = httptest.NewRequest("GET", "/api/me", nil)
	req.SetBasicAuth("noc1", "second-password-2")
	off := httptest.NewRecorder()
	e.h.ServeHTTP(off, req)
	if off.Code != http.StatusUnauthorized {
		t.Fatalf("disabled user signed in: %d", off.Code)
	}
	if rec, _ = e.asUser(t, admin, "PATCH", "/api/users/noc1", map[string]bool{"disabled": false}); rec.Code != http.StatusOK {
		t.Fatalf("enable: %d", rec.Code)
	}
	if rec, _ = e.asUser(t, admin, "DELETE", "/api/users/noc1", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}

	// The last enabled admin cannot be demoted or deleted from the page.
	if rec, _ = e.asUser(t, admin, "PATCH", "/api/users/"+admin, map[string]string{"role": "viewer"}); rec.Code != http.StatusConflict {
		t.Fatalf("last admin demoted: %d", rec.Code)
	}

	// A viewer's page has no Users section, and the API refuses it too.
	for _, c := range []struct{ method, path string }{{"GET", "/api/users"}, {"POST", "/api/users"}, {"PATCH", "/api/users/noc1"}, {"DELETE", "/api/users/noc1"}} {
		if rec, _ = e.asUser(t, viewer, c.method, c.path, map[string]string{"name": "x", "role": "admin", "password": "another-password-3"}); rec.Code != http.StatusForbidden {
			t.Errorf("viewer %s %s = %d", c.method, c.path, rec.Code)
		}
	}
	shell := mustWeb(t, "web/shell.js")
	if !strings.Contains(shell, `document.getElementById("page-denied")`) || !strings.Contains(shell, `data-page") === "admin"`) {
		t.Error("shell.js does not hide the Admin page from a viewer")
	}

	// Every change is in the audit log as the API writes it.
	for _, c := range []struct{ action, target, detail string }{
		{"POST /api/users", "noc1", "role=viewer"},
		{"PATCH /api/users/{name}", "noc1", "role=operator"},
		{"PATCH /api/users/{name}", "noc1", "password"},
		{"PATCH /api/users/{name}", "noc1", "disabled=true"},
		{"PATCH /api/users/{name}", "noc1", "disabled=false"},
		{"DELETE /api/users/{name}", "noc1", ""},
	} {
		if _, ok := e.audited(c.action, admin, c.target, c.detail, "ok"); !ok {
			t.Errorf("no audit record for %s %s %q", c.action, c.target, c.detail)
		}
	}
	if _, ok := e.audited("POST /api/users", viewer, "", "role viewer below admin", "denied"); !ok {
		t.Error("viewer's refused add is not audited")
	}
	for _, r := range e.store.Records() {
		if strings.Contains(r.Detail+r.Target, "password-") {
			t.Fatalf("password in the audit log: %+v", r)
		}
	}
}

// TestTokensPage drives the calls the Tokens page makes (#175): create with
// a name and lifetime, list, revoke. The secret is in the create answer only,
// the page keeps it in one element and never in storage, and the audit log
// has the change without it.
func TestTokensPage(t *testing.T) {
	e := newUI(t)
	const viewer, admin = "viewer-user", "admin-user"

	js := mustWeb(t, "web/tokens.js")
	for _, want := range []string{
		`api("POST", "/api/tokens", body)`, `api("GET", "/api/tokens")`, `"DELETE", "/api/tokens/"`,
		`body.ttl = ttl`, `me.method === "token"`, `window.addEventListener("pagehide", hideSecret)`, `Confirm revoke`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("tokens.js missing %q", want)
		}
	}
	for _, bad := range []string{"localStorage", "sessionStorage", "document.cookie", "indexedDB"} {
		if strings.Contains(js, bad) {
			t.Errorf("tokens.js uses %s", bad)
		}
	}
	// The secret is read in one place and written to one element.
	if n := strings.Count(js, "made.token"); n != 1 {
		t.Errorf("tokens.js reads the secret %d times", n)
	}

	rec, body := e.asUser(t, viewer, "POST", "/api/tokens", map[string]string{"name": "grafana", "role": "viewer", "ttl": "24h"})
	var made struct{ ID, Name, Token, Expires string }
	_ = json.Unmarshal(rec.Body.Bytes(), &made)
	if rec.Code != http.StatusCreated || !strings.HasPrefix(made.Token, "pkt_") || made.Name != "grafana" {
		t.Fatalf("create: %d %s", rec.Code, body)
	}

	// The list never carries a secret or a hash, and a viewer sees its own.
	rec, body = e.asUser(t, viewer, "GET", "/api/tokens", nil)
	var list struct {
		Tokens []struct{ ID, User, Name string }
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	own := false
	for _, tk := range list.Tokens {
		if tk.User != viewer {
			t.Errorf("viewer sees %s's token", tk.User)
		}
		own = own || tk.ID == made.ID
	}
	if !own || strings.Contains(body, made.Token) || strings.Contains(strings.ToLower(body), "hash") {
		t.Fatalf("list: %s", body)
	}
	if rec, body = e.asUser(t, admin, "GET", "/api/tokens", nil); !strings.Contains(body, made.ID) || !strings.Contains(body, admin) || strings.Contains(body, made.Token) {
		t.Fatalf("admin list: %d %s", rec.Code, body)
	}

	// The page offers roles up to the user's own; the API enforces it. A
	// token cannot create tokens, which the page explains instead of
	// offering the form.
	if rec, _ = e.asUser(t, viewer, "POST", "/api/tokens", map[string]string{"name": "up", "role": "admin"}); rec.Code != http.StatusForbidden {
		t.Errorf("escalation: %d", rec.Code)
	}
	if rec, _ = e.do(t, "POST", "/api/tokens", plugin.RoleViewer, map[string]string{"name": "again"}); rec.Code != http.StatusForbidden {
		t.Errorf("token created a token: %d", rec.Code)
	}
	req := httptest.NewRequest("GET", "/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+made.Token)
	me := httptest.NewRecorder()
	e.h.ServeHTTP(me, req)
	if me.Code != http.StatusOK || !strings.Contains(me.Body.String(), `"method":"token"`) {
		t.Fatalf("me with a token: %d %s", me.Code, me.Body)
	}

	// Revoke ends the token at once.
	if rec, _ = e.asUser(t, viewer, "DELETE", "/api/tokens/"+made.ID, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d", rec.Code)
	}
	me = httptest.NewRecorder()
	e.h.ServeHTTP(me, req)
	if me.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token: %d", me.Code)
	}

	created, ok := e.audited("POST /api/tokens", viewer, made.ID, "*", "ok")
	if !ok || !strings.Contains(created.Detail, "name=grafana") || !strings.Contains(created.Detail, "role=viewer") {
		t.Errorf("create audit: %+v ok=%v", created, ok)
	}
	if r, ok := e.audited("DELETE /api/tokens/{id}", viewer, made.ID, "user=viewer-user name=grafana", "ok"); !ok {
		t.Errorf("revoke audit: %+v ok=%v", r, ok)
	}
	for _, r := range e.store.Records() {
		if strings.Contains(r.Detail+r.Target+r.Action, made.Token) {
			t.Fatalf("token secret in the audit log: %+v", r)
		}
	}
}
