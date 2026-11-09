package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/auth/authtest"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// mcpEnv is a server with auth on and the MCP endpoint, and a token per
// role and scope for one viewer and one operator.
type mcpEnv struct {
	h      http.Handler
	store  *authtest.Store
	maint  *fakeMaint
	tokens map[string]string
}

func newMCPEnv(t *testing.T, opt *MCPOptions) *mcpEnv {
	t.Helper()
	e := &mcpEnv{store: authtest.New(), maint: &fakeMaint{canOpen: true}, tokens: map[string]string{}}
	svc, err := auth.New(auth.Options{Users: e.store})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{
		Auth: svc, Audit: auth.NewAuditor(e.store, func(plugin.Event) {}, nil), Maintenance: e.maint, MCP: opt,
		Snapshot: func() Snapshot { return Assemble(sampleInput()) },
	})
	if err != nil {
		t.Fatal(err)
	}
	e.h = srv.Handler()
	ctx := context.Background()
	for _, r := range []plugin.Role{plugin.RoleViewer, plugin.RoleOperator} {
		name := string(r) + "-user"
		if _, err := svc.CreateUser(ctx, name, r, name+"-password"); err != nil {
			t.Fatal(err)
		}
		for _, scope := range []string{"", auth.ScopeMCP, auth.ScopeMCPWrite} {
			_, tok, err := svc.CreateToken(ctx, auth.Principal{User: name, Role: r, Method: auth.MethodPassword}, "t", r, scope, 0)
			if err != nil {
				t.Fatal(err)
			}
			e.tokens[string(r)+"/"+scope] = tok
		}
	}
	return e
}

func (e *mcpEnv) post(token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func mcpCall(name, args string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}`
}

func mcpText(t *testing.T, rec *httptest.ResponseRecorder) (string, bool) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body)
	}
	var r struct {
		Result struct {
			Content []struct{ Text string }
			IsError bool
		}
		Error *struct{ Message string }
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil || r.Error != nil || len(r.Result.Content) != 1 {
		t.Fatalf("answer %s: %v", rec.Body, err)
	}
	return r.Result.Content[0].Text, r.Result.IsError
}

func (e *mcpEnv) toolNames(t *testing.T, token string) map[string]bool {
	t.Helper()
	rec := e.post(token, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	var r struct {
		Result struct{ Tools []struct{ Name string } }
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tl := range r.Result.Tools {
		names[tl.Name] = true
	}
	return names
}

func TestMCPOffByDefault(t *testing.T) {
	e := newMCPEnv(t, nil)
	if rec := e.post(e.tokens["viewer/"], mcpCall("overview", `{}`)); rec.Code == http.StatusOK {
		t.Fatalf("POST /mcp answered with the endpoint off: %s", rec.Body)
	}
}

func TestMCPNeedsCredentials(t *testing.T) {
	e := newMCPEnv(t, &MCPOptions{RatePerMinute: 60})
	if rec := e.post("", mcpCall("overview", `{}`)); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", rec.Code)
	}
	if rec := e.post("pkt_0123456789abcdef_"+strings.Repeat("A", 43), mcpCall("overview", `{}`)); rec.Code != http.StatusUnauthorized {
		t.Errorf("bad token: %d", rec.Code)
	}
}

func TestMCPReadToolsRunAsTheCaller(t *testing.T) {
	e := newMCPEnv(t, &MCPOptions{RatePerMinute: 60})
	for _, tok := range []string{"viewer/", "viewer/mcp", "operator/mcp"} {
		text, isErr := mcpText(t, e.post(e.tokens[tok], mcpCall("overview", `{}`)))
		if isErr || !strings.Contains(text, `"mode":"observe"`) {
			t.Errorf("%s overview: %q %v", tok, text, isErr)
		}
	}
	text, isErr := mcpText(t, e.post(e.tokens["viewer/mcp"], mcpCall("link_health", `{}`)))
	if isErr || !strings.Contains(text, "transit-a") {
		t.Errorf("link_health: %q %v", text, isErr)
	}
	// An IPv6 prefix reaches the {prefix...} route with its colons intact.
	text, isErr = mcpText(t, e.post(e.tokens["viewer/mcp"], mcpCall("decision_explain", `{"prefix":"2001:db8::/32"}`)))
	if !isErr || !strings.HasPrefix(text, "HTTP 404") || !strings.Contains(text, "decision engine") {
		t.Errorf("decision_explain v6: %q %v", text, isErr)
	}
	// The REST error text comes through as a tool error, not a crash.
	text, isErr = mcpText(t, e.post(e.tokens["viewer/mcp"], mcpCall("decision_explain", `{"prefix":"203.0.113.0/24"}`)))
	if !isErr || !strings.HasPrefix(text, "HTTP ") {
		t.Errorf("decision_explain: %q %v", text, isErr)
	}
	if len(e.store.Records()) != 0 {
		t.Errorf("reads were audited: %+v", e.store.Records())
	}
}

func TestMCPScopedTokenWorksOnlyOnMCP(t *testing.T) {
	e := newMCPEnv(t, &MCPOptions{RatePerMinute: 60, WriteTools: true})
	for _, scope := range []string{"mcp", "mcp:write"} {
		for _, path := range []string{"/api/overview", "/api/me", "/api/tokens", "/metrics"} {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("Authorization", "Bearer "+e.tokens["operator/"+scope])
			rec := httptest.NewRecorder()
			e.h.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "scope "+scope) {
				t.Errorf("%s on %s: %d %s", scope, path, rec.Code, rec.Body)
			}
		}
		before := len(e.store.Records())
		req := httptest.NewRequest(http.MethodPost, "/api/maintenance", strings.NewReader(`{"providers":["transit-a"],"duration":"1h"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+e.tokens["operator/"+scope])
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || len(e.maint.opened) != 0 {
			t.Errorf("%s: REST write %d, opened %v", scope, rec.Code, e.maint.opened)
		}
		if recs := e.store.Records(); len(recs) != before+1 || recs[before].Result != auth.ResultDenied {
			t.Errorf("%s: REST write not audited as denied: %+v", scope, recs[before:])
		}
	}
}

func TestMCPToolListFollowsOptionAndScope(t *testing.T) {
	on := newMCPEnv(t, &MCPOptions{RatePerMinute: 60, WriteTools: true})
	for tok, want := range map[string]bool{"operator/mcp:write": true, "operator/mcp": false, "operator/": false, "viewer/": false} {
		if got := on.toolNames(t, on.tokens[tok])["maintenance_open"]; got != want {
			t.Errorf("write tools listed for %s = %v, want %v", tok, got, want)
		}
	}
	if !on.toolNames(t, on.tokens["operator/mcp"])["overview"] {
		t.Error("read tools missing")
	}
	off := newMCPEnv(t, &MCPOptions{RatePerMinute: 60})
	if off.toolNames(t, off.tokens["operator/mcp:write"])["maintenance_open"] {
		t.Error("write tools listed with mcp.write_tools off")
	}
}

func TestMCPWriteToolAuditedAndRoleChecked(t *testing.T) {
	e := newMCPEnv(t, &MCPOptions{RatePerMinute: 60, WriteTools: true})
	args := `{"providers":["transit-a"],"duration":"30m","reason":"lab work"}`

	text, isErr := mcpText(t, e.post(e.tokens["operator/mcp:write"], mcpCall("maintenance_open", args)))
	if isErr || !strings.Contains(text, `"id":"api-1"`) {
		t.Fatalf("open: %q %v", text, isErr)
	}
	if len(e.maint.opened) != 1 || !strings.HasPrefix(e.maint.opened[0], "transit-a/") || !strings.HasSuffix(e.maint.opened[0], "/30m0s/lab work") {
		t.Fatalf("opened %v", e.maint.opened)
	}
	recs := e.store.Records()
	if len(recs) != 1 {
		t.Fatalf("%d audit records, want 1: %+v", len(recs), recs)
	}
	if r := recs[0]; r.Actor != "operator-user" || r.Method != auth.MethodToken || r.Action != "POST /api/maintenance" ||
		r.Result != auth.ResultOK || !strings.HasPrefix(r.Detail, "via mcp ") {
		t.Errorf("audit %+v", r)
	}

	text, isErr = mcpText(t, e.post(e.tokens["operator/mcp:write"], mcpCall("maintenance_close", `{"id":"api-1"}`)))
	if isErr || !strings.Contains(text, "204") {
		t.Errorf("close: %q %v", text, isErr)
	}
	if len(e.maint.closed) != 1 || e.maint.closed[0] != "api-1" {
		t.Errorf("closed %v", e.maint.closed)
	}

	// A viewer's mcp:write token is still a viewer: the route refuses it.
	e.maint.opened = nil
	text, isErr = mcpText(t, e.post(e.tokens["viewer/mcp:write"], mcpCall("maintenance_open", args)))
	if !isErr || !strings.Contains(text, "HTTP 403") || !strings.Contains(text, "needs role operator") || len(e.maint.opened) != 0 {
		t.Errorf("viewer write: %q %v opened %v", text, isErr, e.maint.opened)
	}
}

func TestMCPWriteDeniedWithoutScopeOrOption(t *testing.T) {
	for name, tc := range map[string]struct {
		opt   MCPOptions
		token string
	}{
		"read-only scope":   {MCPOptions{RatePerMinute: 60, WriteTools: true}, "operator/mcp"},
		"unscoped token":    {MCPOptions{RatePerMinute: 60, WriteTools: true}, "operator/"},
		"write tools off":   {MCPOptions{RatePerMinute: 60}, "operator/mcp:write"},
		"viewer scope only": {MCPOptions{RatePerMinute: 60, WriteTools: true}, "viewer/mcp"},
	} {
		e := newMCPEnv(t, &tc.opt)
		text, isErr := mcpText(t, e.post(e.tokens[tc.token], mcpCall("maintenance_open", `{"providers":["transit-a"],"duration":"1h"}`)))
		if !isErr || !strings.Contains(text, "mcp:write") {
			t.Errorf("%s: %q %v", name, text, isErr)
		}
		if len(e.maint.opened) != 0 {
			t.Errorf("%s: a window was opened: %v", name, e.maint.opened)
		}
		recs := e.store.Records()
		if len(recs) != 1 || recs[0].Action != "MCP tools/call maintenance_open" || recs[0].Result != auth.ResultDenied || recs[0].Status != http.StatusForbidden {
			t.Errorf("%s: audit %+v", name, recs)
		}
	}
}

func TestMCPTransportRules(t *testing.T) {
	e := newMCPEnv(t, &MCPOptions{RatePerMinute: 60})
	tok := e.tokens["viewer/mcp"]
	if rec := e.post(tok, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
		t.Errorf("notification: %d %q", rec.Code, rec.Body)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("content type: %d", rec.Code)
	}
	if rec := e.post(tok, `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"`+strings.Repeat("a", 70<<10)+`"}}`); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("large body: %d", rec.Code)
	}
	if rec := e.post(tok, `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`); !strings.Contains(rec.Body.String(), "batches are not supported") {
		t.Errorf("batch: %d %s", rec.Code, rec.Body)
	}
	get := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	get.Header.Set("Authorization", "Bearer "+tok)
	rec = httptest.NewRecorder()
	e.h.ServeHTTP(rec, get)
	if rec.Code == http.StatusOK {
		t.Errorf("GET /mcp answered: %d", rec.Code)
	}
}

func TestMCPRateLimitPerCaller(t *testing.T) {
	e := newMCPEnv(t, &MCPOptions{RatePerMinute: 3})
	ping := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	for i := range 3 {
		if rec := e.post(e.tokens["viewer/mcp"], ping); rec.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i+1, rec.Code)
		}
	}
	rec := e.post(e.tokens["viewer/mcp"], ping)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("past the limit: %d retry-after %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	if rec := e.post(e.tokens["operator/mcp"], ping); rec.Code != http.StatusOK {
		t.Errorf("another user shares the limit: %d", rec.Code)
	}
}

func TestMCPWithBasicAuthIsReadOnly(t *testing.T) {
	srv, err := New(Options{User: "ops", Password: "secret", Maintenance: &fakeMaint{canOpen: true}, MCP: &MCPOptions{RatePerMinute: 60, WriteTools: true},
		Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if err != nil {
		t.Fatal(err)
	}
	post := func(user bool, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if user {
			req.SetBasicAuth("ops", "secret")
		}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}
	if rec := post(false, mcpCall("overview", `{}`)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no credentials: %d", rec.Code)
	}
	if text, isErr := mcpText(t, post(true, mcpCall("overview", `{}`))); isErr || !strings.Contains(text, `"mode"`) {
		t.Errorf("overview: %q %v", text, isErr)
	}
	if text, isErr := mcpText(t, post(true, mcpCall("maintenance_open", `{"providers":["transit-a"],"duration":"1h"}`))); !isErr || !strings.Contains(text, "mcp:write") {
		t.Errorf("write under basic auth: %q %v", text, isErr)
	}
}

func TestTokenScopeThroughTheAPI(t *testing.T) {
	e := newRBAC(t, nil)
	create := func(body string) *httptest.ResponseRecorder {
		return e.do(http.MethodPost, "/api/tokens", "", body, func(r *http.Request) { r.SetBasicAuth("operator-user", "operator-user-password") })
	}
	rec := create(`{"name":"assistant","scope":"mcp"}`)
	var got struct {
		Scope string `json:"scope"`
		Token string `json:"token"`
	}
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.Scope != "mcp" || got.Token == "" {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if rec := create(`{"name":"assistant","scope":"root"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown scope: %d %s", rec.Code, rec.Body)
	}
	// A scoped token cannot mint tokens, and the listing shows the scope.
	if rec := e.do(http.MethodPost, "/api/tokens", got.Token, `{"name":"x"}`); rec.Code != http.StatusForbidden {
		t.Errorf("scoped token created a token: %d", rec.Code)
	}
	list := e.do(http.MethodGet, "/api/tokens", "", "", func(r *http.Request) { r.SetBasicAuth("operator-user", "operator-user-password") })
	if !strings.Contains(list.Body.String(), `"scope":"mcp"`) {
		t.Errorf("listing: %s", list.Body)
	}
}

// With no auth at all the caller is anonymous: a refused write tool is
// answered but not audited, so nobody who reaches the port fills the log.
func TestMCPAnonymousRefusalsAreNotAudited(t *testing.T) {
	store := authtest.New()
	srv, err := New(Options{Audit: auth.NewAuditor(store, func(plugin.Event) {}, nil), Maintenance: &fakeMaint{canOpen: true}, MCP: &MCPOptions{RatePerMinute: 60, WriteTools: true},
		Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(mcpCall("maintenance_open", `{"providers":["transit-a"],"duration":"1h"}`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if text, isErr := mcpText(t, rec); !isErr || !strings.Contains(text, "mcp:write") {
		t.Errorf("answer %q %v", text, isErr)
	}
	if recs := store.Records(); len(recs) != 0 {
		t.Errorf("anonymous refusal audited: %+v", recs)
	}
}
