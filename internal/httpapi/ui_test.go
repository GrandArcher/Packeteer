package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/auth/authtest"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/configedit"
	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/subscribe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const editorYAML = `mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
  - name: transit-b
    source_ip: 192.0.2.12
    next_hop: 192.0.2.2
`

const editorInjectYAML = `mode: inject
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 250
hold_time: 5m
thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
  - name: transit-b
    source_ip: 192.0.2.12
    next_hop: 192.0.2.2
allowlist:
  prefixes: [198.51.100.0/24]
bgp:
  neighbors:
    - address: 192.0.2.254
announcer:
  type: gobgp
`

func newEditor(t *testing.T) (*configedit.Editor, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(editorYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	running, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	diff := func(a, b *config.Config) (restart, online []string) {
		if a.Mode != b.Mode {
			restart = append(restart, "mode")
		}
		if !reflect.DeepEqual(a.BGP.Neighbors, b.BGP.Neighbors) {
			online = append(online, "bgp.neighbors")
		}
		return restart, online
	}
	e, err := configedit.New(path, running, config.Parse, diff)
	if err != nil {
		t.Fatal(err)
	}
	return e, path
}

type memDashboards struct {
	mu sync.Mutex
	m  map[string]plugin.Dashboard
}

func (d *memDashboards) Dashboards(_ context.Context, owner string) ([]plugin.Dashboard, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []plugin.Dashboard
	for _, v := range d.m {
		if v.Owner == owner {
			out = append(out, v)
		}
	}
	return out, nil
}

func (d *memDashboards) PutDashboard(_ context.Context, v plugin.Dashboard) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.m == nil {
		d.m = map[string]plugin.Dashboard{}
	}
	d.m[v.Owner+"/"+v.Name] = v
	return nil
}

func (d *memDashboards) DeleteDashboard(_ context.Context, owner, name string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.m[owner+"/"+name]
	delete(d.m, owner+"/"+name)
	return ok, nil
}

type fakeSubs struct {
	sent []string
	fail error
}

func (f *fakeSubs) Status() []subscribe.Status {
	return []subscribe.Status{{Name: "weekly", Report: "summary", Schedule: "weekly", At: "06:00", Weekday: "monday", Days: 7, Notifier: "mail"}}
}

func (f *fakeSubs) SendNow(_ context.Context, name string) error {
	if name != "weekly" {
		return subscribe.ErrNotFound
	}
	if f.fail != nil {
		return f.fail
	}
	f.sent = append(f.sent, name)
	return nil
}

// uiEnv is a server with auth (a user per role), the editor on a temp
// file, an in-memory dashboard store, and fake subscriptions.
type uiEnv struct {
	h      http.Handler
	srv    *Server
	path   string
	store  *authtest.Store
	dash   *memDashboards
	subs   *fakeSubs
	tokens map[plugin.Role]string
}

func newUI(t *testing.T) *uiEnv {
	t.Helper()
	e := &uiEnv{store: authtest.New(), dash: &memDashboards{}, subs: &fakeSubs{}, tokens: map[plugin.Role]string{}}
	svc, err := auth.New(auth.Options{Users: e.store})
	if err != nil {
		t.Fatal(err)
	}
	ed, path := newEditor(t)
	e.path = path
	srv, err := New(Options{Auth: svc, Audit: auth.NewAuditor(e.store, nil, nil), ConfigEditor: ed, Dashboards: e.dash, Subscriptions: e.subs,
		Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if err != nil {
		t.Fatal(err)
	}
	e.srv, e.h = srv, srv.Handler()
	for _, r := range []plugin.Role{plugin.RoleViewer, plugin.RoleOperator, plugin.RoleAdmin} {
		name := string(r) + "-user"
		if _, err := svc.CreateUser(context.Background(), name, r, name+"-password"); err != nil {
			t.Fatal(err)
		}
		_, tok, err := svc.CreateToken(context.Background(), auth.Principal{User: name, Role: r, Method: auth.MethodPassword}, "t", r, 0)
		if err != nil {
			t.Fatal(err)
		}
		e.tokens[r] = tok
	}
	return e
}

func (e *uiEnv) do(t *testing.T, method, path string, role plugin.Role, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var rd *strings.Reader
	if s, ok := body.(string); ok {
		rd = strings.NewReader(s)
	} else if body != nil {
		raw, _ := json.Marshal(body)
		rd = strings.NewReader(string(raw))
	} else {
		rd = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+e.tokens[role])
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func TestConfigEditorAPI(t *testing.T) {
	e := newUI(t)
	admin := plugin.RoleAdmin

	rec, got := e.do(t, "GET", "/api/config", admin, nil)
	if rec.Code != http.StatusOK || got["yaml"] != editorYAML || got["sha256"] != configedit.Hash([]byte(editorYAML)) {
		t.Fatalf("get: %d %s", rec.Code, rec.Body)
	}
	base := got["sha256"].(string)

	// Validate reports errors without writing.
	rec, got = e.do(t, "POST", "/api/config/validate", admin, map[string]any{"yaml": editorYAML + "bogus: 1\n"})
	if rec.Code != http.StatusOK || got["valid"] != false || !strings.Contains(rec.Body.String(), "bogus") {
		t.Fatalf("validate: %d %s", rec.Code, rec.Body)
	}

	// Invalid: 422, file untouched.
	rec, _ = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": "mode: observe\n", "base": base})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid: %d %s", rec.Code, rec.Body)
	}
	// Stale base: 409.
	rec, _ = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": editorYAML, "base": strings.Repeat("0", 64)})
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale: %d %s", rec.Code, rec.Body)
	}
	// Turning inject on needs confirm_inject.
	rec, got = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": editorInjectYAML, "base": base})
	if rec.Code != http.StatusPreconditionRequired || got["result"].(map[string]any)["enables_inject"] != true {
		t.Fatalf("inject unconfirmed: %d %s", rec.Code, rec.Body)
	}
	if disk, _ := os.ReadFile(e.path); string(disk) != editorYAML {
		t.Fatal("file changed by refused writes")
	}

	// A valid edit is written and round-trips through config.Load.
	next := strings.Replace(editorYAML, "router_id: 192.0.2.10", "router_id: 192.0.2.20", 1)
	rec, got = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": next, "base": base})
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	loaded, err := config.Load(e.path)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := config.Parse([]byte(next))
	if !reflect.DeepEqual(loaded, want) || loaded.RouterID != "192.0.2.20" {
		t.Fatalf("round trip: %+v", loaded)
	}
	if got["file"].(map[string]any)["sha256"] != configedit.Hash([]byte(next)) {
		t.Fatalf("file = %v", got["file"])
	}

	// Audited, with hashes, never the content.
	var found bool
	for _, r := range e.store.Records() {
		if r.Action == "PUT /api/config" && r.Result == auth.ResultOK {
			found = true
			if r.Target != "config" || !strings.Contains(r.Detail, "new="+configedit.Hash([]byte(next))[:12]) || strings.Contains(r.Detail, "router_id") {
				t.Fatalf("audit = %+v", r)
			}
		}
	}
	if !found {
		t.Fatal("config write not audited")
	}

	// Below admin: refused and audited as denied.
	for _, role := range []plugin.Role{plugin.RoleViewer, plugin.RoleOperator} {
		if rec, _ := e.do(t, "PUT", "/api/config", role, map[string]any{"yaml": editorYAML, "base": configedit.Hash([]byte(next))}); rec.Code != http.StatusForbidden {
			t.Fatalf("%s write: %d", role, rec.Code)
		}
		if rec, _ := e.do(t, "GET", "/api/config", role, nil); rec.Code != http.StatusForbidden {
			t.Fatalf("%s read: %d", role, rec.Code)
		}
	}
	if disk, _ := os.ReadFile(e.path); string(disk) != next {
		t.Fatal("non-admin changed the file")
	}
}

func TestConfigEditorOffAndNoAuth(t *testing.T) {
	srv, err := New(Options{Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/config", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("editor off: %d", rec.Code)
	}
	// The wizard is part of the editor: off with it, even with auth.
	off, _ := New(Options{User: "ops", Password: "secret", Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	rec = httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/config/wizard", strings.NewReader(`{"asn":64512}`))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("ops", "secret")
	off.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("wizard with the editor off: %d %s", rec.Code, rec.Body)
	}
	// On, but no auth at all: refused, so nobody anonymous edits the file.
	ed, _ := newEditor(t)
	srv, _ = New(Options{ConfigEditor: ed, Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	for _, m := range []string{"GET", "PUT"} {
		rec = httptest.NewRecorder()
		req := httptest.NewRequest(m, "/api/config", strings.NewReader(`{"yaml":"","base":""}`))
		req.Header.Set("Content-Type", "application/json")
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s without auth: %d %s", m, rec.Code, rec.Body)
		}
	}
	// With basic auth the one account is admin.
	srv, _ = New(Options{User: "ops", Password: "secret", ConfigEditor: ed, Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/config", nil)
	req.SetBasicAuth("ops", "secret")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("basic auth: %d", rec.Code)
	}
}

func TestWizardAPIRoundTrip(t *testing.T) {
	e := newUI(t)
	in := configedit.WizardInput{ASN: 64512, RouterID: "192.0.2.10", Edge: "192.0.2.254",
		Providers: []configedit.WizardProvider{{Name: "transit-a", SourceIP: "192.0.2.11", NextHop: "192.0.2.1"}, {Name: "transit-b", SourceIP: "192.0.2.12", NextHop: "192.0.2.2"}},
		Prefix:    "198.51.100.0/26", Host: "198.51.100.1"}
	rec, got := e.do(t, "POST", "/api/config/wizard", plugin.RoleAdmin, in)
	if rec.Code != http.StatusOK || got["mode"] != "observe" {
		t.Fatalf("wizard: %d %s", rec.Code, rec.Body)
	}
	yml := got["yaml"].(string)
	// The wizard output goes through the editor like any edit.
	rec, _ = e.do(t, "PUT", "/api/config", plugin.RoleAdmin, map[string]any{"yaml": yml, "base": configedit.Hash([]byte(editorYAML))})
	if rec.Code != http.StatusOK {
		t.Fatalf("save wizard config: %d %s", rec.Code, rec.Body)
	}
	cfg, err := config.Load(e.path)
	if err != nil || cfg.Mode != config.ModeObserve || len(cfg.BGP.Neighbors) != 1 || cfg.Announcer != nil {
		t.Fatalf("wizard config after save: %+v %v", cfg, err)
	}
	if rec, _ := e.do(t, "POST", "/api/config/wizard", plugin.RoleAdmin, map[string]any{"asn": 64512}); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad wizard input: %d", rec.Code)
	}
	if rec, got := e.do(t, "POST", "/api/config/wizard", plugin.RoleAdmin, map[string]any{"asn": 64512, "router_id": "192.0.2.10", "edge": "192.0.2.254", "providers": []map[string]string{{"name": "transit-a", "source_ip": "192.0.2.11", "next_hop": "192.0.2.1"}}, "mode": "inject"}); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "inject is not a step") {
		t.Fatalf("inject step: %d %s", rec.Code, rec.Body)
	} else if y, _ := got["yaml"].(string); strings.Contains(y, "inject") {
		t.Fatalf("inject yaml returned: %s", y)
	}
	if rec, _ := e.do(t, "POST", "/api/config/wizard", plugin.RoleAdmin, map[string]any{"asn": 64512, "router_id": "192.0.2.10", "edge": "192.0.2.254", "providers": []map[string]string{{"name": "transit-a", "source_ip": "192.0.2.11", "next_hop": "192.0.2.1"}}, "password": "secret"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("secret field: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := e.do(t, "POST", "/api/config/wizard", plugin.RoleOperator, in); rec.Code != http.StatusForbidden {
		t.Fatalf("operator wizard: %d", rec.Code)
	}
}

func TestDashboardsAPI(t *testing.T) {
	e := newUI(t)
	rec, got := e.do(t, "GET", "/api/dashboards", plugin.RoleViewer, nil)
	if rec.Code != http.StatusOK || got["enabled"] != true || len(got["widget_types"].([]any)) != len(WidgetTypes) || len(got["dashboards"].([]any)) != 0 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	spec := DashboardSpec{Title: "Transit", Widgets: []Widget{{Type: "providers"}, {Type: "improvements", Wide: true}, {Type: "report", Report: "summary", Days: 7}}}
	if rec, _ := e.do(t, "PUT", "/api/dashboards/transit", plugin.RoleViewer, spec); rec.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rec.Code, rec.Body)
	}
	rec, got = e.do(t, "GET", "/api/dashboards", plugin.RoleViewer, nil)
	ds := got["dashboards"].([]any)
	if len(ds) != 1 || ds[0].(map[string]any)["name"] != "transit" || len(ds[0].(map[string]any)["spec"].(map[string]any)["widgets"].([]any)) != 3 {
		t.Fatalf("after put: %s", rec.Body)
	}
	// Another user does not see it.
	if _, got := e.do(t, "GET", "/api/dashboards", plugin.RoleOperator, nil); len(got["dashboards"].([]any)) != 0 {
		t.Fatalf("dashboards leak between users: %v", got["dashboards"])
	}
	for name, bad := range map[string]any{
		"unknown widget":       DashboardSpec{Widgets: []Widget{{Type: "shell"}}},
		"unknown report":       DashboardSpec{Widgets: []Widget{{Type: "report", Report: "nope"}}},
		"report on non-report": DashboardSpec{Widgets: []Widget{{Type: "providers", Report: "summary"}}},
		"bucket on report":     DashboardSpec{Widgets: []Widget{{Type: "report", Report: "summary", Bucket: "all"}}},
		"bucket on providers":  DashboardSpec{Widgets: []Widget{{Type: "providers", Bucket: "all"}}},
		"unknown bucket":       DashboardSpec{Widgets: []Widget{{Type: "timeseries", Bucket: "better_99"}}},
		"report on timeseries": DashboardSpec{Widgets: []Widget{{Type: "timeseries", Report: "summary"}}},
		"days too long":        DashboardSpec{Widgets: []Widget{{Type: "timeseries", Days: MaxReportDays + 1}}},
		"newline title":        DashboardSpec{Title: "a\nb"},
		"too many":             DashboardSpec{Widgets: make([]Widget, MaxDashboardWidgets+1)},
		"unknown field":        `{"widgets":[],"script":"x"}`,
	} {
		if rec, _ := e.do(t, "PUT", "/api/dashboards/x", plugin.RoleViewer, bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec, _ := e.do(t, "PUT", "/api/dashboards/"+strings.Repeat("a", 70), plugin.RoleViewer, spec); rec.Code != http.StatusBadRequest {
		t.Fatalf("long name: %d", rec.Code)
	}
	for i := range MaxDashboards - 1 {
		if rec, _ := e.do(t, "PUT", "/api/dashboards/d"+string(rune('a'+i)), plugin.RoleViewer, spec); rec.Code != http.StatusOK {
			t.Fatalf("put %d: %d", i, rec.Code)
		}
	}
	if rec, _ := e.do(t, "PUT", "/api/dashboards/one-more", plugin.RoleViewer, spec); rec.Code != http.StatusConflict {
		t.Fatalf("over the limit: %d", rec.Code)
	}
	if rec, _ := e.do(t, "PUT", "/api/dashboards/transit", plugin.RoleViewer, spec); rec.Code != http.StatusOK {
		t.Fatalf("replace at the limit: %d", rec.Code)
	}
	if rec, _ := e.do(t, "DELETE", "/api/dashboards/transit", plugin.RoleViewer, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec, _ := e.do(t, "DELETE", "/api/dashboards/transit", plugin.RoleViewer, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("delete twice: %d", rec.Code)
	}
}

func TestSubscriptionsAPI(t *testing.T) {
	e := newUI(t)
	rec, got := e.do(t, "GET", "/api/subscriptions", plugin.RoleViewer, nil)
	if rec.Code != http.StatusOK || got["enabled"] != true || len(got["subscriptions"].([]any)) != 1 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := e.do(t, "POST", "/api/subscriptions/weekly/send", plugin.RoleViewer, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer send: %d", rec.Code)
	}
	if rec, _ := e.do(t, "POST", "/api/subscriptions/weekly/send", plugin.RoleOperator, nil); rec.Code != http.StatusOK || len(e.subs.sent) != 1 {
		t.Fatalf("operator send: %d %v", rec.Code, e.subs.sent)
	}
	if rec, _ := e.do(t, "POST", "/api/subscriptions/nope/send", plugin.RoleOperator, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown: %d", rec.Code)
	}
	e.subs.fail = errors.New("relay down")
	if rec, _ := e.do(t, "POST", "/api/subscriptions/weekly/send", plugin.RoleOperator, nil); rec.Code != http.StatusBadGateway {
		t.Fatalf("failed send: %d", rec.Code)
	}
}

// The settings and dashboards pages are served, use only same-origin
// scripts (no inline script under the CSP), and call the #34 endpoints.
func TestUIPages(t *testing.T) {
	e := newUI(t)
	for page, wants := range map[string][]string{
		"/settings.html":   {`src="/ui.js"`, `src="/settings.js"`, `id="ed-yaml"`, `id="wz-run"`, `id="wz-edge"`, `id="wz-add-provider"`, `id="wz-host"`, `id="subs"`, `id="form-apply"`, `id="form-providers"`, `id="sug-refresh"`, `id="fm-rtt-pct"`, `id="fm-rounds"`},
		"/dashboards.html": {`src="/ui.js"`, `src="/charts.js"`, `src="/dashboards.js"`, `id="db-grid"`, `id="db-bucket"`},
		"/settings.js":     {"/api/config/validate", "/api/config/wizard", "/api/config/form", "/api/config/suggestions", "confirm_inject", "/api/subscriptions/", "function acceptSuggestion", "inject is not a step", "function renderWzProviders", "min_rtt_delta_pct", "confirm_rounds"},
		"/dashboards.js":   {"/api/dashboards", "widget_types", "renderTimeSeries"},
		"/graphs.html":     {`src="/charts.js"`, `src="/graphs.js"`, `id="graph"`},
		"/graphs.js":       {"/api/reports/timeseries", "renderTimeSeries"},
		"/charts.js":       {"createElementNS", "function renderTimeSeries", "No before/after data in this range"},
		"/":                {`href="/settings.html"`, `href="/dashboards.html"`},
	} {
		rec, _ := e.do(t, "GET", page, plugin.RoleViewer, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", page, rec.Code)
		}
		body := rec.Body.String()
		for _, w := range wants {
			if !strings.Contains(body, w) {
				t.Errorf("%s missing %q", page, w)
			}
		}
		if strings.HasSuffix(page, ".html") && strings.Contains(body, "<script>") {
			t.Errorf("%s has an inline script", page)
		}
	}
}

func TestDecisionWeightInSnapshot(t *testing.T) {
	out := assembleDecisions([]policy.Decision{{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Action: policy.ActionImprove, Weight: 530}})
	if len(out) != 1 || out[0].Weight != 530 {
		t.Fatalf("decisions = %+v", out)
	}
	raw, _ := json.Marshal(out[0])
	if !strings.Contains(string(raw), `"weight":530`) {
		t.Fatalf("json = %s", raw)
	}
}

func TestConfigFormAndSuggestions(t *testing.T) {
	e := newUI(t)
	admin := plugin.RoleAdmin
	e.srv.SetSuggestions(func() []Suggestion {
		return []Suggestion{{NextHop: "192.0.2.9", ASN: 64496, Prefixes: 4}}
	})
	before, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}

	rec, got := e.do(t, "GET", "/api/config/suggestions", admin, nil)
	if rec.Code != http.StatusOK || len(got["suggestions"].([]any)) != 1 {
		t.Fatalf("suggestions: %d %s", rec.Code, rec.Body)
	}
	after, err := os.ReadFile(e.path)
	if err != nil || string(after) != string(before) {
		t.Fatal("suggestions wrote the config file")
	}
	if rec, _ := e.do(t, "GET", "/api/config/suggestions", plugin.RoleOperator, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("operator suggestions: %d", rec.Code)
	}

	rec, got = e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": editorYAML, "apply": false})
	if rec.Code != http.StatusOK {
		t.Fatalf("parse: %d %s", rec.Code, rec.Body)
	}
	fm := got["form"].(map[string]any)
	provs := fm["providers"].([]any)
	if len(provs) != 2 {
		t.Fatalf("providers: %s", rec.Body)
	}
	// Accepting a suggestion is a draft row: next hop and AS only.
	// Cost, commit, and probe source stay empty. Apply must not write
	// the AS, must not add an announcer, and must not save.
	provs = append(provs, map[string]any{
		"key": "", "name": "transit-c", "source_ip": "192.0.2.13", "next_hop": "192.0.2.9",
		"cost": "", "commit_mbps": "", "asn": "64496", "draft": true,
	})
	fm["providers"] = provs
	rec, got = e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": editorYAML, "apply": true, "form": fm})
	if rec.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body)
	}
	yml := got["yaml"].(string)
	if strings.Contains(yml, "64496") || strings.Contains(yml, "announcer:") || strings.Contains(yml, "graceful") {
		t.Fatalf("apply wrote a suggestion AS or an announcer:\n%s", yml)
	}
	if !strings.Contains(yml, "next_hop: 192.0.2.9") || !strings.Contains(yml, "mode: observe") {
		t.Fatalf("apply:\n%s", yml)
	}
	disk, err := os.ReadFile(e.path)
	if err != nil || string(disk) != editorYAML {
		t.Fatal("apply wrote the file")
	}

	// The form can put mode inject into the YAML text. Save still refuses
	// it: an incomplete inject file fails the start checks, and a valid
	// one still needs confirm_inject. Neither write touches the file.
	fm["mode"] = "inject"
	rec, got = e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": yml, "apply": true, "form": fm})
	if rec.Code != http.StatusOK || !strings.Contains(got["yaml"].(string), "mode: inject") {
		t.Fatalf("inject text: %d %s", rec.Code, rec.Body)
	}
	rec, _ = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": got["yaml"], "base": configedit.Hash([]byte(editorYAML))})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("incomplete inject: %d %s", rec.Code, rec.Body)
	}
	rec, _ = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": editorInjectYAML, "base": configedit.Hash([]byte(editorYAML))})
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("inject without confirm: %d %s", rec.Code, rec.Body)
	}
	disk, _ = os.ReadFile(e.path)
	if string(disk) != editorYAML {
		t.Fatal("refused inject still wrote the file")
	}

	// The page's accept function must not call the API.
	rec, _ = e.do(t, "GET", "/settings.js", plugin.RoleViewer, nil)
	js := rec.Body.String()
	i := strings.Index(js, "function acceptSuggestion")
	j := strings.Index(js[i:], "\nfunction ")
	if i < 0 || j < 0 {
		t.Fatal("acceptSuggestion missing")
	}
	body := js[i : i+j]
	if strings.Contains(body, "api(") || strings.Contains(body, "PUT") || strings.Contains(body, "/api/") {
		t.Fatalf("accepting a suggestion calls the API:\n%s", body)
	}
}

// TestHeterogeneousInSnapshot checks the #121 sub-range view reaches
// /api/decisions and the dashboard prefix card.
func TestHeterogeneousInSnapshot(t *testing.T) {
	wide := netip.MustParsePrefix("198.51.100.0/24")
	d := policy.Decision{Prefix: wide, Action: policy.ActionNone, Recommended: "a", Heterogeneous: true,
		Subranges: []policy.SubrangeDecision{
			{Prefix: netip.MustParsePrefix("198.51.100.0/26"), Weight: 600, Best: "a", Candidates: []policy.Candidate{{Provider: "a", Score: 10, Usable: true}}},
			{Prefix: netip.MustParsePrefix("198.51.100.192/26"), Weight: 400, Best: "b", Candidates: []policy.Candidate{{Provider: "b", Score: 12, Usable: true}}},
		}}
	out := assembleDecisions([]policy.Decision{d})
	if len(out) != 1 || !out[0].Heterogeneous || len(out[0].Subranges) != 2 || out[0].Subranges[1].Best != "b" {
		t.Fatalf("decisions = %+v", out)
	}
	raw, _ := json.Marshal(out[0])
	for _, want := range []string{`"heterogeneous":true`, `"prefix":"198.51.100.192/26"`, `"weight":400`, `"best":"b"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("json missing %s: %s", want, raw)
		}
	}
	plain, _ := json.Marshal(assembleDecisions([]policy.Decision{{Prefix: wide, Action: policy.ActionNone}})[0])
	if strings.Contains(string(plain), "heterogeneous") || strings.Contains(string(plain), "subranges") {
		t.Fatalf("plain decision json = %s", plain)
	}
	ps := assemblePrefixes(Input{Decisions: []policy.Decision{d}})
	if len(ps) != 1 || !ps[0].Heterogeneous || len(ps[0].Subranges) != 2 {
		t.Fatalf("prefixes = %+v", ps)
	}
}

// TestIndirectProbeInSnapshot checks the #123 indirect mark reaches the
// prefix rows and the dashboard labels it.
func TestIndirectProbeInSnapshot(t *testing.T) {
	r := probe.Result{Provider: "a", Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		Target: netip.MustParseAddr("192.0.2.7"), Indirect: true, Stats: probe.Stats{Sent: 3, Received: 3}}
	raw, _ := json.Marshal(probeFrom(r))
	if !strings.Contains(string(raw), `"indirect":true`) || !strings.Contains(string(raw), `"target":"192.0.2.7"`) {
		t.Fatalf("indirect probe json = %s", raw)
	}
	r.Indirect = false
	raw, _ = json.Marshal(probeFrom(r))
	if strings.Contains(string(raw), "indirect") {
		t.Fatalf("direct probe json = %s", raw)
	}
	js, err := fs.ReadFile(webFS, "web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), "pr.indirect") || !strings.Contains(string(js), `"indirect"`) {
		t.Fatal("app.js does not label indirect probes")
	}
}

// The online apply after a PUT gets a context the request does not
// cancel, so sources it starts survive the response.
func TestConfigSaveOnlineApplyContextOutlivesRequest(t *testing.T) {
	e := newUI(t)
	var got context.Context
	e.srv.SetOnlineApply(func(c context.Context) ([]string, error, error) {
		got = c
		return []string{"bgp.neighbors"}, nil, nil
	})
	next := editorYAML + "bgp:\n  neighbors:\n    - address: 192.0.2.254\n"
	rec, _ := e.do(t, "PUT", "/api/config", plugin.RoleAdmin, map[string]any{"yaml": next, "base": configedit.Hash([]byte(editorYAML))})
	if rec.Code != http.StatusOK || got == nil {
		t.Fatalf("save: %d %s applied=%v", rec.Code, rec.Body, got != nil)
	}
	if got.Err() != nil || got.Done() != nil {
		t.Fatal("online apply context is cancelled with the request")
	}
}

// The before/after graph widget (#129) is saved with its days and bucket,
// goes through the same dashboard validation and audit as every widget, and
// reads only the report endpoint.
func TestDashboardTimeSeriesWidget(t *testing.T) {
	e := newUI(t)
	spec := DashboardSpec{Widgets: []Widget{
		{Type: "timeseries"},
		{Type: "timeseries", Days: 30, Bucket: "better_50", Wide: true},
	}}
	if rec, _ := e.do(t, "PUT", "/api/dashboards/graphs", plugin.RoleViewer, spec); rec.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rec.Code, rec.Body)
	}
	rec, got := e.do(t, "GET", "/api/dashboards", plugin.RoleViewer, nil)
	ws := got["dashboards"].([]any)[0].(map[string]any)["spec"].(map[string]any)["widgets"].([]any)
	if len(ws) != 2 || ws[1].(map[string]any)["bucket"] != "better_50" || ws[1].(map[string]any)["days"] != float64(30) {
		t.Fatalf("round trip: %s", rec.Body)
	}
	var found bool
	for _, w := range got["widget_types"].([]any) {
		m := w.(map[string]any)
		if m["type"] == "timeseries" {
			found = m["api"] == "/api/reports/timeseries"
		}
	}
	if !found {
		t.Fatalf("widget_types has no timeseries: %s", rec.Body)
	}
	for _, b := range history.Buckets {
		if err := (DashboardSpec{Widgets: []Widget{{Type: "timeseries", Bucket: b}}}).Validate(); err != nil {
			t.Errorf("bucket %s: %v", b, err)
		}
	}
}
