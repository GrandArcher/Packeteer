package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/configedit"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// The #130 sections go through the same two calls as the older fields:
// POST /api/config/form merges and writes nothing, PUT /api/config saves
// after the start checks, audited, admin only.
func TestConfigFormSections(t *testing.T) {
	e := newUI(t)
	admin := plugin.RoleAdmin

	rec, got := e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": editorYAML})
	if rec.Code != http.StatusOK {
		t.Fatalf("parse: %d %s", rec.Code, rec.Body)
	}
	fm := got["form"].(map[string]any)
	for _, k := range []string{"flows", "policies", "vips", "outages"} {
		if l, ok := fm[k].([]any); !ok || len(l) != 0 {
			t.Fatalf("form has no empty %s list: %s", k, rec.Body)
		}
	}

	fm["flows"] = []map[string]any{{"listen": []string{"192.0.2.10:2055"}, "window": "10m", "top_n": "50", "min_pct": "0.5", "aggregate_v4": "22", "exclude": []string{"192.0.2.0/25"}}}
	fm["policies"] = []map[string]any{{"rules": []map[string]any{
		{"name": "pin-a", "action": "static", "providers": []string{"transit-a"}, "prefixes": []string{"203.0.113.0/24"}, "max_loss_pct": "1", "max_rtt": "150ms"},
		{"name": "no-b", "action": "deny", "providers": []string{"transit-b"}, "asns": []string{"64500"}},
	}}}
	fm["vips"] = []map[string]any{{"interval": "10s", "prefixes": []map[string]any{{"prefix": "198.51.100.0/24", "host": "198.51.100.1"}}}}
	fm["outages"] = []map[string]any{{"min_prefixes": "4", "loss_pct": "30"}}
	rec, got = e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": editorYAML, "apply": true, "form": fm})
	if rec.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body)
	}
	yml := got["yaml"].(string)
	for _, want := range []string{"type: flow", "listen: 192.0.2.10:2055", "min_pct: 0.5", "aggregate_v4: 22", "type: rules", "name: pin-a", "max_loss_pct: 1", "type: vip", "type: outage", "min_prefixes: 4"} {
		if !strings.Contains(yml, want) {
			t.Errorf("merged yaml missing %q:\n%s", want, yml)
		}
	}
	if strings.Contains(yml, "mode: inject") || strings.Contains(yml, "announcer:") || strings.Contains(yml, "allowlist:") {
		t.Fatalf("sections changed the safety fields:\n%s", yml)
	}
	if disk, _ := os.ReadFile(e.path); string(disk) != editorYAML {
		t.Fatal("apply wrote the file")
	}
	// The read-back form has the sections again.
	if back := got["form"].(map[string]any); len(back["flows"].([]any)) != 1 || len(back["policies"].([]any)[0].(map[string]any)["rules"].([]any)) != 2 {
		t.Fatalf("read-back = %v", back)
	}

	// Refused with the field named; nothing is written.
	fm["flows"] = []map[string]any{{"listen": []string{"2055"}}}
	rec, _ = e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": editorYAML, "apply": true, "form": fm})
	if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "flow[0].listen") {
		t.Fatalf("bad flow: %d %s", rec.Code, rec.Body)
	}

	// Save goes through the editor's checks and the audit log.
	rec, _ = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": yml, "base": configedit.Hash([]byte(editorYAML))})
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	cfg, err := config.Load(e.path)
	if err != nil || cfg.Mode != config.ModeObserve || len(cfg.Sources) != 3 || len(cfg.Policies) != 1 || cfg.Announcer != nil {
		t.Fatalf("saved config: %v %+v", err, cfg)
	}
	var audited bool
	for _, r := range e.store.Records() {
		if r.Action == "PUT /api/config" && r.Result == auth.ResultOK && r.Target == "config" {
			audited = true
		}
	}
	if !audited {
		t.Fatal("save not audited")
	}

	// A request from a client that does not know the sections leaves them.
	rec, got = e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": yml, "apply": true,
		"form": map[string]any{"mode": "observe", "hold_time": "20m", "providers": []map[string]any{
			{"key": "transit-a", "name": "transit-a", "source_ip": "192.0.2.11", "next_hop": "192.0.2.1"},
			{"key": "transit-b", "name": "transit-b", "source_ip": "192.0.2.12", "next_hop": "192.0.2.2"}}}})
	if rec.Code != http.StatusOK {
		t.Fatalf("old client: %d %s", rec.Code, rec.Body)
	}
	if out := got["yaml"].(string); !strings.Contains(out, "type: flow") || !strings.Contains(out, "type: outage") || !strings.Contains(out, "name: pin-a") || !strings.Contains(out, "hold_time: 20m") {
		t.Fatalf("old client lost a section:\n%s", out)
	}

	// Below admin: the form endpoint is refused.
	for _, role := range []plugin.Role{plugin.RoleViewer, plugin.RoleOperator} {
		if rec, _ := e.do(t, "POST", "/api/config/form", role, map[string]any{"yaml": editorYAML}); rec.Code != http.StatusForbidden {
			t.Fatalf("%s: %d", role, rec.Code)
		}
	}
}

func TestWizardAPIFlowStep(t *testing.T) {
	e := newUI(t)
	in := configedit.WizardInput{ASN: 64512, RouterID: "192.0.2.10", Edge: "192.0.2.254",
		Providers: []configedit.WizardProvider{{Name: "transit-a", SourceIP: "192.0.2.11", NextHop: "192.0.2.1"}},
		Flow:      &configedit.WizardFlow{Listen: "192.0.2.10:2055"}}
	rec, got := e.do(t, "POST", "/api/config/wizard", plugin.RoleAdmin, in)
	if rec.Code != http.StatusOK || got["mode"] != "observe" {
		t.Fatalf("wizard: %d %s", rec.Code, rec.Body)
	}
	yml := got["yaml"].(string)
	cfg, err := config.Parse([]byte(yml))
	if err != nil || cfg.Mode != config.ModeObserve || len(cfg.Allowlist.Prefixes) != 0 || cfg.Announcer != nil || len(cfg.Sources) != 1 || cfg.Sources[0].Type != "flow" {
		t.Fatalf("wizard flow config: %v %+v\n%s", err, cfg, yml)
	}
	in.Flow.Listen = "nope"
	if rec, _ := e.do(t, "POST", "/api/config/wizard", plugin.RoleAdmin, in); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "flow listen") {
		t.Fatalf("bad flow listen: %d %s", rec.Code, rec.Body)
	}
	if disk, _ := os.ReadFile(e.path); string(disk) != editorYAML {
		t.Fatal("wizard wrote the file")
	}
}

const twoSourcesYAML = editorYAML + `sources:
  - type: flow
    name: flow-a
    config:
      listen: 192.0.2.10:2055
      window: 5m
  - type: flow
    name: flow-b
    config:
      listen: 192.0.2.10:6343
      window: 10m
policies:
  - type: rules
    name: rules-a
    config:
      rules:
        - name: quiet
          action: ignore
          prefixes: [192.0.2.0/24]
  - type: rules
    name: rules-b
    config:
      rules:
        - name: no-b
          action: deny
          providers: [transit-b]
          asns: [64500]
`

// Two flow sources and two rules policies: the form lists both of each,
// an edit to the second of each reaches the file, and the first stays.
func TestSettingsEditsSecondOfEachType(t *testing.T) {
	e := newUI(t)
	admin := plugin.RoleAdmin
	if err := os.WriteFile(e.path, []byte(twoSourcesYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	rec, got := e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": twoSourcesYAML})
	if rec.Code != http.StatusOK {
		t.Fatalf("parse: %d %s", rec.Code, rec.Body)
	}
	fm := got["form"].(map[string]any)
	flows, pols := fm["flows"].([]any), fm["policies"].([]any)
	if len(flows) != 2 || len(pols) != 2 || flows[1].(map[string]any)["name"] != "flow-b" || pols[1].(map[string]any)["name"] != "rules-b" {
		t.Fatalf("form = %v", fm)
	}

	flows[1].(map[string]any)["window"] = "20m"
	flows[1].(map[string]any)["aggregate_v4"] = "23"
	rule := pols[1].(map[string]any)["rules"].([]any)[0].(map[string]any)
	rule["providers"] = []string{"transit-a"}
	pols[1].(map[string]any)["geoip_db"] = ""
	rec, got = e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": twoSourcesYAML, "apply": true, "form": fm})
	if rec.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body)
	}
	yml := got["yaml"].(string)
	rec, _ = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": yml, "base": configedit.Hash([]byte(twoSourcesYAML))})
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	cfg, err := config.Load(e.path)
	if err != nil || cfg.Mode != config.ModeObserve || len(cfg.Sources) != 2 || len(cfg.Policies) != 2 || cfg.Announcer != nil {
		t.Fatalf("saved config: %v %+v", err, cfg)
	}
	back, err := configedit.ParseForm([]byte(yml))
	if err != nil {
		t.Fatal(err)
	}
	if back.Flows[0].Window != "5m" || back.Flows[0].AggregateV4 != "" || back.Flows[1].Window != "20m" || back.Flows[1].AggregateV4 != "23" ||
		back.Policies[0].Rules[0].Name != "quiet" || back.Policies[1].Rules[0].Providers[0] != "transit-a" || back.Policies[1].Rules[0].ASNs[0] != "64500" {
		t.Fatalf("saved form = %+v\n%s", back, yml)
	}
}

// chromeBinary is the headless browser the page test drives, or "" when
// none is installed (the UI e2e job in CI has one).
func chromeBinary() string {
	for _, c := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

// The page itself, in a real browser: settings.js loads the file through
// the API and renders a card for each flow source and each rules policy,
// with their saved values in the markup.
func TestSettingsPageRendersEveryEntry(t *testing.T) {
	chrome := chromeBinary()
	if chrome == "" {
		t.Skip("no Chrome or Chromium installed")
	}
	ed, path := newEditor(t)
	if err := os.WriteFile(path, []byte(twoSourcesYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{User: "ops", Password: "pw", ConfigEditor: ed, Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if err != nil {
		t.Fatal(err)
	}
	// Chrome refuses fetch() on a URL with credentials, so the test adds
	// the Basic header in front of the server.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.SetBasicAuth("ops", "pw")
		srv.Handler().ServeHTTP(w, r)
	}))
	defer ts.Close()
	page := ts.URL + "/settings.html"

	want := []string{`value="flow-a"`, `value="flow-b"`, `value="192.0.2.10:2055"`, `value="192.0.2.10:6343"`, `value="5m"`, `value="10m"`,
		`value="rules-a"`, `value="rules-b"`, `value="quiet"`, `value="no-b"`, `value="64500"`, ">Flow collector 2<", ">Rules policy 2<", "GeoIP database (absolute path)"}
	var dom []byte
	for attempt := 0; attempt < 5; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		dom, _ = exec.CommandContext(ctx, chrome, "--headless=new", "--no-sandbox", "--disable-gpu", "--no-first-run",
			"--user-data-dir="+t.TempDir(), "--virtual-time-budget=8000", "--dump-dom", page).Output()
		cancel()
		var missing []string
		for _, w := range want {
			if !strings.Contains(string(dom), w) {
				missing = append(missing, w)
			}
		}
		if len(missing) == 0 {
			if n := strings.Count(string(dom), ">Flow collector "); n != 2 {
				t.Fatalf("flow cards = %d, want 2", n)
			}
			if n := strings.Count(string(dom), ">Rules policy "); n != 2 {
				t.Fatalf("policy cards = %d, want 2", n)
			}
			return
		}
		if attempt == 4 {
			t.Fatalf("rendered page is missing %q\n%s", missing, dom)
		}
	}
}

// The settings page carries the list sections, and the wizard's flow step
// has no way to send a mode or a secret.
func TestSettingsPageSections(t *testing.T) {
	e := newUI(t)
	rec, _ := e.do(t, "GET", "/settings.html", plugin.RoleViewer, nil)
	html := rec.Body.String()
	for _, w := range []string{`id="form-flows"`, `id="form-add-flow"`, `id="form-policies"`, `id="form-add-policy"`, `id="form-vips"`, `id="form-add-vip"`,
		`id="form-outages"`, `id="form-add-outage"`, `id="wz-4"`, `id="wz-flow"`, `id="wz-flow-addr"`, `id="wz-flow-port"`, "Exporter setup", "do not publish it"} {
		if !strings.Contains(html, w) {
			t.Errorf("settings.html missing %q", w)
		}
	}
	rec, _ = e.do(t, "GET", "/settings.js", plugin.RoleViewer, nil)
	js := rec.Body.String()
	for _, w := range []string{"function renderFlows", "function renderPolicies", "function renderVIPs", "function renderOutages", "function moveItem", "function readSections", "function wizardFlowListen", "body.flow"} {
		if !strings.Contains(js, w) {
			t.Errorf("settings.js missing %q", w)
		}
	}
	i := strings.Index(js, "function runWizard")
	j := strings.Index(js[i:], "\nfunction ")
	if i < 0 || j < 0 {
		t.Fatal("runWizard missing")
	}
	if body := js[i : i+j]; strings.Contains(body, `"inject"`) || strings.Contains(body, "confirm_inject") || !strings.Contains(body, `body.mode = "observe"`) {
		t.Fatalf("wizard can send inject:\n%s", body)
	}
}
