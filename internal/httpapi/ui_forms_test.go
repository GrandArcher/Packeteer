package httpapi

import (
	"net/http"
	"os"
	"strings"
	"testing"

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
	for _, k := range []string{"flow", "policies", "vip", "outage"} {
		if _, ok := fm[k].(map[string]any); !ok {
			t.Fatalf("form has no %s section: %s", k, rec.Body)
		}
	}
	if fm["flow"].(map[string]any)["enabled"] != false {
		t.Fatalf("flow starts enabled: %v", fm["flow"])
	}

	fm["flow"] = map[string]any{"enabled": true, "listen": []string{"192.0.2.10:2055"}, "window": "10m", "top_n": "50", "min_pct": "0.5", "exclude": []string{"192.0.2.0/25"}}
	fm["policies"] = map[string]any{"rules": []map[string]any{
		{"name": "pin-a", "action": "static", "providers": []string{"transit-a"}, "prefixes": []string{"203.0.113.0/24"}, "max_loss_pct": "1", "max_rtt": "150ms"},
		{"name": "no-b", "action": "deny", "providers": []string{"transit-b"}, "asns": []string{"64500"}},
	}}
	fm["vip"] = map[string]any{"enabled": true, "interval": "10s", "prefixes": []map[string]any{{"prefix": "198.51.100.0/24", "host": "198.51.100.1"}}}
	fm["outage"] = map[string]any{"enabled": true, "min_prefixes": "4", "loss_pct": "30"}
	rec, got = e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": editorYAML, "apply": true, "form": fm})
	if rec.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body)
	}
	yml := got["yaml"].(string)
	for _, want := range []string{"type: flow", "listen: 192.0.2.10:2055", "min_pct: 0.5", "type: rules", "name: pin-a", "max_loss_pct: 1", "type: vip", "type: outage", "min_prefixes: 4"} {
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
	if back := got["form"].(map[string]any); back["flow"].(map[string]any)["enabled"] != true || len(back["policies"].(map[string]any)["rules"].([]any)) != 2 {
		t.Fatalf("read-back = %v", back)
	}

	// Refused with the field named; nothing is written.
	bad := map[string]any{"enabled": true, "listen": []string{"2055"}}
	fm["flow"] = bad
	rec, _ = e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": editorYAML, "apply": true, "form": fm})
	if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "flow.listen") {
		t.Fatalf("bad flow: %d %s", rec.Code, rec.Body)
	}

	// Save goes through the editor's checks and the audit log.
	rec, got = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": yml, "base": configedit.Hash([]byte(editorYAML))})
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

// The settings page carries the new sections, and the wizard's flow step
// has no way to send a mode or a secret.
func TestSettingsPageSections(t *testing.T) {
	e := newUI(t)
	rec, _ := e.do(t, "GET", "/settings.html", plugin.RoleViewer, nil)
	html := rec.Body.String()
	for _, w := range []string{`id="fl-enabled"`, `id="fl-listen"`, `id="fl-top-n"`, `id="fl-max-targets"`, `id="fl-tail"`, `id="fl-min-bytes"`, `id="fl-min-pct"`,
		`id="fl-exclude"`, `id="form-rules"`, `id="form-add-rule"`, `id="vip-enabled"`, `id="vip-interval"`, `id="form-vip-prefixes"`, `id="out-enabled"`, `id="out-min"`,
		`id="out-ignore"`, `id="wz-4"`, `id="wz-flow"`, `id="wz-flow-addr"`, `id="wz-flow-port"`, "Exporter setup", "do not publish it"} {
		if !strings.Contains(html, w) {
			t.Errorf("settings.html missing %q", w)
		}
	}
	rec, _ = e.do(t, "GET", "/settings.js", plugin.RoleViewer, nil)
	js := rec.Body.String()
	for _, w := range []string{"function renderRules", "function renderVIPPrefixes", "function readSections", "function wizardFlowListen", "body.flow"} {
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
