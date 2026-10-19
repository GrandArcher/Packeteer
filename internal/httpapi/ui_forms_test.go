package httpapi

import (
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/configedit"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
	"gopkg.in/yaml.v3"
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
		if list, _ := fm[k].([]any); len(list) != 0 {
			t.Fatalf("a file without sources has %s: %s", k, rec.Body)
		}
	}

	fm["flows"] = []map[string]any{
		{"name": "edge-a", "listen": []string{"192.0.2.10:2055"}, "window": "10m", "top_n": "50", "min_pct": "0.5", "aggregate_v4": "22", "exclude": []string{"192.0.2.0/25"}},
		{"name": "edge-b", "listen": []string{"192.0.2.10:6343"}},
	}
	fm["policies"] = []map[string]any{
		{"name": "pins", "rules": []map[string]any{{"name": "pin-a", "action": "static", "providers": []string{"transit-a"}, "prefixes": []string{"203.0.113.0/24"}, "max_loss_pct": "1", "max_rtt": "150ms"}}},
		{"name": "denies", "rules": []map[string]any{{"name": "no-b", "action": "deny", "providers": []string{"transit-b"}, "asns": []string{"64500"}}}},
	}
	fm["vips"] = []map[string]any{{"interval": "10s", "prefixes": []map[string]any{{"prefix": "198.51.100.0/24", "host": "198.51.100.1"}}}}
	fm["outages"] = []map[string]any{{"min_prefixes": "4", "loss_pct": "30"}}
	rec, got = e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": editorYAML, "apply": true, "form": fm})
	if rec.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body)
	}
	yml := got["yaml"].(string)
	for _, want := range []string{"type: flow", "name: edge-a", "name: edge-b", "listen: 192.0.2.10:2055", "listen: 192.0.2.10:6343", "min_pct: 0.5", "aggregate_v4: 22", "name: pins", "name: denies", "name: pin-a", "name: no-b", "max_loss_pct: 1", "type: vip", "type: outage", "min_prefixes: 4"} {
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
	if back := got["form"].(map[string]any); len(back["flows"].([]any)) != 2 || len(back["policies"].([]any)) != 2 {
		t.Fatalf("read-back = %v", back)
	}

	// Refused with the field named; nothing is written.
	fm["flows"] = []map[string]any{{"name": "edge-a", "listen": []string{"2055"}}}
	rec, _ = e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": editorYAML, "apply": true, "form": fm})
	if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "flow.listen") {
		t.Fatalf("bad flow: %d %s", rec.Code, rec.Body)
	}

	// Save goes through the editor's checks and the audit log.
	rec, _ = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": yml, "base": configedit.Hash([]byte(editorYAML))})
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	cfg, err := config.Load(e.path)
	if err != nil || cfg.Mode != config.ModeObserve || len(cfg.Sources) != 4 || len(cfg.Policies) != 2 || cfg.Announcer != nil {
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
	if out := got["yaml"].(string); !strings.Contains(out, "name: edge-b") || !strings.Contains(out, "type: outage") || !strings.Contains(out, "name: no-b") || !strings.Contains(out, "hold_time: 20m") {
		t.Fatalf("old client lost a section:\n%s", out)
	}

	// Below admin: the form endpoint is refused.
	for _, role := range []plugin.Role{plugin.RoleViewer, plugin.RoleOperator} {
		if rec, _ := e.do(t, "POST", "/api/config/form", role, map[string]any{"yaml": editorYAML}); rec.Code != http.StatusForbidden {
			t.Fatalf("%s: %d", role, rec.Code)
		}
	}
}

// #181: the exchanges block goes through the same two calls. Apply writes
// nothing, Save runs the loader (route check requirement included), and a
// client that does not send the section leaves the block alone.
func TestConfigFormExchanges(t *testing.T) {
	e := newUI(t)
	admin := plugin.RoleAdmin
	withIX := editorYAML + `exchanges:
  - name: ix-lab
    lans: [203.0.113.0/24]
    peers:
      - name: ix-peer-a
        asn: 64501
        next_hop: 203.0.113.11
        source_ip: 192.0.2.31
        precedence: 50
bgp:
  neighbors:
    - address: 192.0.2.254
      add_path: true
`
	rec, got := e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": withIX})
	if rec.Code != http.StatusOK {
		t.Fatalf("parse: %d %s", rec.Code, rec.Body)
	}
	fm := got["form"].(map[string]any)
	exs := fm["exchanges"].([]any)
	peers := exs[0].(map[string]any)["peers"].([]any)
	if len(exs) != 1 || len(peers) != 1 || peers[0].(map[string]any)["asn"] != "64501" || peers[0].(map[string]any)["next_hop"] != "203.0.113.11" {
		t.Fatalf("exchanges = %v", exs)
	}

	exs[0].(map[string]any)["peers"] = append(peers, map[string]any{"name": "ix-peer-b", "asn": "64502", "next_hop": "203.0.113.12", "source_ip": "192.0.2.32", "cost": "2"})
	rec, got = e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": withIX, "apply": true, "form": fm})
	if rec.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body)
	}
	yml := got["yaml"].(string)
	for _, want := range []string{"name: ix-peer-b", "asn: 64502", "precedence: 50", "add_path: true"} {
		if !strings.Contains(yml, want) {
			t.Errorf("merged yaml missing %q:\n%s", want, yml)
		}
	}
	if disk, _ := os.ReadFile(e.path); string(disk) != editorYAML {
		t.Fatal("apply wrote the file")
	}
	if back := got["form"].(map[string]any)["exchanges"].([]any); len(back[0].(map[string]any)["peers"].([]any)) != 2 {
		t.Fatalf("read-back = %v", back)
	}

	// A next hop off the LAN is refused with the field named.
	exs[0].(map[string]any)["peers"].([]any)[1].(map[string]any)["next_hop"] = "198.51.100.9"
	rec, _ = e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": withIX, "apply": true, "form": fm})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "not inside the exchange") {
		t.Fatalf("off-LAN next hop: %d %s", rec.Code, rec.Body)
	}

	rec, _ = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": yml, "base": configedit.Hash([]byte(editorYAML))})
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	cfg, err := config.Load(e.path)
	if err != nil || len(cfg.Exchanges) != 1 || len(cfg.Exchanges[0].Peers) != 2 || cfg.Mode != config.ModeObserve {
		t.Fatalf("saved config: %v %+v", err, cfg)
	}

	// A client that does not know the section leaves it.
	rec, got = e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": yml, "apply": true,
		"form": map[string]any{"mode": "observe", "hold_time": "20m", "providers": []map[string]any{
			{"key": "transit-a", "name": "transit-a", "source_ip": "192.0.2.11", "next_hop": "192.0.2.1"},
			{"key": "transit-b", "name": "transit-b", "source_ip": "192.0.2.12", "next_hop": "192.0.2.2"}}}})
	if out, _ := got["yaml"].(string); rec.Code != http.StatusOK || !strings.Contains(out, "name: ix-peer-b") || !strings.Contains(out, "hold_time: 20m") {
		t.Fatalf("old client: %d %s", rec.Code, rec.Body)
	}
}

// #226: with two flow sources and two policies of the same type, editing
// the second of each reaches the saved file and leaves the first alone.
func TestSettingsEditSecondOfEachType(t *testing.T) {
	const seeded = editorYAML + `sources:
  - {type: flow, name: edge-a, config: {listen: "192.0.2.10:2055"}}
  - {type: flow, name: edge-b, config: {listen: "192.0.2.10:6343"}}
policies:
  - type: rules
    name: pins
    config:
      rules:
        - {name: pin-a, action: allow, providers: [transit-a], prefixes: [203.0.113.0/24]}
  - type: rules
    name: denies
    config:
      rules:
        - {name: no-b, action: deny, providers: [transit-b]}
`
	e := newUI(t)
	admin := plugin.RoleAdmin
	if err := os.WriteFile(e.path, []byte(seeded), 0o600); err != nil {
		t.Fatal(err)
	}
	rec, got := e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": seeded})
	if rec.Code != http.StatusOK {
		t.Fatalf("parse: %d %s", rec.Code, rec.Body)
	}
	fm := got["form"].(map[string]any)
	flows, policies := fm["flows"].([]any), fm["policies"].([]any)
	if len(flows) != 2 || len(policies) != 2 {
		t.Fatalf("form lists %d flows and %d policies: %s", len(flows), len(policies), rec.Body)
	}
	flows[1].(map[string]any)["window"] = "7m"
	flows[1].(map[string]any)["aggregate_v4"] = "20"
	rules := policies[1].(map[string]any)["rules"].([]any)
	rules[0].(map[string]any)["asns"] = []string{"64500"}

	rec, got = e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": seeded, "apply": true, "form": fm})
	if rec.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body)
	}
	rec, _ = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": got["yaml"], "base": configedit.Hash([]byte(seeded))})
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	cfg, err := config.Load(e.path)
	if err != nil || len(cfg.Sources) != 2 || len(cfg.Policies) != 2 {
		t.Fatalf("saved config: %v %+v", err, cfg)
	}
	decode := func(n yaml.Node) map[string]any {
		var m map[string]any
		if err := n.Decode(&m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	a, b := decode(cfg.Sources[0].Config), decode(cfg.Sources[1].Config)
	if _, ok := a["window"]; ok || a["listen"] != "192.0.2.10:2055" {
		t.Errorf("first flow changed: %v", a)
	}
	if b["window"] != "7m" || b["aggregate_v4"] != 20 || b["listen"] != "192.0.2.10:6343" {
		t.Errorf("second flow = %v", b)
	}
	p0, p1 := cfg.Policies[0], cfg.Policies[1]
	if p0.InstanceName() != "pins" || p1.InstanceName() != "denies" {
		t.Fatalf("policy order = %s, %s", p0.InstanceName(), p1.InstanceName())
	}
	if r := decode(p0.Config)["rules"].([]any)[0].(map[string]any); r["asns"] != nil {
		t.Errorf("first policy changed: %v", r)
	}
	if r := decode(p1.Config)["rules"].([]any)[0].(map[string]any); r["asns"] == nil {
		t.Errorf("second policy not edited: %v", r)
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
	for _, w := range []string{`id="form-flows"`, `id="form-add-flow"`, `id="form-policies"`, `id="form-add-policy"`, `id="form-vips"`, `id="form-add-vip"`,
		`id="form-outages"`, `id="form-add-outage"`, `id="form-exchanges"`, `id="form-add-exchange"`, `id="wz-4"`, `id="wz-flow"`, `id="wz-flow-addr"`, `id="wz-flow-port"`, "Exporter setup", "do not publish it"} {
		if !strings.Contains(html, w) {
			t.Errorf("settings.html missing %q", w)
		}
	}
	rec, _ = e.do(t, "GET", "/settings.js", plugin.RoleViewer, nil)
	js := rec.Body.String()
	for _, w := range []string{"function renderFlows", "function renderPolicies", "function renderVIPs", "function renderOutages", "function renderExchanges", "function moveButtons", "function readSections", "function wizardFlowListen", "body.flow"} {
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

// The wizard over a current config returns a diff and what is lost, keeps
// auth, and turns it off only on request (#345).
func TestWizardAPIOverCurrentConfig(t *testing.T) {
	e := newUI(t)
	in := map[string]any{"asn": 64512, "router_id": "192.0.2.10", "edge": "192.0.2.254",
		"providers": []map[string]string{{"name": "transit-a", "source_ip": "192.0.2.11", "next_hop": "192.0.2.1"}},
		"current":   wizardSmokeYAML}
	rec, got := e.do(t, "POST", "/api/config/wizard", plugin.RoleAdmin, in)
	if rec.Code != http.StatusOK || got["existing"] != true {
		t.Fatalf("wizard: %d %s", rec.Code, rec.Body)
	}
	cfg, err := config.Parse([]byte(got["yaml"].(string)))
	if err != nil || !cfg.AuthEnabled() || !cfg.HTTP.ConfigEditor || cfg.Storage == nil {
		t.Fatalf("kept blocks: %v %+v", err, cfg)
	}
	if rm, _ := got["removes"].([]any); len(rm) != 1 || rm[0] != "Removes 2 providers (transit-b, transit-c)" {
		t.Fatalf("removes = %v", got["removes"])
	}
	if d, _ := got["diff"].(string); !strings.Contains(d, "-   - name: transit-b") {
		t.Fatalf("diff = %q", got["diff"])
	}

	in["disable_auth"] = true
	rec, got = e.do(t, "POST", "/api/config/wizard", plugin.RoleAdmin, in)
	cfg, err = config.Parse([]byte(got["yaml"].(string)))
	if rec.Code != http.StatusOK || err != nil || cfg.AuthEnabled() || !strings.Contains(rec.Body.String(), "Turns off sign-in") {
		t.Fatalf("explicit off: %d %v %s", rec.Code, err, rec.Body)
	}

	in["current"] = "mode: [observe"
	if rec, _ = e.do(t, "POST", "/api/config/wizard", plugin.RoleAdmin, in); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "cannot be kept") {
		t.Fatalf("broken current: %d %s", rec.Code, rec.Body)
	}

	// GET /api/config says the file is configured, so the page collapses.
	if _, got = e.do(t, "GET", "/api/config", plugin.RoleAdmin, nil); got["configured"] != true {
		t.Fatalf("configured = %v", got["configured"])
	}
}

func TestConfigPreviewAndSchema(t *testing.T) {
	e := newUI(t)
	admin := plugin.RoleAdmin
	next := strings.Replace(editorYAML, "router_id: 192.0.2.10", "router_id: 192.0.2.20", 1)

	rec, got := e.do(t, "POST", "/api/config/preview", admin, map[string]any{"yaml": next})
	if rec.Code != http.StatusOK {
		t.Fatalf("preview: %d %s", rec.Code, rec.Body)
	}
	diff, _ := got["diff"].(string)
	if !strings.Contains(diff, "- router_id: 192.0.2.10") || !strings.Contains(diff, "+ router_id: 192.0.2.20") {
		t.Fatalf("diff = %q", diff)
	}
	if res, _ := got["result"].(map[string]any); res["valid"] != true {
		t.Fatalf("result = %v", got["result"])
	}
	if disk, _ := os.ReadFile(e.path); string(disk) != editorYAML {
		t.Fatal("preview wrote the file")
	}

	rec, _ = e.do(t, "POST", "/api/config/preview", plugin.RoleOperator, map[string]any{"yaml": next})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator preview: %d", rec.Code)
	}
	rec, _ = e.do(t, "GET", "/api/config/schema", plugin.RoleOperator, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator schema: %d", rec.Code)
	}

	rec, got = e.do(t, "GET", "/api/config/schema", admin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("schema: %d %s", rec.Code, rec.Body)
	}
	ids := map[string]bool{}
	for _, b := range got["blocks"].([]any) {
		ids[b.(map[string]any)["id"].(string)] = true
	}
	for _, id := range []string{"scorer", "bgp", "bmp", "maintenance", "inbound_announcer", "anomaly", "mitigation", "http", "inject"} {
		if !ids[id] {
			t.Fatalf("schema lacks block %s: %s", id, rec.Body)
		}
	}
	types, _ := got["plugin_types"].(map[string]any)
	if policies, _ := types["policies"].([]any); !slices.Contains(policies, any("maintenance")) {
		t.Fatalf("policies offer %v, want maintenance", policies)
	}
}
