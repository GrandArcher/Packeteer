package httpapi

import (
	"context"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/configedit"
	"github.com/GrandArcher/Packeteer/internal/mitigation"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// silentAnn is a mitigation announcer that records every call. In observe
// the controller must never reach it.
type silentAnn struct {
	plugin.Base
	calls atomic.Int32
}

func (a *silentAnn) Catalog() plugin.MitigationCatalog {
	return plugin.MitigationCatalog{Blackhole: true, BlackholeNextHops: []netip.Addr{netip.MustParseAddr("192.0.2.66")},
		Targets: []plugin.MitigationTarget{{Name: "scrubber", NextHop: netip.MustParseAddr("192.0.2.77")}}}
}
func (a *silentAnn) Announce(context.Context, plugin.MitigationRoute) error {
	a.calls.Add(1)
	return nil
}
func (a *silentAnn) Withdraw(context.Context, netip.Prefix) error { a.calls.Add(1); return nil }
func (a *silentAnn) WithdrawAll(context.Context) error            { a.calls.Add(1); return nil }

// learnedRIB is a RIB view with a fixed set of learned prefixes.
type learnedRIB struct{ prefixes []netip.Prefix }

func (r learnedRIB) Ready() bool { return true }
func (r learnedRIB) Contains(p netip.Prefix) bool {
	for _, q := range r.prefixes {
		if q == p {
			return true
		}
	}
	return false
}

// candidates is the picker's source the controller wires: learned
// prefixes inside the allowlist that contain q.
func (r learnedRIB) candidates(allow []netip.Prefix) MitigationCandidates {
	return func(q string, limit int) ([]string, bool, bool) {
		var out []string
		for _, p := range r.prefixes {
			inside := false
			for _, a := range allow {
				if a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
					inside = true
				}
			}
			if inside && strings.Contains(p.String(), q) {
				out = append(out, p.String())
			}
		}
		return out, false, true
	}
}

type protEnv struct {
	*uiEnv
	ctl *mitigation.Controller
	ann *silentAnn
}

func newProtEnv(t *testing.T) *protEnv {
	t.Helper()
	allow := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	ann := &silentAnn{}
	ctl, err := mitigation.New(mitigation.Config{Mode: config.ModeObserve, Allowlist: allow, MaxRules: 2,
		DefaultTTL: time.Hour, MaxTTL: 2 * time.Hour}, ann, nil)
	if err != nil {
		t.Fatal(err)
	}
	rib := learnedRIB{prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("203.0.113.0/25"),
		netip.MustParsePrefix("198.51.100.0/24")}}
	if err := ctl.SetRIB(rib); err != nil {
		t.Fatal(err)
	}
	e := newUIWith(t, func(o *Options) { o.Mitigation = mitControl{ctl} })
	e.srv.SetMitigationCandidates(rib.candidates(allow))
	return &protEnv{uiEnv: e, ctl: ctl, ann: ann}
}

// The Protection page's add and remove, end to end in observe: the page
// ships the form, the picker offers only learned prefixes inside the
// allowlist, the request the form builds is accepted and listed, the
// remove is accepted, both are audited, and nothing reaches the announcer.
func TestProtectionFormAddRemoveObserve(t *testing.T) {
	e := newProtEnv(t)
	op := plugin.RoleOperator

	rec, _ := e.do(t, "GET", "/protection.html", plugin.RoleViewer, nil)
	html := rec.Body.String()
	for _, w := range []string{`id="mit-form"`, `id="mf-prefix"`, `id="mf-action"`, `id="mf-ttl"`, `id="mf-flowspec"`, `id="mf-source"`, `id="mf-protocols"`,
		`id="mf-dports"`, `id="mf-sports"`, `id="mf-rate"`, `id="mf-countries"`, `id="mit-badge"`, `src="/protection.js"`,
		`<div id="banner" class="banner" role="status" hidden>`} {
		if !strings.Contains(html, w) {
			t.Errorf("protection.html missing %q", w)
		}
	}
	rec, _ = e.do(t, "GET", "/protection.js", plugin.RoleViewer, nil)
	if js := rec.Body.String(); rec.Code != http.StatusOK || !strings.Contains(js, "/api/mitigations/candidates") || !strings.Contains(js, `"DELETE"`) {
		t.Fatalf("protection.js: %d", rec.Code)
	}

	// The picker: learned and inside the allowlist only.
	rec, got := e.do(t, "GET", "/api/mitigations/candidates", plugin.RoleViewer, nil)
	if rec.Code != http.StatusOK || got["ready"] != true || got["enabled"] != true {
		t.Fatalf("candidates: %d %s", rec.Code, rec.Body)
	}
	pf := got["prefixes"].([]any)
	if len(pf) != 2 || pf[0] != "203.0.113.0/24" || pf[1] != "203.0.113.0/25" {
		t.Fatalf("picker offered %v, want only the learned prefixes inside the allowlist", pf)
	}
	if _, got = e.do(t, "GET", "/api/mitigations/candidates?q=198.51", plugin.RoleViewer, nil); len(got["prefixes"].([]any)) != 0 {
		t.Fatalf("a learned prefix outside the allowlist was offered: %v", got["prefixes"])
	}
	if _, got = e.do(t, "GET", "/api/mitigations/candidates?q=/25", plugin.RoleViewer, nil); len(got["prefixes"].([]any)) != 1 {
		t.Fatalf("q filter: %v", got["prefixes"])
	}

	// Add exactly what the form sends.
	rec, got = e.do(t, "POST", "/api/mitigations", op, map[string]any{"prefix": "203.0.113.0/24", "action": "blackhole", "ttl": "30m", "reason": "form test"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	id := got["id"].(string)
	_, st := e.do(t, "GET", "/api/mitigations", plugin.RoleViewer, nil)
	rules := st["rules"].([]any)
	if st["mitigation_mode"] != "observe" || st["writable"] != true || len(rules) != 1 || rules[0].(map[string]any)["announced"] != false ||
		!strings.Contains(rules[0].(map[string]any)["pending"].(string), "dry run") || st["routes_announced"] != float64(0) {
		t.Fatalf("after add: %v", st)
	}
	// A second rule with FlowSpec fields reaches the same checks (no
	// FlowSpec announcer here, so the controller refuses it).
	rec, _ = e.do(t, "POST", "/api/mitigations", op, map[string]any{"prefix": "203.0.113.0/25", "action": "flowspec_drop",
		"match": map[string]any{"protocols": []string{"udp"}, "destination_ports": []string{"53", "1000-2000"}, "source": "192.0.2.0/25"}})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "flowspec") {
		t.Fatalf("flowspec without announcer support: %d %s", rec.Code, rec.Body)
	}

	// Remove.
	if rec, _ := e.do(t, "DELETE", "/api/mitigations/"+id, op, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body)
	}
	if _, st = e.do(t, "GET", "/api/mitigations", plugin.RoleViewer, nil); len(st["rules"].([]any)) != 0 {
		t.Fatalf("rule still listed: %v", st["rules"])
	}
	feed := st["feed"].([]any)
	if len(feed) < 2 {
		t.Fatalf("feed = %v", feed)
	}

	// Nothing announced: not at add, not at remove, not at a sync.
	if err := e.ctl.Sync(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if n := e.ann.calls.Load(); n != 0 {
		t.Fatalf("observe reached the announcer %d times", n)
	}
	if e.ctl.Active() != 0 {
		t.Fatalf("active = %d", e.ctl.Active())
	}

	// Both writes are in the audit log under the operator.
	var added, removed bool
	for _, r := range e.store.Records() {
		switch {
		case r.Action == "POST /api/mitigations" && r.Result == auth.ResultOK && r.Role == op:
			added = true
		case r.Action == "DELETE /api/mitigations/{id}" && r.Result == auth.ResultOK && r.Target == id:
			removed = true
		}
	}
	if !added || !removed {
		t.Fatalf("audit: added=%v removed=%v", added, removed)
	}
}

// A viewer cannot write; a prefix outside the allowlist is refused by the
// controller even if a client skips the picker.
func TestProtectionFormRefusals(t *testing.T) {
	e := newProtEnv(t)
	body := map[string]any{"prefix": "203.0.113.0/24", "action": "blackhole"}
	if rec, _ := e.do(t, "POST", "/api/mitigations", plugin.RoleViewer, body); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer add: %d", rec.Code)
	}
	if rec, _ := e.do(t, "DELETE", "/api/mitigations/x", plugin.RoleViewer, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer remove: %d", rec.Code)
	}
	rec, _ := e.do(t, "POST", "/api/mitigations", plugin.RoleOperator, map[string]any{"prefix": "198.51.100.0/24", "action": "blackhole"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "mitigation.allowlist") {
		t.Fatalf("outside allowlist: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := e.do(t, "GET", "/api/mitigations/candidates?q="+strings.Repeat("1", 65), plugin.RoleViewer, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("long q: %d", rec.Code)
	}
	if e.ann.calls.Load() != 0 || e.ctl.Active() != 0 {
		t.Fatal("a refused write announced")
	}
}

// Without the hook, or without mitigation, the picker is empty and says
// so; the page then offers nothing to pick.
func TestMitigationCandidatesStates(t *testing.T) {
	off := newUI(t)
	rec, got := off.do(t, "GET", "/api/mitigations/candidates", plugin.RoleViewer, nil)
	if rec.Code != http.StatusOK || got["enabled"] != false || got["ready"] != false || len(got["prefixes"].([]any)) != 0 {
		t.Fatalf("not configured: %d %s", rec.Code, rec.Body)
	}
	e := newUIWith(t, func(o *Options) { o.Mitigation = newMitControl(t) })
	rec, got = e.do(t, "GET", "/api/mitigations/candidates", plugin.RoleViewer, nil)
	if rec.Code != http.StatusOK || got["enabled"] != true || got["ready"] != false || len(got["prefixes"].([]any)) != 0 ||
		len(got["allowlist"].([]any)) != 1 {
		t.Fatalf("no RIB hook: %d %s", rec.Code, rec.Body)
	}
}

// The inbound and anomaly sections go through the same two calls as the
// other sections: POST /api/config/form merges and writes nothing,
// PUT /api/config saves after the start checks, audited, admin only, and
// a save that turns inbound inject on needs confirm_inject.
const protectionEditorYAML = `mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
  - name: transit-b
    source_ip: 192.0.2.12
    next_hop: 192.0.2.2
sources:
  - type: flow
    config:
      listen: "192.0.2.10:2055"
mitigation:
  mode: observe
  allowlist: [203.0.113.0/24]
anomaly:
  detector:
    type: baseline
`

func TestConfigFormProtectionSections(t *testing.T) {
	e := newUI(t)
	if err := writeEditorFile(e.path, protectionEditorYAML); err != nil {
		t.Fatal(err)
	}
	admin := plugin.RoleAdmin

	rec, got := e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": protectionEditorYAML})
	if rec.Code != http.StatusOK {
		t.Fatalf("parse: %d %s", rec.Code, rec.Body)
	}
	fm := got["form"].(map[string]any)
	an, ok := fm["anomaly"].(map[string]any)
	if !ok || an["enabled"] != true || an["mitigation_mode"] != "observe" {
		t.Fatalf("anomaly section: %v", fm["anomaly"])
	}
	if in, ok := fm["inbound"].(map[string]any); !ok || in["enabled"] != false || in["mode"] != "observe" {
		t.Fatalf("inbound section: %v", fm["inbound"])
	}

	fm["inbound"] = map[string]any{"enabled": true, "mode": "suggest", "prefixes": []string{"198.51.100.0/24"}, "release_pct": "85",
		"moderated": []string{"performance"}, "performance": map[string]any{"enabled": true, "latency_ms": "40"}, "damping": map[string]any{"confirm": "2m"}}
	fm["anomaly"] = map[string]any{"rules": []map[string]any{
		{"name": "udp-flood", "prefixes": []string{"203.0.113.0/24"}, "protocols": []string{"udp"}, "min_mbps": "100", "action": "flowspec_drop", "ttl": "30m"}}}
	rec, got = e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": protectionEditorYAML, "apply": true, "form": fm})
	if rec.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body)
	}
	yml := got["yaml"].(string)
	for _, want := range []string{"inbound:", "mode: suggest", "release_pct: 85", "name: udp-flood", "action: flowspec_drop", "ttl: 30m", "detector:"} {
		if !strings.Contains(yml, want) {
			t.Errorf("merged yaml missing %q:\n%s", want, yml)
		}
	}
	if strings.Contains(yml, "mode: inject") || strings.Contains(yml, "announcer:") {
		t.Fatalf("sections changed the safety fields:\n%s", yml)
	}

	// The form cannot turn inbound inject on, and a rule outside the
	// mitigation allowlist names the field.
	fm["inbound"].(map[string]any)["mode"] = "inject"
	rec, _ = e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": protectionEditorYAML, "apply": true, "form": fm})
	if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "inbound.mode inject") {
		t.Fatalf("inject via the form: %d %s", rec.Code, rec.Body)
	}
	fm["inbound"].(map[string]any)["mode"] = "suggest"
	fm["anomaly"].(map[string]any)["rules"].([]map[string]any)[0]["prefixes"] = []string{"198.51.100.0/24"}
	rec, _ = e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": protectionEditorYAML, "apply": true, "form": fm})
	if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "mitigation.allowlist") {
		t.Fatalf("rule outside the allowlist: %d %s", rec.Code, rec.Body)
	}

	// Save goes through the editor's checks and the audit log; the file
	// loads as observe.
	rec, _ = e.do(t, "PUT", "/api/config", admin, map[string]any{"yaml": yml, "base": configedit.Hash([]byte(protectionEditorYAML))})
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	cfg, err := config.Load(e.path)
	if err != nil || cfg.Mode != config.ModeObserve || cfg.Inbound == nil || cfg.Inbound.Mode != config.ModeSuggest ||
		len(cfg.Anomaly.Rules) != 1 || cfg.Announcer != nil || cfg.Mitigation.Mode != config.ModeObserve {
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

	// Below admin: refused.
	for _, role := range []plugin.Role{plugin.RoleViewer, plugin.RoleOperator} {
		if rec, _ := e.do(t, "POST", "/api/config/form", role, map[string]any{"yaml": protectionEditorYAML}); rec.Code != http.StatusForbidden {
			t.Fatalf("%s: %d", role, rec.Code)
		}
	}
}

// The settings page ships the new sections and badges.
func TestSettingsPageProtectionSections(t *testing.T) {
	e := newUI(t)
	rec, _ := e.do(t, "GET", "/settings.html", plugin.RoleViewer, nil)
	html := rec.Body.String()
	for _, w := range []string{`id="in-badge"`, `id="in-enabled"`, `id="in-mode"`, `id="in-prefixes"`, `id="in-mod-commit"`, `id="in-perf"`, `id="in-damp-confirm"`,
		`id="an-badge"`, `id="form-anomaly-rules"`, `id="form-add-anomaly-rule"`} {
		if !strings.Contains(html, w) {
			t.Errorf("settings.html missing %q", w)
		}
	}
	// inject is not an option the page offers by itself.
	i := strings.Index(html, `id="in-mode"`)
	if sel := html[i : i+strings.Index(html[i:], "</select>")]; strings.Contains(sel, "inject") {
		t.Fatalf("the inbound mode select offers inject:\n%s", sel)
	}
	rec, _ = e.do(t, "GET", "/settings.js", plugin.RoleViewer, nil)
	js := rec.Body.String()
	for _, w := range []string{"function renderAnomalyRules", "function fillInbound", "function loadProtectionDefaults", "form.inbound", "form.anomaly"} {
		if !strings.Contains(js, w) {
			t.Errorf("settings.js missing %q", w)
		}
	}
}

func writeEditorFile(path, content string) error { return os.WriteFile(path, []byte(content), 0o600) }
