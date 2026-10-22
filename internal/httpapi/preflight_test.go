package httpapi

import (
	"context"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/configedit"
	"github.com/GrandArcher/Packeteer/internal/preflight"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/internal/snippet"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakePreflight struct {
	*preflight.Runner
}

func (fakePreflight) Snippet(vendor string) (string, error) {
	return snippet.Generate(vendor, snippet.Params{ASN: 64512, Router: "192.0.2.254", Packeteer: "192.0.2.10", Community: "64512:666"})
}

func goodFacts() preflight.Facts {
	return preflight.Facts{
		Neighbors:   []preflight.Neighbor{{Address: "192.0.2.254", Established: true}},
		RIBReady:    true,
		Learned:     900000,
		Timers:      []preflight.Timers{{Address: "192.0.2.254", Hold: 30 * time.Second}},
		Providers:   []preflight.Provider{{Name: "transit-a", SourceIP: "192.0.2.11", NextHop: "192.0.2.1", Egress: preflight.EgressOK}},
		Community:   "64512:666",
		Announcer:   true,
		Fingerprint: "fp",
	}
}

func newPreflightUI(t *testing.T, facts *preflight.Facts) *uiEnv {
	t.Helper()
	e := newUI(t)
	store, err := preflight.OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	e.srv.SetPreflight(fakePreflight{preflight.NewRunner(func(context.Context) preflight.Facts { return *facts }, store, nil)})
	return e
}

func TestPreflightIsOffWithoutARunner(t *testing.T) {
	e := newUI(t)
	rec, got := e.do(t, "GET", "/api/preflight", plugin.RoleViewer, nil)
	if rec.Code != http.StatusOK || got["available"] != false || got["report"] != nil {
		t.Fatalf("get: %d %s", rec.Code, rec.Body)
	}
	for _, c := range []struct{ method, path string }{{"POST", "/api/preflight/run"}, {"GET", "/api/snippets?vendor=frr"}} {
		role := plugin.RoleOperator
		if c.method == "GET" {
			role = plugin.RoleAdmin
		}
		if rec, _ := e.do(t, c.method, c.path, role, nil); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d", c.method, c.path, rec.Code)
		}
	}
}

func TestPreflightRunReportsEveryCheck(t *testing.T) {
	f := goodFacts()
	f.Learned = 0
	e := newPreflightUI(t, &f)

	rec, got := e.do(t, "GET", "/api/preflight", plugin.RoleViewer, nil)
	if rec.Code != http.StatusOK || got["available"] != true || got["report"] != nil {
		t.Fatalf("before a run: %d %s", rec.Code, rec.Body)
	}
	if vendors := got["vendors"].([]any); len(vendors) != len(snippet.Vendors) {
		t.Fatalf("vendors = %v", vendors)
	}

	if rec, _ := e.do(t, "POST", "/api/preflight/run", plugin.RoleViewer, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer run = %d", rec.Code)
	}
	rec, got = e.do(t, "POST", "/api/preflight/run", plugin.RoleOperator, "")
	if rec.Code != http.StatusOK || got["ready"] != false {
		t.Fatalf("run: %d %s", rec.Code, rec.Body)
	}
	byID := map[string]map[string]any{}
	for _, r := range got["results"].([]any) {
		m := r.(map[string]any)
		byID[m["id"].(string)] = m
	}
	if len(byID) != 5 || byID["bgp_session"]["status"] != "fail" || !strings.Contains(byID["bgp_session"]["fix"].(string), "export policy toward Packeteer") {
		t.Fatalf("results = %v", byID)
	}
	if byID["import_filter"]["status"] != "unverified" || byID["import_filter"]["confirmable"] != true {
		t.Fatalf("filters = %v", byID["import_filter"])
	}

	// The run is audited, and the page now reads the same report.
	var audited bool
	for _, r := range e.store.Records() {
		if r.Action == "POST /api/preflight/run" && r.Result == auth.ResultOK && r.Target == "preflight" && strings.Contains(r.Detail, "ready=false") && strings.Contains(r.Detail, "bgp_session") {
			audited = true
		}
	}
	if !audited {
		t.Fatal("run not audited")
	}
	_, got = e.do(t, "GET", "/api/preflight", plugin.RoleViewer, nil)
	if rep, _ := got["report"].(map[string]any); rep["ready"] != false || len(rep["results"].([]any)) != 5 {
		t.Fatalf("after a run: %v", got)
	}
}

func TestPreflightConfirmNeedsAdminAndNoLeak(t *testing.T) {
	f := goodFacts()
	e := newPreflightUI(t, &f)
	body := map[string]string{"id": "import_filter"}
	if rec, _ := e.do(t, "POST", "/api/preflight/confirm", plugin.RoleOperator, body); rec.Code != http.StatusForbidden {
		t.Fatalf("operator confirm = %d", rec.Code)
	}
	if rec, _ := e.do(t, "POST", "/api/preflight/confirm", plugin.RoleAdmin, map[string]string{"id": "bgp_session"}); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("confirm a check that cannot be confirmed = %d", rec.Code)
	}
	f.Leaks = 1
	rec, got := e.do(t, "POST", "/api/preflight/confirm", plugin.RoleAdmin, body)
	if rec.Code != http.StatusConflict || !strings.Contains(got["error"].(string), "leak watch holds 1") {
		t.Fatalf("confirm over a leak: %d %s", rec.Code, rec.Body)
	}
	f.Leaks = 0
	rec, got = e.do(t, "POST", "/api/preflight/confirm", plugin.RoleAdmin, body)
	if rec.Code != http.StatusOK || got["ready"] != true {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body)
	}
	for _, r := range got["results"].([]any) {
		m := r.(map[string]any)
		if m["id"] == "import_filter" && (m["status"] != "pass" || !strings.Contains(m["detail"].(string), "Confirmed by admin-user")) {
			t.Fatalf("filters = %v", m)
		}
	}
}

// The editor will not save a config that turns inject on until every check
// has passed; an edit that leaves inject alone is not held back.
func TestSaveThatTurnsInjectOnWaitsForPreflight(t *testing.T) {
	f := goodFacts()
	e := newPreflightUI(t, &f)
	_, got := e.do(t, "GET", "/api/config", plugin.RoleAdmin, nil)
	base := got["sha256"].(string)
	save := map[string]any{"yaml": editorInjectYAML, "base": base, "confirm_inject": true}

	rec, got := e.do(t, "PUT", "/api/config", plugin.RoleAdmin, save)
	if rec.Code != http.StatusPreconditionFailed || got["code"] != "preflight_required" || !strings.Contains(got["error"].(string), "import_filter") {
		t.Fatalf("blocked save: %d %s", rec.Code, rec.Body)
	}
	if rep := got["preflight"].(map[string]any); rep["ready"] != false {
		t.Fatalf("preflight = %v", rep)
	}
	if disk, _ := os.ReadFile(e.path); string(disk) != editorYAML {
		t.Fatal("the file changed although inject was refused")
	}

	// A harmless edit is not held back.
	harmless := strings.Replace(editorYAML, "router_id: 192.0.2.10", "router_id: 192.0.2.20", 1)
	if rec, _ := e.do(t, "PUT", "/api/config", plugin.RoleAdmin, map[string]any{"yaml": harmless, "base": base}); rec.Code != http.StatusOK {
		t.Fatalf("observe edit = %d", rec.Code)
	}
	base = configedit.Hash([]byte(harmless))
	save["base"] = base

	if rec, _ := e.do(t, "POST", "/api/preflight/confirm", plugin.RoleAdmin, map[string]string{"id": "import_filter"}); rec.Code != http.StatusOK {
		t.Fatalf("confirm = %d", rec.Code)
	}
	// Ready, but the existing confirm_inject rule still applies.
	save["confirm_inject"] = false
	if rec, _ := e.do(t, "PUT", "/api/config", plugin.RoleAdmin, save); rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("unconfirmed inject = %d", rec.Code)
	}
	save["confirm_inject"] = true
	if rec, got := e.do(t, "PUT", "/api/config", plugin.RoleAdmin, save); rec.Code != http.StatusOK {
		t.Fatalf("save after preflight: %d %s", rec.Code, rec.Body)
	} else if got["result"].(map[string]any)["mode"] != "inject" {
		t.Fatalf("result = %v", got["result"])
	}
}

func TestSnippetsEndpoint(t *testing.T) {
	f := goodFacts()
	e := newPreflightUI(t, &f)
	rec, got := e.do(t, "GET", "/api/snippets?vendor=bird", plugin.RoleAdmin, nil)
	if rec.Code != http.StatusOK || got["vendor"] != "bird" || !strings.Contains(got["text"].(string), "filter packeteer_in") {
		t.Fatalf("bird: %d %s", rec.Code, rec.Body)
	}
	rec, got = e.do(t, "GET", "/api/snippets?vendor=cumulus", plugin.RoleAdmin, nil)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(got["error"].(string), "unknown vendor") {
		t.Fatalf("unknown vendor: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := e.do(t, "GET", "/api/snippets?vendor=bird", plugin.RoleOperator, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("operator = %d", rec.Code)
	}
}

func TestPreflightMetrics(t *testing.T) {
	f := goodFacts()
	f.Learned = 0
	e := newPreflightUI(t, &f)
	rec, _ := e.do(t, "GET", "/metrics", plugin.RoleViewer, nil)
	if strings.Contains(rec.Body.String(), "packeteer_preflight") {
		t.Fatal("preflight series before any run")
	}
	e.do(t, "POST", "/api/preflight/run", plugin.RoleOperator, "")
	rec, _ = e.do(t, "GET", "/metrics", plugin.RoleViewer, nil)
	for _, want := range []string{
		"packeteer_preflight_ready 0\n",
		`packeteer_preflight_check{check="bgp_session",status="fail"} 1`,
		`packeteer_preflight_check{check="bgp_session",status="pass"} 0`,
		`packeteer_preflight_check{check="import_filter",status="unverified"} 1`,
		`packeteer_preflight_check{check="timers",status="pass"} 1`,
		"packeteer_preflight_last_run_timestamp_seconds ",
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("metrics lack %q", want)
		}
	}
}

const observeInjectReady = `mode: observe
asn: 64512
router_id: 192.0.2.10
packeteer_community: 64512:666
max_improvements: 50
hold_time: 15m
thresholds:
  min_loss_delta_pct: 1
  min_rtt_delta_ms: 15
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
allowlist:
  prefixes: []
bgp:
  neighbors:
    - address: 192.0.2.254
`

type learnedPrefixes []netip.Prefix

func (l learnedPrefixes) Find(keep func(rib.Route) bool, _ func(a, b rib.Route) bool, _ int) ([]rib.Route, int) {
	for _, p := range l {
		keep(rib.Route{Prefix: p})
	}
	return nil, 0
}

func TestInjectPlanWaitsForPreflightAndWarnsAboutUnlearnedPrefixes(t *testing.T) {
	f := goodFacts()
	e := newPreflightUI(t, &f)
	body := map[string]any{"current": observeInjectReady, "allowlist": []string{"198.51.100.0/24", "203.0.113.0/24"}}

	rec, got := e.do(t, "POST", "/api/config/inject", plugin.RoleAdmin, body)
	if rec.Code != http.StatusPreconditionFailed || got["code"] != "preflight_required" {
		t.Fatalf("before the checks pass: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := e.do(t, "POST", "/api/preflight/confirm", plugin.RoleAdmin, map[string]string{"id": "import_filter"}); rec.Code != http.StatusOK {
		t.Fatalf("confirm = %d", rec.Code)
	}

	rec, got = e.do(t, "POST", "/api/config/inject", plugin.RoleAdmin, body)
	if rec.Code != http.StatusOK || !strings.Contains(got["yaml"].(string), "mode: inject") || len(got["explain"].([]any)) < 5 {
		t.Fatalf("plan: %d %s", rec.Code, rec.Body)
	}
	if _, ok := got["not_learned"]; ok {
		t.Fatalf("not_learned without a RIB: %v", got["not_learned"])
	}

	var rv SearchRIB = learnedPrefixes{netip.MustParsePrefix("198.51.100.0/24")}
	e.srv.SetSearchRIB(rv)
	_, got = e.do(t, "POST", "/api/config/inject", plugin.RoleAdmin, body)
	missing, _ := got["not_learned"].([]any)
	if len(missing) != 1 || missing[0] != "203.0.113.0/24" {
		t.Fatalf("not_learned = %v", got["not_learned"])
	}

	// The plan writes nothing.
	if disk, _ := os.ReadFile(e.path); string(disk) != editorYAML {
		t.Fatal("the plan changed the file")
	}
	rec, got = e.do(t, "POST", "/api/config/inject", plugin.RoleAdmin, map[string]any{"current": observeInjectReady, "allowlist": []string{"nonsense"}})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(got["error"].(string), "not a prefix") {
		t.Fatalf("bad prefix: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := e.do(t, "POST", "/api/config/inject", plugin.RoleOperator, body); rec.Code != http.StatusForbidden {
		t.Fatalf("operator = %d", rec.Code)
	}
}

func TestInjectPlanIsOffWithoutPreflight(t *testing.T) {
	e := newUI(t)
	rec, _ := e.do(t, "POST", "/api/config/inject", plugin.RoleAdmin, map[string]any{"current": observeInjectReady, "allowlist": []string{"198.51.100.0/24"}})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("no preflight = %d", rec.Code)
	}
}

// TestPreflightPage runs preflight_page_test.js, which exercises the
// preflight section of settings.js against a DOM stand-in. It is skipped
// without Node locally and required in CI.
func TestPreflightPage(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the preflight page test")
		}
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "preflight_page_test.js").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("preflight page: %v\n%s", err, out)
	}
}
