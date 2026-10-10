package httpapi

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TestUIShell checks the left navigation and one page per area (#170).
// Deep links are real URLs. The mode banner is the first landmark on
// every page. Settings and Admin are marked admin-only. Pages that do
// not exist yet name their issue.
func TestUIShell(t *testing.T) {
	entries, err := fs.ReadDir(webFS, "web")
	if err != nil {
		t.Fatal(err)
	}
	pages := map[string]string{}
	var nav string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		body := mustWeb(t, "web/"+e.Name())
		if strings.Contains(body, "<script>") {
			t.Errorf("%s has an inline script", e.Name())
		}
		if !strings.Contains(body, `src="/shell.js"`) {
			t.Errorf("%s does not load the shell", e.Name())
		}
		for _, id := range []string{`id="banner"`, `id="conn"`, `id="status"`, `id="search-slot"`, `id="events-slot"`, `id="account"`, `id="account-btn"`, `id="refresh"`} {
			if !strings.Contains(body, id) {
				t.Errorf("%s missing %s", e.Name(), id)
			}
		}
		// The search slot does not query (#172). The events slot opens Events.
		if !strings.Contains(body, `id="top-search" type="search" placeholder="Search" readonly`) {
			t.Errorf("%s search slot is not a read-only placeholder", e.Name())
		}
		if !strings.Contains(body, `href="/events.html">Events`) {
			t.Errorf("%s events slot does not open the Events page", e.Name())
		}
		bi, ni := strings.Index(body, `id="banner"`), strings.Index(body, `<nav class="sidenav"`)
		if bi < 0 || ni < 0 || bi > ni {
			t.Errorf("%s mode banner is not before the navigation", e.Name())
		}
		if strings.Index(body, `<header class="topbar">`) < ni {
			t.Errorf("%s top bar is not in the content column", e.Name())
		}
		i := strings.Index(body, `<nav class="sidenav"`)
		j := strings.Index(body, "</nav>")
		if i < 0 || j < i {
			t.Fatalf("%s has no sidenav", e.Name())
		}
		got := body[i : j+len("</nav>")]
		if nav == "" {
			nav = got
		} else if got != nav {
			t.Errorf("%s sidenav differs from the other pages", e.Name())
		}
		page := attr(t, body, "data-page")
		if page == "" {
			t.Errorf("%s has no data-page", e.Name())
		}
		pages[e.Name()] = page
	}
	for _, href := range []string{
		`href="/" data-page="overview"`,
		`href="/dashboards.html" data-page="dashboards"`,
		`href="/improvements.html" data-page="improvements"`,
		`href="/prefixes.html" data-page="prefixes">Prefixes &amp; ASNs`,
		`href="/graphs.html" data-page="graphs"`,
		`href="/reports.html" data-page="reports"`,
		`href="/providers.html" data-page="providers">Providers &amp; Exchanges`,
		`href="/commit.html" data-page="commit">Commit &amp; Cost`,
		`href="/policies.html" data-page="policies"`,
		`href="/protection.html" data-page="protection"`,
		`href="/troubleshooting.html" data-page="troubleshooting"`,
		`href="/events.html" data-page="events"`,
		`href="/settings.html" data-page="settings" data-min-role="admin"`,
		`href="/admin.html" data-page="admin" data-min-role="admin"`,
	} {
		if !strings.Contains(nav, href) {
			t.Errorf("nav missing %s", href)
		}
	}
	want := map[string][]string{
		"index.html":           {`<body data-page="overview" data-live="app">`, `id="tiles"`, `id="setup"`, `id="federation-section" hidden`, "POPs"},
		"improvements.html":    {`<body data-page="improvements" data-live="app">`, `id="improvements"`, `id="improvements-title">Recommended improvements`},
		"prefixes.html":        {`<body data-page="prefixes" data-live="app">`, `id="prefixes"`, `id="asn-map"`, "ASN map", "MED"},
		"providers.html":       {`<body data-page="providers" data-live="app">`, `id="providers"`, "#148"},
		"reports.html":         {`<body data-page="reports" data-live="app">`, `id="report-name"`, `id="report-csv"`},
		"troubleshooting.html": {`<body data-page="troubleshooting" data-live="app">`, `id="tool-run"`, "Looking glass"},
		"protection.html":      {`<body data-page="protection" data-live="app">`, `id="mitigation-section" hidden`, `id="mitigation"`, `id="protection-empty"`, "#131"},
		"graphs.html":          {`<body data-page="graphs" data-live="app">`, `id="graph"`, `id="graph-bucket"`, `id="graph-days"`, `id="graph-csv"`, `src="/charts.js"`, `src="/graphs.js"`, "nothing here announces a route"},
		"commit.html":          {`<body data-page="commit" data-live="app">`, "#174"},
		"policies.html":        {`<body data-page="policies" data-live="app">`, "#130"},
		"events.html":          {`<body data-page="events" data-live="app">`, "#173"},
		"admin.html":           {`<body data-page="admin" data-live="app">`, `id="page-denied"`, `id="admin-body"`, "#175"},
		"settings.html":        {`<body data-page="settings">`, `src="/settings.js"`, `id="ed-yaml"`},
		"dashboards.html":      {`<body data-page="dashboards">`, `src="/dashboards.js"`, `id="db-grid"`, "Custom dashboards"},
	}
	if len(pages) != len(want) {
		t.Fatalf("html pages = %v", pages)
	}
	for name, needles := range want {
		if pages[name] == "" {
			t.Errorf("missing page %s", name)
		}
		body := mustWeb(t, "web/"+name)
		for _, n := range needles {
			if !strings.Contains(body, n) {
				t.Errorf("%s missing %q", name, n)
			}
		}
	}

	e := newUI(t)
	for _, path := range []string{
		"/", "/improvements.html", "/prefixes.html", "/graphs.html", "/reports.html",
		"/providers.html", "/commit.html", "/policies.html", "/protection.html",
		"/troubleshooting.html", "/events.html", "/settings.html", "/admin.html", "/dashboards.html",
	} {
		rec, _ := e.do(t, "GET", path, plugin.RoleViewer, nil)
		if rec.Code != 200 {
			t.Errorf("%s viewer GET = %d", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `id="banner"`) {
			t.Errorf("%s response has no banner", path)
		}
	}
}

func attr(t *testing.T, body, name string) string {
	t.Helper()
	key := name + `="`
	i := strings.Index(body, key)
	if i < 0 {
		return ""
	}
	rest := body[i+len(key):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("unterminated %s", name)
	}
	return rest[:j]
}

// TestModeBannerCopy checks observe says it announces nothing, on the
// live pages and on the pages whose banner is drawn by the shell.
func TestModeBannerCopy(t *testing.T) {
	app := mustWeb(t, "web/app.js")
	shell := mustWeb(t, "web/shell.js")
	for _, s := range []string{
		`observe: "Observe mode: Packeteer measures and recommends. It announces nothing."`,
		`suggest: "Suggest mode: Packeteer measures and publishes recommendations. It announces nothing."`,
		`inject: "Inject mode: improvements for allowlisted prefixes are announced to the edge routers."`,
	} {
		if !strings.Contains(app, s) {
			t.Errorf("app.js missing %s", s)
		}
		if !strings.Contains(shell, s) {
			t.Errorf("shell.js missing %s", s)
		}
	}
	for _, s := range []string{
		`me.auth === "rbac"`,
		`me.role === "admin"`,
		"Your account may not read this page.",
		`data-min-role`,
		`/auth/logout`,
	} {
		if !strings.Contains(shell, s) {
			t.Errorf("shell.js missing %s", s)
		}
	}
	// A missing section must not throw when the page does not have it.
	for _, fn := range []string{"renderProviders", "renderPrefixes", "renderImprovements", "renderMitigation", "renderFederation", "renderTiles", "renderSetup"} {
		if !strings.Contains(app, "function "+fn) || !strings.Contains(app, "if (!root) return;") {
			t.Errorf("%s is not guarded", fn)
		}
	}
}
