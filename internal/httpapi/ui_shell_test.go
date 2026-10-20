package httpapi

import (
	"io/fs"
	"regexp"
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
		// The sign-in page has no navigation or account menu; TestSigninPage
		// covers it.
		if !strings.HasSuffix(e.Name(), ".html") || e.Name() == "signin.html" {
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
		// The search box is the same on every page (#172). The events slot opens Events.
		if !strings.Contains(body, `<input id="top-search" type="search" placeholder="Prefix, AS, or name" maxlength="64" autocomplete="off" list="top-search-recent"></label><datalist id="top-search-recent"></datalist>`) {
			t.Errorf("%s search slot is not the search box", e.Name())
		}
		if !strings.Contains(body, `href="/events.html">Events`) {
			t.Errorf("%s events slot does not open the Events page", e.Name())
		}
		// The brand logo and the favicon are the embedded file (#327).
		if !strings.Contains(body, `<link rel="icon" href="/logo.png" type="image/png" sizes="128x128">`) {
			t.Errorf("%s missing favicon", e.Name())
		}
		if !strings.Contains(body, `<a class="brand" href="/"><img class="logo" src="/logo.png" width="32" height="32" alt="Packeteer logo">Packeteer</a>`) {
			t.Errorf("%s brand has no logo", e.Name())
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
		`href="/system.html" data-page="system"`,
		`href="/tokens.html" data-page="tokens"`,
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
		"providers.html":       {`<body data-page="providers" data-live="app">`, `id="providers"`, `id="exchanges"`, `id="exchange-report"`, `src="/exchanges.js"`, "only reads"},
		"reports.html":         {`<body data-page="reports" data-live="app">`, `id="report-catalog"`, `id="report-range"`, `id="report-csv"`, `id="report-xlsx"`, `id="report-add"`, `src="/reports.js"`},
		"troubleshooting.html": {`<body data-page="troubleshooting" data-live="app">`, `id="tool-run"`, `id="tool-results"`, `id="tool-empty"`, `src="/tools.js"`, "Looking glass"},
		"protection.html":      {`<body data-page="protection" data-live="app">`, `id="mitigation-section" hidden`, `id="mitigation"`, `id="protection-empty"`, `id="mit-form"`, `id="mf-prefix"`, `src="/protection.js"`, `id="mit-badge"`},
		"graphs.html":          {`<body data-page="graphs" data-live="app">`, `id="graph"`, `id="graph-bucket"`, `id="graph-days"`, `id="graph-csv"`, `src="/charts.js"`, `src="/graphs.js"`, "nothing here announces a route"},
		"prefix.html":          {`<body data-page="prefixes" data-live="app">`, `id="prefix-title"`, `id="prefix-live"`, `id="prefix-probe"`, `id="prefix-timeline"`, `id="prefix-days"`, `src="/prefix.js"`, "MED is display only"},
		"commit.html":          {`<body data-page="commit" data-live="app">`, `id="commit-days"`, `id="commit-summary"`, `id="commit-graphs"`, `src="/charts.js"`, `src="/commit.js"`, "nothing here announces a route"},
		"policies.html":        {`<body data-page="policies" data-live="app">`, "#130", `id="maint-section" hidden`, `id="maint-form" hidden`, `src="/maintenance.js"`},
		"events.html":          {`<body data-page="events">`, `id="events"`, `id="audit"`, `id="tab-audit"`, `data-min-role="admin">Audit`, `id="ev-severity"`, `id="ev-q"`, `id="ev-range"`, `src="/events.js"`},
		"search.html":          {`<body data-page="search">`, `id="search-results"`, `id="search-status"`, `id="search-recent"`, `src="/search.js"`, "only reads"},
		"ixp-member.html":      {`<body data-page="ixp-member">`, `id="member-title"`, `id="member-links"`, `id="member-list"`, `id="member-connections"`, `id="member-fabric"`, `id="member-sessions"`, `id="member-history"`, `src="/ixp-member.js"`, "announces nothing"},
		"ixp-sites.html":       {`<body data-page="ixp-sites">`, `id="sites-incidents"`, `id="sites-list"`, `id="sites-links"`, `id="sites-members"`, `src="/ixp-sites.js"`, "announces nothing"},
		"system.html":          {`<body data-page="system">`, `id="system"`, `id="system-summary"`, `src="/system.js"`, "only reads"},
		"admin.html":           {`<body data-page="admin">`, `id="page-denied"`, `id="admin-body"`, `id="user-form"`, `id="uf-name"`, `id="uf-role"`, `id="uf-password" type="password"`, `id="users-off" class="empty" hidden`, `id="users-on" hidden`, `src="/admin.js"`},
		"tokens.html":          {`<body data-page="tokens">`, `id="tokens-off" class="empty" hidden`, `id="tokens-on" hidden`, `id="token-secret" class="secret" role="alert" hidden`, `id="token-form"`, `id="tf-name"`, `id="tf-role"`, `id="tf-ttl"`, `src="/tokens.js"`},
		"settings.html":        {`<body data-page="settings">`, `src="/settings.js"`, `id="ed-yaml"`, `id="commit-setup"`, `src="/commitsetup.js"`, `src="/upgrade.js"`, `id="up-check"`, `id="up-confirm"`},
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
		"/", "/improvements.html", "/prefixes.html", "/prefix/192.0.2.0/24", "/graphs.html", "/reports.html",
		"/providers.html", "/commit.html", "/policies.html", "/protection.html",
		"/troubleshooting.html", "/events.html", "/search.html?q=AS64510", "/system.html", "/tokens.html", "/settings.html", "/admin.html", "/dashboards.html",
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

// TestUIKeyboardAccess checks every page for the keyboard and screen reader
// rules of #353: the skip link is the first focusable element and points at
// a focusable main, there is exactly one h1, and the YAML editor has a label.
// Focus ring size and contrast are checked in a browser by lab/ui-fixtures/a11y/driver.js.
func TestUIKeyboardAccess(t *testing.T) {
	entries, err := fs.ReadDir(webFS, "web")
	if err != nil {
		t.Fatal(err)
	}
	focusable := regexp.MustCompile(`<(?:a|button|input|select|textarea)[\s>]`)
	pages := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		pages++
		body := mustWeb(t, "web/"+e.Name())
		after := body[strings.Index(body, "<body"):]
		loc := focusable.FindStringIndex(after)
		if loc == nil || !strings.HasPrefix(after[loc[0]:], `<a class="skip-link" href="#main">Skip to content</a>`) {
			t.Errorf("%s: the first focusable element is not the skip link", e.Name())
		}
		if !strings.Contains(body, `<main id="main" tabindex="-1"`) {
			t.Errorf("%s: main is not the skip link target", e.Name())
		}
		if n := strings.Count(body, "<h1"); n != 1 {
			t.Errorf("%s has %d h1 elements, want 1", e.Name(), n)
		}
	}
	if pages == 0 {
		t.Fatal("no pages checked")
	}
	settings := mustWeb(t, "web/settings.html")
	if !strings.Contains(settings, `<label for="ed-yaml">Config file (YAML)</label>`) {
		t.Error("the YAML editor has no label")
	}
	css := mustWeb(t, "web/app.css")
	for _, s := range []string{":focus-visible { outline: 3px solid #2f80ed;", ".skip-link:focus { top: 8px; }"} {
		if !strings.Contains(css, s) {
			t.Errorf("app.css missing %q", s)
		}
	}
}

// TestUINarrowLayout checks the phone layout of #352: every page with the
// navigation has a Menu button that names and controls the link list and
// starts closed, and the stylesheet and shell script carry the collapse and
// the card layout. The widths are measured in a browser by
// lab/ui-fixtures/mobile/driver.js.
func TestUINarrowLayout(t *testing.T) {
	entries, err := fs.ReadDir(webFS, "web")
	if err != nil {
		t.Fatal(err)
	}
	pages := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".html") || e.Name() == "signin.html" {
			continue
		}
		pages++
		body := mustWeb(t, "web/"+e.Name())
		btn := `<button type="button" id="nav-toggle" class="nav-toggle" aria-expanded="false" aria-controls="nav-links">Menu</button>`
		list := `<div id="nav-links" class="nav-links">`
		bi, li, first := strings.Index(body, btn), strings.Index(body, list), strings.Index(body, `href="/" data-page="overview"`)
		if bi < 0 || li < bi || first < li {
			t.Errorf("%s: the Menu button must come before the link list that holds the first link", e.Name())
		}
		if strings.Count(body[strings.Index(body, list):strings.Index(body, "</nav>")], "<a ") != 16 {
			t.Errorf("%s: the link list does not hold the 16 page links", e.Name())
		}
	}
	if pages == 0 {
		t.Fatal("no pages checked")
	}
	css := mustWeb(t, "web/app.css")
	for _, s := range []string{
		"@media (max-width: 759px) {",
		".nav-toggle { display: none; }",
		".nav-links { display: none;",
		".sidenav.open .nav-links { display: block; }",
		"table.stacked thead { position: absolute;",
		"table.stacked td[data-label]::before { content: attr(data-label)",
		`#providers td[data-label="Health"]`,
	} {
		if !strings.Contains(css, s) {
			t.Errorf("app.css missing %q", s)
		}
	}
	shell := mustWeb(t, "web/shell.js")
	for _, s := range []string{
		`window.matchMedia("(max-width: 759px)")`,
		`btn.setAttribute("aria-expanded"`,
		`ev.key !== "Escape"`,
		`t.classList.toggle("stacked", narrow)`,
		`!t.closest(".table-wrap")`,
		`cells[c].setAttribute("data-label", name)`,
	} {
		if !strings.Contains(shell, s) {
			t.Errorf("shell.js missing %q", s)
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
		`out.hidden = !(me && me.session)`,
	} {
		if !strings.Contains(shell, s) {
			t.Errorf("shell.js missing %s", s)
		}
	}
	// A missing section must not throw when the page does not have it.
	for _, fn := range []string{"renderProviders", "renderImprovements", "renderMitigation", "renderFederation", "renderTiles", "renderSetup"} {
		if !strings.Contains(app, "function "+fn) || !strings.Contains(app, "if (!root) return;") {
			t.Errorf("%s is not guarded", fn)
		}
	}
}
