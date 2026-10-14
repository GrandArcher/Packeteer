package httpapi

import (
	"regexp"
	"strings"
	"testing"
)

// jsIDs are the element ids a script looks up with byId or getElementById.
func jsIDs(js string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`(?:byId|getElementById)\("([^"]+)"\)`).FindAllStringSubmatch(js, -1) {
		out = append(out, m[1])
	}
	return out
}

// TestCommitPageAssets checks the Commit & Cost page wiring (#174): it reads
// only /api/commit, draws with the shared chart helpers, never builds
// markup, and calls a move "announced" only when the server says so. The
// rendered page is covered by the UI smoke test in CI.
func TestCommitPageAssets(t *testing.T) {
	html := mustWeb(t, "web/commit.html")
	page := mustWeb(t, "web/commit.js")
	js := page + mustWeb(t, "web/charts.js") // the drawing code is shared with the dashboard widget (#182)

	if strings.Contains(html, "#174") || strings.Contains(html, "not built yet") {
		t.Error("commit.html still has the placeholder")
	}
	charts, app := strings.Index(html, `src="/charts.js"`), strings.Index(html, `src="/app.js"`)
	if charts < 0 || charts > app || strings.Index(html, `src="/commit.js"`) < app {
		t.Error("commit.html must load charts.js, app.js, then commit.js")
	}
	for _, id := range jsIDs(page) {
		if !strings.Contains(html, `id="`+id+`"`) {
			t.Errorf("commit.js looks up #%s, which commit.html lacks", id)
		}
	}
	for _, s := range []string{
		`getJSON("/api/commit?days="`,
		`new URLSearchParams(window.location.search).get("days")`,
		`m.announced ? "Announced" : "Recommended"`,
		`"Moves are not recorded without storage."`,
		`"Samples are not stored, so there is no history to draw.`,
		`"No provider has a telemetry binding`,
		`href = "/settings.html#commit-setup"`,
		`svgEl("line", {"class": "usage-commit"`,
	} {
		if !strings.Contains(js, s) {
			t.Errorf("commit.js missing %s", s)
		}
	}
	if strings.Count(js, "Announced") != 1 {
		t.Error("commit.js says Announced outside the announced check")
	}
	for _, bad := range []string{"innerHTML", "api(", "method:", "fetch("} {
		if strings.Contains(js, bad) {
			t.Errorf("commit.js uses %q: the page is read-only", bad)
		}
	}
	if !strings.Contains(html, `<option value="1">`) || !strings.Contains(html, `<option value="7" selected>`) || !strings.Contains(html, `<option value="30">`) {
		t.Error("commit.html lacks the 1, 7, and 30 day ranges")
	}
}

// TestCommitSetupAssets checks the Settings flow (#174): every element the
// script uses is on the page, the only write is the settings form's
// existing Apply (which edits the editor text and never saves), and no field
// takes a secret.
func TestCommitSetupAssets(t *testing.T) {
	html := mustWeb(t, "web/settings.html")
	js := mustWeb(t, "web/commitsetup.js")
	settings := mustWeb(t, "web/settings.js")

	for _, id := range jsIDs(js) {
		if !strings.Contains(html, `id="`+id+`"`) {
			t.Errorf("commitsetup.js looks up #%s, which settings.html lacks", id)
		}
	}
	if strings.Index(html, `src="/settings.js"`) > strings.Index(html, `src="/commitsetup.js"`) || !strings.Contains(html, `<section id="commit-setup">`) {
		t.Error("settings.html must load settings.js before commitsetup.js and hold the commit-setup section")
	}
	for _, bad := range []string{"innerHTML", "api(", "fetch(", `"PUT"`, `type = "password"`, "passphrase"} {
		if strings.Contains(js, bad) {
			t.Errorf("commitsetup.js uses %q", bad)
		}
	}
	for _, s := range []string{
		`postForm(csStatus)`,                 // the form's own Apply, role check and audit included
		`CS_ENV_NAME.test(h.community_env`,   // a variable name, not a community
		`"Community variable (name only)"`,   // the label says so
		`form.commit.scorer = cs.scorer !==`, // asks for a switch only when it differs
		`form.precedence = cs.scorer === "cost"`,
		`checkConfig()`, // validated right after Apply
	} {
		if !strings.Contains(js, s) {
			t.Errorf("commitsetup.js missing %s", s)
		}
	}
	if !strings.Contains(settings, "function postForm(report)") || !strings.Contains(settings, `"/api/config/form"`) {
		t.Error("settings.js lost the form endpoint the commit setup shares")
	}
	for _, s := range []string{"Observe stays the default", "nothing is saved or announced", "never typed in"} {
		if !strings.Contains(html, s) {
			t.Errorf("settings.html lacks %q", s)
		}
	}
}
