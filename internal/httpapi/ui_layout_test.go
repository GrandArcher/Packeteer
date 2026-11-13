package httpapi

import (
	"regexp"
	"strings"
	"testing"
)

// TestSettingsFoldsClosed keeps the long Settings sections closed until
// asked for (#580), so the Decision settings sit near the top, and keeps each
// one a details element a link can open by its id.
func TestSettingsFoldsClosed(t *testing.T) {
	html := mustWeb(t, "web/settings.html")
	for _, id := range []string{"wizard", "preflight", "router-snippet", "blast", "whatif", "commit-setup"} {
		open := `<details id="` + id + `" class="fold">` + "\n" + `    <summary><h2>`
		if !strings.Contains(html, open) {
			t.Errorf("settings.html: #%s must be a closed fold with its h2 in the summary", id)
		}
	}
	if !strings.Contains(html, `<details id="raw-yaml" class="advanced">`) {
		t.Error("settings.html: the raw YAML must stay a closed details element")
	}
	editor := strings.Index(html, `id="editor-section"`)
	for _, id := range []string{"wizard", "preflight", "router-snippet", "blast"} {
		if at := strings.Index(html, `<details id="`+id+`"`); at < 0 || at > editor {
			t.Errorf("settings.html: #%s must come before the settings forms, closed", id)
		}
	}
	if n := strings.Count(html, "<h1>"); n != 1 {
		t.Errorf("settings.html has %d h1", n)
	}
}

// TestWideTablesStackBelowSameWidth checks that the script and the style
// sheet agree on where Improvements and Providers turn into cards (#580):
// the card rules apply from the phone breakpoint up to the width the script
// stacks tables at.
func TestWideTablesStackBelowSameWidth(t *testing.T) {
	css, shell := mustWeb(t, "web/app.css"), mustWeb(t, "web/shell.js")
	js := regexp.MustCompile(`shellMedium = window\.matchMedia\("\(max-width: (\d+)px\)"\)`).FindStringSubmatch(shell)
	if js == nil {
		t.Fatal("shell.js has no medium stacking query")
	}
	rule := `@media (min-width: 760px) and (max-width: ` + js[1] + `px) {`
	if !strings.Contains(css, rule) {
		t.Errorf("app.css lacks %q, the card rules for the width shell.js stacks at", rule)
	}
	if !strings.Contains(shell, `t.matches("#improvements table, #providers > table:first-of-type")`) {
		t.Error("shell.js must stack only the Improvements and provider tables at the medium width, not the BGP sessions table")
	}
	if !strings.Contains(css, `:is(#improvements, #providers) table.stacked tr { display: grid;`) {
		t.Error("app.css lacks the card grid for the stacked rows")
	}
}
