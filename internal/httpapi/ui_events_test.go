package httpapi

import (
	"strings"
	"testing"
)

// TestEventsPageAssets checks the page's wiring (#173): the filters it
// offers are the ones the API takes, the Audit tab is admin-gated in the
// shell and reads the existing endpoint, the page marks events as seen with
// the controller's clock, and the top bar indicator counts warnings only.
// The rendered result is covered by the UI smoke test in CI.
func TestEventsPageAssets(t *testing.T) {
	html := mustWeb(t, "web/events.html")
	js := mustWeb(t, "web/events.js")
	shell := mustWeb(t, "web/shell.js")

	for _, s := range []string{
		`<option value="warning">`, `<option value="critical">`,
		`<option value="1h">`, `<option value="24h">`, `<option value="7d">`, `<option value="30d">`, `<option value="custom">`,
		`id="tab-audit" aria-selected="false" aria-controls="panel-audit" data-min-role="admin"`,
		`id="panel-audit" role="tabpanel" aria-labelledby="tab-audit" hidden`,
		"Passwords and token secrets are never recorded",
	} {
		if !strings.Contains(html, s) {
			t.Errorf("events.html missing %s", s)
		}
	}
	for _, s := range []string{
		`"/api/events?"`, `"/api/audit?limit="`, `"severity="`, `"q="`, `"from="`, `"to="`,
		`["Time", "Source", "Severity", "Event", "Detail"]`,
		`["Time", "Actor", "Role", "Method", "Action", "Target", "Result", "Status"]`,
		`shellMarkEventsSeen(data.now)`,
		`window.location.hash === "#audit"`,
		"Storage is off: these are the events since",
	} {
		if !strings.Contains(js, s) {
			t.Errorf("events.js missing %s", s)
		}
	}
	// The audit columns are the issue's list. No detail, remote, or id.
	if strings.Contains(js, "r.detail") || strings.Contains(js, "r.remote") {
		t.Error("events.js shows an audit field outside the list")
	}
	if strings.Contains(js, "innerHTML") || strings.Contains(shell, "innerHTML") {
		t.Error("a page builds markup from event text")
	}
	for _, s := range []string{
		`"/api/events?severity=warning&limit="`, `packeteer.events.seen`, `"&from=" + encodeURIComponent(seen)`,
		`!== "events"`, `.events-count`,
	} {
		if !strings.Contains(shell, s) {
			t.Errorf("shell.js missing %s", s)
		}
	}
}
