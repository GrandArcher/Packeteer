package httpapi

import (
	"strings"
	"testing"
)

// TestPrefixPageAssets checks the click-through wiring (#179): every
// improvement row links to the prefix page, the page reads the endpoint the
// server serves, "announced" is reserved for records made in inject mode,
// and Probe now only links to the Probe tool. The rendered page is covered
// by the UI smoke test in CI.
func TestPrefixPageAssets(t *testing.T) {
	app := mustWeb(t, "web/app.js")
	js := mustWeb(t, "web/prefix.js")
	ui := mustWeb(t, "web/ui.js")
	dash := mustWeb(t, "web/dashboards.js")

	for _, s := range []string{
		`tr.appendChild(prefixCell(im.prefix));`,           // live improvements table
		`data.report === "improvements"`,                   // report rows
		`c === "prefix" && linkable ? prefixCell(r[c])`,    // report prefix cells
		`return "/prefix/" + encodeURI(prefix);`,           // shareable URL
		`defaultValue = qs.get("target")`,                  // Probe tool prefill
		`prefixPageUpdate(lastPrefixes)`,                   // live card refresh
		`function prefixCard(row)`,                         // the existing card, shared
		`"Learned paths. MED is display only and does not`, // MED label inside the card
	} {
		if !strings.Contains(app, s) {
			t.Errorf("app.js missing %s", s)
		}
	}
	for _, s := range []string{
		`"/api/prefixes/history?prefix=" + encodeURIComponent(thisPrefix)`,
		`mode === "inject" ? "Announced" : "Recommended"`,
		`"/troubleshooting.html?tool=probe&target=" + encodeURIComponent(thisPrefix)`,
		"History is off",
		"No stored history for this prefix",
	} {
		if !strings.Contains(js, s) {
			t.Errorf("prefix.js missing %s", s)
		}
	}
	if strings.Count(js, "Announced") != 1 {
		t.Error("prefix.js says Announced outside the inject check")
	}
	if strings.Contains(js, "postJSON") || strings.Contains(js, "method:") || strings.Contains(js, "innerHTML") {
		t.Error("prefix.js writes or builds markup")
	}
	if !strings.Contains(ui, `prefixLinks && c === "prefix"`) || !strings.Contains(dash, `dataTable(rows, w.type === "improvements")`) {
		t.Error("the dashboard improvements widget does not link prefixes")
	}
}
