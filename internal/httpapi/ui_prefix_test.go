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
		`return "/prefix/" + encodeURI(prefix);`,           // shareable URL
		`prefixPageUpdate(lastPrefixes)`,                   // live card refresh
		`function prefixCard(row)`,                         // the existing card, shared
		`"Learned paths. MED is display only and does not`, // MED label inside the card
	} {
		if !strings.Contains(app, s) {
			t.Errorf("app.js missing %s", s)
		}
	}
	if reports := mustWeb(t, "web/reports.js"); !strings.Contains(reports, `prefixCell(v)`) || strings.Contains(reports, "innerHTML") {
		t.Error("reports.js does not link prefix cells to the prefix page, or builds markup") // report prefix cells
	}
	if tools := mustWeb(t, "web/tools.js"); !strings.Contains(tools, `defaultValue = qs.get("target")`) {
		t.Error("tools.js does not prefill the target from the link") // Probe tool prefill
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

// TestPrefixListAssets checks the paged Prefixes page wiring (#183): the
// filter lives in the URL, only the visible page is fetched, a row opens
// the existing card, and nothing on the page writes. The rendered page is
// covered by the UI smoke test in CI.
func TestPrefixListAssets(t *testing.T) {
	app := mustWeb(t, "web/app.js")
	js := mustWeb(t, "web/prefixes.js")
	html := mustWeb(t, "web/prefixes.html")
	prefix := mustWeb(t, "web/prefix.js")
	prefixPage := mustWeb(t, "web/prefix.html")

	for _, s := range []string{
		`getJSON("/api/prefixes?" + prefixListQuery())`,
		`typeof prefixListQuery !== "function"`, // pages without a list fetch none
		`refreshAgain`,                          // a filter change during a refresh is fetched
		`data.asn_total > nodes.length`,         // the ASN map says it is cut
		`site.count || prefs.length`,
		`"/prefixes.html?asn=" + node.asn`,
	} {
		if !strings.Contains(app, s) {
			t.Errorf("app.js missing %s", s)
		}
	}
	if strings.Contains(app, "function renderPrefixes") || strings.Contains(app, `getJSON("/api/prefixes")`) {
		t.Error("app.js still renders or fetches the whole list")
	}
	for _, s := range []string{
		`q.set("offset", String((v.page - 1) * v.size))`,
		`q.set("limit", String(v.size))`,
		`window.history.replaceState(null, "", window.location.pathname`,
		`new URLSearchParams(window.location.search)`,
		`td.appendChild(prefixCard(row))`, // the existing card, built when a row opens
		`prefixExpanded = keep`,           // open rows are pruned to the visible page
		`"Expected gain"`,
		`if (!root) return;`,
		`window.addEventListener("DOMContentLoaded", initPrefixList)`,
	} {
		if !strings.Contains(js, s) {
			t.Errorf("prefixes.js missing %s", s)
		}
	}
	for _, bad := range []string{"postJSON", "method:", "innerHTML", "localStorage", "eval("} {
		if strings.Contains(js, bad) {
			t.Errorf("prefixes.js contains %s", bad)
		}
	}
	for _, id := range []string{"prefix-filter", "prefix-asn", "prefix-asn-error", "prefix-provider", "prefix-changes", "prefix-sort", "prefix-size"} {
		if !strings.Contains(html, `id="`+id+`"`) {
			t.Errorf("prefixes.html has no #%s", id)
		}
	}
	for name, page := range map[string]string{"/prefixes.js": html, "/prefix.js": prefixPage} {
		own, appAt := strings.Index(page, `src="`+name+`"`), strings.Index(page, `src="/app.js"`)
		if own < 0 || appAt < 0 || own > appAt {
			t.Errorf("%s must load before app.js so app.js sees prefixListQuery", name)
		}
	}
	if !strings.Contains(prefix, `"prefix=" + encodeURIComponent(thisPrefix) + "&limit=1"`) {
		t.Error("the prefix page does not ask for its one prefix")
	}
}
