package httpapi

import (
	"strings"
	"testing"
)

// TestLinkoutAssets checks the link-out wiring (#211): the pages place the
// server's URLs in a new tab without opener access, build none themselves,
// and the prefix, ASN map, ASN filter, and provider views each ask for
// them. The rendered pages and their encoded URLs are covered by the UI
// smoke test in CI.
func TestLinkoutAssets(t *testing.T) {
	app := mustWeb(t, "web/app.js")
	for _, s := range []string{
		`getJSON("/api/linkouts?" + q.toString())`,
		`a.target = "_blank";`,
		`a.rel = "noopener noreferrer";`,
		`/^https:/.test(l.url)`, // only https is placed
		`head.appendChild(linkoutSpan("asn", node.asn))`,
		`peer.appendChild(linkoutSpan("asn", p.peer_asn))`,
		`function originASN(row)`,
	} {
		if !strings.Contains(app, s) {
			t.Errorf("app.js missing %s", s)
		}
	}
	for file, want := range map[string][]string{
		"web/prefix.js":   {`linkoutSpan("prefix", thisPrefix)`, `linkoutSpan("asn", origin)`},
		"web/prefixes.js": {`linkoutSpan("asn", asn)`, `linkoutSpan("prefix", row.prefix)`},
	} {
		js := mustWeb(t, file)
		for _, s := range want {
			if !strings.Contains(js, s) {
				t.Errorf("%s missing %s", file, s)
			}
		}
	}
	for file, id := range map[string]string{"web/prefix.html": "prefix-links", "web/prefixes.html": "prefix-asn-links"} {
		if !strings.Contains(mustWeb(t, file), `id="`+id+`"`) {
			t.Errorf("%s has no #%s", file, id)
		}
	}
	// URLs come from the server: the pages hold no site address.
	for _, file := range []string{"web/app.js", "web/prefix.js", "web/prefixes.js"} {
		js := mustWeb(t, file)
		for _, host := range []string{"bgp.he.net", "stat.ripe.net", "peeringdb.com", "bgp.tools", "radar.cloudflare.com", "irrexplorer", "ring.nlnog.net"} {
			if strings.Contains(js, host) {
				t.Errorf("%s builds a %s URL itself", file, host)
			}
		}
	}
}
