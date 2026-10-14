package httpapi

import (
	"net/http"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// #148: the exchange view on the Providers & Exchanges page only reads. The
// viewer role may load the page, its script, and the endpoints it calls, and
// the script makes no write call and builds no HTML from data.
func TestExchangePageIsReadOnly(t *testing.T) {
	e := newUI(t)
	viewer := plugin.RoleViewer
	for _, path := range []string{"/providers.html", "/exchanges.js", "/api/exchanges"} {
		if rec, _ := e.do(t, "GET", path, viewer, nil); rec.Code != http.StatusOK {
			t.Errorf("viewer GET %s = %d", path, rec.Code)
		}
	}
	// #156: the member comparison is open to the viewer. This server has
	// no such exchange, so the answer is a 404, not a refusal.
	if rec, _ := e.do(t, "GET", "/api/exchanges/member?exchange=ix-lab&next_hop=203.0.113.11", viewer, nil); rec.Code != http.StatusNotFound {
		t.Errorf("viewer GET /api/exchanges/member = %d, want 404", rec.Code)
	}
	// #152: the offload report is open to the viewer; this server has no
	// exchange, so it answers 404.
	if rec, _ := e.do(t, "GET", "/api/exchanges/offload", viewer, nil); rec.Code != http.StatusNotFound {
		t.Errorf("viewer GET /api/exchanges/offload = %d, want 404", rec.Code)
	}
	rec, _ := e.do(t, "GET", "/exchanges.js", viewer, nil)
	js := rec.Body.String()
	for _, want := range []string{`getJSON("/api/exchanges")`, `"/api/reports/exchanges?days="`, `p.reach`, `data-degraded`, `"/api/exchanges/member?exchange="`, `"/api/exchanges/offload?limit="`} {
		if !strings.Contains(js, want) {
			t.Errorf("exchanges.js missing %q", want)
		}
	}
	for _, banned := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "postJSON", "method:", "PUT", "DELETE", "eval("} {
		if strings.Contains(js, banned) {
			t.Errorf("exchanges.js contains %q", banned)
		}
	}
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		for _, path := range []string{"/api/exchanges", "/api/exchanges/member", "/api/exchanges/offload"} {
			if rec, _ := e.do(t, method, path, plugin.RoleAdmin, nil); rec.Code == http.StatusOK {
				t.Errorf("%s %s = %d, want a refusal", method, path, rec.Code)
			}
		}
	}
}

// #152: the page shows the offload report from the endpoint, with a CSV
// link, and a viewer can read both the JSON and the CSV.
func TestExchangePageShowsOffloadReport(t *testing.T) {
	saving := 160.0
	e := newUI(t)
	e.srv.SetExchangeMembers(ExchangeMembers{Offload: func(int) exchange.Offload {
		return exchange.Offload{Prefixes: 1, Bytes: 100000000, Mbps: 80, EstSavings: &saving, Rows: []exchange.OffloadRow{{
			Prefix: "198.51.100.0/24", Bytes: 100000000, Mbps: 80, Transit: "transit-a", EstSavings: &saving,
			Peers: []exchange.OffloadPeerRef{{Exchange: "ix-lab", Peer: "ix-peer-a"}},
		}}}
	}})
	viewer := plugin.RoleViewer
	rec, _ := e.do(t, "GET", "/providers.html", viewer, nil)
	page := rec.Body.String()
	for _, want := range []string{`id="offload"`, `id="offload-note"`, `href="/api/exchanges/offload?format=csv"`, `<script src="/exchanges.js">`} {
		if !strings.Contains(page, want) {
			t.Errorf("providers.html missing %q", want)
		}
	}
	rec, _ = e.do(t, "GET", "/api/exchanges/offload?limit=50", viewer, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"transit":"transit-a"`) || !strings.Contains(rec.Body.String(), `"est_savings":160`) {
		t.Errorf("viewer offload JSON = %d %s", rec.Code, rec.Body.String())
	}
	rec, _ = e.do(t, "GET", "/api/exchanges/offload?format=csv", viewer, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "198.51.100.0/24,100000000,80.00,transit-a,ix-lab/ix-peer-a,160.00") {
		t.Errorf("viewer offload CSV = %d %s", rec.Code, rec.Body.String())
	}
}
