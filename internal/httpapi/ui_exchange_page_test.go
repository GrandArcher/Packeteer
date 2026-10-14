package httpapi

import (
	"net/http"
	"strings"
	"testing"

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
	rec, _ := e.do(t, "GET", "/exchanges.js", viewer, nil)
	js := rec.Body.String()
	for _, want := range []string{`getJSON("/api/exchanges")`, `"/api/reports/exchanges?days="`, `p.reach`, `data-degraded`, `"/api/exchanges/member?exchange="`} {
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
		for _, path := range []string{"/api/exchanges", "/api/exchanges/member"} {
			if rec, _ := e.do(t, method, path, plugin.RoleAdmin, nil); rec.Code == http.StatusOK {
				t.Errorf("%s %s = %d, want a refusal", method, path, rec.Code)
			}
		}
	}
}
