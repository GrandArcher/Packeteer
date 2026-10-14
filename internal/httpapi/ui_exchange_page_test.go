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
	rec, _ := e.do(t, "GET", "/exchanges.js", viewer, nil)
	js := rec.Body.String()
	for _, want := range []string{`getJSON("/api/exchanges")`, `"/api/reports/exchanges?days="`} {
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
		if rec, _ := e.do(t, method, "/api/exchanges", plugin.RoleAdmin, nil); rec.Code == http.StatusOK {
			t.Errorf("%s /api/exchanges = %d, want a refusal", method, rec.Code)
		}
	}
}
