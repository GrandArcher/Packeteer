package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/troubleshoot"
)

// TestTraceAnswerOriginAS checks the traceroute answer carries each hop's
// origin AS from the learned RIB (#180) and nothing for a hop the RIB does
// not cover. The rendered tables are covered by the UI smoke test in CI.
func TestTraceAnswerOriginAS(t *testing.T) {
	h, _ := toolServer(t, true, nil)
	rec := mdo(h, "POST", "/api/troubleshoot/traceroute", "application/json", `{"target":"198.51.100.5","provider":"transit-a"}`, false)
	var ans troubleshoot.TraceAnswer
	if err := json.Unmarshal(rec.Body.Bytes(), &ans); err != nil || rec.Code != 200 || len(ans.Traces) != 1 || len(ans.Traces[0].Hops) != 2 {
		t.Fatalf("trace: %d %s", rec.Code, rec.Body)
	}
	hops := ans.Traces[0].Hops
	if hops[0].OriginAS != 0 || hops[1].OriginAS != 64496 || !hops[1].Reached {
		t.Fatalf("origin AS: %+v", hops)
	}
	if strings.Contains(rec.Body.String(), `"name"`) {
		t.Fatalf("a reverse name appeared with no resolver: %s", rec.Body)
	}
}

// TestTroubleshootingPageAssets checks the wiring of the results view
// (#180): tools.js is served, reads only the endpoints the page always
// used, draws with textContent (no markup built from an answer), keeps a
// raw JSON view, and stacks results with rerun and remove.
func TestTroubleshootingPageAssets(t *testing.T) {
	e := newUI(t)
	rec, _ := e.do(t, "GET", "/tools.js", "viewer", nil)
	if rec.Code != 200 {
		t.Fatalf("/tools.js: %d", rec.Code)
	}
	js := rec.Body.String()
	for _, s := range []string{
		`"/api/troubleshoot/lookingglass?prefix="`,
		`"/api/troubleshoot/traceroute"`,
		`"/api/troubleshoot/probe"`,
		`"/api/troubleshoot/optimize"`,
		`"Probe and optimize"`,
		`" resolved to "`,
		`". The best measured exit is "`,
		`"indirect: nothing in the target answered`,
		`"/api/troubleshoot/whois"`,
		`"Learned paths for "`,
		`sameRoute(r, g.exact) ? "selected" : "inactive"`,
		`"Display only. MED does not choose the exit."`,
		`"hop-diagram"`,
		`"Origin AS"`,
		`"Reverse name"`,
		`"Raw JSON"`,
		`toolStack.unshift(e)`,
		`"Rerun"`,
		`"Remove"`,
		`TOOL_STACK_MAX`,
	} {
		if !strings.Contains(js, s) {
			t.Errorf("tools.js missing %s", s)
		}
	}
	for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "http://", "https://", "localStorage", "sessionStorage", `"PUT"`, `"DELETE"`} {
		if strings.Contains(js, bad) {
			t.Errorf("tools.js contains %s", bad)
		}
	}
	if app := mustWeb(t, "web/app.js"); strings.Contains(app, "function runTool") || strings.Contains(app, "tool-out") {
		t.Error("app.js still has the raw JSON tool runner")
	}
}
