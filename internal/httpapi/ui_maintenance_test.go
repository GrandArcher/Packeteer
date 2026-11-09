package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/plugins/policy/maintenance"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// realMaint serves the API from the real maintenance policy, so the page's
// calls meet its limits and its effect on Decide.
type realMaint struct{ *maintenance.Policy }

func (realMaint) CanOpen() bool { return true }

func newRealMaint(t *testing.T) realMaint {
	t.Helper()
	cfg, err := plugin.ConfigFromYAML(`
windows:
  - {name: past, providers: [transit-a], start: "2020-01-01T00:00:00Z", end: "2020-01-01T01:00:00Z"}
  - {name: far, providers: [transit-b], start: "2099-01-01T00:00:00Z", end: "2099-01-01T01:00:00Z"}
`)
	if err != nil {
		t.Fatal(err)
	}
	p, err := maintenance.New(cfg, plugin.Env{Providers: []string{"transit-a", "transit-b"}})
	if err != nil {
		t.Fatal(err)
	}
	return realMaint{p.(*maintenance.Policy)}
}

// The Policies page opens a window from RFC 3339 start and end, lists it
// as current, upcoming, or finished, and closes it. A viewer reads the
// list and cannot change it; each change is audited and the policy's own
// Active decides what is excluded.
func TestMaintenancePageRoles(t *testing.T) {
	e := newRBAC(t, nil)
	rm := newRealMaint(t)
	e.srv.maint = rm
	viewer, op := e.tokens[plugin.RoleViewer], e.tokens[plugin.RoleOperator]

	page := mustWeb(t, "web/policies.html")
	for _, w := range []string{`id="maint-form"`, `id="mw-providers"`, `id="mw-start" type="datetime-local"`, `id="mw-end" type="datetime-local"`, `id="mw-note"`, `id="maint-list"`, `src="/maintenance.js"`} {
		if !strings.Contains(page, w) {
			t.Errorf("policies.html missing %q", w)
		}
	}
	js := mustWeb(t, "web/maintenance.js")
	for _, w := range []string{`"/api/maintenance"`, `toISOString()`, `"DELETE"`, `maintMe.role === "operator"`} {
		if !strings.Contains(js, w) {
			t.Errorf("maintenance.js missing %q", w)
		}
	}

	now := time.Now().UTC().Truncate(time.Second)
	body := func(provider string, start, end time.Time) string {
		b, _ := json.Marshal(map[string]any{"providers": []string{provider}, "start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339), "reason": "page"})
		return string(b)
	}
	cur := body("transit-a", now, now.Add(time.Hour))
	next := body("transit-b", now.Add(48*time.Hour), now.Add(50*time.Hour))

	if rec := e.do("POST", "/api/maintenance", viewer, cur); !needsRole(rec) {
		t.Fatalf("viewer open: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("DELETE", "/api/maintenance/api-1", viewer, ""); !needsRole(rec) {
		t.Fatalf("viewer close: %d %s", rec.Code, rec.Body)
	}
	if len(rm.Active(now)) != 0 {
		t.Fatal("a refused viewer open excluded a provider")
	}

	if rec := e.do("POST", "/api/maintenance", op, cur); rec.Code != http.StatusCreated {
		t.Fatalf("operator open: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("POST", "/api/maintenance", op, next); rec.Code != http.StatusCreated {
		t.Fatalf("operator open ahead: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("POST", "/api/maintenance", op, body("transit-a", now, now.Add(10*24*time.Hour))); rec.Code != http.StatusBadRequest {
		t.Fatalf("a window longer than max_api_duration: %d", rec.Code)
	}

	list := func() MaintenanceList {
		rec := e.do("GET", "/api/maintenance", viewer, "")
		var l MaintenanceList
		if err := json.Unmarshal(rec.Body.Bytes(), &l); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("viewer list: %d %s", rec.Code, rec.Body)
		}
		return l
	}
	l := list()
	if !l.OnDemand || len(l.Windows) != 1 || l.Windows[0].ID != "api-1" || l.Windows[0].Reason != "page" ||
		len(l.Upcoming) != 2 || l.Upcoming[0].ID != "api-2" || l.Upcoming[1].ID != "schedule-far" ||
		len(l.Finished) != 1 || l.Finished[0].ID != "schedule-past" {
		t.Fatalf("list = %+v", l)
	}
	// Only the open window excludes a provider; the one ahead does not yet.
	if act := rm.Active(now); len(act) != 1 || strings.Join(act[0].Providers, ",") != "transit-a" {
		t.Fatalf("Active = %+v", act)
	}

	if rec := e.do("DELETE", "/api/maintenance/api-1", op, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("operator close: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("DELETE", "/api/maintenance/schedule-far", op, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("a configured window was closed: %d", rec.Code)
	}
	if l = list(); len(l.Windows) != 0 || len(l.Upcoming) != 2 || len(rm.Active(now)) != 0 {
		t.Fatalf("after close: %+v", l)
	}

	var audit struct{ Records []plugin.AuditRecord }
	rec := e.do("GET", "/api/audit?limit=1000", e.tokens[plugin.RoleAdmin], "")
	_ = json.Unmarshal(rec.Body.Bytes(), &audit)
	var okOpen, denied, closed int
	for _, r := range audit.Records {
		switch {
		case r.Action == "POST /api/maintenance" && r.Result == auth.ResultOK && strings.Contains(r.Detail, "providers=transit-a start="+now.Format(time.RFC3339)):
			okOpen++
		case r.Action == "POST /api/maintenance" && r.Result == auth.ResultDenied && r.Actor == "viewer-user":
			denied++
		case r.Action == "DELETE /api/maintenance/{id}" && r.Result == auth.ResultOK && r.Target == "api-1":
			closed++
		}
	}
	if okOpen != 1 || denied != 1 || closed != 1 {
		t.Fatalf("audit: open %d denied %d closed %d in %+v", okOpen, denied, closed, audit.Records)
	}
}
