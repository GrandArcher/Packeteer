package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/registry"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type pdbStub struct {
	plugin.Base
	pushed []plugin.RegistryChange
	err    error
}

func (p *pdbStub) Check(context.Context, plugin.RegistryFacts) ([]plugin.RegistryFinding, error) {
	return []plugin.RegistryFinding{
		{Kind: "pdb_maxprefix", Severity: plugin.RegistryWarning, Registry: "peeringdb", Subject: "AS64496 info_prefixes4", Message: "low",
			Diff:   "net 42\n- info_prefixes4: 1\n+ info_prefixes4: 4",
			Change: &plugin.RegistryChange{Registry: "peeringdb", Op: "update_field", Class: "net", Key: "42", Field: "info_prefixes4", Old: "1", New: "4"}},
		{Kind: "pdb_facility_missing", Severity: plugin.RegistryWarning, Registry: "peeringdb", Subject: "AS64496 facilities", Message: "none"},
	}, nil
}

func (p *pdbStub) Push(_ context.Context, c plugin.RegistryChange) error {
	if p.err != nil {
		return p.err
	}
	p.pushed = append(p.pushed, c)
	return nil
}

func registryEnv(t *testing.T, pushEnabled bool) (*rbacEnv, *pdbStub, registry.Report) {
	t.Helper()
	stub := &pdbStub{}
	svc := registry.New(registry.Config{ASNs: []uint32{64496}, PushEnabled: pushEnabled}, registry.Deps{
		Observe:  func() registry.Observed { return registry.Observed{} },
		Checkers: []registry.Checker{{Name: "peeringdb", Type: "peeringdb", Plugin: stub}},
	})
	svc.Scan(context.Background())
	e := newRBAC(t, nil)
	e.srv.SetRegistry(svc)
	return e, stub, svc.Report()
}

func findingOf(t *testing.T, r registry.Report, kind string) registry.Finding {
	t.Helper()
	for _, f := range r.Findings {
		if f.Kind == kind {
			return f
		}
	}
	t.Fatalf("no %s finding in %+v", kind, r.Findings)
	return registry.Finding{}
}

func jsonOf(t *testing.T, rec interface{ Bytes() []byte }, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Bytes(), v); err != nil {
		t.Fatalf("%v: %s", err, rec.Bytes())
	}
}

// #289: /api/registry is off by default, and with a scan it lists each
// finding with its diff; only a finding with a change carries a digest.
func TestRegistryReport(t *testing.T) {
	off := newRBAC(t, nil)
	rec := off.do("GET", "/api/registry", off.tokens[plugin.RoleViewer], "")
	var body struct {
		Enabled  bool `json:"enabled"`
		Writable bool `json:"writable"`
		Findings []struct {
			ID       string `json:"id"`
			Kind     string `json:"kind"`
			Diff     string `json:"diff"`
			Pushable bool   `json:"pushable"`
			Digest   string `json:"digest"`
		} `json:"findings"`
	}
	jsonOf(t, rec.Body, &body)
	if rec.Code != 200 || body.Enabled || body.Writable || body.Findings == nil || len(body.Findings) != 0 {
		t.Fatalf("off: %d %s", rec.Code, rec.Body)
	}

	e, _, _ := registryEnv(t, true)
	rec = e.do("GET", "/api/registry", e.tokens[plugin.RoleViewer], "")
	jsonOf(t, rec.Body, &body)
	if !body.Enabled || !body.Writable || len(body.Findings) != 2 {
		t.Fatalf("on: %s", rec.Body)
	}
	f := body.Findings[1]
	if f.Kind != "pdb_maxprefix" || !f.Pushable || f.Digest == "" || !strings.Contains(f.Diff, "+ info_prefixes4: 4") {
		t.Fatalf("finding = %+v", f)
	}
	if g := body.Findings[0]; g.Kind != "pdb_facility_missing" || g.Pushable || g.Digest != "" {
		t.Fatalf("suggest-only finding = %+v", g)
	}

	e, _, _ = registryEnv(t, false)
	rec = e.do("GET", "/api/registry", e.tokens[plugin.RoleViewer], "")
	jsonOf(t, rec.Body, &body)
	if !body.Enabled || body.Writable || body.Findings[1].Pushable {
		t.Fatalf("push off: %s", rec.Body)
	}
}

// #289: a push is admin only, needs the digest of the shown diff, reaches
// the plugin with exactly that change, and every outcome is audited with
// the change.
func TestRegistryPush(t *testing.T) {
	e, stub, rep := registryEnv(t, true)
	f := findingOf(t, rep, "pdb_maxprefix")
	push := func(token, id, digest string) (int, plugin.AuditRecord) {
		t.Helper()
		rec := e.do("POST", "/api/registry/push", token, `{"id":"`+id+`","digest":"`+digest+`"}`)
		recs := e.store.Records()
		return rec.Code, recs[len(recs)-1]
	}

	if code, a := push(e.tokens[plugin.RoleOperator], f.ID, f.Digest); code != http.StatusForbidden || a.Result != "denied" || len(stub.pushed) != 0 {
		t.Fatalf("operator: %d %+v pushed %v", code, a, stub.pushed)
	}
	if code, a := push(e.tokens[plugin.RoleAdmin], f.ID, "0000"); code != http.StatusConflict || !strings.Contains(a.Detail, "differs from the one shown") || len(stub.pushed) != 0 {
		t.Fatalf("wrong digest: %d %+v pushed %v", code, a, stub.pushed)
	}
	if code, _ := push(e.tokens[plugin.RoleAdmin], "nope", f.Digest); code != http.StatusNotFound {
		t.Fatalf("unknown finding: %d", code)
	}
	if code, _ := push(e.tokens[plugin.RoleAdmin], findingOf(t, rep, "pdb_facility_missing").ID, ""); code != http.StatusConflict {
		t.Fatalf("suggest-only finding: %d", code)
	}
	if rec := e.do("POST", "/api/registry/push", e.tokens[plugin.RoleAdmin], `{"id":"x","digest":"y","force":true}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", rec.Code)
	}
	if len(stub.pushed) != 0 {
		t.Fatalf("pushed before a valid confirm: %v", stub.pushed)
	}

	code, a := push(e.tokens[plugin.RoleAdmin], f.ID, f.Digest)
	if code != http.StatusOK || len(stub.pushed) != 1 || stub.pushed[0] != *f.Change {
		t.Fatalf("push: %d, plugin got %v", code, stub.pushed)
	}
	if a.Actor != "admin-user" || a.Result != "ok" || a.Target != "peeringdb net 42" || a.Detail != "registry push update_field info_prefixes4: 1 -> 4" {
		t.Fatalf("audit = %+v", a)
	}
	if code, _ = push(e.tokens[plugin.RoleAdmin], f.ID, f.Digest); code != http.StatusConflict || len(stub.pushed) != 1 {
		t.Fatalf("second push: %d, pushed %d", code, len(stub.pushed))
	}
}

// #289: push off refuses, and a registry error is a bad gateway that is
// audited and leaves the finding open.
func TestRegistryPushOffAndFailure(t *testing.T) {
	e, stub, rep := registryEnv(t, false)
	rec := e.do("POST", "/api/registry/push", e.tokens[plugin.RoleAdmin], `{"id":"`+findingOf(t, rep, "pdb_maxprefix").ID+`","digest":""}`)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "push_enabled is off") || len(stub.pushed) != 0 {
		t.Fatalf("push off: %d %s", rec.Code, rec.Body)
	}

	e, stub, rep = registryEnv(t, true)
	stub.err = context.DeadlineExceeded
	f := findingOf(t, rep, "pdb_maxprefix")
	rec = e.do("POST", "/api/registry/push", e.tokens[plugin.RoleAdmin], `{"id":"`+f.ID+`","digest":"`+f.Digest+`"}`)
	recs := e.store.Records()
	if rec.Code != http.StatusBadGateway || !strings.Contains(recs[len(recs)-1].Detail, "registry push refused or failed") {
		t.Fatalf("failure: %d %s audit %+v", rec.Code, rec.Body, recs[len(recs)-1])
	}
	if p := e.srv.registryControl().Report().Findings[1].Pushed; p != nil {
		t.Fatal("a failed push is shown as done")
	}

	e, stub, rep = registryEnv(t, true)
	stub.err = plugin.ErrRegistryNoPush
	f = findingOf(t, rep, "pdb_maxprefix")
	rec = e.do("POST", "/api/registry/push", e.tokens[plugin.RoleAdmin], `{"id":"`+f.ID+`","digest":"`+f.Digest+`"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("a change the plugin does not apply: %d %s", rec.Code, rec.Body)
	}

	none := newRBAC(t, nil)
	if rec := none.do("POST", "/api/registry/push", none.tokens[plugin.RoleAdmin], `{"id":"a","digest":"b"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("no registry: %d", rec.Code)
	}
}

// #289: the audit text of an object push holds the RPSL, so a delete can be
// undone from the log.
func TestPushDetailHoldsObject(t *testing.T) {
	ch := plugin.RegistryChange{Registry: "ripe", Op: "delete_object", Class: "route", Key: "192.0.2.0/24AS64496",
		Object: "route:          192.0.2.0/24\norigin:         AS64496\nsource:         RIPE\n"}
	want := "registry push delete_object: route:          192.0.2.0/24; origin:         AS64496; source:         RIPE"
	if got := pushDetail(ch); got != want {
		t.Fatalf("detail = %q, want %q", got, want)
	}
}
