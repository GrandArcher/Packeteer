package httpapi

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/pbr"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakePBR struct {
	preview    pbr.Preview
	previewErr error
	applyErr   error
	applied    []string
}

func (f *fakePBR) Preview(context.Context) (pbr.Preview, error) { return f.preview, f.previewErr }
func (f *fakePBR) Apply(_ context.Context, tok string) (pbr.Result, error) {
	f.applied = append(f.applied, tok)
	if f.applyErr != nil {
		return pbr.Result{}, f.applyErr
	}
	return pbr.Result{Applied: 1, Verified: true, Paths: []pbr.Path{{Provider: "transit-a", OK: true}}}, nil
}

func newPBRUI(t *testing.T, f *fakePBR) *uiEnv {
	t.Helper()
	e := newUI(t)
	e.srv.SetPolicyRouting(f)
	return e
}

func TestPolicyRoutingNeedsAdmin(t *testing.T) {
	f := &fakePBR{preview: pbr.Preview{Token: "t1"}}
	e := newPBRUI(t, f)
	for _, r := range []plugin.Role{plugin.RoleViewer, plugin.RoleOperator} {
		if rec, _ := e.do(t, "GET", "/api/pbr", r, nil); rec.Code != http.StatusForbidden {
			t.Fatalf("%s preview: %d", r, rec.Code)
		}
		if rec, _ := e.do(t, "POST", "/api/pbr/apply", r, map[string]any{"confirm": true, "token": "t1"}); rec.Code != http.StatusForbidden {
			t.Fatalf("%s apply: %d", r, rec.Code)
		}
	}
	if len(f.applied) != 0 {
		t.Fatalf("a refused request applied: %v", f.applied)
	}
}

func TestPolicyRoutingOffWithoutManager(t *testing.T) {
	e := newUI(t)
	if rec, _ := e.do(t, "GET", "/api/pbr", plugin.RoleAdmin, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("preview: %d", rec.Code)
	}
	if rec, _ := e.do(t, "POST", "/api/pbr/apply", plugin.RoleAdmin, map[string]any{"confirm": true, "token": "t1"}); rec.Code != http.StatusNotFound {
		t.Fatalf("apply: %d", rec.Code)
	}
}

// The preview runs nothing that changes the host: it never calls Apply.
func TestPolicyRoutingPreviewDoesNotApply(t *testing.T) {
	f := &fakePBR{preview: pbr.Preview{Token: "t1", Lines: []pbr.Line{{Command: "ip rule add from 192.0.2.11 lookup 1001 priority 2001"}}}}
	e := newPBRUI(t, f)
	rec, got := e.do(t, "GET", "/api/pbr", plugin.RoleAdmin, nil)
	if rec.Code != http.StatusOK || got["token"] != "t1" || len(got["lines"].([]any)) != 1 || len(f.applied) != 0 {
		t.Fatalf("preview: %d %s applied=%v", rec.Code, rec.Body, f.applied)
	}
	f.previewErr = errors.New("no provider is measured from this instance")
	rec, got = e.do(t, "GET", "/api/pbr", plugin.RoleAdmin, nil)
	if rec.Code != http.StatusUnprocessableEntity || got["error"] == nil {
		t.Fatalf("preview error: %d %s", rec.Code, rec.Body)
	}
}

// Nothing runs without an explicit confirm and the token of the shown plan.
func TestPolicyRoutingApplyNeedsConfirm(t *testing.T) {
	f := &fakePBR{}
	e := newPBRUI(t, f)
	for _, body := range []any{"{}", map[string]any{"token": "t1"}, map[string]any{"confirm": true}, map[string]any{"confirm": false, "token": "t1"}} {
		if rec, _ := e.do(t, "POST", "/api/pbr/apply", plugin.RoleAdmin, body); rec.Code != http.StatusBadRequest {
			t.Fatalf("body %v: %d %s", body, rec.Code, rec.Body)
		}
	}
	if len(f.applied) != 0 {
		t.Fatalf("applied without a confirm: %v", f.applied)
	}
	rec, got := e.do(t, "POST", "/api/pbr/apply", plugin.RoleAdmin, map[string]any{"confirm": true, "token": "t1"})
	if rec.Code != http.StatusOK || got["verified"] != true || len(f.applied) != 1 || f.applied[0] != "t1" {
		t.Fatalf("apply: %d %s %v", rec.Code, rec.Body, f.applied)
	}
	found := false
	for _, r := range e.store.Records() {
		if r.Target == "pbr" && r.Detail == "applied 1 commands, verified=true" {
			found = true
		}
	}
	if !found {
		t.Fatal("the apply was not audited")
	}
}

func TestPolicyRoutingApplyPlanChangedAndFailure(t *testing.T) {
	f := &fakePBR{applyErr: pbr.ErrPlanChanged}
	e := newPBRUI(t, f)
	rec, got := e.do(t, "POST", "/api/pbr/apply", plugin.RoleAdmin, map[string]any{"confirm": true, "token": "old"})
	if rec.Code != http.StatusConflict || got["code"] != "plan_changed" {
		t.Fatalf("changed plan: %d %s", rec.Code, rec.Body)
	}
	f.applyErr = errors.New("ip rule add: RTNETLINK answers: Operation not permitted")
	rec, got = e.do(t, "POST", "/api/pbr/apply", plugin.RoleAdmin, map[string]any{"confirm": true, "token": "t1"})
	if rec.Code != http.StatusInternalServerError || got["error"] == nil {
		t.Fatalf("failed apply: %d %s", rec.Code, rec.Body)
	}
}
