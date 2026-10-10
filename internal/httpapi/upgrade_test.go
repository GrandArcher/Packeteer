package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/auth/authtest"
	"github.com/GrandArcher/Packeteer/internal/upgrade"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakeUpgrade struct {
	checks, applies, rollbacks int
	err                        error
	last                       upgrade.Request
	status                     upgrade.Status
}

func (f *fakeUpgrade) Status() upgrade.Status { return f.status }
func (f *fakeUpgrade) Check(context.Context) (upgrade.Status, error) {
	f.checks++
	return f.status, f.err
}
func (f *fakeUpgrade) Apply(_ context.Context, r upgrade.Request) (upgrade.Result, error) {
	f.applies++
	f.last = r
	return upgrade.Result{From: "0.5.0", To: "0.6.0", Message: "Upgrading"}, f.err
}
func (f *fakeUpgrade) Rollback(_ context.Context, r upgrade.Request) (upgrade.Result, error) {
	f.rollbacks++
	f.last = r
	return upgrade.Result{From: "0.6.0", To: "0.5.0", Message: "Rolling back"}, f.err
}

func upgradeEnv(t *testing.T, up UpgradeControl) *rbacEnv {
	t.Helper()
	e := &rbacEnv{store: authtest.New(), tokens: map[plugin.Role]string{}}
	svc, err := auth.New(auth.Options{Users: e.store})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Auth: svc, Audit: auth.NewAuditor(e.store, nil, nil), Upgrade: up,
		Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if err != nil {
		t.Fatal(err)
	}
	e.svc, e.srv, e.h = svc, srv, srv.Handler()
	for _, r := range []plugin.Role{plugin.RoleViewer, plugin.RoleOperator, plugin.RoleAdmin} {
		name := string(r) + "-user"
		if _, err := svc.CreateUser(context.Background(), name, r, name+"-password"); err != nil {
			t.Fatal(err)
		}
		_, tok, err := svc.CreateToken(context.Background(), auth.Principal{User: name, Role: r, Method: auth.MethodPassword}, "test", r, 0)
		if err != nil {
			t.Fatal(err)
		}
		e.tokens[r] = tok
	}
	return e
}

func TestUpgradeAPIDisabled(t *testing.T) {
	e := upgradeEnv(t, nil)
	rec := e.do("GET", "/api/upgrade", e.tokens[plugin.RoleAdmin], "")
	var st struct {
		Enabled  bool
		Version  string
		Install  string
		Releases []any
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &st) != nil || st.Enabled || st.Version == "" || st.Install == "" || st.Releases == nil {
		t.Fatalf("status: %d %s", rec.Code, rec.Body)
	}
	for _, p := range []string{"check", "apply", "rollback"} {
		rec := e.do("POST", "/api/upgrade/"+p, e.tokens[plugin.RoleAdmin], `{"confirm":true,"tag":"v0.6.0"}`)
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "upgrade.enabled") {
			t.Fatalf("%s: %d %s", p, rec.Code, rec.Body)
		}
	}
}

func TestUpgradeAPIAdminOnlyAndAudited(t *testing.T) {
	f := &fakeUpgrade{status: upgrade.Status{Enabled: true, Version: "0.5.0", Releases: []upgrade.ReleaseInfo{}}}
	e := upgradeEnv(t, f)
	for _, role := range []plugin.Role{plugin.RoleViewer, plugin.RoleOperator} {
		for _, p := range []string{"check", "apply", "rollback"} {
			rec := e.do("POST", "/api/upgrade/"+p, e.tokens[role], `{"confirm":true,"tag":"v0.6.0"}`)
			if !needsRole(rec) {
				t.Fatalf("%s %s: %d %s", role, p, rec.Code, rec.Body)
			}
		}
		if rec := e.do("GET", "/api/upgrade", e.tokens[role], ""); !needsRole(rec) {
			t.Fatalf("%s GET: %d", role, rec.Code)
		}
	}
	if f.checks+f.applies+f.rollbacks != 0 {
		t.Fatal("a refused role reached the manager")
	}
	admin := e.tokens[plugin.RoleAdmin]
	if rec := e.do("POST", "/api/upgrade/check", admin, `{}`); rec.Code != 200 {
		t.Fatalf("check: %d %s", rec.Code, rec.Body)
	}
	rec := e.do("POST", "/api/upgrade/apply", admin, `{"tag":"v0.6.0","confirm":true,"standby_upgraded":true}`)
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"to":"0.6.0"`) {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body)
	}
	if f.last.Tag != "v0.6.0" || !f.last.Confirm || !f.last.StandbyUpgraded {
		t.Fatalf("request = %+v", f.last)
	}
	if rec := e.do("POST", "/api/upgrade/rollback", admin, `{"confirm":true}`); rec.Code != http.StatusAccepted {
		t.Fatalf("rollback: %d %s", rec.Code, rec.Body)
	}
	// Unknown fields and non-JSON are refused before the manager.
	if rec := e.do("POST", "/api/upgrade/apply", admin, `{"tag":"v0.6.0","confirm":true,"force":true}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", rec.Code)
	}
	req := httptest.NewRequest("POST", "/api/upgrade/apply", strings.NewReader("tag=v0.6.0"))
	req.Header.Set("Authorization", "Bearer "+admin)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	if w.Code != http.StatusUnsupportedMediaType || f.applies != 1 {
		t.Fatalf("form post: %d applies=%d", w.Code, f.applies)
	}

	// One audit record per check, upgrade, and rollback, with the user.
	var got []string
	for _, r := range e.store.Records() {
		if strings.HasPrefix(r.Action, "POST /api/upgrade/") && r.Result == auth.ResultOK {
			got = append(got, fmt.Sprintf("%s|%s|%s|%s", r.Actor, r.Action, r.Target, r.Detail))
		}
	}
	want := []string{
		"admin-user|POST /api/upgrade/check|releases|check: no newer release",
		"admin-user|POST /api/upgrade/apply|v0.6.0|upgrade from=0.5.0 to=v0.6.0 standby_upgraded=true",
		"admin-user|POST /api/upgrade/rollback||rollback from=0.5.0 to=",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("audit:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestUpgradeAPIErrors(t *testing.T) {
	f := &fakeUpgrade{status: upgrade.Status{Enabled: true, Version: "0.5.0"}}
	e := upgradeEnv(t, f)
	admin := e.tokens[plugin.RoleAdmin]
	for _, tc := range []struct {
		err  error
		code int
	}{
		{upgrade.ErrNoConfirm, 400},
		{upgrade.ErrNotFound, 404},
		{fmt.Errorf("%w: signature does not match", upgrade.ErrVerify), 422},
		{upgrade.ErrTrial, 422},
		{upgrade.ErrNotInstall, 422},
		{upgrade.ErrHA, 409},
		{upgrade.ErrBusy, 409},
		{upgrade.ErrFetch, 502},
		{errors.New("open /var/lib/packeteer/upgrade/state.json: permission denied"), 500},
	} {
		f.err = tc.err
		rec := e.do("POST", "/api/upgrade/apply", admin, `{"tag":"v0.6.0","confirm":true}`)
		if rec.Code != tc.code {
			t.Errorf("%v: %d, want %d", tc.err, rec.Code, tc.code)
		}
		if tc.code == 500 && strings.Contains(rec.Body.String(), "state.json") {
			t.Errorf("internal error leaked: %s", rec.Body)
		}
	}
	// A refused upgrade is a failed audit record.
	last := e.store.Records()[len(e.store.Records())-1]
	if last.Result != auth.ResultFailed || last.Status != 500 {
		t.Fatalf("audit = %+v", last)
	}
}

func TestUpgradeAPINeedsAuthToWrite(t *testing.T) {
	f := &fakeUpgrade{}
	srv, err := New(Options{Upgrade: f, Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/upgrade/apply", strings.NewReader(`{"tag":"v0.6.0","confirm":true}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || f.applies != 0 {
		t.Fatalf("no auth: %d applies=%d", w.Code, f.applies)
	}
}
