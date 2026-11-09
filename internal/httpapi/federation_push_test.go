package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/auth/authtest"
	"github.com/GrandArcher/Packeteer/internal/federation"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TestFederationPushIsAdminOnly: a settings push (#137) needs the admin
// role, reaches the pusher only with the sections and peers asked for, and
// is audited with each peer's answer. Without a pusher it is not found.
func TestFederationPushIsAdminOnly(t *testing.T) {
	store := authtest.New()
	svc, err := auth.New(auth.Options{Users: store})
	if err != nil {
		t.Fatal(err)
	}
	type call struct{ sections, peers []string }
	var calls []call
	push := func(_ context.Context, sections, peers []string) (federation.PushReport, error) {
		calls = append(calls, call{sections, peers})
		if sections[0] == "mode" {
			return federation.PushReport{}, errors.New(`section "mode" cannot be pushed`)
		}
		return federation.NewPushReport(sections, []federation.PeerPush{
			{Peer: "pop-b", Status: plugin.SettingsApplied, Applied: []string{"thresholds"}},
			{Peer: "pop-c", Status: plugin.SettingsRefused, Errors: []string{"bad"}},
		}), nil
	}
	srv, err := New(Options{
		Auth: svc, Audit: auth.NewAuditor(store, nil, nil), FederationPush: push,
		Snapshot: func() Snapshot { return Assemble(sampleInput()) },
	})
	if err != nil {
		t.Fatal(err)
	}
	e := &rbacEnv{h: srv.Handler(), tokens: map[plugin.Role]string{}}
	for _, r := range []plugin.Role{plugin.RoleViewer, plugin.RoleOperator, plugin.RoleAdmin} {
		name := string(r) + "-user"
		if _, err := svc.CreateUser(context.Background(), name, r, name+"-password"); err != nil {
			t.Fatal(err)
		}
		_, tok, err := svc.CreateToken(context.Background(), auth.Principal{User: name, Role: r, Method: auth.MethodPassword}, "t", r, 0)
		if err != nil {
			t.Fatal(err)
		}
		e.tokens[r] = tok
	}

	body := `{"sections":["thresholds"],"peers":["pop-b"]}`
	for _, r := range []plugin.Role{plugin.RoleViewer, plugin.RoleOperator} {
		if rec := e.do(http.MethodPost, "/api/federation/push", e.tokens[r], body); rec.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", r, rec.Code)
		}
	}
	if len(calls) != 0 {
		t.Fatalf("pusher ran for a role below admin: %+v", calls)
	}
	rec := e.do(http.MethodPost, "/api/federation/push", e.tokens[plugin.RoleAdmin], body)
	var rep federation.PushReport
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &rep) != nil || rep.OK || len(rep.Peers) != 2 || rep.Peers[1].Status != plugin.SettingsRefused {
		t.Fatalf("admin push: %d %s", rec.Code, rec.Body)
	}
	if len(calls) != 1 || calls[0].sections[0] != "thresholds" || len(calls[0].peers) != 1 || calls[0].peers[0] != "pop-b" {
		t.Fatalf("pusher calls = %+v", calls)
	}
	recs, _ := store.Audit(context.Background(), plugin.AuditQuery{})
	found := false
	for _, r := range recs {
		found = found || (r.Actor == "admin-user" && r.Target == "federation" && strings.Contains(r.Detail, "pop-b=applied pop-c=refused"))
	}
	if !found {
		t.Fatalf("audit = %+v", recs)
	}

	if rec := e.do(http.MethodPost, "/api/federation/push", e.tokens[plugin.RoleAdmin], `{"sections":["mode"]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("mode: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do(http.MethodPost, "/api/federation/push", e.tokens[plugin.RoleAdmin], `{"sections":["thresholds"],"extra":1}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", rec.Code)
	}

	// The central view says whether the dashboard may offer the push.
	rec = e.do(http.MethodGet, "/api/federation", e.tokens[plugin.RoleViewer], "")
	var view struct {
		PushEnabled bool `json:"push_enabled"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &view) != nil || !view.PushEnabled {
		t.Fatalf("push_enabled: %s", rec.Body)
	}

	none, err := New(Options{Auth: svc, Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if err != nil {
		t.Fatal(err)
	}
	e.h = none.Handler()
	if rec := e.do(http.MethodPost, "/api/federation/push", e.tokens[plugin.RoleAdmin], body); rec.Code != http.StatusNotFound {
		t.Fatalf("no pusher: %d", rec.Code)
	}
	rec = e.do(http.MethodGet, "/api/federation", e.tokens[plugin.RoleViewer], "")
	if json.Unmarshal(rec.Body.Bytes(), &view) != nil || view.PushEnabled {
		t.Fatalf("push_enabled without a pusher: %s", rec.Body)
	}
}
