package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TestUsersTokensAudit covers the #32 tables, including a restart on the
// same file and prune by retention.
func TestUsersTokensAudit(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "p.db")
	s := newStore(t, "path: "+path)
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	u := plugin.User{Name: "noc", Role: plugin.RoleOperator, Source: plugin.UserLocal, PasswordHash: "h", Created: now, Updated: now}
	if err := s.PutUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := s.PutUser(ctx, plugin.User{Name: "sso@example.net", Role: plugin.RoleViewer, Source: plugin.UserSSO, Disabled: true, Created: now, Updated: now}); err != nil {
		t.Fatal(err)
	}
	tok := plugin.APIToken{ID: "0123456789abcdef", User: "noc", Name: "grafana", Role: plugin.RoleViewer, Hash: "x", Created: now, Expires: now.Add(time.Hour)}
	if err := s.PutToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	for i, at := range []time.Time{now.Add(-500 * 24 * time.Hour), now, now.Add(time.Minute)} {
		if err := s.AppendAudit(ctx, plugin.AuditRecord{ID: string(rune('a' + i)), Time: at, Actor: "noc", Role: plugin.RoleOperator,
			Method: "password", Action: "POST /api/maintenance", Result: "ok", Status: 201}); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.Stop(ctx)

	s = newStore(t, "path: "+path)
	s.now = func() time.Time { return now }
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	got, ok, err := s.User(ctx, "noc")
	if err != nil || !ok || got != u {
		t.Fatalf("user after restart: %+v %v %v", got, ok, err)
	}
	us, _ := s.Users(ctx)
	if len(us) != 2 || !us[1].Disabled || us[1].Source != plugin.UserSSO {
		t.Fatalf("users: %+v", us)
	}
	gt, ok, err := s.Token(ctx, tok.ID)
	if err != nil || !ok || gt != tok {
		t.Fatalf("token: %+v %v %v", gt, ok, err)
	}
	if _, ok, _ := s.Token(ctx, "ffffffffffffffff"); ok {
		t.Fatal("unknown token found")
	}
	// Retention pruned the old audit record on start; newest first.
	recs, err := s.Audit(ctx, plugin.AuditQuery{})
	if err != nil || len(recs) != 2 || recs[0].ID != "c" || recs[1].Status != 201 || recs[1].Role != plugin.RoleOperator {
		t.Fatalf("audit: %+v %v", recs, err)
	}
	if recs, _ := s.Audit(ctx, plugin.AuditQuery{Limit: 1}); len(recs) != 1 || recs[0].ID != "c" {
		t.Fatalf("limit: %+v", recs)
	}
	if recs, _ := s.Audit(ctx, plugin.AuditQuery{To: now.Add(time.Second)}); len(recs) != 1 || recs[0].ID != "b" {
		t.Fatalf("to: %+v", recs)
	}
	// Deleting a user deletes its tokens.
	if ok, err := s.DeleteUser(ctx, "noc"); !ok || err != nil {
		t.Fatalf("delete: %v %v", ok, err)
	}
	if ts, _ := s.Tokens(ctx); len(ts) != 0 {
		t.Fatalf("tokens left: %+v", ts)
	}
	if ok, _ := s.DeleteToken(ctx, tok.ID); ok {
		t.Fatal("deleted twice")
	}
}

// TestUserMustChangeAndMigration keeps must_change across a restart and adds
// the column to a users table created before #328 (#328).
func TestUserMustChangeAndMigration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "p.db")
	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`CREATE TABLE users (name TEXT PRIMARY KEY, role TEXT NOT NULL, source TEXT NOT NULL, password_hash TEXT NOT NULL,
		disabled INTEGER NOT NULL, created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL);
		INSERT INTO users VALUES ('legacy', 'admin', 'local', 'h', 0, 1, 1)`); err != nil {
		t.Fatal(err)
	}
	_ = old.Close()

	s := newStore(t, "path: "+path)
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.User(ctx, "legacy")
	if err != nil || !ok || got.MustChange {
		t.Fatalf("legacy user: %+v %v %v", got, ok, err)
	}
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	if err := s.PutUser(ctx, plugin.User{Name: "admin", Role: plugin.RoleAdmin, Source: plugin.UserLocal, PasswordHash: "h", MustChange: true, Created: now, Updated: now}); err != nil {
		t.Fatal(err)
	}
	_ = s.Stop(ctx)

	s = newStore(t, "path: "+path)
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	if got, _, _ := s.User(ctx, "admin"); !got.MustChange {
		t.Fatalf("must_change lost across a restart: %+v", got)
	}
}
