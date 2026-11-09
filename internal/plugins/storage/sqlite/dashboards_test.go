package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestDashboards(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "p.db")
	s := newStore(t, "path: "+path)
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for _, d := range []plugin.Dashboard{
		{Owner: "noc", Name: "transit", Spec: []byte(`{"widgets":[]}`), Updated: now},
		{Owner: "noc", Name: "commit", Spec: []byte(`{"widgets":[{"type":"providers"}]}`), Updated: now},
		{Owner: "other", Name: "transit", Spec: []byte(`{}`), Updated: now},
	} {
		if err := s.PutDashboard(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	// Replace in place.
	if err := s.PutDashboard(ctx, plugin.Dashboard{Owner: "noc", Name: "transit", Spec: []byte(`{"widgets":[{"type":"improvements"}]}`), Updated: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	_ = s.Stop(ctx)

	// Restart on the same file.
	s = newStore(t, "path: "+path)
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	ds, err := s.Dashboards(ctx, "noc")
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 2 || ds[0].Name != "commit" || ds[1].Name != "transit" || string(ds[1].Spec) != `{"widgets":[{"type":"improvements"}]}` || !ds[1].Updated.Equal(now.Add(time.Minute)) {
		t.Fatalf("dashboards = %+v", ds)
	}
	if ok, err := s.DeleteDashboard(ctx, "noc", "commit"); !ok || err != nil {
		t.Fatalf("delete: %v %v", ok, err)
	}
	if ok, _ := s.DeleteDashboard(ctx, "noc", "commit"); ok {
		t.Fatal("deleted twice")
	}
	// Deleting a user deletes that user's dashboards only.
	if err := s.PutUser(ctx, plugin.User{Name: "noc", Role: plugin.RoleViewer, Source: plugin.UserLocal, Created: now, Updated: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteUser(ctx, "noc"); err != nil {
		t.Fatal(err)
	}
	if ds, _ := s.Dashboards(ctx, "noc"); len(ds) != 0 {
		t.Fatalf("dashboards left after user delete: %+v", ds)
	}
	if ds, _ := s.Dashboards(ctx, "other"); len(ds) != 1 {
		t.Fatalf("other user's dashboards: %+v", ds)
	}
}
