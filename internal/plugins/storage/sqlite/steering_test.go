package sqlite

import (
	"context"
	"path/filepath"
	"testing"
)

func TestSteeringStateSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "p.db")
	s := newStore(t, "path: "+path)
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if doc, err := s.SteeringState(ctx); err != nil || doc != nil {
		t.Fatalf("empty store: %q, %v", doc, err)
	}
	if loc := s.SteeringLocation(); loc != path+" (table steering_state)" {
		t.Fatalf("location %q", loc)
	}
	for _, doc := range []string{`{"version":1}`, `{"version":1,"pause":{"paused":true}}`} {
		if err := s.PutSteeringState(ctx, []byte(doc)); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.Stop(ctx)

	s = newStore(t, "path: "+path)
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	doc, err := s.SteeringState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(doc) != `{"version":1,"pause":{"paused":true}}` {
		t.Fatalf("after restart: %q", doc)
	}
}
