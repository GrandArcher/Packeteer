package lease

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// The instance that takes over reads what the active one saved, and a
// standby never overwrites it.
func TestSteeringStateReachesTheStandby(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "lease.json")
	a, b := newNode(t, path, "pk-a"), newNode(t, path, "pk-b")
	if doc, err := a.SteeringState(ctx); err != nil || doc != nil {
		t.Fatalf("nothing saved: %q, %v", doc, err)
	}
	a.start(t)
	waitFor(t, "a active", 5*time.Second, a.Active)
	b.start(t)
	if err := a.PutSteeringState(ctx, []byte(`{"pause":{"paused":true}}`)); err != nil {
		t.Fatal(err)
	}
	if err := b.PutSteeringState(ctx, []byte(`{}`)); err == nil {
		t.Fatal("the standby saved the steering state")
	}
	if err := a.Resign(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "b active", 5*time.Second, b.Active)
	doc, err := b.SteeringState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(doc) != `{"pause":{"paused":true}}` {
		t.Fatalf("after takeover: %q", doc)
	}
}
