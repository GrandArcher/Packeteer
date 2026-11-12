package lease

import (
	"context"
	"os"
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

// An instance that still thinks it is active but no longer holds the lease
// record must not overwrite the steering file the new holder saved.
func TestSteeringStateNotWrittenAfterLosingTheLease(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "lease.json")
	a := newNode(t, path, "pk-a")
	a.start(t)
	waitFor(t, "a active", 5*time.Second, a.Active)
	_ = a.Stop(ctx)
	// a's flag is still set, as in a process that froze across the takeover.
	a.mu.Lock()
	a.active, a.lastOK = true, time.Now().Add(time.Hour)
	a.mu.Unlock()
	if err := os.WriteFile(path, []byte(`{"holder":"pk-b#1","id":"pk-b","seq":9}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".steering", []byte(`newer`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := a.PutSteeringState(ctx, []byte(`older`)); err == nil {
		t.Fatal("an instance that lost the lease saved the steering state")
	}
	doc, err := a.SteeringState(ctx)
	if err != nil || string(doc) != "newer" {
		t.Fatalf("steering file = %q, %v", doc, err)
	}
}
