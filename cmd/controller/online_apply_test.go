package main

import (
	"context"
	"testing"
	"time"
)

// A source started by a PUT /api/config online apply keeps running after
// the request returns; only the daemon context stops it.
func TestOnlineApplySourceOutlivesRequest(t *testing.T) {
	daemon, stopDaemon := context.WithCancel(context.Background())
	defer stopDaemon()
	stopped := make(chan struct{})
	reload := func(ctx context.Context) ([]string, error, error) {
		go func() { <-ctx.Done(); close(stopped) }() // like flow.go: <-ctx.Done(); closeGen
		return []string{"sources"}, nil, nil
	}
	var auditCtx context.Context
	apply := onlineApplier(daemon, reload, func(c context.Context, _ []string, _, _ error) { auditCtx = c })

	req, endRequest := context.WithCancel(context.Background())
	if applied, refused, fatal := apply(req); len(applied) != 1 || refused != nil || fatal != nil {
		t.Fatalf("apply: %v %v %v", applied, refused, fatal)
	}
	if auditCtx != req {
		t.Fatal("audit did not get the request context")
	}
	endRequest()
	select {
	case <-stopped:
		t.Fatal("source stopped when the request ended")
	case <-time.After(100 * time.Millisecond):
	}
	stopDaemon()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("source did not stop with the daemon")
	}
}
