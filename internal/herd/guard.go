package herd

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync/atomic"
	"time"
)

// guard runs herd goroutines so that a panic or error in herd stops only
// herd work: it is logged, raised as an event, and the goroutine restarts
// with backoff. Nothing in the controller waits on a guarded goroutine.
type guard struct {
	log      *slog.Logger
	event    func(msg string)
	restarts atomic.Uint64
	backoff  time.Duration
}

func newGuard(log *slog.Logger, event func(string)) *guard {
	if log == nil {
		log = slog.Default()
	}
	return &guard{log: log, event: event, backoff: time.Second}
}

// run calls fn until ctx ends. fn returns when ctx is done; any other
// return, or a panic, restarts it after a growing pause.
func (g *guard) run(ctx context.Context, name string, fn func(context.Context)) {
	wait := g.backoff
	for ctx.Err() == nil {
		started := time.Now()
		func() {
			defer func() {
				if v := recover(); v != nil {
					g.restarts.Add(1)
					g.log.Error("herd stopped; restarting", "part", name, "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
					if g.event != nil {
						g.event(fmt.Sprintf("herd %s stopped on a panic and restarts: %v", name, v))
					}
				}
			}()
			fn(ctx)
		}()
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) > time.Minute {
			wait = g.backoff
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		wait = min(wait*2, time.Minute)
	}
}
