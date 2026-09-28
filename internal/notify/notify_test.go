package notify

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fake struct {
	plugin.Base
	mu    sync.Mutex
	got   []plugin.Event
	gate  *plugin.EventGate
	err   error
	block chan struct{}
}

func (f *fake) Notify(ctx context.Context, e plugin.Event) error {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, e)
	return f.err
}

func (f *fake) events() []plugin.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]plugin.Event(nil), f.got...)
}

type gated struct{ *fake }

func (g gated) EventGate() *plugin.EventGate { return g.gate }

func closeNow(t *testing.T, d *Dispatcher) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestFanOutFillsCatalogDefaults(t *testing.T) {
	a, b := &fake{}, &fake{}
	now := time.Unix(500, 0)
	d := New([]Target{{Name: "a", Notifier: a}, {Name: "b", Notifier: b}}, Options{Now: func() time.Time { return now }})
	d.Emit(plugin.Event{Kind: plugin.EventBGPSessionDown, Message: "down"})
	closeNow(t, d)
	for _, f := range []*fake{a, b} {
		got := f.events()
		if len(got) != 1 || got[0].Severity != plugin.SeverityCritical || !got[0].Time.Equal(now) {
			t.Fatalf("got %+v", got)
		}
	}
	if s := d.Stats(); s.Delivered != 2 {
		t.Fatalf("stats %+v", s)
	}
}

func TestFilterAndRateLimitPerNotifier(t *testing.T) {
	crit, _ := plugin.NewEventGate(plugin.EventFilter{MinSeverity: plugin.SeverityCritical})
	lim, _ := plugin.NewEventGate(plugin.EventFilter{RateLimit: 1, RateWindow: time.Hour})
	pager := &fake{gate: crit}
	mail := &fake{gate: lim}
	all := &fake{}
	d := New([]Target{{Name: "pager", Notifier: gated{pager}}, {Name: "mail", Notifier: gated{mail}}, {Name: "all", Notifier: all}}, Options{})
	d.Emit(plugin.NewEvent(plugin.EventImprovementAdded, time.Now(), "a", nil))
	d.Emit(plugin.NewEvent(plugin.EventProviderDown, time.Now(), "b", nil))
	d.Emit(plugin.NewEvent(plugin.EventProviderUp, time.Now(), "c", nil))
	closeNow(t, d)
	if got := pager.events(); len(got) != 2 || got[0].Kind != plugin.EventProviderDown || got[1].Kind != plugin.EventProviderUp {
		t.Fatalf("pager got %+v", got)
	}
	if got := mail.events(); len(got) != 1 || got[0].Kind != plugin.EventImprovementAdded {
		t.Fatalf("mail got %+v", got)
	}
	if got := all.events(); len(got) != 3 {
		t.Fatalf("all got %d", len(got))
	}
	s := d.Stats()
	if s.Filtered != 1 || s.RateLimits != 2 || s.Delivered != 6 {
		t.Fatalf("stats %+v", s)
	}
}

func TestSuppressedCountIsDelivered(t *testing.T) {
	lim, _ := plugin.NewEventGate(plugin.EventFilter{RateLimit: 1, RateWindow: time.Minute})
	f := &fake{gate: lim}
	now := time.Unix(0, 0)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	d := New([]Target{{Name: "f", Notifier: gated{f}}}, Options{Now: clock})
	for i := 0; i < 4; i++ {
		d.Emit(plugin.NewEvent(plugin.EventProviderDown, time.Time{}, "", nil))
	}
	// Wait for the three rate-limited events to be processed.
	deadline := time.Now().Add(5 * time.Second)
	for d.Stats().RateLimits < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	now = now.Add(time.Minute)
	mu.Unlock()
	d.Emit(plugin.NewEvent(plugin.EventProviderUp, time.Time{}, "", nil))
	closeNow(t, d)
	got := f.events()
	if len(got) != 2 || got[1].Fields["suppressed"] != "3" {
		t.Fatalf("got %+v", got)
	}
}

func TestSlowNotifierDoesNotBlockEmitOrOthers(t *testing.T) {
	slow := &fake{block: make(chan struct{})}
	fast := &fake{}
	d := New([]Target{{Name: "slow", Notifier: slow}, {Name: "fast", Notifier: fast}}, Options{Queue: 2, Timeout: time.Minute})
	start := time.Now()
	for i := 0; i < 10; i++ {
		d.Emit(plugin.NewEvent(plugin.EventImprovementAdded, time.Time{}, "", nil))
	}
	if time.Since(start) > time.Second {
		t.Fatal("Emit blocked on a slow notifier")
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(fast.events()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(fast.events()) == 0 {
		t.Fatal("fast notifier was held up by the slow one")
	}
	if d.Stats().Dropped == 0 {
		t.Fatal("a full queue must drop and count")
	}
	// Close with an expired context cancels the stuck delivery.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := d.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close err = %v", err)
	}
	d.Emit(plugin.NewEvent(plugin.EventImprovementAdded, time.Time{}, "", nil)) // after close: dropped, no panic
}

func TestFailuresAreCounted(t *testing.T) {
	f := &fake{err: errors.New("boom")}
	d := New([]Target{{Name: "f", Notifier: f}}, Options{})
	d.Emit(plugin.NewEvent(plugin.EventAnnounceFailed, time.Time{}, "", nil))
	closeNow(t, d)
	if s := d.Stats(); s.Failed != 1 || s.Delivered != 0 {
		t.Fatalf("stats %+v", s)
	}
}

func TestNoNotifiers(t *testing.T) {
	d := New(nil, Options{})
	if d.Enabled() {
		t.Fatal("enabled without notifiers")
	}
	d.Emit(plugin.Event{Kind: plugin.EventProviderDown})
	closeNow(t, d)
	var nilD *Dispatcher
	nilD.Emit(plugin.Event{})
	_ = nilD.Close(context.Background())
}
