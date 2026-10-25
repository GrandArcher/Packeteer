package train

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestCollect(t *testing.T) {
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	sentAt := []time.Time{t0, t0.Add(10 * time.Millisecond), t0.Add(20 * time.Millisecond), t0.Add(30 * time.Millisecond)}
	replies := make(chan Reply, 8)
	// Packet 2 overtakes packet 1; packet 3 is lost; a duplicate and an
	// index past the train are dropped.
	for _, r := range []Reply{
		{Seq: 0, At: t0.Add(5 * time.Millisecond)},
		{Seq: 2, At: t0.Add(24 * time.Millisecond)},
		{Seq: 1, At: t0.Add(27 * time.Millisecond)},
		{Seq: 1, At: t0.Add(28 * time.Millisecond)},
		{Seq: 9, At: t0.Add(29 * time.Millisecond)},
	} {
		replies <- r
	}
	close(replies)
	rtts, order := Collect(sentAt, replies)
	if !slices.Equal(order, []int{0, 2, 1}) {
		t.Fatalf("order %v", order)
	}
	if !slices.Equal(rtts, []time.Duration{5 * time.Millisecond, 17 * time.Millisecond, 4 * time.Millisecond}) {
		t.Fatalf("rtts %v", rtts)
	}
	empty := make(chan Reply)
	close(empty)
	if rtts, order := Collect(nil, empty); rtts != nil || order != nil {
		t.Fatalf("empty train: %v %v", rtts, order)
	}
}

func TestSleepUntil(t *testing.T) {
	start := time.Now()
	if err := SleepUntil(context.Background(), start.Add(20*time.Millisecond)); err != nil || time.Since(start) < 20*time.Millisecond {
		t.Fatalf("err %v after %s", err, time.Since(start))
	}
	if err := SleepUntil(context.Background(), start); err != nil {
		t.Fatalf("past time: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := SleepUntil(ctx, time.Now().Add(time.Hour)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
	if err := SleepUntil(ctx, start); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled, past time: %v", err)
	}
}

func TestEndReads(t *testing.T) {
	var set []time.Time
	record := func(at time.Time) error { set = append(set, at); return nil }
	at := time.Now().Add(time.Hour)
	EndReads(context.Background(), record, at)
	if len(set) != 1 || !set[0].Equal(at) {
		t.Fatalf("set %v, want only %s", set, at)
	}

	// The context's earlier deadline wins.
	set = nil
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
	defer cancel()
	want, _ := ctx.Deadline()
	EndReads(ctx, record, at)
	if len(set) != 1 || !set[0].Equal(want) {
		t.Fatalf("set %v, want only %s", set, want)
	}

	// Already cancelled: the reads end now, after the set that would
	// otherwise have overwritten the cancel's deadline.
	set = nil
	cancel()
	before := time.Now()
	EndReads(ctx, record, at)
	if len(set) != 2 || set[1].Before(before) || set[1].After(time.Now()) {
		t.Fatalf("set %v, want the deadline then now", set)
	}
}
