// Package train is shared by the probers that send one train of packets
// without waiting for each reply and match replies as they arrive (icmp,
// twamp): the reply record, the absolute-schedule wait between packets,
// and the assembly of a result's RTTs (send order) and Order (arrival
// order, #224).
package train

import (
	"context"
	"time"
)

// Reply is one matched reply: the 0-based send index and the arrival time.
type Reply struct {
	Seq int
	At  time.Time
}

// SleepUntil waits until at, or until ctx ends. A time already past
// returns at once with the context's error, if any.
func SleepUntil(ctx context.Context, at time.Time) error {
	wait := time.Until(at)
	if wait <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// EndReads sets the read deadline that ends a run's reads: deadline, or
// the context's deadline when that is earlier. The cancel check comes
// after the set: a cancel that already fired the caller's AfterFunc set
// the deadline to now, and the set here would push it back out to
// deadline.
func EndReads(ctx context.Context, setReadDeadline func(time.Time) error, deadline time.Time) {
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = setReadDeadline(deadline)
	if ctx.Err() != nil {
		_ = setReadDeadline(time.Now())
	}
}

// Collect drains replies (closed by the caller once the reads are done)
// and returns one RTT per reply in send order and the send index of each
// reply in arrival order. sentAt holds each packet's send time by index;
// a reply with an index outside it is dropped.
func Collect(sentAt []time.Time, replies <-chan Reply) (rtts []time.Duration, order []int) {
	count := len(sentAt)
	got := make([]bool, count)
	byIndex := make([]time.Duration, count)
	for r := range replies {
		if r.Seq < 0 || r.Seq >= count || got[r.Seq] {
			continue
		}
		got[r.Seq] = true
		byIndex[r.Seq] = r.At.Sub(sentAt[r.Seq])
		order = append(order, r.Seq)
	}
	for seq := range count {
		if got[seq] {
			rtts = append(rtts, byIndex[seq])
		}
	}
	return rtts, order
}
