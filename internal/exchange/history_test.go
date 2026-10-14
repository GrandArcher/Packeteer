package exchange

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func statsFor(nh string, rs, bil, both int) []Stats {
	return []Stats{{Name: "ix-lab", Peers: []PeerStats{{NextHop: nh, Availability: Availability{RouteServerOnly: rs, BilateralOnly: bil, Both: both}}}}}
}

func TestHistoryKeepsRecentSamples(t *testing.T) {
	h := NewHistory()
	nh := netip.MustParseAddr("203.0.113.11")
	t0 := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	for i := 0; i < maxSamples+10; i++ {
		h.Record(t0.Add(time.Duration(i)*SampleEvery), statsFor(nh.String(), i, 1, 2))
	}
	got := h.Series("ix-lab", nh)
	if len(got) != maxSamples {
		t.Fatalf("kept %d samples, want %d", len(got), maxSamples)
	}
	if got[0].RouteServerOnly != 10 || got[len(got)-1].RouteServerOnly != maxSamples+9 || got[0].BilateralOnly != 1 || got[0].Both != 2 {
		t.Fatalf("window = first %+v last %+v", got[0], got[len(got)-1])
	}
	got[0].RouteServerOnly = -1
	if h.Series("ix-lab", nh)[0].RouteServerOnly != 10 {
		t.Fatal("Series returned the stored slice")
	}
	if len(h.Series("ix-lab", netip.MustParseAddr("203.0.113.99"))) != 0 || len(h.Series("other", nh)) != 0 {
		t.Fatal("unknown member has samples")
	}
}

func TestHistoryForgetsGonePeers(t *testing.T) {
	h := NewHistory()
	t0 := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	gone, stay := "203.0.113.11", "203.0.113.12"
	h.Record(t0, statsFor(gone, 1, 0, 0))
	for i := 1; i <= maxSamples; i++ {
		h.Record(t0.Add(time.Duration(i)*SampleEvery), statsFor(stay, 1, 0, 0))
	}
	if len(h.Series("ix-lab", netip.MustParseAddr(gone))) != 0 {
		t.Fatal("a member unseen for the whole window was kept")
	}
}

func TestHistoryRunSamplesUntilCancelled(t *testing.T) {
	h := NewHistory()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	calls := make(chan struct{}, 8)
	go func() {
		h.Run(ctx, 5*time.Millisecond, func() []Stats {
			calls <- struct{}{}
			return statsFor("203.0.113.11", 3, 0, 0)
		})
		close(done)
	}()
	<-calls
	<-calls
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}
	if n := len(h.Series("ix-lab", netip.MustParseAddr("203.0.113.11"))); n < 2 {
		t.Fatalf("samples = %d, want at least 2", n)
	}
}

// Samples are kept per exchange: the same next hop on two exchanges has two
// series, and a discovered member (no availability) has none.
func TestHistoryIsPerExchangeAndPeersOnly(t *testing.T) {
	h := NewHistory()
	nh := netip.MustParseAddr("203.0.113.11")
	peer := func(ex string, rs int) Stats {
		return Stats{Name: ex, Peers: []PeerStats{{NextHop: nh.String(), Availability: Availability{RouteServerOnly: rs}}}}
	}
	disc := Stats{Name: "ix-a", Discovered: []Discovered{{NextHop: "203.0.113.13", Prefixes: 3}}}
	h.Record(time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC), []Stats{peer("ix-a", 1), peer("ix-b", 2), disc})
	if a, b := h.Series("ix-a", nh), h.Series("ix-b", nh); len(a) != 1 || len(b) != 1 || a[0].RouteServerOnly != 1 || b[0].RouteServerOnly != 2 {
		t.Fatalf("series = %+v %+v", a, b)
	}
	if len(h.series) != 2 {
		t.Fatalf("series = %d, want 2 (the discovered member is not recorded)", len(h.series))
	}
}
