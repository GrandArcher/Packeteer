package exchange

import (
	"slices"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func spec(peers ...string) HealthSpec {
	return HealthSpec{Exchange: "ix-lab", Peers: peers, HealthOptions: HealthOptions{
		LossPct: 50, MinPeers: 3, Window: 5 * time.Minute,
	}}
}

func good(peer string) HopSample {
	return HopSample{Peer: peer, Measured: true, RTT: 2 * time.Millisecond}
}

func lost(peer string, pct float64) HopSample {
	return HopSample{Peer: peer, Measured: true, LossPct: pct}
}

func TestOneDegradedPeerIsNotTheExchange(t *testing.T) {
	h := NewHealth([]HealthSpec{spec("a", "b", "c", "d")})
	if ch := h.Update(t0, []HopSample{lost("a", 100), good("b"), good("c"), good("d")}); len(ch) != 0 {
		t.Fatalf("one peer down raised %+v", ch)
	}
	snap := h.Snapshot(t0)["ix-lab"]
	if snap.Degraded || !slices.Equal(snap.DegradedPeers, []string{"a"}) {
		t.Fatalf("snapshot = %+v", snap)
	}
	if r := snap.Peers["a"]; r.State != ReachUnreachable || !r.Degraded || r.LossPct != 100 {
		t.Fatalf("peer a = %+v", r)
	}
	if r := snap.Peers["b"]; r.State != ReachReachable || r.Degraded || r.RTTMs != 2 {
		t.Fatalf("peer b = %+v", r)
	}
}

func TestKPeersDegradeThenRecover(t *testing.T) {
	h := NewHealth([]HealthSpec{spec("a", "b", "c", "d")})
	// Two peers are not enough for MinPeers 3.
	h.Update(t0, []HopSample{lost("a", 100), lost("b", 60), good("c"), good("d")})
	t1 := t0.Add(time.Minute)
	// The third degrades a minute later: the window adds them up.
	ch := h.Update(t1, []HopSample{good("a"), good("b"), lost("c", 50), good("d")})
	if len(ch) != 1 || !ch[0].Degraded || ch[0].Exchange != "ix-lab" || ch[0].Peers != 4 ||
		!slices.Equal(ch[0].DegradedPeers, []string{"a", "b", "c"}) {
		t.Fatalf("change = %+v", ch)
	}
	if snap := h.Snapshot(t1)["ix-lab"]; !snap.Since.Equal(t1) {
		t.Fatalf("since = %v, want %v", snap.Since, t1)
	}
	// Still inside the window: no repeat.
	t2 := t1.Add(time.Minute)
	if ch := h.Update(t2, []HopSample{good("a"), good("b"), good("c"), good("d")}); len(ch) != 0 {
		t.Fatalf("repeat or early clear: %+v", ch)
	}
	// a and b age out first (t0+5m), leaving only c: recovered.
	t3 := t0.Add(5*time.Minute + time.Second)
	ch = h.Update(t3, []HopSample{good("a"), good("b"), good("c"), good("d")})
	if len(ch) != 1 || ch[0].Degraded || !slices.Equal(ch[0].DegradedPeers, []string{"c"}) {
		t.Fatalf("recovery = %+v", ch)
	}
	if snap := h.Snapshot(t3)["ix-lab"]; snap.Degraded || !snap.Since.IsZero() {
		t.Fatalf("after recovery degraded = %v since = %v", snap.Degraded, snap.Since)
	}
}

func TestPercentThreshold(t *testing.T) {
	sp := spec("a", "b", "c", "d", "e")
	sp.MinPeers, sp.MinPercent = 5, 40
	h := NewHealth([]HealthSpec{sp})
	if ch := h.Update(t0, []HopSample{lost("a", 100), good("b"), good("c"), good("d"), good("e")}); len(ch) != 0 {
		t.Fatalf("20%% raised %+v", ch)
	}
	ch := h.Update(t0, []HopSample{lost("b", 100)})
	if len(ch) != 1 || !ch[0].Degraded || len(ch[0].DegradedPeers) != 2 {
		t.Fatalf("40%% of 5 peers = %+v", ch)
	}
}

func TestRTTDegradesOnlyWhenSet(t *testing.T) {
	slow := HopSample{Peer: "a", Measured: true, RTT: 80 * time.Millisecond}
	h := NewHealth([]HealthSpec{spec("a", "b")})
	h.Update(t0, []HopSample{slow})
	if h.Snapshot(t0)["ix-lab"].Peers["a"].Degraded {
		t.Fatal("slow peer degraded with rtt_ms off")
	}
	sp := spec("a", "b")
	sp.RTT = 50 * time.Millisecond
	h = NewHealth([]HealthSpec{sp})
	h.Update(t0, []HopSample{slow})
	if !h.Snapshot(t0)["ix-lab"].Peers["a"].Degraded {
		t.Fatal("slow peer not degraded with rtt_ms 50")
	}
}

func TestUnmeasuredSamplesDoNotCount(t *testing.T) {
	h := NewHealth([]HealthSpec{spec("a", "b", "c")})
	none := func(p string) HopSample { return HopSample{Peer: p} }
	if ch := h.Update(t0, []HopSample{none("a"), none("b"), none("c")}); len(ch) != 0 {
		t.Fatalf("prober errors raised %+v", ch)
	}
	snap := h.Snapshot(t0)["ix-lab"]
	if len(snap.DegradedPeers) != 0 || snap.Peers["a"].State != ReachUnknown {
		t.Fatalf("snapshot = %+v", snap)
	}
}

func TestSinglePeerExchangeNeverDegrades(t *testing.T) {
	sp := spec("a")
	sp.MinPeers, sp.MinPercent = 2, 1
	h := NewHealth([]HealthSpec{sp})
	if ch := h.Update(t0, []HopSample{lost("a", 100)}); len(ch) != 0 {
		t.Fatalf("one member is not the exchange: %+v", ch)
	}
}

func TestMinPeersAboveSizeIsCapped(t *testing.T) {
	// Two peers with the default MinPeers 3 can still raise the alert.
	h := NewHealth([]HealthSpec{spec("a", "b")})
	if ch := h.Update(t0, []HopSample{lost("a", 100), lost("b", 100)}); len(ch) != 1 || !ch[0].Degraded {
		t.Fatalf("both peers of a two-peer exchange down = %+v", ch)
	}
}

func TestUnknownPeerSampleIgnored(t *testing.T) {
	h := NewHealth([]HealthSpec{spec("a", "b")})
	h.Update(t0, []HopSample{lost("zzz", 100)})
	if got := h.Snapshot(t0)["ix-lab"]; len(got.DegradedPeers) != 0 || len(got.Peers) != 2 {
		t.Fatalf("snapshot = %+v", got)
	}
	var nilHealth *Health
	if nilHealth.Snapshot(t0) != nil {
		t.Fatal("nil Health has no snapshot")
	}
}
