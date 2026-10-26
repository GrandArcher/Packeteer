package verify

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

func rates(at time.Time, in map[string]float64, out map[string]float64) map[string]Rate {
	m := map[string]Rate{}
	for n, v := range in {
		r := m[n]
		r.InMbps, r.Updated = v, at
		m[n] = r
	}
	for n, v := range out {
		r := m[n]
		r.OutMbps, r.Updated = v, at
		m[n] = r
	}
	return m
}

func outClaim(expected float64, base map[string]Rate) Claim {
	return Claim{Kind: Outbound, Prefix: netip.MustParsePrefix("198.51.100.0/24"), Provider: "transit-b", From: "transit-a",
		Expected: expected, Rates: base}
}

func TestOutboundClassification(t *testing.T) {
	base := rates(t0, nil, map[string]float64{"transit-a": 100, "transit-b": 10})
	cases := []struct {
		name  string
		after map[string]float64
		want  Status
		moved float64
	}{
		{"all moved", map[string]float64{"transit-a": 60, "transit-b": 50}, Verified, 40},
		{"half moved is verified at the edge", map[string]float64{"transit-a": 80, "transit-b": 30}, Verified, 20},
		{"a quarter moved", map[string]float64{"transit-a": 90, "transit-b": 20}, Partial, 10},
		{"nothing moved", map[string]float64{"transit-a": 100, "transit-b": 10}, NotMoved, 0},
		{"new provider grew but the old did not shrink", map[string]float64{"transit-a": 100, "transit-b": 50}, NotMoved, 0},
		{"old shrank but the new did not grow", map[string]float64{"transit-a": 60, "transit-b": 10}, NotMoved, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := New(Config{}, nil)
			tr.Begin(t0, outClaim(40, base))
			at := t0.Add(DefaultOutboundWindow)
			got := tr.Observe(at, Observation{Rates: rates(at, nil, tc.after)})
			if len(got) != 1 || got[0].Status != tc.want || got[0].MovedMbps != tc.moved {
				t.Fatalf("got %+v, want status %s moved %v", got, tc.want, tc.moved)
			}
		})
	}
}

func TestPendingUntilDue(t *testing.T) {
	tr := New(Config{OutboundWindow: time.Minute}, nil)
	tr.Begin(t0, outClaim(40, rates(t0, nil, map[string]float64{"transit-a": 100, "transit-b": 10})))
	at := t0.Add(59 * time.Second)
	if got := tr.Observe(at, Observation{Rates: rates(at, nil, map[string]float64{"transit-a": 60, "transit-b": 50})}); len(got) != 0 {
		t.Fatalf("judged before the window: %+v", got)
	}
	l := tr.List()
	if len(l) != 1 || l[0].Status != Pending || !l[0].Due.Equal(t0.Add(time.Minute)) {
		t.Fatalf("list = %+v, want one pending result due at 1m", l)
	}
	at = t0.Add(time.Minute)
	got := tr.Observe(at, Observation{Rates: rates(at, nil, map[string]float64{"transit-a": 60, "transit-b": 50})})
	if len(got) != 1 || got[0].Status != Verified {
		t.Fatalf("got %+v", got)
	}
	if l := tr.List(); len(l) != 1 || l[0].Status != Verified {
		t.Fatalf("list after judging = %+v", l)
	}
}

func TestStaleCountersWaitThenUnknown(t *testing.T) {
	tr := New(Config{OutboundWindow: time.Minute}, nil)
	base := rates(t0, nil, map[string]float64{"transit-a": 100, "transit-b": 10})
	tr.Begin(t0, outClaim(40, base))
	// Counters stamped before half the window are the steer's old view.
	stale := rates(t0.Add(10*time.Second), nil, map[string]float64{"transit-a": 60, "transit-b": 50})
	if got := tr.Observe(t0.Add(time.Minute), Observation{Rates: stale}); len(got) != 0 {
		t.Fatalf("judged on counters from before the settle time: %+v", got)
	}
	fresh := rates(t0.Add(90*time.Second), nil, map[string]float64{"transit-a": 60, "transit-b": 50})
	got := tr.Observe(t0.Add(90*time.Second), Observation{Rates: fresh})
	if len(got) != 1 || got[0].Status != Verified {
		t.Fatalf("fresh counters inside the grace window: %+v", got)
	}

	tr.Begin(t0, outClaim(40, base))
	got = tr.Observe(t0.Add(2*time.Minute), Observation{Rates: stale})
	if len(got) != 1 || got[0].Status != Unknown || got[0].BackedOut {
		t.Fatalf("no fresh counters after two windows should be unknown and undo nothing: %+v", got)
	}
}

func TestSmallTrafficIsUnknownNotAFailure(t *testing.T) {
	tr := New(Config{}, nil)
	tr.Begin(t0, outClaim(0.4, rates(t0, nil, map[string]float64{"transit-a": 5, "transit-b": 5})))
	at := t0.Add(DefaultOutboundWindow)
	got := tr.Observe(at, Observation{Rates: rates(at, nil, map[string]float64{"transit-a": 5, "transit-b": 5})})
	if len(got) != 1 || got[0].Status != Unknown || !strings.Contains(got[0].Detail, "min_mbps") {
		t.Fatalf("got %+v", got)
	}
}

func TestInboundNeedsTheTrafficToArriveElsewhere(t *testing.T) {
	base := rates(t0, map[string]float64{"transit-a": 150, "transit-b": 30}, nil)
	claim := Claim{Kind: Inbound, Provider: "transit-a", Rates: base}
	cases := []struct {
		name  string
		after map[string]float64
		want  Status
		moved float64
	}{
		{"moved to the other provider", map[string]float64{"transit-a": 50, "transit-b": 130}, Verified, 100},
		{"demand fell instead", map[string]float64{"transit-a": 50, "transit-b": 30}, NotMoved, 0},
		{"partial shed", map[string]float64{"transit-a": 120, "transit-b": 60}, Partial, 30},
		{"unchanged", map[string]float64{"transit-a": 150, "transit-b": 30}, NotMoved, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := New(Config{}, nil)
			tr.Begin(t0, claim)
			at := t0.Add(DefaultInboundWindow)
			got := tr.Observe(at, Observation{Rates: rates(at, tc.after, nil)})
			if len(got) != 1 || got[0].Status != tc.want || got[0].MovedMbps != tc.moved || got[0].ExpectedMbps != 150 {
				t.Fatalf("got %+v, want %s moved %v of 150", got, tc.want, tc.moved)
			}
		})
	}
}

func TestInboundWindowIsLongerThanOutbound(t *testing.T) {
	tr := New(Config{}, nil)
	tr.Begin(t0, Claim{Kind: Inbound, Provider: "transit-a", Rates: rates(t0, map[string]float64{"transit-a": 150}, nil)})
	tr.Begin(t0, outClaim(40, rates(t0, nil, map[string]float64{"transit-a": 100, "transit-b": 10})))
	l := tr.List()
	if len(l) != 2 {
		t.Fatalf("list = %+v", l)
	}
	for _, r := range l {
		want := DefaultOutboundWindow
		if r.Kind == Inbound {
			want = DefaultInboundWindow
		}
		if got := r.Due.Sub(r.Started); got != want {
			t.Errorf("%s window = %s, want %s", r.Kind, got, want)
		}
	}
}

func TestBackoutIsConfigurableAndDoubles(t *testing.T) {
	inClaim := Claim{Kind: Inbound, Provider: "transit-a", Rates: rates(t0, map[string]float64{"transit-a": 150, "transit-b": 30}, nil)}
	flat := func(at time.Time) Observation {
		return Observation{Rates: rates(at, map[string]float64{"transit-a": 150, "transit-b": 30}, map[string]float64{"transit-a": 100, "transit-b": 10})}
	}

	tr := New(Config{Backoff: time.Hour, MaxBackoff: 3 * time.Hour}, nil)
	var want = []time.Duration{time.Hour, 2 * time.Hour, 3 * time.Hour, 3 * time.Hour}
	now := t0
	for i, w := range want {
		inClaim.Rates = rates(now, map[string]float64{"transit-a": 150, "transit-b": 30}, nil)
		tr.Begin(now, inClaim)
		now = now.Add(DefaultInboundWindow)
		got := tr.Observe(now, flat(now))
		if len(got) != 1 || got[0].Status != NotMoved || !got[0].BackedOut || got[0].Backoff != w {
			t.Fatalf("round %d: %+v, want backed out for %s", i, got, w)
		}
	}

	// A verified steer clears the count: the next failure starts over.
	inClaim.Rates = rates(now, map[string]float64{"transit-a": 150, "transit-b": 30}, nil)
	tr.Begin(now, inClaim)
	now = now.Add(DefaultInboundWindow)
	if got := tr.Observe(now, Observation{Rates: rates(now, map[string]float64{"transit-a": 40, "transit-b": 140}, nil)}); got[0].Status != Verified || got[0].BackedOut {
		t.Fatalf("verified steer: %+v", got)
	}
	inClaim.Rates = rates(now, map[string]float64{"transit-a": 150, "transit-b": 30}, nil)
	tr.Begin(now, inClaim)
	now = now.Add(DefaultInboundWindow)
	if got := tr.Observe(now, flat(now)); got[0].Backoff != time.Hour {
		t.Fatalf("after a verified steer the hold-off should restart at 1h: %+v", got)
	}

	// Outbound is only reported unless backout names it.
	out := New(Config{}, nil)
	out.Begin(t0, outClaim(40, rates(t0, nil, map[string]float64{"transit-a": 100, "transit-b": 10})))
	at := t0.Add(DefaultOutboundWindow)
	if got := out.Observe(at, flat(at)); got[0].Status != NotMoved || got[0].BackedOut {
		t.Fatalf("outbound default: %+v", got)
	}
	both := New(Config{Backout: []string{"outbound"}}, nil)
	both.Begin(t0, outClaim(40, rates(t0, nil, map[string]float64{"transit-a": 100, "transit-b": 10})))
	if got := both.Observe(at, flat(at)); !got[0].BackedOut {
		t.Fatalf("outbound backout: %+v", got)
	}
	none := New(Config{Backout: []string{}}, nil)
	none.Begin(t0, inClaim)
	at = t0.Add(DefaultInboundWindow)
	if got := none.Observe(at, flat(at)); got[0].Status != NotMoved || got[0].BackedOut {
		t.Fatalf("backout: [] only warns: %+v", got)
	}
}

func TestCancelDropsAnOpenClaim(t *testing.T) {
	tr := New(Config{}, nil)
	c := outClaim(40, rates(t0, nil, map[string]float64{"transit-a": 100, "transit-b": 10}))
	tr.Begin(t0, c)
	tr.Cancel(Outbound, c.Prefix.String())
	at := t0.Add(time.Hour)
	if got := tr.Observe(at, Observation{Rates: rates(at, nil, nil)}); len(got) != 0 || len(tr.List()) != 0 {
		t.Fatalf("cancelled claim still judged: %+v %+v", got, tr.List())
	}
}

func TestKeepDropsSteersThatLeftTheWire(t *testing.T) {
	tr := New(Config{}, nil)
	a := outClaim(40, rates(t0, nil, map[string]float64{"transit-a": 100, "transit-b": 10}))
	b := a
	b.Prefix = netip.MustParsePrefix("203.0.113.0/24")
	in := Claim{Kind: Inbound, Provider: "transit-a", Rates: rates(t0, map[string]float64{"transit-a": 150, "transit-b": 30}, nil)}
	tr.Begin(t0, a)
	tr.Begin(t0, b)
	tr.Begin(t0, in)
	tr.Keep(func(k Kind, key string) bool { return k == Outbound && key == b.Prefix.String() })
	l := tr.List()
	if len(l) != 1 || l[0].Prefix != b.Prefix {
		t.Fatalf("list = %+v, want only %s", l, b.Prefix)
	}
	at := t0.Add(time.Hour)
	if got := tr.Observe(at, Observation{Rates: rates(at, nil, nil)}); len(got) != 1 || got[0].Prefix != b.Prefix {
		t.Fatalf("a dropped claim was judged: %+v", got)
	}
}

func TestDegradedPathIsReported(t *testing.T) {
	worse := func(before, after Path) bool { return after.LossPct-before.LossPct >= 5 }
	tr := New(Config{}, worse)
	c := outClaim(40, rates(t0, nil, map[string]float64{"transit-a": 100, "transit-b": 10}))
	c.Path = &Path{LossPct: 0, RTTMs: 20}
	tr.Begin(t0, c)
	at := t0.Add(DefaultOutboundWindow)
	obs := Observation{
		Rates: rates(at, nil, map[string]float64{"transit-a": 60, "transit-b": 50}),
		Path: func(p netip.Prefix, provider string) (Path, bool) {
			if p != c.Prefix || provider != "transit-b" {
				t.Errorf("path asked for %s via %s", p, provider)
			}
			return Path{LossPct: 12, RTTMs: 90}, true
		},
	}
	got := tr.Observe(at, obs)
	if len(got) != 1 || got[0].Status != Verified || !got[0].PathDegraded || !strings.Contains(got[0].Detail, "loss 0.0% to 12.0%") {
		t.Fatalf("got %+v", got)
	}
}

func TestFinishedResultsAreBounded(t *testing.T) {
	tr := New(Config{}, nil)
	for i := 0; i < maxDone+50; i++ {
		p := netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, byte(i >> 8), byte(i)}), 48)
		c := outClaim(40, rates(t0, nil, map[string]float64{"transit-a": 100, "transit-b": 10}))
		c.Prefix = p
		tr.Begin(t0, c)
	}
	at := t0.Add(DefaultOutboundWindow)
	tr.Observe(at, Observation{Rates: rates(at, nil, map[string]float64{"transit-a": 60, "transit-b": 50})})
	if n := len(tr.List()); n != maxDone {
		t.Fatalf("kept %d finished results, want %d", n, maxDone)
	}
}
