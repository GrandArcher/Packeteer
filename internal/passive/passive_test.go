package passive

import (
	"net/netip"
	"testing"
	"time"
)

var (
	pA = netip.MustParsePrefix("198.51.100.0/24")
	pB = netip.MustParsePrefix("203.0.113.0/24")
	hA = netip.MustParseAddr("198.51.100.7")
	hB = netip.MustParseAddr("198.51.100.8")
)

func TestScore(t *testing.T) {
	th := Thresholds{RetransPct: 5, FailurePct: 20, RTT: 100 * time.Millisecond, MinSegments: 100, MinFlows: 10}
	cases := []struct {
		name    string
		c       Counts
		score   float64
		reasons []string
	}{
		{"quiet", Counts{}, 0, nil},
		{"retrans under min segments", Counts{Segments: 99, Retrans: 99}, 0, nil},
		{"retrans", Counts{Segments: 100, Retrans: 10}, 2, []string{ReasonRetrans}},
		{"failure under min flows", Counts{Flows: 9, Timeouts: 9}, 0, nil},
		{"failure", Counts{Flows: 10, Timeouts: 2, Resets: 2}, 2, []string{ReasonFailure}},
		{"failure capped at 100%", Counts{Flows: 10, Resets: 50}, 5, []string{ReasonFailure}},
		{"rtt", Counts{Flows: 10, RTTSamples: 10, RTTSum: 1500 * time.Millisecond}, 1.5, []string{ReasonRTT}},
		{"rtt under min", Counts{Flows: 10, RTTSamples: 9, RTTSum: 9 * time.Second}, 0, nil},
		{"healthy", Counts{Flows: 10, Segments: 1000, Retrans: 10, RTTSamples: 10, RTTSum: 500 * time.Millisecond}, 0.5, nil},
		{"all", Counts{Flows: 10, Timeouts: 5, Segments: 100, Retrans: 30, RTTSamples: 10, RTTSum: 2 * time.Second}, 6, []string{ReasonRetrans, ReasonFailure, ReasonRTT}},
	}
	for _, c := range cases {
		s, r := th.Score(c.c)
		if s != c.score || len(r) != len(c.reasons) {
			t.Errorf("%s: score %v reasons %v, want %v %v", c.name, s, r, c.score, c.reasons)
			continue
		}
		for i := range r {
			if r[i] != c.reasons[i] {
				t.Errorf("%s: reasons %v", c.name, r)
			}
		}
	}
	// A disabled check never contributes.
	off := Thresholds{FailurePct: 20}
	if s, _ := off.Score(Counts{Segments: 1000, Retrans: 1000, RTTSamples: 5, RTTSum: time.Hour}); s != 0 {
		t.Fatalf("disabled checks scored %v", s)
	}
}

func TestValidate(t *testing.T) {
	for _, th := range []Thresholds{
		{},
		{RetransPct: -1, FailurePct: 1},
		{RetransPct: 101},
		{FailurePct: 101},
		{FailurePct: 1, RTT: -1},
	} {
		if th.Validate() == nil {
			t.Errorf("accepted %+v", th)
		}
	}
	if err := (Thresholds{RTT: time.Millisecond}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowSlidesAndPicksHost(t *testing.T) {
	w := NewWindow(time.Minute, 10)
	t0 := time.Unix(1_800_000_000, 0)
	th := Thresholds{FailurePct: 20, MinFlows: 2}
	w.Add(t0, pA, hA, Counts{Flows: 2})
	w.Add(t0, pA, hB, Counts{Flows: 1, Timeouts: 1})
	w.Add(t0.Add(10*time.Second), pA, hA, Counts{Flows: 1})
	w.Add(t0.Add(30*time.Second), pB, netip.MustParseAddr("203.0.113.9"), Counts{Flows: 4, Resets: 4})
	w.Add(t0, pA, netip.MustParseAddr("192.0.2.1"), Counts{Flows: 1}) // host outside prefix ignored
	w.Add(t0, netip.Prefix{}, hA, Counts{Flows: 1})                   // invalid prefix ignored

	ps := w.Problems(t0.Add(40*time.Second), th, 0)
	if len(ps) != 2 || ps[0].Prefix != pB || ps[1].Prefix != pA {
		t.Fatalf("problems = %+v", ps)
	}
	if ps[1].Host != hB || ps[1].Counts.Flows != 5 || ps[1].Counts.Timeouts != 1 {
		t.Fatalf("pA = %+v", ps[1])
	}
	if ps := w.Problems(t0.Add(40*time.Second), th, 1); len(ps) != 1 || ps[0].Prefix != pB {
		t.Fatalf("capped = %+v", ps)
	}
	// After the window, the early pA counters are gone.
	tot := w.Totals(t0.Add(65 * time.Second))
	if tot[pA].Counts.Flows != 1 || tot[pB].Counts.Resets != 4 {
		t.Fatalf("totals = %+v", tot)
	}
	if len(w.Totals(t0.Add(3*time.Minute))) != 0 {
		t.Fatal("window did not expire")
	}
}

func TestWindowBucketCap(t *testing.T) {
	w := NewWindow(time.Minute, 1)
	t0 := time.Unix(1_800_000_000, 0)
	w.Add(t0, pA, hA, Counts{Flows: 1})
	w.Add(t0, pB, netip.Addr{}, Counts{Flows: 1})
	w.Add(t0, pA, hA, Counts{Flows: 1})
	tot := w.Totals(t0)
	if len(tot) != 1 || tot[pA].Counts.Flows != 2 {
		t.Fatalf("totals = %+v", tot)
	}
}

func TestFreshAndHelpers(t *testing.T) {
	var f Fresh
	got := f.Mark([]Problem{{Prefix: pA}, {Prefix: pB}})
	if !got[0] || !got[1] {
		t.Fatal("first mark not new")
	}
	got = f.Mark([]Problem{{Prefix: pA}})
	if got[0] {
		t.Fatal("repeat marked new")
	}
	got = f.Mark([]Problem{{Prefix: pB}})
	if !got[0] {
		t.Fatal("returning prefix not new")
	}
	nets, err := ParseNets("local", []string{"192.0.2.0/24", "2001:db8::/32"})
	if err != nil || !Contains(nets, netip.MustParseAddr("2001:db8::1")) || Contains(nets, hA) {
		t.Fatalf("nets = %v %v", nets, err)
	}
	for _, bad := range [][]string{{"x"}, {"192.0.2.1/24"}, {"192.0.2.0/24", "192.0.2.0/24"}} {
		if _, err := ParseNets("local", bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}
