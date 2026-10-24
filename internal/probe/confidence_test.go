package probe

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func stats(sent, received int, rtts ...float64) Stats {
	r := plugin.ProbeResult{Sent: sent, RTTs: ms(rtts...)}
	st := Compute(r)
	st.Received = received
	return st
}

func TestRateConfidence(t *testing.T) {
	tests := []struct {
		name       string
		res        Result
		protocol   string
		dispersion time.Duration
		level      string
		score      float64
		beyond     bool
		text       string
	}{
		{"tcp, full replies, tight", Result{Stats: stats(10, 10, 20, 21, 22)}, "tcp", 0, ConfidenceHigh, 1, true, "tcp, 10/10 replies"},
		{"udp counts as beyond icmp", Result{Stats: stats(10, 10, 20, 21, 22)}, "udp", 0, ConfidenceHigh, 1, true, "udp, 10/10 replies"},
		{"icmp alone is medium", Result{Stats: stats(10, 10, 20, 21, 22)}, "icmp", 0, ConfidenceMedium, 0.5, false, "icmp, 10/10 replies"},
		{"exec is not known to be beyond icmp", Result{Stats: stats(10, 10, 20, 21, 22)}, "exec", 0, ConfidenceMedium, 0.5, false, "exec, 10/10 replies"},
		{"one reply", Result{Stats: stats(10, 1, 20)}, "tcp", 0, ConfidenceMedium, 0.5, true, "tcp, 1/10 replies"},
		{"two replies", Result{Stats: stats(10, 2, 20, 21)}, "tcp", 0, ConfidenceHigh, 0.75, true, "tcp, 2/10 replies"},
		{"no reply", Result{Stats: stats(10, 0)}, "tcp", 0, ConfidenceLow, 0.25, true, "tcp, 0/10 replies"},
		{"icmp one reply", Result{Stats: stats(10, 1, 20)}, "icmp", 0, ConfidenceLow, 0.25, false, "icmp, 1/10 replies"},
		{"traceroute hop", Result{Stats: stats(10, 10, 20, 21, 22), Indirect: true}, "tcp", 0, ConfidenceMedium, 0.5, true, "tcp, 10/10 replies, traceroute hop"},
		{"icmp at a hop", Result{Stats: stats(10, 10, 20, 21, 22), Indirect: true}, "icmp", 0, ConfidenceLow, 0.25, false, "icmp, 10/10 replies, traceroute hop"},
		// Spread 40 ms over the mean of 40 ms is not wide; 60 ms is.
		{"spread inside the mean", Result{Stats: stats(10, 3, 20, 40, 60)}, "tcp", 0, ConfidenceHigh, 1, true, "tcp, 3/10 replies"},
		{"spread over the mean", Result{Stats: stats(10, 3, 10, 40, 70)}, "tcp", 0, ConfidenceMedium, 0.5, true, "tcp, 3/10 replies, wide spread"},
		{"spread over dispersion_ms", Result{Stats: stats(10, 3, 20, 25, 30)}, "tcp", 5 * time.Millisecond, ConfidenceMedium, 0.5, true, "tcp, 3/10 replies, wide spread"},
		{"spread at dispersion_ms", Result{Stats: stats(10, 3, 20, 25, 30)}, "tcp", 10 * time.Millisecond, ConfidenceHigh, 1, true, "tcp, 3/10 replies"},
		{"failed sample", Result{Err: "boom", Stats: stats(10, 0)}, "tcp", 0, ConfidenceNone, 0, false, "no measurement"},
		{"unknown prober", Result{Stats: stats(10, 10, 20, 21, 22)}, "", 0, ConfidenceMedium, 0.5, false, "unknown prober, 10/10 replies"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := RateConfidence(tt.res, tt.protocol, tt.dispersion)
			if c.Level != tt.level || c.Score != tt.score || c.BeyondICMP() != tt.beyond || c.String() != tt.text {
				t.Fatalf("got %+v (beyond %v, %q), want %s %v beyond %v %q", c, c.BeyondICMP(), c, tt.level, tt.score, tt.beyond, tt.text)
			}
		})
	}
}

func TestConfidenceWithPassive(t *testing.T) {
	icmp := RateConfidence(Result{Stats: stats(10, 10, 20, 21, 22)}, "icmp", 0)
	agree := icmp.WithPassive(true)
	if agree.Level != ConfidenceHigh || agree.Score != 1 || !agree.BeyondICMP() || agree.String() != "icmp, 10/10 replies, passive agrees" {
		t.Fatalf("agree = %+v %q", agree, agree)
	}
	disagree := icmp.WithPassive(false)
	if disagree.Level != ConfidenceLow || disagree.Score != 0.25 || disagree.BeyondICMP() || disagree.String() != "icmp, 10/10 replies, passive disagrees" {
		t.Fatalf("disagree = %+v %q", disagree, disagree)
	}
	// Disagreement weakens a TCP sample too: 10/10 TCP replies that
	// contradict the observed traffic are medium, not high.
	tcp := RateConfidence(Result{Stats: stats(10, 10, 20, 21, 22)}, "tcp", 0).WithPassive(false)
	if tcp.Level != ConfidenceMedium || tcp.Score != 0.5 || !tcp.BeyondICMP() {
		t.Fatalf("tcp disagree = %+v", tcp)
	}
	none := RateConfidence(Result{Err: "boom"}, "tcp", 0).WithPassive(true)
	if none.Level != ConfidenceNone || none.Passive != "" {
		t.Fatalf("failed sample took a passive state: %+v", none)
	}
}

// TestRoundResultsCarryConfidence runs a round with an icmp prober that
// gets no reply and a tcp prober that answers, so the stored result's
// confidence names the prober type that produced it, and a provider whose
// probe failed carries none.
func TestRoundResultsCarryConfidence(t *testing.T) {
	icmp := &fakeProber{fn: func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		return plugin.ProbeResult{Sent: req.Count}, nil
	}}
	tcp := &fakeProber{fn: func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		if req.Provider == provB.Name {
			return plugin.ProbeResult{}, errors.New("socket closed")
		}
		return plugin.ProbeResult{Sent: req.Count, RTTs: ms(20, 21, 22)}, nil
	}}
	o := opts()
	o.Dispersion = 5 * time.Millisecond
	e, err := New([]Provider{provA, provB}, []NamedProber{{Name: "ping", Prober: icmp, Type: "icmp"}, {Name: "syn", Prober: tcp, Type: "tcp"}},
		src(plugin.Target{Prefix: pfx1, Host: pfx1.Addr().Next()}), o)
	if err != nil {
		t.Fatal(err)
	}
	e.RunOnce(context.Background())
	got := map[string]Result{}
	for _, r := range e.Results() {
		got[r.Provider] = r
	}
	a := got[provA.Name]
	if a.Prober != "syn" || a.Confidence.Protocol != "tcp" || a.Confidence.Level != ConfidenceHigh || a.Confidence.Replies != 3 || a.Confidence.Sent != 3 || a.Confidence.WideSpread {
		t.Fatalf("transit-a = %+v", a)
	}
	// icmp was silent and the tcp prober errored: the result is the icmp
	// sample with no reply, so the confidence is low and names icmp.
	b := got[provB.Name]
	if b.Prober != "ping" || b.Confidence.Protocol != "icmp" || b.Confidence.Level != ConfidenceLow || b.Confidence.Replies != 0 || b.Confidence.BeyondICMP() {
		t.Fatalf("transit-b = %+v", b)
	}
}
