package policy

import (
	"testing"
	"time"
)

func TestReasonTextIsASCII(t *testing.T) {
	to := Candidate{Provider: "b", LossPct: 0.5, RTTAvg: 20 * time.Millisecond}
	from := Candidate{Provider: "a", LossPct: 3, RTTAvg: 80 * time.Millisecond}
	got := reasonText(to, from)
	want := "b: loss 3.0%->0.5%, rtt 80ms->20ms"
	if got != want {
		t.Fatalf("reasonText = %q, want %q", got, want)
	}
}

// The display rule must agree with better, minus the score check.
func TestThresholdsMatchBetter(t *testing.T) {
	th := Thresholds{MinLossDeltaPct: 1, MinRTTDelta: 15 * time.Millisecond, MinRTTDeltaPct: 10}
	cfg := Config{MinLossDeltaPct: 1, MinRTTDelta: 15 * time.Millisecond, MinRTTDeltaPct: 10}
	from := Candidate{LossPct: 2, RTTAvg: 100 * time.Millisecond, Score: 10}
	for name, tc := range map[string]struct {
		to        Candidate
		loss, rtt bool
	}{
		"loss win":            {Candidate{LossPct: 0.5, RTTAvg: 110 * time.Millisecond}, true, false},
		"rtt win":             {Candidate{LossPct: 2, RTTAvg: 80 * time.Millisecond}, false, true},
		"under min_rtt_delta": {Candidate{LossPct: 2, RTTAvg: 90 * time.Millisecond}, false, false},
		"worse loss":          {Candidate{LossPct: 2.5, RTTAvg: 50 * time.Millisecond}, false, false},
	} {
		if got := th.LossWins(tc.to, from); got != tc.loss {
			t.Errorf("%s: LossWins = %v, want %v", name, got, tc.loss)
		}
		if got := th.RTTWins(tc.to, from); got != tc.rtt {
			t.Errorf("%s: RTTWins = %v, want %v", name, got, tc.rtt)
		}
		if got := better(tc.to, from, cfg); got != (tc.loss || tc.rtt) {
			t.Errorf("%s: better = %v, want %v", name, got, tc.loss || tc.rtt)
		}
	}
	var e *Engine
	if got := e.Thresholds(); got != (Thresholds{}) {
		t.Errorf("nil engine thresholds = %+v", got)
	}
}
