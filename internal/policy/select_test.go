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
