package httpapi

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func explainInput(cause string, natLoss, toLoss float64, natRTT, toRTT time.Duration) Input {
	p := netip.MustParsePrefix("198.51.100.0/24")
	at := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	return Input{
		Mode: "observe",
		At:   at,
		Decisions: []policy.Decision{{
			Prefix: p, Native: "lab-a",
			Candidates: []policy.Candidate{
				{Provider: "lab-a", LossPct: natLoss, RTTAvg: natRTT, Usable: true},
				{Provider: "lab-b", LossPct: toLoss, RTTAvg: toRTT, Usable: true},
			},
		}},
		Improvements: []policy.Improvement{{
			Prefix: p, Provider: "lab-b", Native: "lab-a", Cause: cause,
			Since: at.Add(-time.Minute), Reason: "lab-b: loss 0.0%->0.0%, rtt 60ms->20ms",
		}},
		Paths:      map[netip.Prefix][]rib.Route{p: {{Prefix: p, Provider: "lab-a", ASPath: []uint32{64500, 64496}}}},
		Thresholds: policy.Thresholds{MinLossDeltaPct: 1, MinRTTDelta: 15 * time.Millisecond, HoldTime: 5 * time.Minute},
	}
}

func TestImprovementExplainsLatencyWin(t *testing.T) {
	snap := Assemble(explainInput(plugin.CausePerformance, 0, 0, 60*time.Millisecond, 20*time.Millisecond))
	im := snap.Improvements[0]
	want := "lab-b is 40 ms faster (60 -> 20 ms, 67%), loss equal. Threshold 15 ms."
	if im.Explain != want {
		t.Fatalf("explain = %q, want %q", im.Explain, want)
	}
	if *im.GainMs != 40 || *im.NativeRTTMs != 60 || *im.RTTMs != 20 || *im.NativeLossPct != 0 || *im.LossPct != 0 {
		t.Fatalf("columns = %+v", im)
	}
	if im.HoldLeftS != 240 {
		t.Fatalf("hold left = %d, want 240", im.HoldLeftS)
	}
	if im.ASN != 64496 {
		t.Fatalf("asn = %d, want 64496", im.ASN)
	}
}

func TestImprovementExplainsPercentThreshold(t *testing.T) {
	in := explainInput(plugin.CausePerformance, 0.5, 0.2, 60*time.Millisecond, 20*time.Millisecond)
	in.Thresholds.MinRTTDeltaPct = 10
	got := Assemble(in).Improvements[0].Explain
	want := "lab-b is 40 ms faster (60 -> 20 ms, 67%), loss 0.5% -> 0.2%. Threshold 15 ms and 10%."
	if got != want {
		t.Fatalf("explain = %q, want %q", got, want)
	}
}

func TestImprovementExplainsLossWin(t *testing.T) {
	in := explainInput(plugin.CausePerformance, 4, 0.5, 30*time.Millisecond, 32*time.Millisecond)
	got := Assemble(in).Improvements[0].Explain
	want := "lab-b has 3.5 pt less loss (4% -> 0.5%), rtt 30 -> 32 ms. Threshold 1 pt of loss."
	if got != want {
		t.Fatalf("explain = %q, want %q", got, want)
	}
}

// A kept move whose gain shrank below the thresholds must not claim it
// beat them.
func TestImprovementBelowThresholdQuotesNone(t *testing.T) {
	for name, tc := range map[string]struct {
		natRTT, toRTT time.Duration
		pct           float64
	}{
		"under min_rtt_delta":     {25 * time.Millisecond, 20 * time.Millisecond, 0},
		"under min_rtt_delta_pct": {200 * time.Millisecond, 180 * time.Millisecond, 15},
	} {
		in := explainInput(plugin.CausePerformance, 0, 0, tc.natRTT, tc.toRTT)
		in.Thresholds.MinRTTDeltaPct = tc.pct
		im := Assemble(in).Improvements[0]
		if strings.Contains(im.Explain, "Threshold") || strings.Contains(im.Explain, "faster") {
			t.Errorf("%s: explain = %q quotes a threshold the move does not beat", name, im.Explain)
		}
		if !strings.HasSuffix(im.Explain, "under the thresholds now. It cleared them when chosen.") {
			t.Errorf("%s: explain = %q", name, im.Explain)
		}
		if im.GainMs == nil || *im.GainMs <= 0 || im.LossGainPct != nil {
			t.Errorf("%s: gain columns = %+v", name, im)
		}
	}
}

func TestImprovementLossGainOnlyWhenNotEqual(t *testing.T) {
	im := Assemble(explainInput(plugin.CausePerformance, 4, 0.5, 30*time.Millisecond, 32*time.Millisecond)).Improvements[0]
	if im.LossGainPct == nil || *im.LossGainPct != 3.5 {
		t.Fatalf("loss gain = %v, want 3.5", im.LossGainPct)
	}
	im = Assemble(explainInput(plugin.CausePerformance, 0.53, 0.5, 60*time.Millisecond, 20*time.Millisecond)).Improvements[0]
	if im.LossGainPct != nil || !strings.Contains(im.Explain, "loss equal") {
		t.Fatalf("loss gain = %v, explain = %q, want loss equal", im.LossGainPct, im.Explain)
	}
}

func TestImprovementExplainsOtherCause(t *testing.T) {
	got := Assemble(explainInput(plugin.CauseCommit, 0, 0, 60*time.Millisecond, 20*time.Millisecond)).Improvements[0].Explain
	if !strings.HasPrefix(got, "Commit control: ") || !strings.Contains(got, "lab-b measures rtt 60 -> 20 ms, loss 0% -> 0%.") {
		t.Fatalf("explain = %q", got)
	}
}

func TestImprovementWithoutMeasurementsKeepsReason(t *testing.T) {
	in := explainInput(plugin.CausePerformance, 0, 0, 60*time.Millisecond, 20*time.Millisecond)
	in.Decisions = nil
	im := Assemble(in).Improvements[0]
	if im.Explain != "lab-b: loss 0.0%->0.0%, rtt 60ms->20ms." {
		t.Fatalf("explain = %q", im.Explain)
	}
	if im.GainMs != nil || im.RTTMs != nil || im.NativeLossPct != nil {
		t.Fatalf("columns set without measurements: %+v", im)
	}
}

func TestImprovementHoldElapsed(t *testing.T) {
	in := explainInput(plugin.CausePerformance, 0, 0, 60*time.Millisecond, 20*time.Millisecond)
	in.Improvements[0].Since = in.At.Add(-10 * time.Minute)
	if got := Assemble(in).Improvements[0].HoldLeftS; got != 0 {
		t.Fatalf("hold left = %d, want 0 after hold_time", got)
	}
}

func TestWithASNamesPrefersWhoisThenProvider(t *testing.T) {
	imps := []Improvement{{Prefix: "198.51.100.0/24", ASN: 64496}, {Prefix: "203.0.113.0/24", ASN: 64497}, {Prefix: "192.0.2.0/24"}}
	providers := []Provider{{Name: "lab-b", ASN: 64497}}
	got := withASNames(imps, providers, map[uint32]string{64496: "EXAMPLE-NET"})
	if got[0].ASName != "EXAMPLE-NET" || got[1].ASName != "lab-b" || got[2].ASName != "" {
		t.Fatalf("names = %q %q %q", got[0].ASName, got[1].ASName, got[2].ASName)
	}
	if imps[0].ASName != "" {
		t.Fatal("input slice was changed")
	}
}

func TestAPIImprovementsCarryExplanation(t *testing.T) {
	in := explainInput(plugin.CausePerformance, 0, 0, 60*time.Millisecond, 20*time.Millisecond)
	snap := Assemble(in)
	snap.Providers = []Provider{{Name: "lab-origin", ASN: 64496}}
	ts := newTestServer(t, snap, "", "")
	code, _, body := do(t, "GET", ts.URL+"/api/improvements", "", "")
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	var doc struct {
		Improvements []Improvement `json:"improvements"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	im := doc.Improvements[0]
	if im.ASN != 64496 || im.ASName != "lab-origin" || !strings.Contains(im.Explain, "Threshold 15 ms.") || im.HoldLeftS != 240 {
		t.Fatalf("improvement = %+v", im)
	}
}
