package policy

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var (
	synLo = netip.MustParsePrefix("198.51.100.0/25")
	synHi = netip.MustParsePrefix("198.51.100.128/25")
)

// synthResults is pA measured as two /25s of equal weight: b is much
// faster toward synLo, a toward synHi, so the aggregate keeps native a.
func synthResults(at time.Time) []probe.Result {
	rtt := map[string][2]float64{"a": {80, 10}, "b": {10, 80}}
	out := results(at, pA, m{"a", 0, 45}, m{"b", 0, 45})
	for i, r := range out {
		v := rtt[r.Provider]
		r.Subranges = []probe.SubrangeResult{
			{Prefix: synLo, Weight: 1, Time: at, Stats: probe.Stats{Sent: 5, Received: 5, RTTAvg: time.Duration(v[0] * float64(time.Millisecond))}},
			{Prefix: synHi, Weight: 1, Time: at, Stats: probe.Stats{Sent: 5, Received: 5, RTTAvg: time.Duration(v[1] * float64(time.Millisecond))}},
		}
		out[i] = r
	}
	return out
}

func synthInput(at time.Time, native map[netip.Prefix]string) Input {
	input := in(synthResults(at), native)
	input.Synthesize = map[netip.Prefix]netip.Prefix{synLo: pA, synHi: pA}
	return input
}

func TestSynthesizeOffDecidesOnlyTheLearnedPrefix(t *testing.T) {
	input := in(synthResults(t0), map[netip.Prefix]string{pA: "a"})
	st, out := Decide(NewState(), input, cfg(), scorer(t), t0)
	if len(out.Decisions) != 1 || out.Decisions[0].Prefix != pA || len(st.Improvements) != 0 {
		t.Fatalf("decisions %+v improvements %+v", out.Decisions, st.Improvements)
	}
}

func TestSynthesizeDecidesSubrangeAsItsOwnPrefix(t *testing.T) {
	native := map[netip.Prefix]string{pA: "a"}
	input := synthInput(t0, native)
	st, out := Decide(NewState(), input, cfg(), scorer(t), t0)
	if d := decision(t, out, pA); d.Action != ActionNone || d.Covering.IsValid() {
		t.Fatalf("covering decision = %+v", d)
	}
	d := decision(t, out, synLo)
	if d.Action != ActionImprove || d.Current != "b" || d.Native != "a" || d.Covering != pA {
		t.Fatalf("sub-range decision = %+v", d)
	}
	if d := decision(t, out, synHi); d.Action != ActionNone || d.Covering != pA || d.Native != "a" {
		t.Fatalf("native-best sub-range = %+v", d)
	}
	imp, ok := st.Improvements[synLo]
	if !ok || imp.Covering != pA || imp.Provider != "b" || imp.Native != "a" || len(st.Improvements) != 1 {
		t.Fatalf("improvements = %+v", st.Improvements)
	}
	if len(out.Changes) != 1 || out.Changes[0].New.Covering != pA {
		t.Fatalf("changes = %+v", out.Changes)
	}
	// The caller's input is not changed.
	if len(input.Results) != 2 || len(native) != 1 {
		t.Fatalf("input changed: %d results, native %v", len(input.Results), native)
	}
}

func TestSynthesizeKeepsConfirmRoundsAndCap(t *testing.T) {
	native := map[netip.Prefix]string{pA: "a"}
	c := cfg()
	c.ConfirmRounds = 2
	st, out := Decide(NewState(), synthInput(t0, native), c, scorer(t), t0)
	if d := decision(t, out, synLo); d.Action != ActionNone || !strings.Contains(d.Reason, "confirming b (1/2)") {
		t.Fatalf("first round = %+v", d)
	}
	t1 := t0.Add(30 * time.Second)
	st, out = Decide(st, synthInput(t1, native), c, scorer(t), t1)
	if d := decision(t, out, synLo); d.Action != ActionImprove {
		t.Fatalf("second round = %+v", d)
	}
	if _, ok := st.Improvements[synLo]; !ok {
		t.Fatal("no improvement after confirm_rounds")
	}

	c = cfg()
	c.MaxImprovements = 0
	st, out = Decide(NewState(), synthInput(t0, native), c, scorer(t), t0)
	if d := decision(t, out, synLo); d.Action != ActionCapped || len(st.Improvements) != 0 {
		t.Fatalf("cap = %+v", d)
	}
}

func TestSynthesizeNeedsTheCoveringPrefixInRIB(t *testing.T) {
	st, out := Decide(NewState(), synthInput(t0, map[netip.Prefix]string{}), cfg(), scorer(t), t0)
	if d := decision(t, out, synLo); d.Action != ActionNone || d.Reason != "covering prefix 198.51.100.0/24 not in RIB" {
		t.Fatalf("decision = %+v", d)
	}
	if len(st.Improvements) != 0 {
		t.Fatalf("improvements = %+v", st.Improvements)
	}
}

// The covering prefix leaving the RIB retires the sub-range by the
// NativePathConfirm rule, with the cooldown a real leave gets.
func TestSynthesizeRetiresWhenCoveringPrefixLeaves(t *testing.T) {
	c := cfg()
	native := map[netip.Prefix]string{pA: "a"}
	st, _ := Decide(NewState(), synthInput(t0, native), c, scorer(t), t0)
	t1 := t0.Add(time.Second)
	st, _ = Decide(st, synthInput(t1, native), c, scorer(t), t1)
	// Gone briefly before confirmation: kept.
	t2 := t1.Add(time.Second)
	st, out := Decide(st, synthInput(t2, map[netip.Prefix]string{}), c, scorer(t), t2)
	if d := decision(t, out, synLo); d.Action != ActionKeep {
		t.Fatalf("brief gap = %+v", d)
	}
	t3 := t2.Add(time.Second)
	st, _ = Decide(st, synthInput(t3, native), c, scorer(t), t3)
	t4 := t3.Add(NativePathConfirm + time.Second)
	st, _ = Decide(st, synthInput(t4, native), c, scorer(t), t4)
	t5 := t4.Add(time.Second)
	st, out = Decide(st, synthInput(t5, map[netip.Prefix]string{}), c, scorer(t), t5)
	if d := decision(t, out, synLo); d.Action != ActionRetire || d.Reason != "prefix no longer in RIB" {
		t.Fatalf("leave = %+v", d)
	}
	if _, ok := st.Improvements[synLo]; ok {
		t.Fatal("still improved after the covering prefix left")
	}
	if _, cool := st.Cooldown[synLo]; !cool {
		t.Fatal("no cooldown after a real leave")
	}
}

func TestSynthesizeRetiresWhenNoLongerEligible(t *testing.T) {
	native := map[netip.Prefix]string{pA: "a"}
	st, _ := Decide(NewState(), synthInput(t0, native), cfg(), scorer(t), t0)
	t1 := t0.Add(time.Second)
	input := synthInput(t1, native)
	delete(input.Synthesize, synLo)
	st, out := Decide(st, input, cfg(), scorer(t), t1)
	if _, ok := st.Improvements[synLo]; ok {
		t.Fatal("kept after leaving Synthesize")
	}
	if len(out.Changes) != 1 || out.Changes[0].Action != ActionRetire || out.Changes[0].Old.Reason != "sub-range no longer measured or no longer eligible to synthesize" {
		t.Fatalf("changes = %+v", out.Changes)
	}
}

func TestSynthesizeSkipsPinnedOrIgnoredCoveringPrefix(t *testing.T) {
	native := map[netip.Prefix]string{pA: "a"}
	for _, v := range []plugin.PolicyVerdict{
		{Action: plugin.PolicyIgnore, Rule: "skip"},
		{Action: plugin.PolicyStatic, Rule: "pin", Providers: []string{"a"}},
	} {
		input := synthInput(t0, native)
		input.Policies = map[netip.Prefix]plugin.PolicyVerdict{pA: v}
		st, out := Decide(NewState(), input, cfg(), scorer(t), t0)
		for _, d := range out.Decisions {
			if d.Prefix != pA {
				t.Fatalf("%s: sub-range decided under a %s covering prefix: %+v", v.Action, v.Action, d)
			}
		}
		if _, ok := st.Improvements[synLo]; ok {
			t.Fatalf("%s: sub-range improved", v.Action)
		}
	}
}
