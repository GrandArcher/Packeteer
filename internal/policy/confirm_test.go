package policy

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func cand(loss, rttMs, score float64) Candidate {
	return Candidate{
		LossPct: loss,
		RTTAvg:  time.Duration(rttMs * float64(time.Millisecond)),
		Score:   score,
		Usable:  true,
	}
}

func TestRTTWinNeedsMillisecondsAndPercent(t *testing.T) {
	base := cfg()
	tests := []struct {
		name string
		pct  float64
		cur  Candidate
		alt  Candidate
		want bool
	}{
		{"percent off, 20ms wins", 0, cand(0, 50, 2), cand(0, 30, 1), true},
		{"40 percent of 50ms is 20ms, exact wins", 40, cand(0, 50, 2), cand(0, 30, 1), true},
		{"41 percent of 50ms misses", 41, cand(0, 50, 2), cand(0, 30, 1), false},
		{"20 percent of 100ms is 20ms, exact wins", 20, cand(0, 100, 2), cand(0, 80, 1), true},
		{"21 percent of 100ms misses", 21, cand(0, 100, 2), cand(0, 80, 1), false},
		{"milliseconds bind when the percent is smaller", 20, cand(0, 50, 2), cand(0, 35, 1), true},
		{"14ms misses the 15ms floor even though it clears 20 percent", 20, cand(0, 50, 2), cand(0, 36, 1), false},
		{"loss win ignores the percent", 90, cand(5, 20, 2), cand(0, 80, 1), true},
		{"more loss is not an RTT win", 0, cand(0, 80, 2), cand(3, 20, 1), false},
		{"equal score is not a win", 0, cand(0, 50, 1), cand(0, 30, 1), false},
		{"zero millisecond threshold never wins on RTT", 0, cand(0, 100, 2), cand(0, 10, 1), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base
			c.MinRTTDeltaPct = tt.pct
			if tt.name == "zero millisecond threshold never wins on RTT" {
				c.MinRTTDelta = 0
			}
			if got := better(tt.alt, tt.cur, c); got != tt.want {
				t.Fatalf("better = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecideRTTPercent(t *testing.T) {
	cases := []struct {
		name   string
		pct    float64
		ms     []m
		want   string
		reason string
	}{
		{"20ms is 40 percent, accepted", 40, []m{{"a", 0, 50}, {"b", 0, 30}}, ActionImprove, "b: loss"},
		{"20ms is under 41 percent", 41, []m{{"a", 0, 50}, {"b", 0, 30}}, ActionNone, "native path is best"},
		{"20ms of 100ms clears 20 percent", 20, []m{{"a", 0, 100}, {"b", 0, 80}}, ActionImprove, ""},
		{"20ms of 100ms misses 21 percent", 21, []m{{"a", 0, 100}, {"b", 0, 80}}, ActionNone, "native path is best"},
		{"15ms binds over a 20 percent floor of 10ms", 20, []m{{"a", 0, 50}, {"b", 0, 35}}, ActionImprove, ""},
		{"14ms misses the millisecond floor", 20, []m{{"a", 0, 50}, {"b", 0, 36}}, ActionNone, "native path is best"},
		{"loss win ignores a high percent", 90, []m{{"a", 5, 20}, {"b", 0, 80}}, ActionImprove, ""},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := cfg()
			c.MinRTTDeltaPct = tt.pct
			_, out := Decide(NewState(), in(results(t0, pA, tt.ms...), map[netip.Prefix]string{pA: "a"}), c, scorer(t), t0)
			d := decision(t, out, pA)
			if d.Action != tt.want || (tt.reason != "" && !strings.Contains(d.Reason, tt.reason)) {
				t.Fatalf("decision = %+v", d)
			}
		})
	}
}

func step(t *testing.T, st State, c Config, at time.Time, ms []m) (State, Output) {
	t.Helper()
	return Decide(st, in(results(at, pA, ms...), map[netip.Prefix]string{pA: "a"}), c, scorer(t), at)
}

func TestConfirmRounds(t *testing.T) {
	c := cfg()
	c.ConfirmRounds = 3
	win := []m{{"a", 0, 90}, {"b", 0, 30}}

	st, out := step(t, NewState(), c, t0, win)
	d := decision(t, out, pA)
	if d.Action != ActionNone || !strings.Contains(d.Reason, "confirming b (1/3)") || len(st.Improvements) != 0 || len(out.Changes) != 0 {
		t.Fatalf("first win: %+v %+v", d, out.Changes)
	}
	if st.confirm[pA].Streak != 1 || st.confirm[pA].Provider != "b" {
		t.Fatalf("streak = %+v", st.confirm[pA])
	}
	if len(out.Urgent) != 1 || out.Urgent[0] != pA {
		t.Fatalf("urgent = %v", out.Urgent)
	}

	// Same measurements, later clock: a RIB re-eval is not a new round.
	// It is still a comparison, so the early probe stays requested.
	st, out = Decide(st, in(results(t0, pA, win...), map[netip.Prefix]string{pA: "a"}), c, scorer(t), t0.Add(30*time.Second))
	d = decision(t, out, pA)
	if st.confirm[pA].Streak != 1 || !strings.Contains(d.Reason, "confirming b (1/3)") || len(st.Improvements) != 0 || len(out.Urgent) != 1 {
		t.Fatalf("repeat counted: streak=%d decision=%+v urgent=%v", st.confirm[pA].Streak, d, out.Urgent)
	}

	st, out = step(t, st, c, t0.Add(time.Minute), win)
	if st.confirm[pA].Streak != 2 || !strings.Contains(decision(t, out, pA).Reason, "confirming b (2/3)") || len(st.Improvements) != 0 {
		t.Fatalf("second fresh: streak=%d %+v", st.confirm[pA].Streak, decision(t, out, pA))
	}
	if len(out.Urgent) != 1 || out.Urgent[0] != pA {
		t.Fatalf("urgent during the streak = %v", out.Urgent)
	}

	st, out = step(t, st, c, t0.Add(2*time.Minute), win)
	d = decision(t, out, pA)
	if d.Action != ActionImprove || st.Improvements[pA].Provider != "b" || len(out.Changes) != 1 {
		t.Fatalf("third fresh: %+v %+v", d, st.Improvements)
	}
	if _, ok := st.confirm[pA]; ok || len(out.Urgent) != 0 {
		t.Fatalf("streak or urgent survived the announce: %+v %v", st.confirm, out.Urgent)
	}
}

func TestConfirmRoundsLossResets(t *testing.T) {
	c := cfg()
	c.ConfirmRounds = 3
	st, _ := step(t, NewState(), c, t0, []m{{"a", 0, 90}, {"b", 0, 30}})
	if st.confirm[pA].Streak != 1 {
		t.Fatal(st.confirm[pA])
	}
	// 10ms is inside the 15ms floor.
	st, out := step(t, st, c, t0.Add(time.Minute), []m{{"a", 0, 50}, {"b", 0, 40}})
	d := decision(t, out, pA)
	if _, ok := st.confirm[pA]; ok || !strings.Contains(d.Reason, "native path is best") || len(st.Improvements) != 0 {
		t.Fatalf("loss did not reset: streak=%+v decision=%+v", st.confirm[pA], d)
	}
	st, out = step(t, st, c, t0.Add(2*time.Minute), []m{{"a", 0, 90}, {"b", 0, 30}})
	if st.confirm[pA].Streak != 1 || !strings.Contains(decision(t, out, pA).Reason, "confirming b (1/3)") {
		t.Fatalf("next win = %+v %+v", st.confirm[pA], decision(t, out, pA))
	}
}

func TestConfirmRoundsInterruptedByAnotherProvider(t *testing.T) {
	c := cfg()
	c.ConfirmRounds = 3
	st, _ := step(t, NewState(), c, t0, []m{{"a", 0, 90}, {"b", 0, 30}})
	if st.confirm[pA].Provider != "b" || st.confirm[pA].Streak != 1 {
		t.Fatal(st.confirm[pA])
	}
	// c is the new best. The streak starts over at 1, not 2.
	st, out := step(t, st, c, t0.Add(time.Minute), []m{{"a", 0, 90}, {"b", 0, 40}, {"c", 0, 20}})
	if st.confirm[pA].Provider != "c" || st.confirm[pA].Streak != 1 || !strings.Contains(decision(t, out, pA).Reason, "confirming c (1/3)") {
		t.Fatalf("interrupt = %+v %+v", st.confirm[pA], decision(t, out, pA))
	}
	st, out = step(t, st, c, t0.Add(2*time.Minute), []m{{"a", 0, 90}, {"b", 0, 40}, {"c", 0, 20}})
	if st.confirm[pA].Streak != 2 || len(st.Improvements) != 0 {
		t.Fatalf("second c win announced or skipped: %+v %+v", st.confirm[pA], decision(t, out, pA))
	}
	st, out = step(t, st, c, t0.Add(3*time.Minute), []m{{"a", 0, 90}, {"b", 0, 40}, {"c", 0, 20}})
	if decision(t, out, pA).Action != ActionImprove || st.Improvements[pA].Provider != "c" {
		t.Fatalf("third c win = %+v %+v", decision(t, out, pA), st.Improvements)
	}
}

func TestConfirmRoundsStaleDoesNotCount(t *testing.T) {
	c := cfg()
	c.ConfirmRounds = 3
	win := []m{{"a", 0, 90}, {"b", 0, 30}}
	st, _ := step(t, NewState(), c, t0, win)
	if st.confirm[pA].Streak != 1 {
		t.Fatal(st.confirm[pA])
	}

	staleAt := t0.Add(10 * time.Minute)
	st, out := Decide(st, in(results(t0, pA, win...), map[netip.Prefix]string{pA: "a"}), c, scorer(t), staleAt)
	d := decision(t, out, pA)
	if st.confirm[pA].Streak != 1 || !strings.Contains(d.Reason, "stale") || len(st.Improvements) != 0 || len(out.Urgent) != 0 {
		t.Fatalf("stale round: streak=%+v decision=%+v urgent=%v", st.confirm[pA], d, out.Urgent)
	}

	// A provider-down round is not a comparison, so it does not reset either,
	// and it does not ask for another probe.
	down := in(results(t0.Add(11*time.Minute), pA, win...), map[netip.Prefix]string{pA: "a"})
	down.ProviderUp = map[string]bool{"b": true}
	st, out = Decide(st, down, c, scorer(t), t0.Add(11*time.Minute))
	if st.confirm[pA].Streak != 1 || !strings.Contains(decision(t, out, pA).Reason, "provider down") || len(out.Urgent) != 0 {
		t.Fatalf("provider down reset the streak: %+v %+v urgent=%v", st.confirm[pA], decision(t, out, pA), out.Urgent)
	}

	st, out = step(t, st, c, t0.Add(12*time.Minute), win)
	if st.confirm[pA].Streak != 2 || len(st.Improvements) != 0 {
		t.Fatalf("first fresh after stale = %+v %+v", st.confirm[pA], decision(t, out, pA))
	}
	st, out = step(t, st, c, t0.Add(13*time.Minute), win)
	if decision(t, out, pA).Action != ActionImprove || st.Improvements[pA].Provider != "b" {
		t.Fatalf("second fresh after stale = %+v", decision(t, out, pA))
	}
}

func TestConfirmRoundsDoesNotDelayFlipBackOrStatic(t *testing.T) {
	c := cfg()
	c.ConfirmRounds = 5
	s := NewState()
	s.Improvements[pA] = Improvement{Prefix: pA, Provider: "b", Native: "a", Since: t0, nativeSeen: t0, nativeHeld: true}
	at := t0.Add(20 * time.Minute)
	st, out := step(t, s, c, at, []m{{"a", 0, 20}, {"b", 0, 80}})
	d := decision(t, out, pA)
	if d.Action != ActionRetire || !strings.Contains(d.Reason, "native path better") || len(st.Improvements) != 0 {
		t.Fatalf("flip-back waited: %+v %+v", d, st.Improvements)
	}
	if strings.Contains(d.Reason, "confirming") {
		t.Fatalf("flip-back reason %q", d.Reason)
	}

	// A static pin is created on the first round.
	input := withPolicy(routingInput(), pA, verdict(plugin.PolicyStatic, "c"))
	st, out = Decide(NewState(), input, c, scorer(t), t0)
	d = decision(t, out, pA)
	if d.Action != ActionImprove || st.Improvements[pA].Provider != "c" || st.Improvements[pA].Cause != plugin.CauseStatic {
		t.Fatalf("static pin waited: %+v %+v", d, st.Improvements[pA])
	}
}

func TestConfirmRoundsSwitch(t *testing.T) {
	c := cfg()
	c.ConfirmRounds = 3
	s := NewState()
	s.Improvements[pA] = Improvement{Prefix: pA, Provider: "b", Native: "a", Since: t0, nativeSeen: t0, nativeHeld: true}
	ms := []m{{"a", 0, 90}, {"b", 0, 60}, {"c", 0, 20}}
	native := map[netip.Prefix]string{pA: "a"}

	// Inside hold the wins still count, and the switch waits for hold time.
	at := t0.Add(time.Minute)
	st, out := Decide(s, in(results(at, pA, ms...), native), c, scorer(t), at)
	if decision(t, out, pA).Action != ActionKeep || !strings.Contains(decision(t, out, pA).Reason, "confirming switch to c (1/3)") || st.Improvements[pA].Provider != "b" {
		t.Fatalf("inside hold: %+v %+v", decision(t, out, pA), st.Improvements[pA])
	}
	at = t0.Add(2 * time.Minute)
	st, out = Decide(st, in(results(at, pA, ms...), native), c, scorer(t), at)
	if st.confirm[pA].Streak != 2 || st.Improvements[pA].Provider != "b" {
		t.Fatalf("second win inside hold: %+v", st.confirm[pA])
	}
	at = t0.Add(3 * time.Minute)
	st, out = Decide(st, in(results(at, pA, ms...), native), c, scorer(t), at)
	d := decision(t, out, pA)
	if d.Action != ActionKeep || !strings.Contains(d.Reason, "improvement still valid") || st.Improvements[pA].Provider != "b" || st.confirm[pA].Streak < 3 {
		t.Fatalf("confirmed but held: %+v streak=%+v", d, st.confirm[pA])
	}

	at = t0.Add(20 * time.Minute)
	st, out = Decide(st, in(results(at, pA, ms...), native), c, scorer(t), at)
	if st.Improvements[pA].Provider != "c" || out.Changes[0].Action != ActionSwitch || len(out.Urgent) != 0 {
		t.Fatalf("switch after hold: %+v %+v urgent=%v", st.Improvements[pA], out.Changes, out.Urgent)
	}
}

func TestConfirmRoundsDefaultAnnouncesImmediately(t *testing.T) {
	win := []m{{"a", 0, 90}, {"b", 0, 30}}
	for _, rounds := range []int{0, 1} {
		c := cfg()
		c.ConfirmRounds = rounds
		st, out := step(t, NewState(), c, t0, win)
		if decision(t, out, pA).Action != ActionImprove || st.Improvements[pA].Provider != "b" || len(out.Urgent) != 0 {
			t.Fatalf("rounds %d: %+v urgent=%v", rounds, decision(t, out, pA), out.Urgent)
		}
	}
}

func TestConfirmRoundsClearedWhenThePrefixLeaves(t *testing.T) {
	c := cfg()
	c.ConfirmRounds = 3
	win := []m{{"a", 0, 90}, {"b", 0, 30}}
	st, _ := step(t, NewState(), c, t0, win)
	if st.confirm[pA].Streak != 1 {
		t.Fatal(st.confirm[pA])
	}

	left := in(results(t0.Add(time.Minute), pA, win...), map[netip.Prefix]string{})
	st, out := Decide(st, left, c, scorer(t), t0.Add(time.Minute))
	if _, ok := st.confirm[pA]; ok || !strings.Contains(decision(t, out, pA).Reason, "not in RIB") {
		t.Fatalf("RIB leave: %+v %+v", st.confirm, decision(t, out, pA))
	}
	st, _ = step(t, st, c, t0.Add(2*time.Minute), win)
	if st.confirm[pA].Streak != 1 || len(st.Improvements) != 0 {
		t.Fatalf("return did not start over: %+v", st.confirm[pA])
	}

	down := in(results(t0.Add(3*time.Minute), pA, win...), map[netip.Prefix]string{pA: "a"})
	down.RIBReady = false
	st, _ = Decide(st, down, c, scorer(t), t0.Add(3*time.Minute))
	if len(st.confirm) != 0 {
		t.Fatalf("RIB not ready kept %+v", st.confirm)
	}
	st, _ = step(t, st, c, t0.Add(4*time.Minute), win)
	if st.confirm[pA].Streak != 1 {
		t.Fatalf("after session loss streak = %+v", st.confirm[pA])
	}
}

func TestConfirmRoundsAllowlistAndCap(t *testing.T) {
	c := cfg()
	c.ConfirmRounds = 2
	c.Mode = "inject"
	c.Allowlist = []netip.Prefix{pB}
	win := []m{{"a", 0, 90}, {"b", 0, 30}}
	st, out := step(t, NewState(), c, t0, win)
	if _, ok := st.confirm[pA]; ok || !strings.Contains(decision(t, out, pA).Reason, "not allowlisted") {
		t.Fatalf("allowlist counted a blocked move: %+v %+v", st.confirm, decision(t, out, pA))
	}
	c.Allowlist = []netip.Prefix{pA}
	st, out = step(t, st, c, t0.Add(time.Minute), win)
	if st.confirm[pA].Streak != 1 || len(st.Improvements) != 0 {
		t.Fatalf("first allowed round = %+v %+v", st.confirm[pA], decision(t, out, pA))
	}

	c = cfg()
	c.ConfirmRounds = 2
	c.MaxImprovements = 0
	st, out = step(t, NewState(), c, t0, win)
	if len(out.Urgent) != 1 || st.confirm[pA].Streak != 1 {
		t.Fatalf("before the cap: %+v urgent=%v", st.confirm[pA], out.Urgent)
	}
	st, out = step(t, st, c, t0.Add(time.Minute), win)
	d := decision(t, out, pA)
	if d.Action != ActionCapped || st.confirm[pA].Streak != 2 || len(st.Improvements) != 0 || len(out.Urgent) != 0 {
		t.Fatalf("capped: %+v streak=%+v urgent=%v", d, st.confirm[pA], out.Urgent)
	}
	// The same round must not make a capped prefix start over.
	st, out = Decide(st, in(results(t0.Add(time.Minute), pA, win...), map[netip.Prefix]string{pA: "a"}), c, scorer(t), t0.Add(time.Minute))
	if decision(t, out, pA).Action != ActionCapped || st.confirm[pA].Streak != 2 {
		t.Fatalf("capped prefix restarted: %+v %+v", decision(t, out, pA), st.confirm[pA])
	}
	c.MaxImprovements = 1
	st, out = Decide(st, in(results(t0.Add(time.Minute), pA, win...), map[netip.Prefix]string{pA: "a"}), c, scorer(t), t0.Add(time.Minute))
	if decision(t, out, pA).Action != ActionImprove || st.Improvements[pA].Provider != "b" {
		t.Fatalf("cap opened: %+v %+v", decision(t, out, pA), st.Improvements)
	}
}

func TestConfirmRoundsOnCommitSwitch(t *testing.T) {
	c := commitCfg()
	c.ConfirmRounds = 2
	s := NewState()
	s.Improvements[pA] = Improvement{
		Prefix: pA, Provider: "b", Native: "a", Since: t0, Cause: plugin.CauseCommit,
		nativeSeen: t0, nativeHeld: true,
	}
	ms := []m{{"a", 0, 90}, {"b", 0, 60}, {"c", 0, 20}}
	native := map[netip.Prefix]string{pA: "a"}
	sc := commitScorer(t, "")

	// Wins count during hold_time, the same as a performance improvement.
	// The switch itself waits until hold_time has elapsed.
	at := t0.Add(time.Minute)
	st, out := Decide(s, in(results(at, pA, ms...), native), c, sc, at)
	d := decision(t, out, pA)
	if d.Action != ActionKeep || !strings.Contains(d.Reason, "confirming switch to c (1/2)") || st.confirm[pA].Streak != 1 || st.Improvements[pA].Provider != "b" || len(out.Urgent) != 1 {
		t.Fatalf("held commit switch: %+v streak=%+v urgent=%v", d, st.confirm[pA], out.Urgent)
	}

	at = t0.Add(2 * time.Minute)
	st, out = Decide(st, in(results(at, pA, ms...), native), c, sc, at)
	d = decision(t, out, pA)
	if d.Action != ActionKeep || !strings.Contains(d.Reason, "hold_time") || st.confirm[pA].Streak != 2 || st.Improvements[pA].Provider != "b" || len(out.Urgent) != 0 {
		t.Fatalf("confirmed during hold: %+v streak=%+v urgent=%v", d, st.confirm[pA], out.Urgent)
	}

	at = t0.Add(20 * time.Minute)
	st, out = Decide(st, in(results(at, pA, ms...), native), c, sc, at)
	d = decision(t, out, pA)
	if d.Action != ActionSwitch || st.Improvements[pA].Provider != "c" || st.Improvements[pA].Cause != plugin.CausePerformance || out.Changes[0].Action != ActionSwitch {
		t.Fatalf("commit switch: %+v imp=%+v changes=%+v", d, st.Improvements[pA], out.Changes)
	}
}

func TestConfirmRoundsNativeDownDoesNotUrgentProbe(t *testing.T) {
	c := cfg()
	c.ConfirmRounds = 3
	win := []m{{"a", 0, 90}, {"b", 0, 30}}
	st, out := step(t, NewState(), c, t0, win)
	if st.confirm[pA].Streak != 1 || len(out.Urgent) != 1 {
		t.Fatalf("start %+v urgent=%v", st.confirm[pA], out.Urgent)
	}
	// The native provider stays down. The streak is kept, and the prefix
	// is not probed early on every round.
	for i := 1; i <= 4; i++ {
		at := t0.Add(time.Duration(i) * time.Minute)
		down := in(results(at, pA, win...), map[netip.Prefix]string{pA: "a"})
		down.ProviderUp = map[string]bool{"b": true}
		st, out = Decide(st, down, c, scorer(t), at)
		d := decision(t, out, pA)
		if st.confirm[pA].Streak != 1 || st.confirm[pA].Provider != "b" || len(out.Urgent) != 0 || !strings.Contains(d.Reason, "provider down") {
			t.Fatalf("down round %d: streak=%+v urgent=%v reason=%s", i, st.confirm[pA], out.Urgent, d.Reason)
		}
	}
	at := t0.Add(5 * time.Minute)
	none := in(results(at, pA, win...), map[netip.Prefix]string{pA: ""})
	st, out = Decide(st, none, c, scorer(t), at)
	if st.confirm[pA].Streak != 1 || len(out.Urgent) != 0 || !strings.Contains(decision(t, out, pA).Reason, "matches no provider") {
		t.Fatalf("no provider: %+v urgent=%v reason=%s", st.confirm[pA], out.Urgent, decision(t, out, pA).Reason)
	}
	// A cooldown is not a comparison either.
	st.Cooldown[pA] = t0.Add(time.Hour)
	at = t0.Add(6 * time.Minute)
	st, out = Decide(st, in(results(at, pA, win...), map[netip.Prefix]string{pA: "a"}), c, scorer(t), at)
	if st.confirm[pA].Streak != 1 || len(out.Urgent) != 0 || !strings.Contains(decision(t, out, pA).Reason, "cooldown") {
		t.Fatalf("cooldown: %+v urgent=%v reason=%s", st.confirm[pA], out.Urgent, decision(t, out, pA).Reason)
	}
	delete(st.Cooldown, pA)
	// A static pin that cannot be used does not wake the prober either.
	at = t0.Add(7 * time.Minute)
	pinned := withPolicy(in(results(at, pA, win...), map[netip.Prefix]string{pA: "a"}), pA, staticVerdict("c", 100, time.Hour))
	pinned.ProviderUp = map[string]bool{"a": true, "b": true}
	st, out = Decide(st, pinned, c, scorer(t), at)
	if st.confirm[pA].Streak != 1 || len(out.Urgent) != 0 || len(st.Improvements) != 0 || !strings.Contains(decision(t, out, pA).Reason, "not usable") {
		t.Fatalf("static: %+v urgent=%v improvements=%v reason=%s", st.confirm[pA], out.Urgent, st.Improvements, decision(t, out, pA).Reason)
	}
	st, out = step(t, st, c, t0.Add(8*time.Minute), win)
	if st.confirm[pA].Streak != 2 || len(out.Urgent) != 1 || len(st.Improvements) != 0 {
		t.Fatalf("recovered: %+v urgent=%v", st.confirm[pA], out.Urgent)
	}
}

func TestConfirmRoundsCommitMissResets(t *testing.T) {
	c := commitCfg()
	c.ConfirmRounds = 3
	s := NewState()
	s.Improvements[pA] = Improvement{
		Prefix: pA, Provider: "b", Native: "a", Since: t0, Cause: plugin.CauseCommit,
		nativeSeen: t0, nativeHeld: true,
	}
	native := map[netip.Prefix]string{pA: "a"}
	sc := commitScorer(t, "")
	win := []m{{"a", 0, 90}, {"b", 0, 60}, {"c", 0, 20}}
	// Inside hold_time the steer stays up, so a miss has to clear the
	// streak itself. Past hold, a relieved commit steer retires and
	// deletes the streak on the way out.
	at := t0.Add(time.Minute)
	st, out := Decide(s, in(results(at, pA, win...), native), c, sc, at)
	if st.confirm[pA].Streak != 1 || len(out.Urgent) != 1 || st.Improvements[pA].Provider != "b" {
		t.Fatalf("first win: %+v urgent=%v imp=%+v", st.confirm[pA], out.Urgent, st.Improvements[pA])
	}
	// 5ms is inside the 15ms floor: a fresh miss, not a stale round.
	at = t0.Add(2 * time.Minute)
	miss := []m{{"a", 0, 40}, {"b", 0, 50}, {"c", 0, 35}}
	st, out = Decide(st, in(results(at, pA, miss...), native), c, sc, at)
	d := decision(t, out, pA)
	if _, ok := st.confirm[pA]; ok || len(out.Urgent) != 0 || d.Action == ActionSwitch || st.Improvements[pA].Provider != "b" {
		t.Fatalf("miss kept %+v urgent=%v decision=%+v imp=%+v", st.confirm, out.Urgent, d, st.Improvements[pA])
	}
	at = t0.Add(3 * time.Minute)
	st, out = Decide(st, in(results(at, pA, win...), native), c, sc, at)
	if st.confirm[pA].Streak != 1 || !strings.Contains(decision(t, out, pA).Reason, "confirming switch to c (1/3)") || st.Improvements[pA].Provider != "b" {
		t.Fatalf("next win = %+v %+v imp=%+v", st.confirm[pA], decision(t, out, pA), st.Improvements[pA])
	}
}
