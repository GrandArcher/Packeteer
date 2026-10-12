package policy

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func flapCfg() Config {
	c := cfg()
	c.HoldTime = time.Minute
	c.Flap = FlapConfig{MaxFlips: 3, Window: time.Hour, Cooldown: 10 * time.Minute, MaxCooldown: time.Hour}
	return c
}

var (
	bBetter = []m{{"a", 0, 50}, {"b", 0, 30}}
	aBetter = []m{{"a", 0, 30}, {"b", 0, 50}}
)

// oscillate feeds alternating latency every two minutes starting with b
// better. It returns the state and the time of the last round.
func oscillate(t *testing.T, st State, c Config, from time.Time, rounds int) (State, time.Time) {
	t.Helper()
	at := from
	for i := range rounds {
		ms := bBetter
		if i%2 == 1 {
			ms = aBetter
		}
		st, _ = step(t, st, c, at, ms)
		at = at.Add(2 * time.Minute)
	}
	return st, at.Add(-2 * time.Minute)
}

func TestFlapQuarantinesAfterNFlipsAndReleasesAfterCooldown(t *testing.T) {
	c := flapCfg()
	st := NewState()
	// improve (1), flip-back (2), improve (3): all allowed.
	st, last := oscillate(t, st, c, t0, 3)
	if _, ok := st.Improvements[pA]; !ok || len(st.quarantine) != 0 {
		t.Fatalf("after 3 flips: improvements %v quarantine %v", st.Improvements, st.quarantine)
	}
	// The 4th change, the flip-back, passes N=3: the route is withdrawn and the prefix parked.
	at := last.Add(2 * time.Minute)
	st, out := step(t, st, c, at, aBetter)
	q, ok := st.quarantine[pA]
	if !ok || len(st.Improvements) != 0 {
		t.Fatalf("not quarantined: %+v improvements %v", st.quarantine, st.Improvements)
	}
	if q.Flips != 4 || q.Strikes != 1 || !q.Until.Equal(at.Add(10*time.Minute)) {
		t.Fatalf("quarantine = %+v", q)
	}
	if len(out.Changes) != 1 || out.Changes[0].Action != ActionRetire {
		t.Fatalf("changes = %+v", out.Changes)
	}
	if len(out.Quarantines) != 1 || out.Quarantines[0].Action != QuarantineStart || out.Quarantines[0].Quarantine.Prefix != pA {
		t.Fatalf("quarantine events = %+v", out.Quarantines)
	}

	// A clear win for b while parked announces nothing and says why.
	for i := 1; i <= 4; i++ {
		st, out = step(t, st, c, at.Add(time.Duration(i)*2*time.Minute), bBetter)
		d := decision(t, out, pA)
		if len(st.Improvements) != 0 || len(out.Changes) != 0 || d.Action != ActionNone || !strings.Contains(d.Reason, "flap quarantine") {
			t.Fatalf("round %d while parked: %+v changes %+v", i, d, out.Changes)
		}
	}

	// Cool-down over: released, and the still-better path may be used again.
	st, out = step(t, st, c, at.Add(10*time.Minute), bBetter)
	if len(st.quarantine) != 0 || len(out.Quarantines) != 1 || out.Quarantines[0].Action != QuarantineRelease {
		t.Fatalf("release: quarantine %v events %+v", st.quarantine, out.Quarantines)
	}
	if imp, ok := st.Improvements[pA]; !ok || imp.Provider != "b" {
		t.Fatalf("released prefix not improved: %v", st.Improvements)
	}
}

func TestFlapCooldownGrowsOnRepeatOffense(t *testing.T) {
	c := flapCfg()
	st, last := oscillate(t, NewState(), c, t0, 3)
	at := last.Add(2 * time.Minute)
	st, _ = step(t, st, c, at, aBetter)
	first := st.quarantine[pA]

	// Release, then flip four more times inside MaxCooldown.
	at = first.Until
	st, _ = step(t, st, c, at, bBetter)
	if len(st.quarantine) != 0 {
		t.Fatal("not released")
	}
	for i := 1; i <= 3; i++ {
		ms := aBetter
		if i%2 == 0 {
			ms = bBetter
		}
		st, _ = step(t, st, c, at.Add(time.Duration(i)*2*time.Minute), ms)
	}
	at = at.Add(8 * time.Minute)
	st, _ = step(t, st, c, at, aBetter)
	q, ok := st.quarantine[pA]
	if !ok {
		t.Fatalf("second offense not quarantined: %v", st.Improvements)
	}
	if q.Strikes != 2 || q.Until.Sub(q.Since) != 20*time.Minute {
		t.Fatalf("second quarantine = %+v, want 2 strikes and 20m", q)
	}
}

func TestFlapCooldownIsCappedAndStrikesDecay(t *testing.T) {
	c := flapCfg()
	c.Flap.MaxCooldown = 15 * time.Minute
	st := NewState()
	var out Output
	st.offenses[pA] = offense{strikes: 5, last: t0}
	st.flips[pA] = []time.Time{t0, t0, t0}
	if q := st.quarantinePrefix(pA, t0.Add(time.Minute), c.Flap, &out); q.Until.Sub(q.Since) != 15*time.Minute || q.Strikes != 6 {
		t.Fatalf("capped quarantine = %+v", q)
	}
	// A prefix quiet for longer than MaxCooldown starts over.
	st.releaseQuarantine(pA, t0.Add(time.Minute))
	late := t0.Add(time.Hour)
	if q := st.quarantinePrefix(pA, late, c.Flap, &out); q.Strikes != 1 || q.Until.Sub(q.Since) != 10*time.Minute {
		t.Fatalf("decayed quarantine = %+v", q)
	}
	st.releaseQuarantine(pA, late)
	st.expireFlap(late.Add(2*time.Hour), c.Flap, &out)
	if len(st.offenses) != 0 || len(st.flips) != 0 {
		t.Fatalf("history not forgotten: %v %v", st.offenses, st.flips)
	}
}

func TestFlapSwitchBetweenProvidersQuarantines(t *testing.T) {
	c := flapCfg()
	c.Flap.MaxFlips = 2
	bc := func(cLoss float64) []m { return []m{{"a", 0, 80}, {"b", 0, 40}, {"c", 0, 40 + cLoss}} }
	st := NewState()
	// improve to b (1), switch to c (2), then the switch back to b is the third change.
	st, _ = step(t, st, c, t0, bc(0))
	st, out := step(t, st, c, t0.Add(2*time.Minute), []m{{"a", 0, 80}, {"b", 0, 60}, {"c", 0, 30}})
	if st.Improvements[pA].Provider != "c" || len(out.Changes) != 1 || out.Changes[0].Action != ActionSwitch {
		t.Fatalf("switch to c: %v %+v", st.Improvements, out.Changes)
	}
	st, out = step(t, st, c, t0.Add(4*time.Minute), []m{{"a", 0, 80}, {"b", 0, 30}, {"c", 0, 60}})
	if _, ok := st.Improvements[pA]; ok {
		t.Fatalf("improvement kept: %v", st.Improvements)
	}
	if len(out.Changes) != 1 || out.Changes[0].Action != ActionRetire || !strings.Contains(out.Changes[0].Old.Reason, "flap quarantine") {
		t.Fatalf("changes = %+v", out.Changes)
	}
	if len(out.Quarantines) != 1 || out.Quarantines[0].Action != QuarantineStart {
		t.Fatalf("events = %+v", out.Quarantines)
	}
}

func TestFlapOffAndWindow(t *testing.T) {
	// Off: the same oscillation never parks the prefix.
	c := flapCfg()
	c.Flap = FlapConfig{}
	st, _ := oscillate(t, NewState(), c, t0, 12)
	if len(st.quarantine) != 0 || len(st.flips) != 0 {
		t.Fatalf("flap off but state kept: %v %v", st.quarantine, st.flips)
	}

	// Flips older than the window do not count: one flip every 30 minutes
	// with a 40 minute window never reaches 3.
	c = flapCfg()
	c.Flap.Window = 40 * time.Minute
	c.ImprovementTTL = 0
	st = NewState()
	for i := range 8 {
		ms := bBetter
		if i%2 == 1 {
			ms = aBetter
		}
		st, _ = step(t, st, c, t0.Add(time.Duration(i)*30*time.Minute), ms)
	}
	if len(st.quarantine) != 0 {
		t.Fatalf("slow changes quarantined: %v", st.quarantine)
	}
}

func TestFlapTurnedOffReleases(t *testing.T) {
	c := flapCfg()
	st, last := oscillate(t, NewState(), c, t0, 3)
	at := last.Add(2 * time.Minute)
	st, _ = step(t, st, c, at, aBetter)
	if len(st.quarantine) != 1 {
		t.Fatal("not quarantined")
	}
	c.Flap = FlapConfig{}
	st, out := step(t, st, c, at.Add(2*time.Minute), bBetter)
	if len(st.quarantine) != 0 || len(out.Quarantines) != 1 || out.Quarantines[0].Action != QuarantineRelease {
		t.Fatalf("quarantine %v events %+v", st.quarantine, out.Quarantines)
	}
}

func TestEngineReleaseQuarantine(t *testing.T) {
	c := flapCfg()
	e := NewEngine(c, scorer(t))
	at := t0
	for i := range 4 {
		ms := bBetter
		if i%2 == 1 {
			ms = aBetter
		}
		e.Evaluate(in(results(at, pA, ms...), map[netip.Prefix]string{pA: "a"}), at)
		at = at.Add(2 * time.Minute)
	}
	qs := e.Quarantined()
	if len(qs) != 1 || qs[0].Prefix != pA {
		t.Fatalf("quarantined = %+v", qs)
	}
	if ch := e.QuarantineChanges(); len(ch) != 1 || ch[0].Action != QuarantineStart {
		t.Fatalf("changes = %+v", ch)
	}
	if _, ok := e.Release(pB, at); ok {
		t.Fatal("released a prefix that is not quarantined")
	}
	q, ok := e.Release(pA, at)
	if !ok || q.Prefix != pA || len(e.Quarantined()) != 0 {
		t.Fatalf("release = %+v %v, left %v", q, ok, e.Quarantined())
	}
	// Released by hand, the prefix is a repeat offender: strikes remembered.
	e.Evaluate(in(results(at, pA, bBetter...), map[netip.Prefix]string{pA: "a"}), at)
	if len(e.Improvements()) != 1 {
		t.Fatalf("improvements after release = %v", e.Improvements())
	}
}
