package policy

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// parked returns a state with pA in flap quarantine and the time of the
// round that parked it. The quarantine lasts 10 minutes from there.
func parked(t *testing.T, c Config) (State, time.Time) {
	t.Helper()
	st, last := oscillate(t, NewState(), c, t0, 3)
	at := last.Add(2 * time.Minute)
	st, _ = step(t, st, c, at, aBetter)
	if _, ok := st.quarantine[pA]; !ok {
		t.Fatalf("not quarantined: %+v", st.quarantine)
	}
	return st, at
}

// Per prefix, a policy ignore is checked before the flap quarantine, and
// the quarantine before a static pin: a pin or a faster provider does not
// take a parked prefix off its native path, and ignore says so first
// (docs/precedence.md).
func TestQuarantineOutranksStaticPinAndIgnoreOutranksQuarantine(t *testing.T) {
	c := flapCfg()
	st, at := parked(t, c)
	later := at.Add(2 * time.Minute)
	input := func(v plugin.PolicyVerdict) Input {
		return withPolicy(in(results(later, pA, bBetter...), map[netip.Prefix]string{pA: "a"}), pA, v)
	}

	next, out := Decide(st, input(verdict(plugin.PolicyStatic, "b")), c, scorer(t), later)
	d := decision(t, out, pA)
	if _, on := next.Improvements[pA]; on || len(out.Changes) != 0 || !strings.Contains(d.Reason, "flap quarantine") {
		t.Fatalf("static pin on a parked prefix: improvements %v changes %v decision %+v", next.Improvements, out.Changes, d)
	}

	next, out = Decide(st, input(verdict(plugin.PolicyIgnore)), c, scorer(t), later)
	d = decision(t, out, pA)
	if _, on := next.Improvements[pA]; on || !strings.Contains(d.Reason, "policy ignore") {
		t.Fatalf("ignore on a parked prefix: improvements %v decision %+v", next.Improvements, d)
	}
	if _, still := next.quarantine[pA]; !still {
		t.Fatal("an ignore must not end the quarantine")
	}

	// Once the cool-down ends the same pin applies.
	after := at.Add(11 * time.Minute)
	next, out = Decide(st, withPolicy(in(results(after, pA, bBetter...), map[netip.Prefix]string{pA: "a"}), pA, verdict(plugin.PolicyStatic, "b")), c, scorer(t), after)
	if imp, on := next.Improvements[pA]; !on || imp.Provider != "b" || imp.Cause != plugin.CauseStatic {
		t.Fatalf("pin after the cool-down: improvements %v decision %+v", next.Improvements, decision(t, out, pA))
	}
}
