package policy

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// A partial-table or default-only provider sends a default route (#206).
// Learned, allowlisted, and measured as a target, it is still never
// steered, even by a static pin; a learned prefix inside it moves on its
// own in the same round.
func TestDefaultRouteIsNeverSteered(t *testing.T) {
	v4, v6 := netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")
	c := cfg()
	c.Mode, c.Allowlist = "inject", []netip.Prefix{v4, v6}
	res := results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30})
	res = append(res, results(t0, v4, m{"a", 0, 90}, m{"b", 0, 30})...)
	res = append(res, results(t0, v6, m{"a", 0, 90}, m{"b", 0, 30})...)
	input := withPolicy(in(res, map[netip.Prefix]string{pA: "a", v4: "a", v6: "a"}), v6, verdict(plugin.PolicyStatic, "b"))
	st, out := Decide(State{}, input, c, scorer(t), t0)
	if _, ok := st.Improvements[pA]; !ok || len(st.Improvements) != 1 {
		t.Fatalf("improvements = %v, want only %s", st.Improvements, pA)
	}
	for _, p := range []netip.Prefix{v4, v6} {
		d := decision(t, out, p)
		if d.Action != ActionNone || d.Reason != "default route is never steered" || d.Native != "a" {
			t.Fatalf("%s decision = %+v", p, d)
		}
	}

	e := NewEngine(c, scorer(t))
	e.Evaluate(input, t0)
	_, ex, _, ok := e.Explain(v4)
	if !ok {
		t.Fatal("no explanation for the default route")
	}
	wantGate(t, ex, GateRIB, GateFail, "default route")
	if ex.Outcome != OutcomeHeld || ex.BlockedBy != GateRIB || !strings.Contains(ex.Counterfactual, "never steered") {
		t.Fatalf("explain = %+v", ex)
	}
}
