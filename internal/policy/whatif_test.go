package policy

import (
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestEngineWhatIf(t *testing.T) {
	native := map[netip.Prefix]string{pA: "a", pB: "a"}
	round := in(append(results(t0, pA, m{"a", 0, 50}, m{"b", 0, 30}), results(t0, pB, m{"a", 0, 50}, m{"b", 0, 30})...), native)
	e := NewEngine(cfg(), scorer(t))
	if _, ok := e.WhatIf(cfg(), t0); ok {
		t.Fatal("WhatIf before any round decided something")
	}
	e.Evaluate(round, t0)
	live := e.Improvements()
	if len(live) != 2 {
		t.Fatalf("observe round: %d improvements, want 2", len(live))
	}
	decisions, at := e.Decisions()

	inject := cfg()
	inject.Mode = "inject"
	inject.Allowlist = []netip.Prefix{pA}
	w, ok := e.WhatIf(inject, t0.Add(time.Second))
	if !ok {
		t.Fatal("WhatIf after a round: not ok")
	}
	if len(w.State.Improvements) != 1 || w.State.Improvements[pA].Provider != "b" {
		t.Fatalf("inject improvements = %+v, want only %s on b (%s is outside the allowlist)", w.State.Improvements, pA, pB)
	}
	if len(w.Before) != 2 || w.Before[0].Prefix != pA || w.Before[1].Prefix != pB {
		t.Fatalf("Before = %+v, want the two live improvements in prefix order", w.Before)
	}

	// The live engine is untouched: same improvements, decisions, and time.
	if got := e.Improvements(); !reflect.DeepEqual(got, live) {
		t.Fatalf("improvements changed by WhatIf: %+v, was %+v", got, live)
	}
	gotD, gotAt := e.Decisions()
	if !reflect.DeepEqual(gotD, decisions) || !gotAt.Equal(at) {
		t.Fatal("decisions changed by WhatIf")
	}

	// The same config gives the next round the same answer WhatIf gave.
	e.SetConfig(inject)
	e.Evaluate(round, t0.Add(time.Second))
	if got := e.Improvements(); len(got) != 1 || got[0].Prefix != pA || got[0].Provider != "b" {
		t.Fatalf("round under the previewed config = %+v, want %s on b", got, pA)
	}

	e.Reset()
	if _, ok := e.WhatIf(inject, t0); ok {
		t.Fatal("WhatIf after Reset decided on a dropped round")
	}
}
