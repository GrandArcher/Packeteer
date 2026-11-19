package herd

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/herdhints"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func ev(kind, value string, vs ...EventVantage) EventRow {
	return EventRow{Target: Target{Kind: kind, Value: value}, Vantages: vs}
}

func vantage(asn uint32, local, counted, degraded bool) EventVantage {
	return EventVantage{VantageRef: VantageRef{ASN: asn, Local: local}, Counted: counted, Degraded: degraded}
}

func hintRIB() *fakeRIB {
	return &fakeRIB{ready: true, paths: map[netip.Prefix][]uint32{
		netip.MustParsePrefix("192.0.2.128/26"): {64501, 64510},
		netip.MustParsePrefix("192.0.2.192/27"): {64501, 64511},
		netip.MustParsePrefix("0.0.0.0/0"):      {64501, 64511},
	}}
}

// A hint counts other members that count and see loss, once per ASN, and
// names only routes in the local RIB view, never a default route.
func TestHintsCountOtherCountedMembersAndNameOnlyLocalRoutes(t *testing.T) {
	events := Events{Events: []EventRow{
		ev(kindOrigin, "64511", vantage(64500, true, true, true), vantage(65537, false, true, true),
			vantage(65537, false, true, true), vantage(65538, false, true, true), vantage(65539, false, false, true)),
		ev(kindPrefix, "198.51.100.0/24", vantage(65537, false, true, true)),
		ev(kindPrefix, "192.0.2.128/26", vantage(65537, false, true, true), vantage(65538, false, true, false)),
		ev(kindOrigin, "64510", vantage(65537, false, true, false)),
		ev(kindOrigin, "65541", vantage(64500, true, true, true), vantage(65539, false, false, true)),
	}}
	got := hintsFrom(events, hintRIB())
	want := []Hint{{netip.MustParsePrefix("192.0.2.192/27"), 2}, {netip.MustParsePrefix("192.0.2.128/26"), 1}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("hints = %v, want %v", got, want)
	}
}

// Herd data never reaches Decide: a hinted route that every member sees
// lose all its packets is only a probe target. Without a local
// measurement, or with local measurements that pass no threshold, nothing
// is steered and nothing is announced; only the local measurements decide.
func TestHintsNeverSteerWithoutALocalMeasurement(t *testing.T) {
	p := netip.MustParsePrefix("192.0.2.192/27")
	hints := hintsFrom(Events{Events: []EventRow{
		ev(kindOrigin, "64511", vantage(65537, false, true, true), vantage(65538, false, true, true), vantage(65539, false, true, true)),
	}}, hintRIB())
	if len(hints) != 1 || hints[0].Prefix != p || hints[0].Vantages != 3 {
		t.Fatalf("hints = %v", hints)
	}
	src, err := herdhints.New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	src.(*herdhints.Source).SetHints(func() []herdhints.Hint {
		return []herdhints.Hint{{Prefix: hints[0].Prefix, Vantages: hints[0].Vantages}}
	})
	targets, err := src.Targets(context.Background())
	if err != nil || len(targets) != 1 || targets[0].Prefix != p || targets[0].Host.IsValid() {
		t.Fatalf("targets = %v, %v; want only %s with no host", targets, err, p)
	}

	scorer, err := weighted.New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := policy.Config{Mode: "inject", Allowlist: []netip.Prefix{p}, MinLossDeltaPct: 1, MinRTTDelta: 15 * time.Millisecond,
		HoldTime: 15 * time.Minute, MaxImprovements: 50, MaxResultAge: 2 * time.Minute}
	measured := func(lossA, lossB float64) []probe.Result {
		var out []probe.Result
		for prov, loss := range map[string]float64{"a": lossA, "b": lossB} {
			out = append(out, probe.Result{Provider: prov, Prefix: p, Time: t0, Stats: probe.Stats{Sent: 10, Received: 10 - int(loss/10), LossPct: loss, RTTAvg: 20 * time.Millisecond}})
		}
		return out
	}
	input := func(res []probe.Result) policy.Input {
		return policy.Input{Results: res, ProviderUp: map[string]bool{"a": true, "b": true}, RIBEnabled: true, RIBReady: true, Native: map[netip.Prefix]string{p: "a"}}
	}
	for name, res := range map[string][]probe.Result{"no local measurement": nil, "local paths equal": measured(0, 0)} {
		st, out := policy.Decide(policy.State{}, input(res), cfg, scorer, t0)
		if len(st.Improvements) != 0 || len(out.Changes) != 0 {
			t.Errorf("%s: improvements %v, changes %v; herd hints alone must never steer", name, st.Improvements, out.Changes)
		}
	}
	st, out := policy.Decide(policy.State{}, input(measured(90, 0)), cfg, scorer, t0)
	if imp, ok := st.Improvements[p]; !ok || imp.Provider != "b" || len(out.Changes) != 1 {
		t.Errorf("a local measurement past the thresholds must steer as usual: %v %v", st.Improvements, out.Changes)
	}
}
