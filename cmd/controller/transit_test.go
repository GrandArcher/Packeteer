package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// fakeClassifier is a target source that classifies traffic, as the flow
// source does with a transit block.
type fakeClassifier struct {
	plugin.Base
	rows []plugin.TrafficMix
	err  error
}

func (f *fakeClassifier) Targets(context.Context) ([]plugin.Target, error) { return nil, nil }
func (f *fakeClassifier) TrafficMix(context.Context) ([]plugin.TrafficMix, error) {
	return f.rows, f.err
}

func withSources(set *pluginhost.Set, srcs ...plugin.TargetSource) *pluginhost.Set {
	for _, s := range srcs {
		set.Sources = append(set.Sources, pluginhost.Instance[plugin.TargetSource]{Name: "flow", Type: "flow", Plugin: s})
	}
	return set
}

func TestCollectTraffic(t *testing.T) {
	pT := netip.MustParsePrefix("198.51.100.0/24")
	pL := netip.MustParsePrefix("203.0.113.0/24")
	first := &fakeClassifier{rows: []plugin.TrafficMix{
		{Prefix: pT, TransitBytes: 10, Class: plugin.TrafficTransit},
		{Prefix: pL, Class: ""}, // unclassified: skipped
	}}
	second := &fakeClassifier{rows: []plugin.TrafficMix{
		{Prefix: pT, LocalBytes: 10, Class: plugin.TrafficLocal}, // first source wins
		{Prefix: pL, LocalBytes: 10, Class: plugin.TrafficLocal},
	}}
	broken := &fakeClassifier{err: errors.New("down")}
	set := withSources(policySet(t, [2]string{"rules", `rules: [{action: vip, traffic: local}]`}), broken, first, second)
	got := collectTraffic(context.Background(), set)
	if len(got) != 2 || got[pT] != plugin.TrafficTransit || got[pL] != plugin.TrafficLocal {
		t.Fatalf("traffic = %v", got)
	}
	// No policy chain: nothing reads the class, so it is not collected.
	if got := collectTraffic(context.Background(), withSources(&pluginhost.Set{}, first)); got != nil {
		t.Fatalf("without policies = %v", got)
	}
	if collectTraffic(context.Background(), nil) != nil {
		t.Fatal("nil set")
	}
}

// Transit (customer-originated) and local prefixes get separate policies
// from simulated flow classification, and Decide still applies the
// allowlist, the learned RIB, and withdraw on RIB loss.
func TestTransitPoliciesDecide(t *testing.T) {
	pT := netip.MustParsePrefix("198.51.100.0/24") // transit, allowlisted
	pL := netip.MustParsePrefix("203.0.113.0/24")  // local, allowlisted
	pX := netip.MustParsePrefix("192.0.2.0/24")    // transit, not allowlisted
	pN := netip.MustParsePrefix("198.51.100.0/25") // transit, allowlisted, not in the RIB
	set := policySet(t, [2]string{"rules", `
rules:
  - {name: customers-via-a, action: allow, providers: [transit-a], traffic: transit}
  - {name: own, action: vip, traffic: local}
`})
	set = withSources(set, &fakeClassifier{rows: []plugin.TrafficMix{
		{Prefix: pT, TransitBytes: 900, LocalBytes: 100, Class: plugin.TrafficTransit},
		{Prefix: pL, LocalBytes: 1000, Class: plugin.TrafficLocal},
		{Prefix: pX, TransitBytes: 1000, Class: plugin.TrafficTransit},
		{Prefix: pN, TransitBytes: 1000, Class: plugin.TrafficTransit},
	}})
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	var res []probe.Result
	for _, p := range []netip.Prefix{pT, pL, pX, pN} {
		// Native is slow; transit-b is the fastest, transit-a second.
		for prov, rtt := range map[string]time.Duration{"native": 120 * time.Millisecond, "transit-a": 60 * time.Millisecond, "transit-b": 20 * time.Millisecond} {
			res = append(res, probe.Result{Provider: prov, Prefix: p, Time: now,
				Stats: probe.Stats{Sent: 10, Received: 10, RTTAvg: rtt}})
		}
	}
	routes := fakeRoutes{ready: true, routes: map[netip.Prefix]rib.Route{}}
	native := map[netip.Prefix]string{}
	for _, p := range []netip.Prefix{pT, pL, pX} {
		routes.routes[p] = rib.Route{Prefix: p, Provider: "native"}
		native[p] = "native"
	}
	build := func(ready bool) policy.Input {
		in := policy.Input{Results: res, ProviderUp: map[string]bool{"native": true, "transit-a": true, "transit-b": true},
			RIBEnabled: true, RIBReady: ready, Native: native}
		applyPolicies(&in, now, routes, set, collectTraffic(context.Background(), set))
		return in
	}
	cfg := policy.Config{Mode: "inject", MinLossDeltaPct: 1, MinRTTDelta: 15 * time.Millisecond, HoldTime: 15 * time.Minute,
		MaxImprovements: 50, MaxResultAge: 2 * time.Minute,
		Allowlist: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24")}}
	sc, err := plugin.Scorers.New("weighted", plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}

	in := build(true)
	if v := in.Policies[pT]; v.Rule != "customers-via-a" || v.Match != "traffic transit" {
		t.Fatalf("pT verdict = %+v", v)
	}
	if v := in.Policies[pL]; v.Rule != "own" {
		t.Fatalf("pL verdict = %+v", v)
	}
	st, out := policy.Decide(policy.NewState(), in, cfg, sc, now)
	if imp := st.Improvements[pT]; imp.Provider != "transit-a" {
		t.Fatalf("transit prefix = %+v", imp)
	}
	if imp := st.Improvements[pL]; imp.Provider != "transit-b" {
		t.Fatalf("local prefix = %+v", imp)
	}
	if _, ok := st.Improvements[pX]; ok {
		t.Fatal("transit prefix outside the allowlist improved")
	}
	if _, ok := st.Improvements[pN]; ok {
		t.Fatal("transit prefix not in the learned RIB improved")
	}
	for _, d := range out.Decisions {
		if d.Prefix == pT && !strings.Contains(d.Policy, "traffic transit") {
			t.Fatalf("pT decision policy = %q", d.Policy)
		}
	}

	// Every BGP session lost: both classes are withdrawn at once.
	st, out = policy.Decide(st, build(false), cfg, sc, now.Add(time.Second))
	if len(st.Improvements) != 0 {
		t.Fatalf("after RIB loss = %+v", st.Improvements)
	}
	retired := 0
	for _, c := range out.Changes {
		if c.Action == policy.ActionRetire {
			retired++
		}
	}
	if retired != 2 {
		t.Fatalf("retired %d, changes %+v", retired, out.Changes)
	}
}
