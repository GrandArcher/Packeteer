package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakeRoutes struct {
	ready  bool
	routes map[netip.Prefix]rib.Route
}

func (f fakeRoutes) Ready() bool { return f.ready }
func (f fakeRoutes) Exact(p netip.Prefix) (rib.Route, bool) {
	rt, ok := f.routes[p]
	return rt, ok
}

func policySet(t *testing.T, specs ...[2]string) *pluginhost.Set {
	t.Helper()
	set := &pluginhost.Set{}
	for _, sp := range specs {
		c, err := plugin.ConfigFromYAML(sp[1])
		if err != nil {
			t.Fatal(err)
		}
		p, err := plugin.Policies.New(sp[0], c, plugin.Env{Providers: []string{"transit-a", "transit-b"}})
		if err != nil {
			t.Fatal(err)
		}
		set.Policies = append(set.Policies, pluginhost.Instance[plugin.Policy]{Name: sp[0], Type: sp[0], Plugin: p})
	}
	return set
}

func TestApplyPolicies(t *testing.T) {
	pA := netip.MustParsePrefix("198.51.100.0/24")
	pB := netip.MustParsePrefix("203.0.113.0/24")
	pC := netip.MustParsePrefix("192.0.2.0/24")
	set := policySet(t,
		[2]string{"maintenance", `windows: [{name: w, providers: [transit-b], start: "2026-09-25T00:00:00Z", end: "2026-09-26T00:00:00Z"}]`},
		[2]string{"rules", `rules: [{name: first, action: deny, providers: [transit-b], asns: [64500]}]`},
		[2]string{"rules", `rules: [{name: second, action: ignore, prefixes: [198.51.100.0/24, 203.0.113.0/24]}]`},
	)
	routes := fakeRoutes{ready: true, routes: map[netip.Prefix]rib.Route{
		pA: {Prefix: pA, ASPath: []uint32{64510, 64500}},
		pB: {Prefix: pB, ASPath: []uint32{64500, 64510}},
	}}
	res := []probe.Result{{Provider: "transit-a", Prefix: pA}, {Provider: "transit-b", Prefix: pA}, {Provider: "transit-a", Prefix: pB}, {Provider: "transit-a", Prefix: pC}}

	in := policy.Input{Results: res}
	applyPolicies(&in, time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC), routes, set)
	if len(in.Maintenance) != 1 || in.Maintenance[0] != "transit-b" {
		t.Fatalf("maintenance = %v", in.Maintenance)
	}
	// First policy in the chain that matches wins.
	if v := in.Policies[pA]; v.Rule != "first" || v.Action != plugin.PolicyDeny {
		t.Fatalf("pA = %+v", v)
	}
	if v := in.Policies[pB]; v.Rule != "second" {
		t.Fatalf("pB = %+v", v)
	}
	if _, ok := in.Policies[pC]; ok {
		t.Fatal("pC matched no rule")
	}

	// Outside the window, and with the RIB not ready, ASN rules cannot match.
	in = policy.Input{Results: res}
	applyPolicies(&in, time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC), fakeRoutes{routes: routes.routes}, set)
	if len(in.Maintenance) != 0 {
		t.Fatalf("maintenance = %v", in.Maintenance)
	}
	if v := in.Policies[pA]; v.Rule != "second" {
		t.Fatalf("pA without RIB = %+v", v)
	}
	// No RIB at all.
	in = policy.Input{Results: res}
	applyPolicies(&in, time.Now(), nil, set)
	if v := in.Policies[pA]; v.Rule != "second" {
		t.Fatalf("pA with nil RIB = %+v", v)
	}
	// No policies: nothing set.
	in = policy.Input{Results: res}
	applyPolicies(&in, time.Now(), routes, &pluginhost.Set{})
	if in.Policies != nil || in.Maintenance != nil {
		t.Fatalf("empty chain set %+v %+v", in.Policies, in.Maintenance)
	}
}

func TestMaintenanceControlWakesDecisions(t *testing.T) {
	if newMaintenanceControl(&pluginhost.Set{}, nil, nil) != nil {
		t.Fatal("control without a maintenance policy")
	}
	woke := 0
	set := policySet(t, [2]string{"maintenance", ``})
	mc := newMaintenanceControl(set, nil, func() { woke++ })
	if mc == nil || !mc.CanOpen() {
		t.Fatal("no control")
	}
	now := time.Now()
	w, err := mc.Open([]string{"transit-a"}, time.Hour, "test", now)
	if err != nil || woke != 1 {
		t.Fatalf("open: %v woke=%d", err, woke)
	}
	in := policy.Input{}
	applyPolicies(&in, now.Add(time.Minute), nil, set)
	if len(in.Maintenance) != 1 || in.Maintenance[0] != "transit-a" {
		t.Fatalf("maintenance = %v", in.Maintenance)
	}
	if len(mc.Active(now)) != 1 || !mc.Close(w.ID) || woke != 2 || mc.Close(w.ID) || woke != 2 {
		t.Fatalf("close woke=%d", woke)
	}
	if _, err := mc.Open([]string{"transit-z"}, time.Hour, "", now); err == nil || woke != 2 {
		t.Fatal("bad open accepted or woke the loop")
	}
}
