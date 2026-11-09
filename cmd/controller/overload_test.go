package main

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/plugins/telemetry/fixed"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const overloadConfig = `mode: observe
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
hold_time: 5m
http: {listen: ""}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2, interface_capacity_threshold_pct: 85}
telemetry:
  - type: fixed
    config:
      providers:
        - {name: transit-b, capacity_mbps: 1000, out_mbps: 800}
`

func TestPolicyConfigCarriesInterfaceCapacityThreshold(t *testing.T) {
	pc, err := policyConfig(mustParse(t, overloadConfig))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, p := range pc.Providers {
		got[p.Name] = p.CapacityThresholdPct
	}
	if got["transit-a"] != 0 || got["transit-b"] != 85 {
		t.Fatalf("thresholds = %v", got)
	}
}

func overloadSet(t *testing.T, scorer string, src *volSrc) *pluginhost.Set {
	t.Helper()
	set := scorerSet(t, scorer, src)
	c, err := plugin.ConfigFromYAML("providers:\n  - {name: transit-b, capacity_mbps: 1000, out_mbps: 800}\n")
	if err != nil {
		t.Fatal(err)
	}
	tel, err := fixed.New(c, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	set.Telemetry = []pluginhost.Instance[plugin.Telemetry]{{Name: "fixed", Type: "fixed", Plugin: tel}}
	return set
}

func TestOverloadInputsReadOnlyWhenAProviderIsLimited(t *testing.T) {
	p := netip.MustParsePrefix("198.51.100.0/24")
	limited := mustParse(t, overloadConfig)
	unlimited := mustParse(t, strings.Replace(overloadConfig, ", interface_capacity_threshold_pct: 85", "", 1))

	src := &volSrc{mbps: 80, pfx: p}
	var in policy.Input
	fillOverloadInputs(context.Background(), &in, unlimited, overloadSet(t, "weighted", src))
	if src.calls != 0 || in.Load != nil || in.WeightVolumeMbps != nil {
		t.Fatalf("no limit: calls %d input %+v", src.calls, in)
	}

	fillOverloadInputs(context.Background(), &in, limited, overloadSet(t, "weighted", src))
	l := in.Load["transit-b"]
	if l.CapacityMbps != 1000 || l.OutMbps != 800 || l.Updated.IsZero() {
		t.Fatalf("load = %+v", l)
	}
	if src.calls != 1 || in.WeightVolumeMbps[p] != 80 {
		t.Fatalf("calls %d weight volume %v, want one read of 80 Mbps", src.calls, in.WeightVolumeMbps)
	}

	// A planner already read the volume: it is not read twice.
	src = &volSrc{mbps: 80, pfx: p}
	set := overloadSet(t, "commit", src)
	in = policy.Input{}
	fillPlannerInputs(context.Background(), &in, set)
	fillOverloadInputs(context.Background(), &in, limited, set)
	if src.calls != 1 || in.VolumeMbps[p] != 80 || in.WeightVolumeMbps != nil {
		t.Fatalf("calls %d volume %v weight volume %v, want the planner's read reused", src.calls, in.VolumeMbps, in.WeightVolumeMbps)
	}
}

func TestUnderLimit(t *testing.T) {
	cfg := mustParse(t, overloadConfig)
	now := time.Unix(1000, 0)
	for _, tc := range []struct {
		name string
		load policy.Load
		want map[string]bool
	}{
		{"under", policy.Load{CapacityMbps: 1000, OutMbps: 850, Updated: now}, map[string]bool{"transit-b": true}},
		{"over", policy.Load{CapacityMbps: 1000, OutMbps: 851, Updated: now}, map[string]bool{"transit-b": false}},
		{"stale", policy.Load{CapacityMbps: 1000, OutMbps: 10, Updated: now.Add(-time.Hour)}, map[string]bool{}},
		{"no capacity", policy.Load{OutMbps: 10, Updated: now}, map[string]bool{}},
		{"no sample yet", policy.Load{CapacityMbps: 1000, OutMbps: 10}, map[string]bool{}},
	} {
		got := underLimit(cfg, map[string]policy.Load{"transit-b": tc.load, "transit-a": {CapacityMbps: 1000, Updated: now}}, now)
		if len(got) != len(tc.want) || got["transit-b"] != tc.want["transit-b"] {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestEventWatchOverloads(t *testing.T) {
	s := &sink{}
	w := newEventWatch(s, "inject")
	p := netip.MustParsePrefix("198.51.100.0/24")
	q := netip.MustParsePrefix("203.0.113.0/24")
	now := time.Unix(10, 0)
	refuse := func(prefix netip.Prefix) policy.Overload {
		return policy.Overload{Action: policy.OverloadRefused, Prefix: prefix, Provider: "transit-b", UsedPct: 80, ProjectedPct: 86, LimitPct: 85, VolumeMbps: 60,
			Reason: "overload: transit-b would reach 86% of its 1000 Mbps interface with this steer (limit 85%)"}
	}
	over := map[string]bool{"transit-b": false}

	w.overloads(now, []policy.Overload{refuse(p), refuse(q)}, over)
	got := s.take()
	if kinds(got) != "overload.refused,overload.refused" {
		t.Fatalf("kinds = %s", kinds(got))
	}
	f := got[0].Fields
	if f["provider"] != "transit-b" || f["prefix"] != p.String() || f["projected_pct"] != "86.0" || f["limit_pct"] != "85.0" || f["volume_mbps"] != "60.0" || got[0].Severity != plugin.SeverityWarning {
		t.Fatalf("refused event = %+v", got[0])
	}

	// The same refusals next round are not reported again.
	w.overloads(now.Add(time.Second), []policy.Overload{refuse(p), refuse(q)}, over)
	if e := s.take(); len(e) != 0 {
		t.Fatalf("repeated refusal reported: %s", kinds(e))
	}

	// A shed is reported every time. q stops being refused; p stays.
	shed := policy.Overload{Action: policy.OverloadShed, Prefix: q, Provider: "transit-b", UsedPct: 90, ProjectedPct: 84, LimitPct: 85, VolumeMbps: 60, Reason: "overload: shed"}
	w.overloads(now.Add(2*time.Second), []policy.Overload{refuse(p), shed}, over)
	if k := kinds(s.take()); k != "overload.shed" {
		t.Fatalf("kinds = %s, want only the shed", k)
	}
	// q is refused again after it was out of the refusals for a round.
	w.overloads(now.Add(3*time.Second), []policy.Overload{refuse(p), refuse(q)}, over)
	if k := kinds(s.take()); k != "overload.refused" {
		t.Fatalf("kinds = %s, want q refused again", k)
	}

	// Nothing refused but the provider is still over its limit: no clear.
	w.overloads(now.Add(4*time.Second), nil, over)
	if e := s.take(); len(e) != 0 {
		t.Fatalf("cleared while over the limit: %s", kinds(e))
	}
	// Under the limit with nothing refused: cleared once.
	under := map[string]bool{"transit-b": true}
	w.overloads(now.Add(5*time.Second), nil, under)
	got = s.take()
	if kinds(got) != "overload.cleared" || got[0].Fields["provider"] != "transit-b" || !got[0].Resolves() {
		t.Fatalf("clear = %+v", got)
	}
	w.overloads(now.Add(6*time.Second), nil, under)
	if e := s.take(); len(e) != 0 {
		t.Fatalf("cleared twice: %s", kinds(e))
	}
	// A refusal and a clear share a dedup key, so a pager can close it.
	w.overloads(now.Add(7*time.Second), []policy.Overload{refuse(p)}, over)
	w.overloads(now.Add(8*time.Second), nil, under)
	if e := s.take(); len(e) != 2 || e[0].DedupKey() != e[1].DedupKey() {
		t.Fatalf("events %+v, want a refused and a cleared with one dedup key", e)
	}
	var nilW *eventWatch
	nilW.overloads(now, nil, nil) // no panic
}
