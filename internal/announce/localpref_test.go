package announce

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func causeImp(prefix, provider, cause string) policy.Improvement {
	im := imp(prefix, provider)
	im.Cause = cause
	return im
}

func withPrefs(cause, provider map[string]uint32) Config {
	cfg := testCfg()
	cfg.CauseLocalPref = cause
	cfg.ProviderLocalPref = provider
	return cfg
}

func TestLocalPrefCauseThenProvider(t *testing.T) {
	ctx := context.Background()
	rib := memRIB{ready: true, has: map[netip.Prefix]bool{
		pfx("198.51.100.0/24"): true,
		pfx("203.0.113.0/24"):  true,
		pfx("2001:db8::/32"):   true,
	}}
	cause := map[string]uint32{
		plugin.CausePerformance: 300,
		plugin.CauseStatic:      400,
		plugin.CauseCommit:      220,
		plugin.CauseCost:        210,
	}
	// transit b overrides every cause. a and c use the cause, else 250.
	provider := map[string]uint32{"b": 350}
	ann := &fakeAnn{}
	c, err := New(withPrefs(cause, provider), ann, &rib, nil)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		prefix, prov, cause string
		want                uint32
	}{
		{"198.51.100.0/24", "a", plugin.CausePerformance, 300},
		{"198.51.100.0/24", "a", "", 300}, // empty cause is performance
		{"198.51.100.0/24", "a", plugin.CauseStatic, 400},
		{"198.51.100.0/24", "a", plugin.CauseCommit, 220},
		{"198.51.100.0/24", "a", plugin.CauseCost, 210},
		{"198.51.100.0/24", "b", plugin.CausePerformance, 350},
		{"198.51.100.0/24", "b", plugin.CauseCommit, 350},
		{"203.0.113.0/24", "a", "other", 250}, // unknown cause uses the global value
	}
	for _, tc := range cases {
		if err := c.Sync(ctx, []policy.Improvement{causeImp(tc.prefix, tc.prov, tc.cause)}); err != nil {
			t.Fatalf("%s %s %s: %v", tc.prefix, tc.prov, tc.cause, err)
		}
		rt := ann.routes[pfx(tc.prefix)]
		if rt.LocalPref != tc.want || rt.Provider != tc.prov || len(rt.Communities) != 1 || rt.Communities[0] != "64512:666" {
			t.Fatalf("%s cause %q provider %s: route %+v, want local_pref %d", tc.prefix, tc.cause, tc.prov, rt, tc.want)
		}
		// The prefix was in the learned RIB. Nothing else was announced.
		if ann.count() != 1 {
			t.Fatalf("routes on the wire = %d, want 1", ann.count())
		}
	}

	// Same provider and cause: do not re-advertise.
	before := ann.announces
	if err := c.Sync(ctx, []policy.Improvement{causeImp("203.0.113.0/24", "a", "other")}); err != nil {
		t.Fatal(err)
	}
	if ann.announces != before {
		t.Fatalf("unchanged sync re-announced: %d -> %d", before, ann.announces)
	}

	// A cause change on the same provider replaces the local preference.
	before = ann.announces
	if err := c.Sync(ctx, []policy.Improvement{causeImp("203.0.113.0/24", "a", plugin.CauseStatic)}); err != nil {
		t.Fatal(err)
	}
	if ann.announces != before+1 || ann.routes[pfx("203.0.113.0/24")].LocalPref != 400 {
		t.Fatalf("cause change announces=%d local_pref=%d", ann.announces, ann.routes[pfx("203.0.113.0/24")].LocalPref)
	}

	if err := c.Sync(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if ann.count() != 0 {
		t.Fatalf("routes left after withdraw: %d", ann.count())
	}

	// A prefix that is not in the learned RIB is still refused.
	delete(rib.has, pfx("203.0.113.0/24"))
	err = c.Sync(ctx, []policy.Improvement{causeImp("203.0.113.0/24", "a", plugin.CausePerformance)})
	if err == nil || !strings.Contains(err.Error(), "not in the RIB") {
		t.Fatalf("err = %v", err)
	}
	if ann.count() != 0 {
		t.Fatalf("refused prefix was announced: %d", ann.count())
	}
}

func TestLocalPrefMoreSpecificFollowsImprovement(t *testing.T) {
	ctx := context.Background()
	rib := learned("198.51.100.0/24", "198.51.100.0/25")
	cfg := msCfg(100, nil)
	cfg.CauseLocalPref = map[string]uint32{plugin.CauseCommit: 220, plugin.CausePerformance: 300}
	cfg.ProviderLocalPref = map[string]uint32{"b": 350}
	ann := &fakeAnn{}
	c, err := New(cfg, ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx, []policy.Improvement{causeImp("198.51.100.0/24", "b", plugin.CauseCommit)}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"198.51.100.0/24", "198.51.100.0/25"} {
		rt := ann.routes[pfx(p)]
		if rt.LocalPref != 350 || rt.Provider != "b" {
			t.Fatalf("%s: %+v, want provider b local_pref 350", p, rt)
		}
		if !rib.has[pfx(p)] {
			t.Fatalf("announced %s, which is not in the learned RIB", p)
		}
	}

	// No provider override: a cause change replaces the improvement and the
	// learned more-specific with the cause's local preference.
	cfg.ProviderLocalPref = nil
	ann = &fakeAnn{}
	c, err = New(cfg, ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx, []policy.Improvement{causeImp("198.51.100.0/24", "a", plugin.CauseCommit)}); err != nil {
		t.Fatal(err)
	}
	before := ann.announces
	if err := c.Sync(ctx, []policy.Improvement{causeImp("198.51.100.0/24", "a", plugin.CausePerformance)}); err != nil {
		t.Fatal(err)
	}
	if ann.announces != before+2 {
		t.Fatalf("cause change re-announced %d routes, want the improvement and its more-specific", ann.announces-before)
	}
	for _, p := range []string{"198.51.100.0/24", "198.51.100.0/25"} {
		rt := ann.routes[pfx(p)]
		if rt.LocalPref != 300 || rt.NextHop.String() != "192.0.2.1" {
			t.Fatalf("after cause change %s: %+v", p, rt)
		}
	}
}

func TestLocalPrefRejectsZeroAndUnknown(t *testing.T) {
	rib := memRIB{ready: true, has: map[netip.Prefix]bool{pfx("198.51.100.0/24"): true}}
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"cause zero", withPrefs(map[string]uint32{plugin.CauseCost: 0}, nil), "cause cost"},
		{"unknown cause", withPrefs(map[string]uint32{"vip": 10}, nil), `cause "vip"`},
		{"provider zero", withPrefs(nil, map[string]uint32{"b": 0}), "provider b"},
		{"unknown provider", withPrefs(nil, map[string]uint32{"nope": 10}), "unknown provider"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg, &fakeAnn{}, &rib, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
