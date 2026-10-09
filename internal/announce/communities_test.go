package announce

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func withCommunities(cause, provider map[string][]string) Config {
	cfg := testCfg()
	cfg.CauseCommunities = cause
	cfg.ProviderCommunities = provider
	return cfg
}

func TestCommunitiesCauseThenProvider(t *testing.T) {
	ctx := context.Background()
	rib := memRIB{ready: true, has: map[netip.Prefix]bool{
		pfx("198.51.100.0/24"): true,
		pfx("203.0.113.0/24"):  true,
	}}
	cause := map[string][]string{
		plugin.CausePerformance: {"64512:100"},
		plugin.CauseStatic:      {"64512:200"},
		plugin.CauseCommit:      {"64512:300"},
		plugin.CauseCost:        {"64512:1:40"},
	}
	provider := map[string][]string{"b": {"64512:200", "64512:1:50"}}
	ann := &fakeAnn{}
	c, err := New(withCommunities(cause, provider), ann, &rib, nil)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		prefix, prov, cause string
		want                []string
	}{
		{"198.51.100.0/24", "a", plugin.CausePerformance, []string{"64512:666", "64512:100"}},
		{"198.51.100.0/24", "a", "", []string{"64512:666", "64512:100"}},
		{"198.51.100.0/24", "a", plugin.CauseStatic, []string{"64512:666", "64512:200"}},
		{"198.51.100.0/24", "a", plugin.CauseCommit, []string{"64512:666", "64512:300"}},
		{"198.51.100.0/24", "a", plugin.CauseCost, []string{"64512:666", "64512:1:40"}},
		{"198.51.100.0/24", "b", plugin.CausePerformance, []string{"64512:666", "64512:100", "64512:200", "64512:1:50"}},
		{"198.51.100.0/24", "b", plugin.CauseStatic, []string{"64512:666", "64512:200", "64512:1:50"}},
		{"203.0.113.0/24", "a", "other", []string{"64512:666"}},
	}
	for _, tc := range cases {
		if err := c.Sync(ctx, []policy.Improvement{causeImp(tc.prefix, tc.prov, tc.cause)}); err != nil {
			t.Fatalf("%s %s %s: %v", tc.prefix, tc.prov, tc.cause, err)
		}
		rt := ann.routes[pfx(tc.prefix)]
		if strings.Join(rt.Communities, ",") != strings.Join(tc.want, ",") || rt.LocalPref != 250 {
			t.Fatalf("%s cause %q provider %s: communities %v local_pref %d, want %v", tc.prefix, tc.cause, tc.prov, rt.Communities, rt.LocalPref, tc.want)
		}
		if ann.count() != 1 {
			t.Fatalf("routes on the wire = %d, want 1", ann.count())
		}
	}

	before := ann.announces
	if err := c.Sync(ctx, []policy.Improvement{causeImp("203.0.113.0/24", "a", "other")}); err != nil {
		t.Fatal(err)
	}
	if ann.announces != before {
		t.Fatalf("unchanged sync re-announced: %d -> %d", before, ann.announces)
	}

	before = ann.announces
	if err := c.Sync(ctx, []policy.Improvement{causeImp("203.0.113.0/24", "a", plugin.CauseCost)}); err != nil {
		t.Fatal(err)
	}
	got := ann.routes[pfx("203.0.113.0/24")].Communities
	if ann.announces != before+1 || strings.Join(got, ",") != "64512:666,64512:1:40" {
		t.Fatalf("cause change announces=%d communities=%v", ann.announces, got)
	}

	if err := c.Sync(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if ann.count() != 0 {
		t.Fatalf("routes left after withdraw: %d", ann.count())
	}

	delete(rib.has, pfx("203.0.113.0/24"))
	err = c.Sync(ctx, []policy.Improvement{causeImp("203.0.113.0/24", "a", plugin.CausePerformance)})
	if err == nil || !strings.Contains(err.Error(), "not in the RIB") {
		t.Fatalf("err = %v", err)
	}
	if ann.count() != 0 {
		t.Fatalf("refused prefix was announced: %d", ann.count())
	}
}

func TestCommunitiesMoreSpecificFollowsImprovement(t *testing.T) {
	ctx := context.Background()
	rib := learned("198.51.100.0/24", "198.51.100.0/25")
	cfg := msCfg(100, nil)
	cfg.CauseCommunities = map[string][]string{plugin.CausePerformance: {"64512:100"}}
	cfg.ProviderCommunities = map[string][]string{"b": {"64512:1:50"}}
	ann := &fakeAnn{}
	c, err := New(cfg, ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	im := causeImp("198.51.100.0/24", "b", plugin.CausePerformance)
	if err := c.Sync(ctx, []policy.Improvement{im}); err != nil {
		t.Fatal(err)
	}
	want := "64512:666,64512:100,64512:1:50"
	for _, p := range []string{"198.51.100.0/24", "198.51.100.0/25"} {
		if got := strings.Join(ann.routes[pfx(p)].Communities, ","); got != want {
			t.Fatalf("%s communities = %s, want %s", p, got, want)
		}
	}
	// A cause change replaces the more-specific's communities too.
	im.Cause = plugin.CauseStatic
	if err := c.Sync(ctx, []policy.Improvement{im}); err != nil {
		t.Fatal(err)
	}
	want = "64512:666,64512:1:50"
	for _, p := range []string{"198.51.100.0/24", "198.51.100.0/25"} {
		if got := strings.Join(ann.routes[pfx(p)].Communities, ","); got != want {
			t.Fatalf("after cause change %s communities = %s, want %s", p, got, want)
		}
	}
}

func TestCommunitiesRejectedAtAnnounce(t *testing.T) {
	rib := memRIB{ready: true, has: map[netip.Prefix]bool{pfx("198.51.100.0/24"): true}}
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"unknown cause", func() Config {
			cfg := testCfg()
			cfg.CauseCommunities = map[string][]string{"vip": {"64512:1"}}
			return cfg
		}(), "communities cause"},
		{"unknown provider", func() Config {
			cfg := testCfg()
			cfg.ProviderCommunities = map[string][]string{"nope": {"64512:1"}}
			return cfg
		}(), "unknown provider"},
		{"well-known", func() Config {
			cfg := testCfg()
			cfg.CauseCommunities = map[string][]string{plugin.CausePerformance: {"65535:65281"}}
			return cfg
		}(), "reserved"},
		{"duplicate", func() Config {
			cfg := testCfg()
			cfg.ProviderCommunities = map[string][]string{"b": {"64512:100", "64512:0100"}}
			return cfg
		}(), "duplicate"},
		{"too many", func() Config {
			cfg := testCfg()
			var list []string
			for i := 1; i <= 17; i++ {
				list = append(list, "64512:"+itoa(i))
			}
			cfg.CauseCommunities = map[string][]string{plugin.CauseCost: list}
			return cfg
		}(), "at most 16"},
		{"four-byte two-part", func() Config {
			cfg := testCfg()
			cfg.Community = "70000:1"
			return cfg
		}(), "0-65535"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg, &fakeAnn{}, &rib, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
	cfg := testCfg()
	cfg.Community = "4200000000:1:666"
	cfg.CauseCommunities = map[string][]string{plugin.CausePerformance: {"64512:0100"}}
	c, err := New(cfg, &fakeAnn{}, &rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.cfg.Community != "4200000000:1:666" || c.cfg.CauseCommunities[plugin.CausePerformance][0] != "64512:100" {
		t.Fatalf("canonical = %q %v", c.cfg.Community, c.cfg.CauseCommunities)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
