package gobgp

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const mitigationYAML = `
marker: "64512:668"
blackhole:
  next_hop: 192.0.2.66
  next_hop_v6: "2001:db8::66"
redirect:
  - name: scrubber
    next_hop: 192.0.2.77
    communities: ["64512:777"]
  - name: scrubber-v6
    next_hop: "2001:db8::77"
`

func mustMitigation(t *testing.T, y string) *MitigationAnnouncer {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewMitigation(c, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	return a.(*MitigationAnnouncer)
}

func TestMitigationConfigValidation(t *testing.T) {
	bad := map[string]string{
		"no marker":            "blackhole: {next_hop: 192.0.2.66}",
		"reserved marker":      "marker: \"65535:666\"\nblackhole: {next_hop: 192.0.2.66}",
		"no action":            "marker: \"64512:668\"",
		"no next hop":          "marker: \"64512:668\"\nblackhole: {}",
		"v6 blackhole on v4":   "marker: \"64512:668\"\nblackhole: {next_hop: \"2001:db8::66\"}",
		"v4 on next_hop_v6":    "marker: \"64512:668\"\nblackhole: {next_hop: 192.0.2.66, next_hop_v6: 192.0.2.67}",
		"loopback":             "marker: \"64512:668\"\nblackhole: {next_hop: 127.0.0.1}",
		"unspecified":          "marker: \"64512:668\"\nblackhole: {next_hop: 0.0.0.0}",
		"no_export community":  "marker: \"64512:668\"\nblackhole: {next_hop: 192.0.2.66, communities: [\"65535:65281\"]}",
		"marker as community":  "marker: \"64512:668\"\nblackhole: {next_hop: 192.0.2.66, communities: [\"64512:668\"]}",
		"duplicate community":  "marker: \"64512:668\"\nblackhole: {next_hop: 192.0.2.66, communities: [\"65535:666\", \"65535:666\"]}",
		"blackhole on target":  "marker: \"64512:668\"\nredirect: [{name: s, next_hop: 192.0.2.77, communities: [\"65535:666\"]}]",
		"target without name":  "marker: \"64512:668\"\nredirect: [{next_hop: 192.0.2.77}]",
		"target name slash":    "marker: \"64512:668\"\nredirect: [{name: a/b, next_hop: 192.0.2.77}]",
		"duplicate target":     "marker: \"64512:668\"\nredirect: [{name: s, next_hop: 192.0.2.77}, {name: s, next_hop: 192.0.2.78}]",
		"shared next hop":      "marker: \"64512:668\"\nblackhole: {next_hop: 192.0.2.66}\nredirect: [{name: s, next_hop: 192.0.2.66}]",
		"bad target next hop":  "marker: \"64512:668\"\nredirect: [{name: s, next_hop: scrubber}]",
		"unknown field":        "marker: \"64512:668\"\nlocal_pref: 5\nblackhole: {next_hop: 192.0.2.66}",
		"unknown nested field": "marker: \"64512:668\"\nblackhole: {next_hop: 192.0.2.66, ttl: 5m}",
	}
	for name, y := range bad {
		c, err := plugin.ConfigFromYAML(y)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewMitigation(c, plugin.Env{}); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}

	a := mustMitigation(t, mitigationYAML)
	cat := a.Catalog()
	if !cat.Blackhole || len(cat.BlackholeNextHops) != 2 || len(cat.BlackholeCommunities) != 1 || cat.BlackholeCommunities[0] != "65535:666" {
		t.Fatalf("catalog blackhole = %+v", cat)
	}
	if len(cat.Targets) != 2 || cat.Targets[0].Name != "scrubber" || cat.Targets[1].Name != "scrubber-v6" {
		t.Fatalf("catalog targets = %+v", cat.Targets)
	}
	if tg, ok := cat.Target("scrubber"); !ok || tg.NextHop != netip.MustParseAddr("192.0.2.77") {
		t.Fatalf("target = %+v %v", tg, ok)
	}
	if nhs := cat.NextHops(); len(nhs) != 4 {
		t.Fatalf("next hops = %v", nhs)
	}
	cat.Targets[0].Communities[0] = "1:1"
	if again := a.Catalog(); again.Targets[0].Communities[0] != "64512:777" {
		t.Fatal("Catalog must return a copy")
	}
	only := mustMitigation(t, "marker: \"64512:668\"\nredirect: [{name: s, next_hop: 192.0.2.77}]")
	if only.Catalog().Blackhole {
		t.Fatal("blackhole reported without a blackhole block")
	}
}

func TestMitigationAnnounceWithdrawAndCrash(t *testing.T) {
	ctx := context.Background()
	r := newRouter(t)
	v := newView(t, r)
	eventually(t, "session", v.Ready)

	allow := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24")}
	m := mustMitigation(t, mitigationYAML)
	if err := m.Bind(v.Server(), "64512:666", allow, 2); err == nil || !strings.Contains(err.Error(), "export policy") {
		t.Fatalf("bind without the gobgp announcer: %v", err)
	}
	out := mustAnnouncer(t)
	if err := out.Bind(v.Server(), "64512:666"); err != nil {
		t.Fatal(err)
	}
	if err := m.Bind(v.Server(), "64512:668", allow, 2); err == nil {
		t.Fatal("marker equal to packeteer_community was accepted")
	}
	if err := m.Bind(v.Server(), "64512:666", nil, 2); err == nil {
		t.Fatal("empty allowlist was accepted")
	}
	if err := m.Bind(v.Server(), "64512:666", allow, 0); err == nil {
		t.Fatal("zero cap was accepted")
	}
	unbound := mustMitigation(t, mitigationYAML)
	if err := unbound.Announce(ctx, plugin.MitigationRoute{Prefix: allow[0], Action: plugin.MitigationBlackhole, LocalPref: 250, Community: "64512:666"}); err == nil {
		t.Fatal("unbound announcer announced")
	}
	if err := m.Bind(v.Server(), "64512:666", allow, 2); err != nil {
		t.Fatal(err)
	}
	if err := m.Bind(v.Server(), "64512:666", allow, 2); err == nil {
		t.Fatal("second bind accepted")
	}

	victim := netip.MustParsePrefix("198.51.100.0/24")
	bh := plugin.MitigationRoute{Prefix: victim, Action: plugin.MitigationBlackhole, LocalPref: 250, Community: "64512:666"}
	bad := []plugin.MitigationRoute{
		{Prefix: netip.MustParsePrefix("192.0.2.128/25"), Action: plugin.MitigationBlackhole, LocalPref: 250, Community: "64512:666"},
		{Prefix: netip.MustParsePrefix("198.51.100.1/24"), Action: plugin.MitigationBlackhole, LocalPref: 250, Community: "64512:666"},
		{Prefix: victim, Action: plugin.MitigationBlackhole, LocalPref: 250, Community: "64512:1"},
		{Prefix: victim, Action: plugin.MitigationBlackhole, Community: "64512:666"},
		{Prefix: victim, Action: plugin.MitigationBlackhole, Target: "scrubber", LocalPref: 250, Community: "64512:666"},
		{Prefix: victim, Action: plugin.MitigationRedirect, Target: "nowhere", LocalPref: 250, Community: "64512:666"},
		{Prefix: victim, Action: plugin.MitigationRedirect, Target: "scrubber-v6", LocalPref: 250, Community: "64512:666"},
		{Prefix: victim, Action: "drop", LocalPref: 250, Community: "64512:666"},
	}
	for _, rt := range bad {
		if err := m.Announce(ctx, rt); err == nil {
			t.Fatalf("announced invalid route %+v", rt)
		}
	}

	want := func(p netip.Prefix, nh string, comms ...string) func() bool {
		return func() bool {
			g, ok := fromUs(collect(t, r.srv, v4Family), p.String())
			if !ok || g.nextHop != nh || g.lp != 250 || !g.comms[noExport] {
				return false
			}
			n := 1 // NO_EXPORT
			for _, c := range comms {
				v, _ := parseCommunity(c)
				if !g.comms[v] {
					return false
				}
				n++
			}
			return len(g.comms) == n
		}
	}

	// RTBH: discard next hop, packeteer community, marker, BLACKHOLE,
	// NO_EXPORT.
	if err := m.Announce(ctx, bh); err != nil {
		t.Fatal(err)
	}
	eventually(t, "blackhole", want(victim, "192.0.2.66", "64512:666", "64512:668", "65535:666"))

	// Redirect replaces it in place.
	rd := bh
	rd.Action, rd.Target = plugin.MitigationRedirect, "scrubber"
	if err := m.Announce(ctx, rd); err != nil {
		t.Fatal(err)
	}
	eventually(t, "redirect", want(victim, "192.0.2.77", "64512:666", "64512:668", "64512:777"))

	// The cap is the announcer's own: a second prefix fits, a third does
	// not, and a replace of one already on the wire always does.
	second := netip.MustParsePrefix("203.0.113.0/24")
	if err := m.Announce(ctx, plugin.MitigationRoute{Prefix: second, Action: plugin.MitigationBlackhole, LocalPref: 250, Community: "64512:666"}); err != nil {
		t.Fatal(err)
	}
	third := netip.MustParsePrefix("203.0.113.0/25")
	if err := m.Announce(ctx, plugin.MitigationRoute{Prefix: third, Action: plugin.MitigationBlackhole, LocalPref: 250, Community: "64512:666"}); err == nil || !strings.Contains(err.Error(), "max rules") {
		t.Fatalf("third route past the cap: %v", err)
	}
	if err := m.Announce(ctx, bh); err != nil {
		t.Fatalf("replace at the cap: %v", err)
	}
	eventually(t, "blackhole again", want(victim, "192.0.2.66", "64512:666", "64512:668", "65535:666"))

	if err := m.Withdraw(ctx, second); err != nil {
		t.Fatal(err)
	}
	eventually(t, "withdraw", func() bool {
		_, ok := fromUs(collect(t, r.srv, v4Family), second.String())
		return !ok
	})
	if err := m.Withdraw(ctx, second); err != nil {
		t.Fatalf("second withdraw: %v", err)
	}

	// An outbound improvement next to a mitigation route: Stop withdraws
	// only the mitigation route.
	imp := netip.MustParsePrefix("203.0.113.0/24")
	if err := out.Announce(ctx, plugin.Route{Prefix: imp, NextHop: netip.MustParseAddr("192.0.2.2"), LocalPref: 250, Communities: []string{"64512:666"}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	eventually(t, "mitigation stop withdraws", func() bool {
		paths := collect(t, r.srv, v4Family)
		_, mit := fromUs(paths, victim.String())
		_, o := fromUs(paths, imp.String())
		return !mit && o
	})

	// The gobgp announcer's WithdrawAll removes every local path; the
	// mitigation WithdrawAll afterwards must not fail.
	if err := m.Announce(ctx, bh); err != nil {
		t.Fatal(err)
	}
	if err := out.WithdrawAll(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.WithdrawAll(ctx); err != nil {
		t.Fatalf("mitigation withdraw after outbound withdraw all: %v", err)
	}

	// Crash: the session drops with no withdraw. With no graceful restart
	// the router forgets the blackhole route.
	if err := m.Announce(ctx, bh); err != nil {
		t.Fatal(err)
	}
	eventually(t, "blackhole before crash", want(victim, "192.0.2.66", "64512:666", "64512:668", "65535:666"))
	if err := v.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	eventually(t, "blackhole gone with the session", func() bool {
		_, ok := fromUs(collect(t, r.srv, v4Family), victim.String())
		return !ok
	})
}
