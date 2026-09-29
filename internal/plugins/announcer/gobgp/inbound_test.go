package gobgp

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const inboundYAML = `
marker: "64512:667"
providers:
  - provider: transit-a
    name: prepend-2
    prepend: 2
    communities: ["64512:1102", "64496:3"]
  - provider: transit-b
    communities: ["64497:70"]
`

func mustInbound(t *testing.T, y string) *InboundAnnouncer {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewInbound(c, plugin.Env{Providers: []string{"transit-a", "transit-b"}})
	if err != nil {
		t.Fatal(err)
	}
	return a.(*InboundAnnouncer)
}

func TestInboundConfigValidation(t *testing.T) {
	bad := map[string]string{
		"no marker":         "providers: [{provider: transit-a, communities: [\"64512:1\"]}]",
		"reserved marker":   "marker: \"65535:65281\"\nproviders: [{provider: transit-a, communities: [\"64512:1\"]}]",
		"no providers":      "marker: \"64512:667\"",
		"unknown provider":  "marker: \"64512:667\"\nproviders: [{provider: transit-z, communities: [\"64512:1\"]}]",
		"duplicate":         "marker: \"64512:667\"\nproviders: [{provider: transit-a, communities: [\"64512:1\"]}, {provider: transit-a, communities: [\"64512:2\"]}]",
		"no communities":    "marker: \"64512:667\"\nproviders: [{provider: transit-a, prepend: 2}]",
		"no_export":         "marker: \"64512:667\"\nproviders: [{provider: transit-a, communities: [\"65535:65281\"]}]",
		"zero asn":          "marker: \"64512:667\"\nproviders: [{provider: transit-a, communities: [\"0:1\"]}]",
		"marker as action":  "marker: \"64512:667\"\nproviders: [{provider: transit-a, communities: [\"64512:667\"]}]",
		"prepend too large": "marker: \"64512:667\"\nproviders: [{provider: transit-a, prepend: 11, communities: [\"64512:1\"]}]",
		"bad community":     "marker: \"64512:667\"\nproviders: [{provider: transit-a, communities: [\"64512\"]}]",
		"unknown field":     "marker: \"64512:667\"\nlocal_pref: 5\nproviders: [{provider: transit-a, communities: [\"64512:1\"]}]",
	}
	for name, y := range bad {
		c, err := plugin.ConfigFromYAML(y)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewInbound(c, plugin.Env{Providers: []string{"transit-a", "transit-b"}}); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
	a := mustInbound(t, inboundYAML)
	act, ok := a.Action("transit-a")
	if !ok || act.Prepend != 2 || act.Name != "prepend-2" || len(act.Communities) != 2 {
		t.Fatalf("action = %+v %v", act, ok)
	}
	act.Communities[0] = "1:1"
	if again, _ := a.Action("transit-a"); again.Communities[0] != "64512:1102" {
		t.Fatal("Action must return a copy")
	}
	if _, ok := a.Action("transit-c"); ok {
		t.Fatal("unknown provider has an action")
	}
}

func TestInboundAnnounceWithdrawAndCrash(t *testing.T) {
	ctx := context.Background()
	r := newRouter(t)
	v := newView(t, r)
	eventually(t, "session", v.Ready)

	in := mustInbound(t, inboundYAML)
	if err := in.Bind(v.Server(), "64512:666", []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}); err == nil || !strings.Contains(err.Error(), "export policy") {
		t.Fatalf("bind without the gobgp announcer: %v", err)
	}
	out := mustAnnouncer(t)
	if err := out.Bind(v.Server(), "64512:666"); err != nil {
		t.Fatal(err)
	}
	if err := in.Bind(v.Server(), "64512:667", []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}); err == nil {
		t.Fatal("marker equal to packeteer_community was accepted")
	}
	if err := in.Bind(v.Server(), "64512:666", []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}); err != nil {
		t.Fatal(err)
	}

	own := netip.MustParsePrefix("203.0.113.0/24")
	nh := netip.MustParseAddr("192.0.2.1")
	bad := []plugin.InboundRoute{
		{Prefix: own, NextHop: nh, LocalPref: 1, Community: "64512:666"},
		{Prefix: own, NextHop: nh, LocalPref: 1, Community: "64512:1", Away: []string{"transit-a"}},
		{Prefix: own, NextHop: nh, Community: "64512:666", Away: []string{"transit-a"}},
		{Prefix: own, NextHop: nh, LocalPref: 1, Community: "64512:666", Away: []string{"transit-c"}},
		{Prefix: own, NextHop: netip.MustParseAddr("2001:db8::1"), LocalPref: 1, Community: "64512:666", Away: []string{"transit-a"}},
		{Prefix: netip.MustParsePrefix("203.0.113.1/24"), NextHop: nh, LocalPref: 1, Community: "64512:666", Away: []string{"transit-a"}},
	}
	for _, rt := range bad {
		if err := in.Announce(ctx, rt); err == nil {
			t.Fatalf("announced invalid route %+v", rt)
		}
	}

	if err := in.Announce(ctx, plugin.InboundRoute{
		Prefix: own, NextHop: nh, LocalPref: 1, Community: "64512:666", Away: []string{"transit-a"},
	}); err != nil {
		t.Fatal(err)
	}
	want := func(comms ...string) func() bool {
		return func() bool {
			g, ok := fromUs(collect(t, r.srv, v4Family), own.String())
			if !ok || g.nextHop != "192.0.2.1" || g.lp != 1 || !g.comms[noExport] {
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
	eventually(t, "steer away from transit-a", want("64512:666", "64512:667", "64512:1102", "64496:3"))

	// Both providers: replaced in place with the union of actions.
	if err := in.Announce(ctx, plugin.InboundRoute{
		Prefix: own, NextHop: nh, LocalPref: 1, Community: "64512:666", Away: []string{"transit-a", "transit-b"},
	}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "steer away from both", want("64512:666", "64512:667", "64512:1102", "64496:3", "64497:70"))

	if err := in.Withdraw(ctx, own); err != nil {
		t.Fatal(err)
	}
	eventually(t, "withdraw", func() bool {
		_, ok := fromUs(collect(t, r.srv, v4Family), own.String())
		return !ok
	})
	if err := in.Withdraw(ctx, own); err != nil {
		t.Fatalf("second withdraw: %v", err)
	}

	// An outbound improvement and a steer route side by side. The inbound
	// WithdrawAll leaves the outbound route alone.
	if err := out.Announce(ctx, plugin.Route{
		Prefix: netip.MustParsePrefix("198.51.100.0/24"), NextHop: netip.MustParseAddr("192.0.2.2"),
		LocalPref: 250, Communities: []string{"64512:666"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := in.Announce(ctx, plugin.InboundRoute{
		Prefix: own, NextHop: nh, LocalPref: 1, Community: "64512:666", Away: []string{"transit-b"},
	}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "steer away from transit-b", want("64512:666", "64512:667", "64497:70"))
	if err := in.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	eventually(t, "inbound stop withdraws", func() bool {
		paths := collect(t, r.srv, v4Family)
		_, steer := fromUs(paths, own.String())
		_, imp := fromUs(paths, "198.51.100.0/24")
		return !steer && imp
	})

	// The gobgp announcer's WithdrawAll removes every local path; the
	// inbound WithdrawAll afterwards must not fail.
	if err := in.Announce(ctx, plugin.InboundRoute{
		Prefix: own, NextHop: nh, LocalPref: 1, Community: "64512:666", Away: []string{"transit-a"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := out.WithdrawAll(ctx); err != nil {
		t.Fatal(err)
	}
	if err := in.WithdrawAll(ctx); err != nil {
		t.Fatalf("inbound withdraw after outbound withdraw all: %v", err)
	}
	eventually(t, "everything withdrawn", func() bool {
		for _, p := range collect(t, r.srv, v4Family) {
			if p.fromUs {
				return false
			}
		}
		return true
	})

	// Crash: the session drops with no withdraw. With no graceful restart
	// the router forgets the steer route.
	if err := in.Announce(ctx, plugin.InboundRoute{
		Prefix: own, NextHop: nh, LocalPref: 1, Community: "64512:666", Away: []string{"transit-a"},
	}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "steer before crash", want("64512:666", "64512:667", "64512:1102", "64496:3"))
	if err := v.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	eventually(t, "steer gone with the session", func() bool {
		_, ok := fromUs(collect(t, r.srv, v4Family), own.String())
		return !ok
	})
}
