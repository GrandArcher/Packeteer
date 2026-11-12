package main

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/pin"
	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// An API pin goes to the edge as a static improvement: via the pinned
// provider, with the packeteer community and NO_EXPORT. A pin for a prefix
// that is allowlisted but not in the learned RIB is refused. Pausing
// withdraws it and resuming brings it back; unpinning and shutdown
// withdraw it.
func TestPinAndPauseOnTheEdge(t *testing.T) {
	edge := newMSEdge(t)
	edge.advertise("203.0.113.0/24")
	// Native (transit-a) measures best, so only the pin moves the prefix.
	d := startIX(t, edge, `thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
allowlist: {prefixes: ["203.0.113.0/24", "198.51.100.0/24"]}
sources:
  - type: static
    config: {targets: [{prefix: 203.0.113.0/24}, {prefix: 198.51.100.0/24}]}
probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 10}, {provider: transit-b, rtt_ms: 80}]}
`)
	empty := func(w map[string]ixRoute) bool { return len(w) == 0 }
	d.holdWire("no steer before the pin", 3*time.Second, empty)

	body := `{"prefix":"%s","provider":"transit-b","max_loss_pct":5,"duration":"10m","reason":"lab"}`
	if code, m := d.call(http.MethodPost, "/api/pins", fmt.Sprintf(body, "198.51.100.0/24")); code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(m["error"]), "not in the learned RIB view") {
		d.fatalf("pin outside the RIB: %d %v", code, m)
	}
	code, p := d.call(http.MethodPost, "/api/pins", fmt.Sprintf(body, "203.0.113.0/24"))
	if code != http.StatusCreated || p["id"] != "pin-1" || p["by"] != "lab" {
		d.fatalf("pin: %d %v", code, p)
	}
	pinned := routeVia("203.0.113.0/24", ixSteered, ixCommunity, ixNoExport)
	d.waitWire("the pinned route", pinned)
	d.holdWire("only the learned prefix is announced", 2*time.Second, func(w map[string]ixRoute) bool { return len(w) == 1 && pinned(w) })

	if code, m := d.call(http.MethodPost, "/api/optimization/pause", `{"reason":"lab"}`); code != http.StatusOK || m["paused"] != true {
		d.fatalf("pause: %d %v", code, m)
	}
	d.waitWire("every route withdrawn while paused", empty)
	d.holdWire("nothing announced while paused", 3*time.Second, empty)
	if code, _ := d.call(http.MethodDelete, "/api/optimization/pause", ""); code != http.StatusNoContent {
		d.fatalf("resume: %d", code)
	}
	d.waitWire("the pinned route after resume", pinned)

	if code, _ := d.call(http.MethodDelete, "/api/pins/pin-1", ""); code != http.StatusNoContent {
		d.fatalf("unpin: %d", code)
	}
	d.waitWire("the route withdrawn after unpin", empty)

	if code, _ := d.call(http.MethodPost, "/api/pins", fmt.Sprintf(body, "203.0.113.0/24")); code != http.StatusCreated {
		d.fatalf("pin again: %d", code)
	}
	d.waitWire("the pinned route again", pinned)
	d.stop()
}

func pinStats(rtt time.Duration, lossPct float64) probe.Stats {
	return probe.Stats{Sent: 20, Received: 20 - int(lossPct/5), LossPct: lossPct, RTTAvg: rtt}
}

// pinRound is one decision round for p with native transit-a and a pin
// to transit-b in store, plus a pin for an unprobed prefix.
func pinRound(t *testing.T, now time.Time, a, b probe.Stats, policies map[netip.Prefix]plugin.PolicyVerdict) (policy.Input, *pin.Store) {
	t.Helper()
	p := netip.MustParsePrefix("203.0.113.0/24")
	other := netip.MustParsePrefix("198.51.100.0/24")
	store := pin.NewStore()
	rails := pin.Rails{Providers: []string{"transit-a", "transit-b"}, Allowlist: []netip.Prefix{p, other},
		Learned: func(netip.Prefix) bool { return true }}
	for _, pfx := range []netip.Prefix{p, other} {
		if _, err := store.Add(pin.Request{Prefix: pfx, Provider: "transit-b", MaxLossPct: 5, Duration: time.Hour}, rails, now); err != nil {
			t.Fatal(err)
		}
	}
	return policy.Input{
		Results: []probe.Result{
			{Provider: "transit-a", Prefix: p, Time: now, Stats: a},
			{Provider: "transit-b", Prefix: p, Time: now, Stats: b},
		},
		ProviderUp: map[string]bool{"transit-a": true, "transit-b": true},
		Native:     map[netip.Prefix]string{p: "transit-a"},
		RIBEnabled: true, RIBReady: true,
		Policies: policies,
	}, store
}

func decideOne(t *testing.T, in policy.Input, c policy.Config, now time.Time) policy.Decision {
	t.Helper()
	sc, err := weighted.New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	e := policy.NewEngine(c, sc)
	e.Evaluate(in, now)
	ds, _ := e.Decisions()
	if len(ds) != 1 {
		t.Fatalf("decisions %+v", ds)
	}
	return ds[0]
}

// A pin takes precedence over the policy chain for its prefix and still
// goes through the static path's rails: the cap, and the allowlist in
// inject read on every round.
func TestApplyPinsFeedsTheStaticRails(t *testing.T) {
	p := netip.MustParsePrefix("203.0.113.0/24")
	other := netip.MustParsePrefix("198.51.100.0/24")
	now := time.Now()
	in, store := pinRound(t, now, pinStats(10*time.Millisecond, 0), pinStats(80*time.Millisecond, 0),
		map[netip.Prefix]plugin.PolicyVerdict{p: {Action: plugin.PolicyIgnore, Rule: "config"}})
	applyPins(&in, store, now)
	if v := in.Policies[p]; v.Action != plugin.PolicyStatic || v.Rule != "api pin-1" {
		t.Fatalf("verdict %+v", v)
	}
	if _, ok := in.Policies[other]; ok {
		t.Fatal("a pin for an unprobed prefix entered the round")
	}

	base := policy.Config{Mode: "inject", MaxImprovements: 50, MaxResultAge: time.Minute, Allowlist: []netip.Prefix{p}}
	if d := decideOne(t, in, base, now); d.Action != policy.ActionImprove || d.Current != "transit-b" || d.Cause != plugin.CauseStatic {
		t.Fatalf("pinned decision %+v", d)
	}
	capped := base
	capped.MaxImprovements = 0
	if d := decideOne(t, in, capped, now); d.Action != policy.ActionCapped {
		t.Fatalf("cap 0: %+v", d)
	}
	narrowed := base
	narrowed.Allowlist = []netip.Prefix{other}
	if d := decideOne(t, in, narrowed, now); d.Action == policy.ActionImprove || !strings.Contains(d.Reason, "not allowlisted") {
		t.Fatalf("allowlist removed after the pin: %+v", d)
	}
}

// A pin to a provider that a config deny rule forbids wins for its prefix
// (docs/mcp.md: a pin takes precedence over the policy chain) and keeps
// the static rails: the allowlist is read on every round, the learned RIB
// view is needed, the cap binds, and a pin whose path leaves its loss
// ceiling is not announced. TestPinOutranksConfigDenyOnTheEdge covers the
// deny rule for an unpinned prefix and the inject-only rail.
func TestPinOutranksConfigDenyAndKeepsTheRails(t *testing.T) {
	p := netip.MustParsePrefix("203.0.113.0/24")
	now := time.Now()
	deny := plugin.PolicyVerdict{Action: plugin.PolicyDeny, Providers: []string{"transit-b"}, Rule: "config deny"}
	// Native loses 20% and transit-b is clean: only the deny rule stops
	// the move to transit-b.
	native, clean := pinStats(10*time.Millisecond, 20), pinStats(20*time.Millisecond, 0)
	in, store := pinRound(t, now, native, clean, map[netip.Prefix]plugin.PolicyVerdict{p: deny})
	base := policy.Config{Mode: "inject", MaxImprovements: 50, MaxResultAge: time.Minute, Allowlist: []netip.Prefix{p}}

	d := decideOne(t, in, base, now)
	if d.Action == policy.ActionImprove || d.Recommended != "transit-a" {
		t.Fatalf("deny did not hold without a pin: %+v", d)
	}
	var b policy.Candidate
	for _, c := range d.Candidates {
		if c.Provider == "transit-b" {
			b = c
		}
	}
	if b.Usable || !strings.Contains(b.Why, "policy deny") {
		t.Fatalf("transit-b under deny: %+v", b)
	}

	applyPins(&in, store, now)
	if v := in.Policies[p]; v.Action != plugin.PolicyStatic || v.Rule != "api pin-1" || len(v.Providers) != 1 || v.Providers[0] != "transit-b" {
		t.Fatalf("pin did not replace the deny verdict: %+v", v)
	}
	if d := decideOne(t, in, base, now); d.Action != policy.ActionImprove || d.Current != "transit-b" || d.Cause != plugin.CauseStatic {
		t.Fatalf("pinned decision %+v", d)
	}

	capped := base
	capped.MaxImprovements = 0
	if d := decideOne(t, in, capped, now); d.Action != policy.ActionCapped {
		t.Fatalf("cap 0: %+v", d)
	}
	narrowed := base
	narrowed.Allowlist = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	if d := decideOne(t, in, narrowed, now); d.Action == policy.ActionImprove || !strings.Contains(d.Reason, "not allowlisted") {
		t.Fatalf("allowlist: %+v", d)
	}
	noRIB := in
	noRIB.Native = map[netip.Prefix]string{}
	if d := decideOne(t, noRIB, base, now); d.Action != policy.ActionNone || d.Reason != "prefix not in RIB" {
		t.Fatalf("prefix missing from the RIB view: %+v", d)
	}

	// A different round for the same prefix: only the transit-b stats
	// differ, and the pin store is the one from above.
	lossy, _ := pinRound(t, now, native, pinStats(20*time.Millisecond, 10), map[netip.Prefix]plugin.PolicyVerdict{p: deny})
	applyPins(&lossy, store, now)
	if d := decideOne(t, lossy, base, now); d.Action == policy.ActionImprove || !strings.Contains(d.Reason, "max_loss_pct") {
		t.Fatalf("pin over its loss ceiling was announced: %+v", d)
	}
}

// On a simulated edge a config deny rule keeps both slow-native prefixes
// off the better provider. Pinning one of them announces it through the
// denied provider in inject, with the community and NO_EXPORT, while the
// unpinned prefix stays native. In observe the same pin announces nothing.
func TestPinOutranksConfigDenyOnTheEdge(t *testing.T) {
	const body = `thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
allowlist: {prefixes: ["203.0.113.0/24", "198.51.100.0/24"]}
sources:
  - type: static
    config: {targets: [{prefix: 203.0.113.0/24}, {prefix: 198.51.100.0/24}]}
probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 100}, {provider: transit-b, rtt_ms: 20}]}
policies:
  - type: rules
    config: {rules: [{name: no-b, action: deny, providers: [transit-b], prefixes: [203.0.113.0/24, 198.51.100.0/24]}]}
`
	pinBody := `{"prefix":"203.0.113.0/24","provider":"transit-b","max_loss_pct":5,"duration":"10m","reason":"lab"}`
	empty := func(w map[string]ixRoute) bool { return len(w) == 0 }
	for _, mode := range []string{"inject", "observe"} {
		t.Run(mode, func(t *testing.T) {
			edge := newMSEdge(t)
			edge.advertise("203.0.113.0/24")
			edge.advertise("198.51.100.0/24")
			d := startIXMode(t, edge, mode, body)
			d.holdWire("the deny rule holds before the pin", 3*time.Second, empty)
			if code, m := d.call(http.MethodPost, "/api/pins", pinBody); code != http.StatusCreated {
				d.fatalf("pin: %d %v", code, m)
			}
			if mode == "observe" {
				d.holdWire("observe announces nothing for a pin", 4*time.Second, empty)
				d.stop()
				return
			}
			pinned := routeVia("203.0.113.0/24", ixSteered, ixCommunity, ixNoExport)
			d.waitWire("the pinned route", pinned)
			d.holdWire("only the pinned prefix is announced", 3*time.Second, func(w map[string]ixRoute) bool { return len(w) == 1 && pinned(w) })
			if code, _ := d.call(http.MethodDelete, "/api/pins/pin-1", ""); code != http.StatusNoContent {
				d.fatalf("unpin: %d", code)
			}
			d.waitWire("the route withdrawn after unpin", empty)
			d.stop()
		})
	}
}
