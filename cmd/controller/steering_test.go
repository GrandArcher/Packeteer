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

// A pin takes precedence over the policy chain for its prefix and still
// goes through the static path's rails: the cap, and the allowlist in
// inject read on every round.
func TestApplyPinsFeedsTheStaticRails(t *testing.T) {
	p := netip.MustParsePrefix("203.0.113.0/24")
	other := netip.MustParsePrefix("198.51.100.0/24")
	now := time.Now()
	store := pin.NewStore()
	rails := pin.Rails{Providers: []string{"transit-a", "transit-b"}, Allowlist: []netip.Prefix{p, other},
		Learned: func(netip.Prefix) bool { return true }}
	for _, pfx := range []netip.Prefix{p, other} {
		if _, err := store.Add(pin.Request{Prefix: pfx, Provider: "transit-b", MaxLossPct: 5, Duration: time.Hour}, rails, now); err != nil {
			t.Fatal(err)
		}
	}
	stats := func(rtt time.Duration) probe.Stats { return probe.Stats{Sent: 4, Received: 4, RTTAvg: rtt} }
	in := policy.Input{
		Results: []probe.Result{
			{Provider: "transit-a", Prefix: p, Time: now, Stats: stats(10 * time.Millisecond)},
			{Provider: "transit-b", Prefix: p, Time: now, Stats: stats(80 * time.Millisecond)},
		},
		ProviderUp: map[string]bool{"transit-a": true, "transit-b": true},
		Native:     map[netip.Prefix]string{p: "transit-a"},
		RIBEnabled: true, RIBReady: true,
		Policies: map[netip.Prefix]plugin.PolicyVerdict{p: {Action: plugin.PolicyIgnore, Rule: "config"}},
	}
	applyPins(&in, store, now)
	if v := in.Policies[p]; v.Action != plugin.PolicyStatic || v.Rule != "api pin-1" {
		t.Fatalf("verdict %+v", v)
	}
	if _, ok := in.Policies[other]; ok {
		t.Fatal("a pin for an unprobed prefix entered the round")
	}

	sc, err := weighted.New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	decide := func(c policy.Config) policy.Decision {
		t.Helper()
		e := policy.NewEngine(c, sc)
		e.Evaluate(in, now)
		ds, _ := e.Decisions()
		if len(ds) != 1 {
			t.Fatalf("decisions %+v", ds)
		}
		return ds[0]
	}
	base := policy.Config{Mode: "inject", MaxImprovements: 50, MaxResultAge: time.Minute, Allowlist: []netip.Prefix{p}}
	if d := decide(base); d.Action != policy.ActionImprove || d.Current != "transit-b" || d.Cause != plugin.CauseStatic {
		t.Fatalf("pinned decision %+v", d)
	}
	capped := base
	capped.MaxImprovements = 0
	if d := decide(capped); d.Action != policy.ActionCapped {
		t.Fatalf("cap 0: %+v", d)
	}
	narrowed := base
	narrowed.Allowlist = []netip.Prefix{other}
	if d := decide(narrowed); d.Action == policy.ActionImprove || !strings.Contains(d.Reason, "not allowlisted") {
		t.Fatalf("allowlist removed after the pin: %+v", d)
	}
}
