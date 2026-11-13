package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/eventlog"
	"github.com/GrandArcher/Packeteer/internal/pin"
	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/plugins/storage/sqlite"
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

// A restart on the same storage keeps the pin and the pause (#565): the
// restarted controller announces nothing while paused. The edge stopped
// advertising the prefix while the controller was down, so after resume
// the restored pin stays off the wire until the prefix is learned again,
// then goes to the edge with the community and NO_EXPORT.
func TestPinAndPauseSurviveRestart(t *testing.T) {
	edge := newMSEdge(t)
	edge.advertise("203.0.113.0/24")
	body := fmt.Sprintf(`storage: {type: sqlite, config: {path: %s}}
thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
allowlist: {prefixes: ["203.0.113.0/24"]}
sources:
  - type: static
    config: {targets: [{prefix: 203.0.113.0/24}]}
probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 10}, {provider: transit-b, rtt_ms: 80}]}
`, filepath.Join(t.TempDir(), "p.db"))
	empty := func(w map[string]ixRoute) bool { return len(w) == 0 }
	pinned := routeVia("203.0.113.0/24", ixSteered, ixCommunity, ixNoExport)

	d := startIX(t, edge, body)
	d.waitLog("steering state restored")
	d.holdWire("no steer before the pin", 3*time.Second, empty)
	pinBody := `{"prefix":"203.0.113.0/24","provider":"transit-b","max_loss_pct":5,"duration":"10m","reason":"lab"}`
	if code, p := d.call(http.MethodPost, "/api/pins", pinBody); code != http.StatusCreated || p["id"] != "pin-1" {
		d.fatalf("pin: %d %v", code, p)
	}
	d.waitWire("the pinned route", pinned)
	if code, m := d.call(http.MethodPost, "/api/optimization/pause", `{"reason":"lab"}`); code != http.StatusOK {
		d.fatalf("pause: %d %v", code, m)
	}
	d.waitWire("every route withdrawn while paused", empty)
	d.stop()
	edge.withdraw("203.0.113.0/24")

	d = startIX(t, edge, body)
	d.waitLog("steering state restored")
	if code, m := d.call(http.MethodGet, "/api/optimization", ""); code != http.StatusOK || m["paused"] != true || m["by"] != "lab" {
		d.fatalf("pause after restart: %d %v", code, m)
	}
	code, m := d.call(http.MethodGet, "/api/pins", "")
	pins, _ := m["pins"].([]any)
	if code != http.StatusOK || len(pins) != 1 || pins[0].(map[string]any)["id"] != "pin-1" {
		d.fatalf("pins after restart: %d %v", code, m)
	}
	d.holdWire("nothing announced while the restored pause holds", 3*time.Second, empty)
	if code, _ := d.call(http.MethodDelete, "/api/optimization/pause", ""); code != http.StatusNoContent {
		d.fatalf("resume: %d", code)
	}
	d.holdWire("a restored pin outside the learned RIB is not announced", 4*time.Second, empty)
	_, m = d.call(http.MethodGet, "/api/pins", "")
	if pins, _ := m["pins"].([]any); len(pins) != 1 {
		d.fatalf("pin dropped while its prefix is not learned: %v", m)
	}
	edge.advertise("203.0.113.0/24")
	d.waitWire("the restored pin once the prefix is learned", pinned)
	d.holdWire("only the learned prefix is announced", 2*time.Second, func(w map[string]ixRoute) bool { return len(w) == 1 && pinned(w) })
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

// steeringConfig has the providers and allowlist the steering tests pin
// under.
func steeringConfig() *config.Config {
	return &config.Config{Providers: []config.Provider{{Name: "transit-a"}, {Name: "transit-b"}},
		Allowlist: config.Allowlist{Prefixes: []string{"198.51.100.0/24"}}}
}

// newTestSteering is one instance's steering state over store and events.
func newTestSteering(store plugin.SteeringStore, events *eventlog.Log, ha *haControl) *steeringState {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &steeringState{store: store, pins: pin.NewStore(), events: events, cfg: steeringConfig, ha: ha, log: log}
	s.opt = &optimizationControl{decider: policy.NewEngine(policy.Config{}, nil), log: log, poke: func() {}, save: s.save}
	events.OnAck(s.save)
	return s
}

func (s *steeringState) testPins() pinControl {
	return pinControl{store: s.pins, cfg: s.cfg, learned: func(netip.Prefix) bool { return true }, log: s.log, poke: func() {}, save: s.save}
}

// A restart on the same sqlite file restores the pins, the pause, and an
// acknowledgement; a pin that expired while the controller was down is
// not restored (#565).
func TestSteeringStateSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	c, err := plugin.ConfigFromYAML("path: " + filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	open := func() *sqlite.Store {
		st, err := sqlite.New(c, plugin.Env{})
		if err != nil {
			t.Fatal(err)
		}
		if err := st.Start(ctx); err != nil {
			t.Fatal(err)
		}
		return st
	}
	now := time.Now()
	down := plugin.Event{Time: now.Add(-time.Minute), Kind: plugin.EventProviderDown, Severity: plugin.SeverityCritical, Message: "down",
		Fields: map[string]string{"provider": "transit-a"}}

	st := open()
	if err := st.AppendEvent(ctx, down); err != nil {
		t.Fatal(err)
	}
	a := newTestSteering(st, eventlog.New(st, nil, nil), nil)
	a.start(ctx, now)
	if a.refuse() {
		t.Fatal("changes refused after start without ha")
	}
	kept, err := a.testPins().Add(pin.Request{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Provider: "transit-b", MaxLossPct: 2, Duration: time.Hour, By: "noc1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.testPins().Add(pin.Request{Prefix: netip.MustParsePrefix("198.51.100.64/26"), Provider: "transit-b", MaxLossPct: 2, Duration: pin.MinDuration}, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.opt.Pause("noc1", "upstream incident", now); !ok {
		t.Fatal("pause refused")
	}
	if _, err := a.events.Acknowledge(ctx, down.DedupKey(), "noc1", "ticket 7", now); err != nil {
		t.Fatal(err)
	}
	_ = a.events.Close(ctx)
	_ = st.Stop(ctx)

	// Two minutes later: the one-minute pin has expired.
	later := now.Add(2 * time.Minute)
	st = open()
	defer st.Stop(ctx)
	b := newTestSteering(st, eventlog.New(st, nil, nil), nil)
	defer b.events.Close(ctx)
	b.start(ctx, later)
	if got := b.pins.List(later); len(got) != 1 || got[0] != kept {
		t.Fatalf("restored pins %+v, want only %+v", got, kept)
	}
	if p := b.opt.State(); !p.Paused || p.By != "noc1" || p.Reason != "upstream incident" {
		t.Fatalf("restored pause %+v", p)
	}
	if ack, ok := b.events.AckOf(down); !ok || ack.Note != "ticket 7" {
		t.Fatalf("restored ack %+v %v", ack, ok)
	}
	// The expired pin is gone from the saved document at the next change.
	if !b.opt.Resume() {
		t.Fatal("resume refused")
	}
	raw, err := st.SteeringState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var doc steeringDoc
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Pins) != 1 || doc.Pause.Paused || len(doc.Acks) != 1 {
		t.Fatalf("saved after resume: %s (%v)", raw, err)
	}
}

// memSteering is a SteeringStore both instances of a pair share.
type memSteering struct {
	mu       sync.Mutex
	doc      []byte
	readFail bool
}

func (m *memSteering) SteeringState(context.Context) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.readFail {
		return nil, errors.New("shared volume unreadable")
	}
	return m.doc, nil
}

func (m *memSteering) PutSteeringState(_ context.Context, doc []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.doc = doc
	return nil
}

func (m *memSteering) SteeringLocation() string { return "/var/lib/packeteer/ha/lease.json.steering" }

// With ha, a standby refuses changes; at takeover it restores what the
// active instance saved after the standby started, then takes changes
// until it steps down (#565).
func TestSteeringStateFollowsTheHAPair(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	shared := &memSteering{}
	elA, elB := &haTestElector{active: true}, &haTestElector{}
	haOf := func(el plugin.Elector) *haControl {
		return &haControl{el: el, log: slog.New(slog.NewTextHandler(io.Discard, nil)), poke: func() {}}
	}
	a := newTestSteering(shared, eventlog.New(nil, nil, nil), haOf(elA))
	b := newTestSteering(shared, eventlog.New(nil, nil, nil), haOf(elB))
	a.start(ctx, now)
	b.start(ctx, now)
	if !a.refuse() {
		t.Fatal("changes taken before this term's takeover restored the saved state")
	}
	a.takeover(ctx, now)
	if a.refuse() || !b.refuse() {
		t.Fatalf("refuse: active %v, standby %v", a.refuse(), b.refuse())
	}
	if _, ok := a.opt.Pause("noc1", "upstream incident", now); !ok {
		t.Fatal("pause refused")
	}
	if _, err := a.testPins().Add(pin.Request{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Provider: "transit-b", MaxLossPct: 2, Duration: time.Hour}, now); err != nil {
		t.Fatal(err)
	}
	if b.opt.State().Paused {
		t.Fatal("the standby's state changed before takeover")
	}

	// Failover: a stops, b becomes active. While the shared store cannot be
	// read, b keeps refusing changes, so no save replaces the pair's state.
	elA.active, elB.active = false, true
	a.stepDown()
	if !b.refuse() {
		t.Fatal("b takes changes before it restored the pair's state")
	}
	shared.readFail = true
	if b.mayDecide(ctx, now, true) {
		t.Fatal("b decides with the pair's pause and pins unread: it would announce stale intent")
	}
	if !b.refuse() {
		t.Fatal("b takes changes after a failed restore")
	}
	if a.mayDecide(ctx, now, false) || b.mayDecide(ctx, now, false) {
		t.Fatal("a standby may decide")
	}
	// An acked alert resolving is not an API change: its save must not
	// replace the pair's newer document with b's older state.
	before := string(shared.doc)
	b.save()
	if string(shared.doc) != before {
		t.Fatalf("a save while the state is unread replaced the pair's document: %s", shared.doc)
	}
	shared.readFail = false
	if !b.mayDecide(ctx, now, true) {
		t.Fatal("b still held after the shared state is readable")
	}
	if p := b.opt.State(); !p.Paused || p.By != "noc1" {
		t.Fatalf("pause after takeover %+v", p)
	}
	if got := b.pins.List(now); len(got) != 1 || got[0].Provider != "transit-b" {
		t.Fatalf("pins after takeover %+v", got)
	}
	if b.refuse() || !a.refuse() {
		t.Fatalf("after failover refuse: b %v, a %v", b.refuse(), a.refuse())
	}
	b.stepDown()
	if !b.refuse() {
		t.Fatal("changes taken after step-down")
	}
}

// Without ha, a store that cannot be read at start leaves the controller
// holding: no decision, changes refused, and the saved pause is not
// replaced. The next readable round restores it (#565).
func TestSteeringStateHoldsWhenTheStoreIsUnreadableAtStart(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	shared := &memSteering{}
	first := newTestSteering(shared, eventlog.New(nil, nil, nil), nil)
	first.start(ctx, now)
	if _, ok := first.opt.Pause("noc1", "upstream incident", now); !ok {
		t.Fatal("pause refused")
	}
	saved := string(shared.doc)

	shared.readFail = true
	s := newTestSteering(shared, eventlog.New(nil, nil, nil), nil)
	s.start(ctx, now)
	if !s.refuse() || s.mayDecide(ctx, now, true) {
		t.Fatalf("unreadable store: refuse %v, may decide %v", s.refuse(), s.mayDecide(ctx, now, true))
	}
	if string(shared.doc) != saved {
		t.Fatalf("saved document replaced: %s", shared.doc)
	}
	shared.readFail = false
	if !s.mayDecide(ctx, now, true) || s.refuse() {
		t.Fatal("still held after the store is readable")
	}
	if p := s.opt.State(); !p.Paused || p.By != "noc1" {
		t.Fatalf("pause after the retry %+v", p)
	}
}

// syncBuffer is a log sink the test reads while the code under test writes.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (w *syncBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *syncBuffer) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

// A saved document that does not parse, or that another version wrote,
// holds the controller like an unreadable store (#565): with and without
// ha it is not restored, makes no decision, refuses changes, and keeps the
// document. The reason is logged with the file and the version seen, once
// per minute while it holds.
func TestSteeringStateHoldsOnAnUnusableDocument(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ name, doc, logged string }{
		{"unparseable", `{"version":1,"pins":`, "cannot be parsed"},
		{"body of another shape", `{"version":1,"pins":"all"}`, "cannot be parsed"},
		{"other version", `{"version":2,"pause":{"paused":false}}`, "version=2 want=1"},
	} {
		for _, withHA := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s ha=%v", tc.name, withHA), func(t *testing.T) {
				now := time.Now()
				shared := &memSteering{doc: []byte(tc.doc)}
				var ha *haControl
				if withHA {
					ha = &haControl{el: &haTestElector{active: true}, log: slog.New(slog.NewTextHandler(io.Discard, nil)), poke: func() {}}
				}
				var logs syncBuffer
				s := newTestSteering(shared, eventlog.New(nil, nil, nil), ha)
				s.log = slog.New(slog.NewTextHandler(&logs, nil))
				s.start(ctx, now)
				for i := range 3 {
					if s.mayDecide(ctx, now.Add(time.Duration(i)*time.Second), true) {
						t.Fatal("decides on an unusable document")
					}
				}
				if s.restored.Load() || !s.refuse() {
					t.Fatalf("restored %v, refuse %v", s.restored.Load(), s.refuse())
				}
				s.save()
				if string(shared.doc) != tc.doc {
					t.Fatalf("document replaced: %s", shared.doc)
				}
				out := logs.String()
				if n := strings.Count(out, "level=ERROR"); n != 1 {
					t.Fatalf("%d error lines in a minute, want 1:\n%s", n, out)
				}
				if !strings.Contains(out, tc.logged) || !strings.Contains(out, "store=/var/lib/packeteer/ha/lease.json.steering") {
					t.Fatalf("log does not name the reason and the file:\n%s", out)
				}
				if s.mayDecide(ctx, now.Add(holdLogEvery), true) {
					t.Fatal("decides a minute later")
				}
				if n := strings.Count(logs.String(), "level=ERROR"); n != 2 {
					t.Fatalf("%d error lines after a minute, want 2", n)
				}
				shared.doc = nil
				if !s.mayDecide(ctx, now.Add(holdLogEvery), true) || s.refuse() {
					t.Fatal("still held once the document is removed")
				}
			})
		}
	}
}

// Step-down drops the pins, the pause, and the acknowledgements: a later
// takeover that cannot use the saved document holds with nothing from the
// earlier term, and one that can acts only on what it read (#565).
func TestSteeringStateStepDownKeepsNothingForTheNextTerm(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	shared := &memSteering{}
	el := &haTestElector{active: true}
	ha := &haControl{el: el, log: slog.New(slog.NewTextHandler(io.Discard, nil)), poke: func() {}}
	s := newTestSteering(shared, eventlog.New(nil, nil, nil), ha)
	s.start(ctx, now)
	if !s.mayDecide(ctx, now, true) {
		t.Fatal("no decision after takeover")
	}
	down := plugin.Event{Time: now.Add(-time.Minute), Kind: plugin.EventProviderDown, Severity: plugin.SeverityCritical, Message: "down",
		Fields: map[string]string{"provider": "transit-a"}}
	s.events.Record(down)
	if _, err := s.events.Acknowledge(ctx, down.DedupKey(), "noc1", "ticket 7", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.testPins().Add(pin.Request{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Provider: "transit-b", MaxLossPct: 2, Duration: time.Hour}, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.opt.Pause("noc1", "upstream incident", now); !ok {
		t.Fatal("pause refused")
	}

	el.active = false
	s.stepDown()
	if got := s.pins.List(now); len(got) != 0 {
		t.Fatalf("pins kept after step-down: %+v", got)
	}
	if s.opt.State().Paused {
		t.Fatal("pause kept after step-down")
	}
	if _, ok := s.events.AckOf(down); ok {
		t.Fatal("ack kept after step-down")
	}

	// The other instance resumed and unpinned, then saved a document this
	// release cannot use.
	shared.doc = []byte(`{"version":2}`)
	el.active = true
	if s.mayDecide(ctx, now, true) {
		t.Fatal("decides on the earlier term's memory")
	}
	if len(s.pins.List(now)) != 0 || s.opt.State().Paused {
		t.Fatalf("held takeover has pins %+v, pause %+v", s.pins.List(now), s.opt.State())
	}
	shared.doc = []byte(`{"version":1}`)
	if !s.mayDecide(ctx, now, true) {
		t.Fatal("no decision on a usable document")
	}
	if len(s.pins.List(now)) != 0 || s.opt.State().Paused {
		t.Fatalf("takeover has pins %+v, pause %+v, want what it read", s.pins.List(now), s.opt.State())
	}
}
