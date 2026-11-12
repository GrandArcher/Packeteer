package main

import (
	"context"
	"encoding/json"
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
	if _, m := d.call(http.MethodGet, "/api/pins", ""); len(m["pins"].([]any)) != 1 {
		d.fatalf("pin dropped while its prefix is not learned: %v", m)
	}
	edge.advertise("203.0.113.0/24")
	d.waitWire("the restored pin once the prefix is learned", pinned)
	d.holdWire("only the learned prefix is announced", 2*time.Second, func(w map[string]ixRoute) bool { return len(w) == 1 && pinned(w) })
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

// steeringConfig has the providers and allowlist the steering tests pin
// under.
func steeringConfig() *config.Config {
	return &config.Config{Providers: []config.Provider{{Name: "transit-a"}, {Name: "transit-b"}},
		Allowlist: config.Allowlist{Prefixes: []string{"198.51.100.0/22"}}}
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
	if _, err := a.testPins().Add(pin.Request{Prefix: netip.MustParsePrefix("198.51.101.0/24"), Provider: "transit-b", MaxLossPct: 2, Duration: pin.MinDuration}, now); err != nil {
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
	mu  sync.Mutex
	doc []byte
}

func (m *memSteering) SteeringState(context.Context) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.doc, nil
}

func (m *memSteering) PutSteeringState(_ context.Context, doc []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.doc = doc
	return nil
}

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

	// Failover: a stops, b becomes active.
	elA.active, elB.active = false, true
	a.stepDown()
	if !b.refuse() {
		t.Fatal("b takes changes before it restored the pair's state")
	}
	b.takeover(ctx, now)
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
