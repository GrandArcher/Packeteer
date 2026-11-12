package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/eventlog"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/pin"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// pinControl is the API's handle on prefix pins (#558). A new pin is
// checked against the running config's providers and allowlist and the
// learned RIB view; Decide then treats it as a static rule.
type pinControl struct {
	store *pin.Store
	cfg   func() *config.Config
	// learned reports whether the exact prefix is in the RIB view. Nil
	// when there is no RIB view, which refuses every pin.
	learned func(netip.Prefix) bool
	log     *slog.Logger
	poke    func()
	save    func()
}

// pinRails is the configured providers and allowlist a pin is checked
// against, when it is set and when it is restored.
func pinRails(cfg *config.Config) pin.Rails {
	var rails pin.Rails
	if cfg == nil {
		return rails
	}
	for _, p := range cfg.Providers {
		rails.Providers = append(rails.Providers, p.Name)
	}
	for _, s := range cfg.Allowlist.Prefixes {
		if p, err := netip.ParsePrefix(s); err == nil {
			rails.Allowlist = append(rails.Allowlist, p)
		}
	}
	return rails
}

func (c pinControl) List(now time.Time) []pin.Pin { return c.store.List(now) }

func (c pinControl) Add(r pin.Request, now time.Time) (pin.Pin, error) {
	rails := pinRails(c.cfg())
	rails.Learned = c.learned
	p, err := c.store.Add(r, rails, now)
	if err != nil {
		return p, err
	}
	c.log.Info("prefix pinned through the API", "id", p.ID, "prefix", p.Prefix, "provider", p.Provider, "expires", p.Expires, "by", p.By)
	c.save()
	c.poke()
	return p, nil
}

func (c pinControl) Remove(id string) bool {
	p, ok := c.store.Remove(id)
	if !ok {
		return false
	}
	c.log.Info("prefix pin removed through the API", "id", id, "prefix", p.Prefix)
	c.save()
	c.poke()
	return true
}

// applyPins puts each probed prefix's pin into the round's policy verdicts
// ahead of the policy chain: an operator's pin is the newer intent.
func applyPins(in *policy.Input, pins *pin.Store, now time.Time) {
	v := pins.Verdicts(now)
	if len(v) == 0 {
		return
	}
	for _, r := range in.Results {
		pv, ok := v[r.Prefix]
		if !ok {
			continue
		}
		if in.Policies == nil {
			in.Policies = map[netip.Prefix]plugin.PolicyVerdict{}
		}
		in.Policies[r.Prefix] = pv
	}
}

// optimizationControl pauses and resumes the decision engine (#558). A
// steering store keeps the pause across a restart (#565).
type optimizationControl struct {
	decider *policy.Engine
	log     *slog.Logger
	poke    func()
	// save runs after each change, without mu: it reads State.
	save func()

	mu sync.Mutex
	st httpapi.Pause
}

func (c *optimizationControl) State() httpapi.Pause {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st
}

func (c *optimizationControl) Pause(by, reason string, now time.Time) (httpapi.Pause, bool) {
	c.mu.Lock()
	if c.st.Paused {
		st := c.st
		c.mu.Unlock()
		return st, false
	}
	c.st = httpapi.Pause{Paused: true, By: by, Reason: reason, Since: now.UTC()}
	c.decider.SetPaused(true)
	st := c.st
	c.mu.Unlock()
	c.log.Warn("optimization paused through the API; every improvement is withdrawn", "by", by, "reason", reason)
	c.save()
	c.poke()
	return st, true
}

func (c *optimizationControl) Resume() bool {
	c.mu.Lock()
	if !c.st.Paused {
		c.mu.Unlock()
		return false
	}
	c.st = httpapi.Pause{}
	c.decider.SetPaused(false)
	c.mu.Unlock()
	c.log.Info("optimization resumed through the API")
	c.save()
	c.poke()
	return true
}

// restore sets the saved pause, or clears it.
func (c *optimizationControl) restore(st httpapi.Pause) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !st.Paused {
		st = httpapi.Pause{}
	}
	c.st = st
	c.decider.SetPaused(st.Paused)
}

// steeringDocVersion is the saved document's format. A document of
// another version holds the controller like an unreadable store.
const steeringDocVersion = 1

// steeringDoc is the saved operator steering state (#565).
type steeringDoc struct {
	Version int                 `json:"version"`
	Pins    []pin.Pin           `json:"pins,omitempty"`
	Pause   httpapi.Pause       `json:"pause"`
	Acks    []eventlog.SavedAck `json:"acks,omitempty"`
}

// steeringTimeout bounds one save or load.
const steeringTimeout = 5 * time.Second

// steeringState saves the pins, the pause, and the alert acknowledgements
// after each change and restores them (#565): at start, and with ha each
// time this instance becomes active, before its first decision. With ha
// the store is the elector's, on the volume both instances mount, so a
// takeover restores what the active instance saved; storage is per
// instance and would bring back this instance's own older state. Without
// ha it is the storage plugin's. With neither, state is in memory.
type steeringState struct {
	store  plugin.SteeringStore
	pins   *pin.Store
	opt    *optimizationControl
	events *eventlog.Log
	cfg    func() *config.Config
	ha     *haControl
	log    *slog.Logger

	// mu orders saves and loads, so an older document never replaces a
	// newer one.
	mu sync.Mutex
	// restored is set once the saved state is in memory: at start, or with
	// ha at this term's takeover. Until then changes are refused, so a
	// restore never discards one.
	restored atomic.Bool
	// held is the reason last logged for not restoring, and heldLogged
	// when; under mu.
	held       string
	heldLogged time.Time
}

// steeringStoreOf picks where the steering state is saved, or nil.
func steeringStoreOf(plugins *pluginhost.Set) plugin.SteeringStore {
	if plugins == nil {
		return nil
	}
	if plugins.Elector != nil {
		s, _ := plugins.Elector.Plugin.(plugin.SteeringStore)
		return s
	}
	if plugins.Storage != nil {
		s, _ := plugins.Storage.Plugin.(plugin.SteeringStore)
		return s
	}
	return nil
}

// refuse reports whether a steering change must be refused now.
func (s *steeringState) refuse() bool {
	return !s.restored.Load() || !s.ha.active()
}

// start restores the saved state. With ha it only fills the read views:
// changes wait for takeover. Without ha, a store that cannot be read leaves
// the state unrestored and the decision loop retries.
func (s *steeringState) start(ctx context.Context, now time.Time) {
	if s.load(ctx, now) && s.ha == nil {
		s.restored.Store(true)
	}
}

// takeover restores what the active instance saved, before this
// instance's first decision as the active one; without ha it is the retry
// after a failed read at start. While the saved state cannot be used,
// changes are refused and the decision loop makes no decision: a save would
// replace the saved state with an older one, and a decision would use a
// pause or pins the operator has since changed.
func (s *steeringState) takeover(ctx context.Context, now time.Time) {
	if s.load(ctx, now) {
		s.restored.Store(true)
	}
}

// mayDecide reports whether this round may decide: this instance is
// active and the saved state is in memory. The state is read first when it
// is not, so a pause or pin the operator changed is never missed.
func (s *steeringState) mayDecide(ctx context.Context, now time.Time, active bool) bool {
	if !active {
		return false
	}
	if !s.restored.Load() {
		s.takeover(ctx, now)
	}
	return s.restored.Load()
}

// stepDown refuses changes until the next takeover and drops the pins,
// the pause, and the acknowledgements, so a takeover acts only on what it
// reads from the store. A lease that moves to the other instance and back
// within one decision round is not seen as a step-down: this instance
// keeps its memory and its next save replaces what the other one saved,
// the same gap decider.Reset has.
func (s *steeringState) stepDown() {
	s.restored.Store(false)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pins.Restore(nil, pin.Rails{}, time.Now())
	s.opt.restore(httpapi.Pause{})
	_ = s.events.RestoreAcks(context.Background(), nil)
}

// holdLogEvery bounds how often an unchanged reason for holding is logged.
const holdLogEvery = time.Minute

// hold logs why the saved state is not restored: when the reason changes,
// and at most once a minute while it stays, since load runs every round.
// s.mu is held.
func (s *steeringState) hold(now time.Time, reason string, args ...any) {
	if reason == s.held && now.Sub(s.heldLogged) < holdLogEvery {
		return
	}
	s.held, s.heldLogged = reason, now
	s.log.Error(reason, append([]any{"store", s.store.SteeringLocation()}, args...)...)
}

// load restores the saved state. It reports false, and changes nothing in
// memory, when the store cannot be read or the document cannot be used: it
// does not parse, or another version wrote it. Running on without it would
// act on pins or a pause the operator has since changed.
func (s *steeringState) load(ctx context.Context, now time.Time) bool {
	if s.store == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, steeringTimeout)
	defer cancel()
	raw, err := s.store.SteeringState(ctx)
	if err != nil {
		s.hold(now, "steering state cannot be read; no decision is made and steering changes are refused until it can", "err", err)
		return false
	}
	const unparsed = "steering state document cannot be parsed; no decision is made and steering changes are refused until it is fixed or removed"
	var doc steeringDoc
	if raw != nil {
		var head struct {
			Version int `json:"version"`
		}
		if err := json.Unmarshal(raw, &head); err != nil {
			s.hold(now, unparsed, "err", err)
			return false
		}
		if head.Version != steeringDocVersion {
			s.hold(now, "steering state document is of another version, from another Packeteer release; no decision is made and steering changes are refused until that release runs again or the document is removed", "version", head.Version, "want", steeringDocVersion)
			return false
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			s.hold(now, unparsed, "version", head.Version, "err", err)
			return false
		}
	}
	s.held = ""
	for _, why := range s.pins.Restore(doc.Pins, pinRails(s.cfg()), now) {
		s.log.Info("saved pin not restored", "pin", why)
	}
	s.opt.restore(doc.Pause)
	if err := s.events.RestoreAcks(ctx, doc.Acks); err != nil {
		s.log.Error("alert acknowledgements not restored", "err", err)
	}
	if doc.Pause.Paused {
		s.log.Warn("optimization is paused (restored); every improvement stays withdrawn until resumed", "by", doc.Pause.By, "reason", doc.Pause.Reason, "since", doc.Pause.Since)
	}
	s.log.Info("steering state restored", "pins", len(s.pins.List(now)), "paused", doc.Pause.Paused, "acks", len(doc.Acks))
	return true
}

// save writes the current state. A failed write is logged: the change
// holds in memory and is lost on a restart or takeover. Nothing is written
// while changes are refused: memory may be older than the store, and not
// every caller is behind the API gate (an alert that resolves drops its ack).
func (s *steeringState) save() {
	if s.store == nil || s.refuse() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := json.Marshal(steeringDoc{Version: steeringDocVersion, Pins: s.pins.List(time.Now()), Pause: s.opt.State(), Acks: s.events.SavedAcks()})
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), steeringTimeout)
		err = s.store.PutSteeringState(ctx, raw)
		cancel()
	}
	if err != nil {
		s.log.Error("steering state not saved; the last change is lost on a restart or failover", "err", err)
	}
}
