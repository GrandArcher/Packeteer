// Package anomaly is automatic traffic anomaly (DDoS) detection (#33).
//
// On its own interval the controller reads per-prefix, per-protocol flow
// counters from a flow source, turns the deltas into rates, and hands
// them to a detector plugin, which keeps the baselines and reports the
// keys far above them. Every anomaly goes to a bounded feed, to Changes
// (notifier events and stored history), and to the log.
//
// An anomaly leads to a mitigation rule only when an explicit anomaly
// rule from config matches it (destination inside the rule's prefixes,
// protocol in its protocols, rate at least its min_mbps), and only through
// the mitigation controller (#28), which keeps its own mode (observe is a
// dry run), allowlist, cap, TTL, community, and NO_EXPORT and announces
// only an exact learned prefix. The controller also checks the exact
// prefix in the learned RIB first, caps detector-held rules
// (max_active) and new rules per rolling hour (max_actions_per_hour),
// never replaces a rule someone else holds, and adds nothing on an HA
// standby. The rule is removed when the anomaly clears, and it expires on
// its TTL in any case; a rule that ended while its anomaly is still active
// is not added again for that anomaly. When the flow source fails for
// staleRounds rounds in a row every anomaly is cleared and its rule
// removed: no mitigation outlives the data that justified it.
//
// Baselines, anomalies, and rules live in memory only; a restart learns
// again and holds nothing.
package anomaly

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/mitigation"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// FeedSize is how many changes the in-memory feed keeps.
const FeedSize = 200

// staleRounds is how many failed flow reads in a row clear every anomaly.
const staleRounds = 3

// maxReason bounds the mitigation rule reason (the API's limit).
const maxReason = 256

// Mitigator is the mitigation controller surface the detector acts
// through.
type Mitigator interface {
	Add(req mitigation.Request, now time.Time) (mitigation.Rule, error)
	Remove(id string) bool
	Has(id string) bool
}

// RIB reports whether an exact prefix is learned.
type RIB interface {
	Ready() bool
	Contains(netip.Prefix) bool
}

// Rule is one explicit anomaly-to-mitigation rule (config.AnomalyRule).
type Rule struct {
	Name      string              `json:"name"`
	Prefixes  []netip.Prefix      `json:"prefixes"`
	Protocols []plugin.IPProtocol `json:"protocols,omitempty"`
	MinMbps   float64             `json:"min_mbps,omitempty"`
	Action    string              `json:"action"`
	Target    string              `json:"target,omitempty"`
	RateMbps  float64             `json:"rate_mbps,omitempty"`
	TTL       time.Duration       `json:"-"`
	TTLText   string              `json:"ttl"`
}

// matches reports whether r acts on anomaly a.
func (r Rule) matches(a *Anomaly) bool {
	if a.PeakMbps < r.MinMbps && a.Mbps < r.MinMbps {
		return false
	}
	if len(r.Protocols) > 0 && !slices.Contains(r.Protocols, a.Protocol) {
		return false
	}
	for _, p := range r.Prefixes {
		if p.Bits() <= a.Prefix.Bits() && p.Contains(a.Prefix.Addr()) {
			return true
		}
	}
	return false
}

// Config is the detection policy.
type Config struct {
	Interval          time.Duration
	MaxActionsPerHour int
	MaxActive         int
	Rules             []Rule
	// Detector and Source name the plugins, for the API.
	Detector string
	Source   string
	// Leader reports whether this instance is the active one of an HA
	// pair (#31). Nil is always active. A standby adds no rule.
	Leader func() bool
	// Poke runs a decision round at once, so a new or removed rule
	// reaches the edge without waiting for the probe interval.
	Poke func()
}

// Anomaly is one open anomaly.
type Anomaly struct {
	ID           string            `json:"id"`
	Prefix       netip.Prefix      `json:"prefix"`
	Protocol     plugin.IPProtocol `json:"protocol"`
	Mbps         float64           `json:"mbps"`
	PeakMbps     float64           `json:"peak_mbps"`
	BaselineMbps float64           `json:"baseline_mbps"`
	Reason       string            `json:"reason"`
	Since        time.Time         `json:"since"`
	// Rule is the anomaly rule that matched ("" when none did).
	Rule string `json:"rule,omitempty"`
	// Mitigation is the mitigation rule the detector added and still
	// holds, and Action its action.
	Mitigation string `json:"mitigation,omitempty"`
	Action     string `json:"action,omitempty"`
	// State says what the detector did about it.
	State string `json:"state"`

	key  plugin.TrafficKey
	done bool // a mitigation was added once, or refused for good
	// lastMit and lastAction are the mitigation rule added for the
	// anomaly, kept for history after it ends.
	lastMit, lastAction string
}

// States.
const (
	StateNoRule     = "alert only: no anomaly rule matches"
	StateMitigating = "mitigating"
)

// Change kinds, in the feed and in Changes.
const (
	ChangeDetected  = "detected"
	ChangeMitigated = "mitigated"
	ChangeHeld      = "held"
	ChangeEnded     = "mitigation_ended"
	ChangeCleared   = "cleared"
)

// Change is one entry of the feed.
type Change struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`
	Detail  string    `json:"detail,omitempty"`
	Anomaly Anomaly   `json:"anomaly"`
}

// Status is the API view.
type Status struct {
	Detector          string    `json:"detector"`
	Source            string    `json:"source"`
	Interval          string    `json:"interval"`
	Tracked           int       `json:"baselines"`
	MaxActive         int       `json:"max_active"`
	MaxActionsPerHour int       `json:"max_actions_per_hour"`
	ActionsLastHour   int       `json:"actions_last_hour"`
	Mitigating        int       `json:"mitigating"`
	LastRound         time.Time `json:"last_round,omitzero"`
	Error             string    `json:"error,omitempty"`
	Rules             []Rule    `json:"rules"`
	Anomalies         []Anomaly `json:"anomalies"`
	// Feed is the most recent changes, newest first.
	Feed []Change `json:"feed"`
}

// Controller runs detection rounds.
type Controller struct {
	cfg Config
	src plugin.FlowCounterSource
	det plugin.Detector
	mit Mitigator
	log *slog.Logger

	mu        sync.Mutex
	rib       RIB
	prev      map[plugin.TrafficKey]uint64
	prevAt    time.Time
	active    map[plugin.TrafficKey]*Anomaly
	actions   []time.Time
	feed      []Change
	pending   []Change
	failures  int
	tracked   int
	lastRound time.Time
	lastErr   string
}

// New validates the policy. mit may be nil only when there are no rules.
func New(cfg Config, src plugin.FlowCounterSource, det plugin.Detector, mit Mitigator, log *slog.Logger) (*Controller, error) {
	if src == nil {
		return nil, errors.New("anomaly: a flow source is required")
	}
	if det == nil {
		return nil, errors.New("anomaly: a detector is required")
	}
	if cfg.Interval <= 0 {
		return nil, errors.New("anomaly: interval must be positive")
	}
	if cfg.MaxActive < 1 || cfg.MaxActionsPerHour < 1 {
		return nil, errors.New("anomaly: max_active and max_actions_per_hour must be positive")
	}
	if len(cfg.Rules) > 0 && mit == nil {
		return nil, errors.New("anomaly: rules act only through threat mitigation, which is not configured")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Controller{cfg: cfg, src: src, det: det, mit: mit, log: log,
		prev: map[plugin.TrafficKey]uint64{}, active: map[plugin.TrafficKey]*Anomaly{}}, nil
}

// SetRIB gives the controller the RIB view. Without one no rule is added.
func (c *Controller) SetRIB(rib RIB) {
	c.mu.Lock()
	c.rib = rib
	c.mu.Unlock()
}

// Run runs a round every interval until ctx ends.
func (c *Controller) Run(ctx context.Context) {
	t := time.NewTicker(c.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			rctx, cancel := context.WithTimeout(ctx, c.cfg.Interval)
			if err := c.Round(rctx, now); err != nil && ctx.Err() == nil {
				c.log.Warn("anomaly round", "err", err)
			}
			cancel()
		}
	}
}

// Round reads the counters, runs the detector, and acts on its anomalies.
func (c *Controller) Round(ctx context.Context, now time.Time) error {
	counters, err := c.src.FlowCounters(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastRound = now
	if err != nil {
		c.failures++
		c.lastErr = err.Error()
		if c.failures >= staleRounds && len(c.active) > 0 {
			c.log.Warn("anomaly: flow data unavailable; clearing anomalies and removing their mitigation rules", "rounds", c.failures, "err", err)
			for _, a := range c.sortedLocked() {
				c.clearLocked(now, a, "flow data unavailable: "+err.Error())
			}
			// The next good read starts a new rate baseline, and the
			// detector learns again.
			c.prev, c.prevAt = map[plugin.TrafficKey]uint64{}, time.Time{}
			c.det.Reset()
			c.tracked = 0
		}
		return err
	}
	c.failures, c.lastErr = 0, ""
	cur := make(map[plugin.TrafficKey]uint64, len(counters))
	for _, fc := range counters {
		if fc.Prefix.IsValid() {
			cur[plugin.TrafficKey{Prefix: fc.Prefix.Masked(), Protocol: fc.Protocol}] += fc.Bytes
		}
	}
	first, elapsed := c.prevAt.IsZero(), now.Sub(c.prevAt)
	prev := c.prev
	c.prev, c.prevAt = cur, now
	if first || elapsed <= 0 {
		return nil
	}
	sec := elapsed.Seconds()
	var samples []plugin.TrafficSample
	for k, b := range cur {
		d := b
		if p, ok := prev[k]; ok && b >= p {
			d = b - p
		}
		if d > 0 {
			samples = append(samples, plugin.TrafficSample{Key: k, Mbps: float64(d) * 8 / sec / 1e6})
		}
	}
	found := c.det.Observe(now, samples)
	c.tracked = c.det.Tracked()
	open := map[plugin.TrafficKey]bool{}
	for _, f := range found {
		if !f.Key.Prefix.IsValid() {
			continue
		}
		open[f.Key] = true
		a := c.active[f.Key]
		if a == nil {
			a = &Anomaly{ID: newID(), Prefix: f.Key.Prefix, Protocol: f.Key.Protocol, Since: f.Since, key: f.Key}
			if a.Since.IsZero() {
				a.Since = now
			}
			c.active[f.Key] = a
			a.Mbps, a.PeakMbps, a.BaselineMbps, a.Reason = f.Mbps, max(f.PeakMbps, f.Mbps), f.BaselineMbps, f.Reason
			c.log.Warn("anomaly detected", "id", a.ID, "prefix", a.Prefix, "protocol", a.Protocol, "mbps", round2(a.Mbps),
				"baseline_mbps", round2(a.BaselineMbps), "reason", a.Reason)
			c.changeLocked(now, ChangeDetected, a, a.Reason)
		}
		a.Mbps, a.PeakMbps, a.BaselineMbps, a.Reason = f.Mbps, max(a.PeakMbps, f.PeakMbps, f.Mbps), f.BaselineMbps, f.Reason
	}
	for _, a := range c.sortedLocked() {
		if !open[a.key] {
			c.clearLocked(now, a, "traffic is back within its baseline")
		}
	}
	for _, a := range c.sortedLocked() {
		c.actLocked(now, a)
	}
	return nil
}

// actLocked adds a mitigation rule for a when a rule matches and every
// limit allows it. The caller holds mu.
func (c *Controller) actLocked(now time.Time, a *Anomaly) {
	if a.Mitigation != "" {
		if c.mit.Has(a.Mitigation) {
			return
		}
		detail := "mitigation rule " + a.Mitigation + " ended (expired or removed); not added again while this anomaly lasts"
		c.log.Info("anomaly mitigation ended", "id", a.ID, "prefix", a.Prefix, "mitigation", a.Mitigation)
		a.Mitigation, a.Action = "", ""
		a.State = "mitigation ended; not added again while this anomaly lasts"
		c.changeLocked(now, ChangeEnded, a, detail)
		return
	}
	if a.done {
		return
	}
	rule, ok := c.matchLocked(a)
	if !ok {
		if a.State != StateNoRule {
			a.State = StateNoRule
			c.log.Info("anomaly: no rule matches; alert only", "id", a.ID, "prefix", a.Prefix, "protocol", a.Protocol)
		}
		return
	}
	a.Rule = rule.Name
	hold := func(state string) {
		if a.State == state {
			return
		}
		a.State = state
		c.log.Warn("anomaly mitigation held back", "id", a.ID, "prefix", a.Prefix, "rule", rule.Name, "state", state)
		c.changeLocked(now, ChangeHeld, a, state)
	}
	if c.cfg.Leader != nil && !c.cfg.Leader() {
		hold("waiting: ha standby (only the active instance adds rules)")
		return
	}
	if c.rib == nil || !c.rib.Ready() || !c.rib.Contains(a.Prefix) {
		hold("waiting: " + a.Prefix.String() + " is not an exact prefix in the learned RIB")
		return
	}
	held := 0
	for _, x := range c.active {
		if x.Mitigation != "" {
			held++
		}
	}
	if held >= c.cfg.MaxActive {
		hold("waiting: anomaly.max_active (" + strconv.Itoa(c.cfg.MaxActive) + ") reached")
		return
	}
	cut := now.Add(-time.Hour)
	c.actions = slices.DeleteFunc(c.actions, func(t time.Time) bool { return !t.After(cut) })
	if len(c.actions) >= c.cfg.MaxActionsPerHour {
		hold("waiting: anomaly.max_actions_per_hour (" + strconv.Itoa(c.cfg.MaxActionsPerHour) + ") reached")
		return
	}
	req := mitigation.Request{Prefix: a.Prefix, Action: rule.Action, Target: rule.Target, TTL: rule.TTL, RateMbps: rule.RateMbps, NoReplace: true}
	if plugin.IsFlowSpec(rule.Action) && a.Protocol != 0 {
		req.Match.Protocols = []plugin.IPProtocol{a.Protocol}
	}
	req.Reason = fmt.Sprintf("anomaly %s (rule %s): %s", a.ID, rule.Name, a.Reason)
	if len(req.Reason) > maxReason {
		req.Reason = req.Reason[:maxReason]
	}
	r, err := c.mit.Add(req, now)
	if err != nil {
		if errors.Is(err, mitigation.ErrFull) {
			hold("waiting: " + err.Error())
			return
		}
		// Invalid or conflicting (someone else holds the key): not
		// retried for this anomaly.
		a.done = true
		hold("refused: " + err.Error())
		return
	}
	a.done = true
	a.Mitigation, a.Action, a.State = r.ID, r.Action, StateMitigating
	a.lastMit, a.lastAction = r.ID, r.Action
	c.actions = append(c.actions, now)
	c.log.Warn("anomaly mitigation added", "id", a.ID, "prefix", a.Prefix, "protocol", a.Protocol, "rule", rule.Name,
		"mitigation", r.ID, "action", r.Action, "expires", r.Expires.UTC().Format(time.RFC3339))
	c.changeLocked(now, ChangeMitigated, a, "mitigation rule "+r.ID+" ("+r.Action+") added by rule "+rule.Name)
	if c.cfg.Poke != nil {
		c.cfg.Poke()
	}
}

func (c *Controller) matchLocked(a *Anomaly) (Rule, bool) {
	for _, r := range c.cfg.Rules {
		if r.matches(a) {
			return r, true
		}
	}
	return Rule{}, false
}

// clearLocked ends a and removes the mitigation rule it added. The caller
// holds mu.
func (c *Controller) clearLocked(now time.Time, a *Anomaly, why string) {
	delete(c.active, a.key)
	detail := why
	if a.Mitigation != "" && c.mit.Remove(a.Mitigation) {
		detail += "; mitigation rule " + a.Mitigation + " removed"
		if c.cfg.Poke != nil {
			c.cfg.Poke()
		}
	}
	c.log.Info("anomaly cleared", "id", a.ID, "prefix", a.Prefix, "protocol", a.Protocol, "peak_mbps", round2(a.PeakMbps), "detail", detail)
	c.changeLocked(now, ChangeCleared, a, detail)
}

func (c *Controller) sortedLocked() []*Anomaly {
	out := make([]*Anomaly, 0, len(c.active))
	for _, a := range c.active {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out
}

func less(a, b *Anomaly) bool {
	if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
		return c < 0
	}
	if a.Prefix.Bits() != b.Prefix.Bits() {
		return a.Prefix.Bits() < b.Prefix.Bits()
	}
	return a.Protocol < b.Protocol
}

// changeLocked appends a change to the feed and to the pending changes.
func (c *Controller) changeLocked(now time.Time, kind string, a *Anomaly, detail string) {
	ch := Change{Time: now, Kind: kind, Detail: detail, Anomaly: *a}
	c.feed = append(c.feed, ch)
	if len(c.feed) > FeedSize {
		c.feed = slices.Clone(c.feed[len(c.feed)-FeedSize:])
	}
	c.pending = append(c.pending, ch)
	if len(c.pending) > 10*FeedSize {
		c.pending = slices.Clone(c.pending[len(c.pending)-FeedSize:])
	}
}

// Changes returns and clears the changes since the last call, oldest
// first, for notifier events and history.
func (c *Controller) Changes() []Change {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.pending
	c.pending = nil
	return out
}

// Status copies the state for the API.
func (c *Controller) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := Status{Detector: c.cfg.Detector, Source: c.cfg.Source, Interval: c.cfg.Interval.String(), Tracked: c.tracked,
		MaxActive: c.cfg.MaxActive, MaxActionsPerHour: c.cfg.MaxActionsPerHour, LastRound: c.lastRound, Error: c.lastErr,
		Rules: []Rule{}, Anomalies: []Anomaly{}, Feed: []Change{}}
	cut := c.lastRound.Add(-time.Hour)
	for _, t := range c.actions {
		if t.After(cut) {
			st.ActionsLastHour++
		}
	}
	for _, r := range c.cfg.Rules {
		r.TTLText = r.TTL.String()
		st.Rules = append(st.Rules, r)
	}
	for _, a := range c.sortedLocked() {
		if a.Mitigation != "" {
			st.Mitigating++
		}
		st.Anomalies = append(st.Anomalies, *a)
	}
	for i := len(c.feed) - 1; i >= 0; i-- {
		st.Feed = append(st.Feed, c.feed[i])
	}
	return st
}

// Record is the stored history row for an anomaly after change ch.
func Record(ch Change) plugin.AnomalyRecord {
	a := ch.Anomaly
	rec := plugin.AnomalyRecord{ID: a.ID, Prefix: a.Prefix, Protocol: a.Protocol.String(), PeakMbps: a.PeakMbps,
		BaselineMbps: a.BaselineMbps, Reason: a.Reason, Rule: a.Rule, Mitigation: a.lastMit, Action: a.lastAction, Start: a.Since}
	if a.Protocol == 0 {
		rec.Protocol = "any"
	}
	if ch.Kind == ChangeCleared {
		rec.End, rec.EndReason = ch.Time, ch.Detail
	}
	return rec
}

func round2(v float64) float64 { return float64(int64(v*100+0.5)) / 100 }

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
