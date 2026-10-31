// Package threatfeed turns external threat-intelligence lists into
// mitigation rules (#134).
//
// Feed plugins fetch lists of networks every interval. A listed network
// becomes a mitigation rule only when an explicit rule from config names
// the feed: with match destination, a listed network inside the rule's
// prefixes is itself the rule's destination; with match source, it is the
// FlowSpec source of a rule toward each of the rule's prefixes. Either
// way the destination must be an exact prefix in the learned RIB, and the
// rule goes through the mitigation controller (#28), which keeps its own
// mode (observe is a dry run), allowlist, cap, TTL, community, and
// NO_EXPORT. The controller caps feed-held rules (max_active) and new
// rules per rolling hour (max_actions_per_hour), never replaces a rule
// someone else holds, and adds nothing on an HA standby.
//
// A rule is removed when a successful fetch no longer lists its network.
// A failed fetch removes nothing and adds nothing: rules already held stay
// until their TTL, so a feed outage neither drops protection at once nor
// keeps it forever. A rule that expired is added again while the feed
// still lists the network; one an operator removed or replaced is not.
//
// State lives in memory only; a restart fetches again.
package threatfeed

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/mitigation"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Tick is how often Run fetches the feeds that are due and retries listed
// networks that wait for the learned RIB or a cap.
const Tick = 10 * time.Second

// fetchTimeout bounds one fetch.
const fetchTimeout = 30 * time.Second

// maxReason bounds the mitigation rule reason (the API's limit).
const maxReason = 256

// Mitigator is the mitigation controller surface the feeds act through.
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

// Feed is one configured feed plugin.
type Feed struct {
	Name   string
	Type   string
	Plugin plugin.ThreatFeed
}

// Rule is one explicit feed-to-mitigation rule (config.ThreatFeedRule).
type Rule struct {
	Name     string         `json:"name"`
	Feed     string         `json:"feed"`
	Match    string         `json:"match"`
	Prefixes []netip.Prefix `json:"prefixes"`
	Action   string         `json:"action"`
	Target   string         `json:"target,omitempty"`
	RateMbps float64        `json:"rate_mbps,omitempty"`
	TTL      time.Duration  `json:"-"`
	TTLText  string         `json:"ttl"`
}

// Widest listed networks a source rule acts on: an RIR's largest block.
// A wider source would drop most traffic toward the protected prefixes, so
// a feed that lists one (by mistake or compromised) is not followed.
const (
	MinSourceBitsV4 = 8
	MinSourceBitsV6 = 12
)

// destinations is where a listed network leads under r: itself when it is
// inside r's prefixes (match destination), or each of r's prefixes of its
// address family (match source), unless it is wider than the source floor.
func (r Rule) destinations(e netip.Prefix) []netip.Prefix {
	if r.Match == config.ThreatMatchSource {
		if (e.Addr().Is4() && e.Bits() < MinSourceBitsV4) || (e.Addr().Is6() && e.Bits() < MinSourceBitsV6) {
			return nil
		}
	}
	var out []netip.Prefix
	for _, p := range r.Prefixes {
		switch {
		case r.Match == config.ThreatMatchSource:
			if p.Addr().Is4() == e.Addr().Is4() {
				out = append(out, p)
			}
		case p.Bits() <= e.Bits() && p.Contains(e.Addr()):
			return []netip.Prefix{e}
		}
	}
	return out
}

// Config is the feed policy.
type Config struct {
	Interval          time.Duration
	MaxActive         int
	MaxActionsPerHour int
	Feeds             []Feed
	Rules             []Rule
	// Leader reports whether this instance is the active one of an HA
	// pair (#31). Nil is always active. A standby adds no rule.
	Leader func() bool
	// Poke runs a decision round at once, so a new or removed rule
	// reaches the edge without waiting for the probe interval.
	Poke func()
}

// Proposal states.
const (
	StateMitigating = "mitigating"
	StateEnded      = "ended: removed or replaced before its ttl; not added again while the feed lists it"
)

// Proposal is one listed network a rule acted on.
type Proposal struct {
	Rule    string       `json:"rule"`
	Feed    string       `json:"feed"`
	Entry   netip.Prefix `json:"entry"`
	Comment string       `json:"comment,omitempty"`
	// Prefix is the mitigation rule's destination.
	Prefix     netip.Prefix `json:"prefix"`
	Action     string       `json:"action"`
	Mitigation string       `json:"mitigation,omitempty"`
	State      string       `json:"state"`
	Since      time.Time    `json:"since"`

	expires time.Time
}

// FeedStatus is one feed in the API view.
type FeedStatus struct {
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Entries     int       `json:"entries"`
	LastFetch   time.Time `json:"last_fetch,omitzero"`
	LastSuccess time.Time `json:"last_success,omitzero"`
	// Error is the last fetch's error; empty when it succeeded.
	Error string `json:"error,omitempty"`
}

// Status is the API view.
type Status struct {
	Interval          string       `json:"interval"`
	MaxActive         int          `json:"max_active"`
	MaxActionsPerHour int          `json:"max_actions_per_hour"`
	ActionsLastHour   int          `json:"actions_last_hour"`
	Held              int          `json:"held"`
	Waiting           string       `json:"waiting,omitempty"`
	Feeds             []FeedStatus `json:"feeds"`
	Rules             []Rule       `json:"rules"`
	Proposals         []Proposal   `json:"proposals"`
}

type feedState struct {
	Feed
	entries                []plugin.ThreatEntry
	listed                 map[netip.Prefix]bool
	ok                     bool
	lastFetch, lastSuccess time.Time
	err                    string
}

type key struct {
	rule          string
	prefix, entry netip.Prefix
}

// Controller fetches the feeds and keeps their mitigation rules.
type Controller struct {
	cfg Config
	mit Mitigator
	log *slog.Logger

	mu      sync.Mutex
	rib     RIB
	feeds   map[string]*feedState
	props   map[key]*Proposal
	actions []time.Time
	waiting string
	last    time.Time
}

// New validates the policy.
func New(cfg Config, mit Mitigator, log *slog.Logger) (*Controller, error) {
	if mit == nil {
		return nil, errors.New("threat_feeds: threat mitigation is not configured")
	}
	if cfg.Interval <= 0 || cfg.MaxActive < 1 || cfg.MaxActionsPerHour < 1 {
		return nil, errors.New("threat_feeds: interval, max_active, and max_actions_per_hour must be positive")
	}
	if log == nil {
		log = slog.Default()
	}
	c := &Controller{cfg: cfg, mit: mit, log: log, feeds: map[string]*feedState{}, props: map[key]*Proposal{}}
	for _, f := range cfg.Feeds {
		if f.Plugin == nil {
			return nil, fmt.Errorf("threat_feeds: feed %s has no plugin", f.Name)
		}
		c.feeds[f.Name] = &feedState{Feed: f}
	}
	for _, r := range cfg.Rules {
		if c.feeds[r.Feed] == nil {
			return nil, fmt.Errorf("threat_feeds: rule %s reads unknown feed %q", r.Name, r.Feed)
		}
	}
	return c, nil
}

// SetRIB gives the controller the RIB view. Without one no rule is added.
func (c *Controller) SetRIB(rib RIB) {
	c.mu.Lock()
	c.rib = rib
	c.mu.Unlock()
}

// Run runs a round at once and then every Tick until ctx ends.
func (c *Controller) Run(ctx context.Context) {
	t := time.NewTicker(Tick)
	defer t.Stop()
	for {
		c.Round(ctx, time.Now)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Round fetches the feeds that are due, then reconciles the rules. The
// clock is read again after the fetches, which can take a while: a rule the
// mitigation controller expired must not look removed before its expiry.
func (c *Controller) Round(ctx context.Context, clock func() time.Time) {
	for _, f := range c.cfg.Feeds {
		st := c.feeds[f.Name]
		now := clock()
		// Only Round writes lastFetch, so this read needs no lock.
		if !st.lastFetch.IsZero() && now.Sub(st.lastFetch) < c.cfg.Interval {
			continue
		}
		fctx, cancel := context.WithTimeout(ctx, fetchTimeout)
		entries, err := f.Plugin.Fetch(fctx)
		cancel()
		if ctx.Err() != nil {
			return
		}
		c.mu.Lock()
		c.storeLocked(st, now, entries, err)
		c.mu.Unlock()
	}
	now := clock()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last = now
	c.reconcileLocked(now)
	c.addLocked(now)
}

func (c *Controller) storeLocked(f *feedState, now time.Time, entries []plugin.ThreatEntry, err error) {
	f.lastFetch = now
	if err != nil {
		f.ok, f.err = false, err.Error()
		c.log.Warn("threat feed fetch failed; its mitigation rules stay until their ttl and none is added until it answers",
			"feed", f.Name, "err", err)
		return
	}
	listed := make(map[netip.Prefix]bool, len(entries))
	var kept []plugin.ThreatEntry
	for _, e := range entries {
		if p := e.Prefix; p.IsValid() && p == p.Masked() && p.Bits() > 0 && !listed[p] {
			listed[p] = true
			kept = append(kept, e)
		}
	}
	c.log.Info("threat feed fetched", "feed", f.Name, "entries", len(kept))
	f.entries, f.listed, f.ok, f.err, f.lastSuccess = kept, listed, true, "", now
}

// reconcileLocked removes the rules whose network a successful fetch no
// longer lists and notes the ones that ended. The caller holds mu.
func (c *Controller) reconcileLocked(now time.Time) {
	for k, p := range c.props {
		f := c.feeds[p.Feed]
		// A feed that failed its last fetch still lists what it listed.
		listed := !f.ok || f.listed[p.Entry]
		if p.Mitigation != "" && !c.mit.Has(p.Mitigation) {
			if !now.Before(p.expires) {
				c.log.Info("threat feed mitigation expired", "feed", p.Feed, "rule", p.Rule, "entry", p.Entry, "mitigation", p.Mitigation)
				delete(c.props, k)
				continue
			}
			c.log.Info("threat feed mitigation removed by someone else; not added again while listed", "feed", p.Feed, "rule", p.Rule,
				"entry", p.Entry, "mitigation", p.Mitigation)
			p.Mitigation, p.State = "", StateEnded
		}
		if listed {
			continue
		}
		if p.Mitigation != "" && c.mit.Remove(p.Mitigation) {
			c.log.Info("threat feed entry delisted; mitigation removed", "feed", p.Feed, "rule", p.Rule, "entry", p.Entry, "mitigation", p.Mitigation)
			c.poke()
		}
		delete(c.props, k)
	}
}

// addLocked adds a mitigation rule for each listed network a rule maps to
// a learned destination, in rule order and then feed order, until a cap is
// reached. The caller holds mu.
func (c *Controller) addLocked(now time.Time) {
	switch {
	case c.cfg.Leader != nil && !c.cfg.Leader():
		c.waitLocked("ha standby (only the active instance adds rules)")
		return
	case c.rib == nil || !c.rib.Ready():
		c.waitLocked("the learned RIB is not ready")
		return
	}
	cut := now.Add(-time.Hour)
	c.actions = slices.DeleteFunc(c.actions, func(t time.Time) bool { return !t.After(cut) })
	held := c.heldLocked()
	for _, r := range c.cfg.Rules {
		f := c.feeds[r.Feed]
		if !f.ok {
			continue
		}
		for _, e := range f.entries {
			for _, dst := range r.destinations(e.Prefix) {
				k := key{r.Name, dst, e.Prefix}
				if c.props[k] != nil || !c.rib.Contains(dst) {
					continue
				}
				if held >= c.cfg.MaxActive {
					c.waitLocked("threat_feeds.max_active (" + strconv.Itoa(c.cfg.MaxActive) + ") reached")
					return
				}
				if len(c.actions) >= c.cfg.MaxActionsPerHour {
					c.waitLocked("threat_feeds.max_actions_per_hour (" + strconv.Itoa(c.cfg.MaxActionsPerHour) + ") reached")
					return
				}
				p := &Proposal{Rule: r.Name, Feed: r.Feed, Entry: e.Prefix, Comment: e.Comment, Prefix: dst, Action: r.Action, Since: now}
				m, err := c.mit.Add(request(r, p), now)
				if errors.Is(err, mitigation.ErrFull) {
					c.waitLocked(err.Error())
					return
				}
				if err != nil {
					// Invalid, or someone else holds the key: not retried
					// while the feed lists the network.
					p.State = "refused: " + err.Error()
					c.props[k] = p
					c.log.Warn("threat feed mitigation refused", "feed", r.Feed, "rule", r.Name, "entry", e.Prefix, "prefix", dst, "err", err)
					continue
				}
				p.Mitigation, p.State, p.expires = m.ID, StateMitigating, m.Expires
				c.props[k] = p
				c.actions = append(c.actions, now)
				held++
				c.log.Warn("threat feed mitigation added", "feed", r.Feed, "rule", r.Name, "entry", e.Prefix, "prefix", dst,
					"mitigation", m.ID, "action", m.Action, "expires", m.Expires.UTC().Format(time.RFC3339))
				c.poke()
			}
		}
	}
	c.waitLocked("")
}

func request(r Rule, p *Proposal) mitigation.Request {
	req := mitigation.Request{Prefix: p.Prefix, Action: r.Action, Target: r.Target, TTL: r.TTL, RateMbps: r.RateMbps, NoReplace: true}
	if r.Match == config.ThreatMatchSource {
		req.Match.Source = p.Entry
	}
	req.Reason = fmt.Sprintf("threat feed %s (rule %s): %s listed", r.Feed, r.Name, p.Entry)
	if p.Comment != "" {
		req.Reason += ": " + p.Comment
	}
	if len(req.Reason) > maxReason {
		req.Reason = req.Reason[:maxReason]
	}
	return req
}

func (c *Controller) heldLocked() int {
	n := 0
	for _, p := range c.props {
		if p.Mitigation != "" {
			n++
		}
	}
	return n
}

// waitLocked records why listed networks wait, logging each new reason.
func (c *Controller) waitLocked(why string) {
	if why == c.waiting {
		return
	}
	c.waiting = why
	if why != "" {
		c.log.Warn("threat feed mitigations waiting", "reason", why)
	}
}

func (c *Controller) poke() {
	if c.cfg.Poke != nil {
		c.cfg.Poke()
	}
}

// Status copies the state for the API.
func (c *Controller) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := Status{Interval: c.cfg.Interval.String(), MaxActive: c.cfg.MaxActive, MaxActionsPerHour: c.cfg.MaxActionsPerHour,
		Held: c.heldLocked(), Waiting: c.waiting, Feeds: []FeedStatus{}, Rules: []Rule{}, Proposals: []Proposal{}}
	cut := c.last.Add(-time.Hour)
	for _, t := range c.actions {
		if t.After(cut) {
			st.ActionsLastHour++
		}
	}
	for _, f := range c.cfg.Feeds {
		s := c.feeds[f.Name]
		st.Feeds = append(st.Feeds, FeedStatus{Name: f.Name, Type: f.Type, Entries: len(s.entries), LastFetch: s.lastFetch,
			LastSuccess: s.lastSuccess, Error: s.err})
	}
	for _, r := range c.cfg.Rules {
		r.TTLText = r.TTL.String()
		st.Rules = append(st.Rules, r)
	}
	for _, p := range c.props {
		st.Proposals = append(st.Proposals, *p)
	}
	slices.SortFunc(st.Proposals, func(a, b Proposal) int {
		if n := strings.Compare(a.Rule, b.Rule); n != 0 {
			return n
		}
		if n := a.Prefix.Addr().Compare(b.Prefix.Addr()); n != 0 {
			return n
		}
		return a.Entry.Addr().Compare(b.Entry.Addr())
	})
	return st
}
