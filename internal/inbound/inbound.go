// Package inbound is inbound commit control (#25, first half). It decides
// when to steer inbound traffic for the operator's own prefixes away from a
// provider, and in inject mode it re-announces those prefixes to the edge
// through an in-process inbound announcer that adds the provider's catalog
// prepend signal and TE communities.
//
// A provider is steered when its inbound 95th percentile is above its
// commit, and released once it is at or below release_pct of the commit
// and the steer has been held for hold_time. A released provider waits
// hold_time before it can be steered again. Stale or missing telemetry
// releases at once (fail closed). Packeteer never steers away from every
// configured provider.
//
// Only inject announces. observe logs; suggest logs and publishes the
// suggestion on the API and as events, so an operator can apply it by hand.
// A steer route is announced only for an inbound prefix that is
// allowlisted and present in the learned RIB, with the learned next hop,
// within the shared max_improvements cap. A route already announced stays
// while the steer is wanted even if the edge stops sending the prefix
// (its best path is then the steer route); improvement_ttl bounds that,
// and a new announcement always needs the prefix back in the RIB.
package inbound

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// RIB is the slice of the RIB view inbound needs. NextHop returns the
// learned next hop of an exact prefix the edge is advertising.
type RIB interface {
	Ready() bool
	NextHop(netip.Prefix) (netip.Addr, bool)
}

// Config is the inbound policy.
type Config struct {
	Mode      string
	Prefixes  []netip.Prefix
	Allowlist []netip.Prefix
	Community string
	LocalPref uint32
	// MaxImprovements caps inbound steer routes.
	MaxImprovements int
	// SharedCap is the top-level max_improvements. Others reports the
	// outbound routes on the wire; inbound never pushes the sum past it.
	SharedCap int
	Others    func() int
	HoldTime  time.Duration
	// TTL retires a steer after this long (improvement_ttl). The route is
	// withdrawn for at least one round, so the prefix has to reappear in
	// the RIB before it is announced again. Zero or negative disables.
	TTL        time.Duration
	ReleasePct float64
	// MaxAge is how old a telemetry row may be. Older rows release.
	MaxAge time.Duration
	// Providers are the configured, non-excluded provider names.
	Providers []string
}

// DefaultMaxAge is how old a telemetry row may be before a steer on it is
// released. It matches the commit scorer's default.
const DefaultMaxAge = 15 * time.Minute

const maxFutureSkew = time.Minute

// Change actions.
const (
	ActionSteer   = "steer"
	ActionRelease = "release"
)

// Steer is one provider inbound traffic is being moved away from.
type Steer struct {
	Provider   string               `json:"provider"`
	Since      time.Time            `json:"since"`
	InMbps95   float64              `json:"in_mbps_95"`
	CommitMbps float64              `json:"commit_mbps"`
	Action     plugin.InboundAction `json:"action"`
}

// Change is one steer or release decided by Evaluate.
type Change struct {
	Action string `json:"action"`
	Steer  Steer  `json:"steer"`
	Reason string `json:"reason"`
}

// Route is a steer route on the wire.
type Route struct {
	Prefix  netip.Prefix `json:"prefix"`
	NextHop netip.Addr   `json:"next_hop"`
	Away    []string     `json:"away"`
}

// Status is the read-only view served on /api/inbound.
type Status struct {
	Mode      string    `json:"mode"`
	Prefixes  []string  `json:"prefixes"`
	Steers    []Steer   `json:"steers"`
	Announced []Route   `json:"announced"`
	Blocked   []Blocked `json:"blocked"`
	// Evaluated is the last Evaluate time.
	Evaluated time.Time `json:"evaluated"`
}

// Blocked is a provider over commit that was not steered, and why.
type Blocked struct {
	Provider string `json:"provider"`
	Reason   string `json:"reason"`
}

// Controller plans inbound steers and syncs them to the announcer.
type Controller struct {
	cfg Config
	ann plugin.InboundAnnouncer
	rib RIB
	log *slog.Logger

	mu        sync.Mutex
	steers    map[string]Steer
	cooldown  map[string]time.Time
	blocked   []Blocked
	evaluated time.Time
	active    map[netip.Prefix]Route
	onWire    atomic.Int64
}

// New validates the settings. ann may be nil outside inject: observe and
// suggest then plan without a catalog.
func New(cfg Config, ann plugin.InboundAnnouncer, rib RIB, log *slog.Logger) (*Controller, error) {
	if cfg.Mode == config.ModeInject {
		switch {
		case ann == nil:
			return nil, errors.New("inbound: inject mode requires an inbound announcer")
		case rib == nil:
			return nil, errors.New("inbound: inject mode requires a RIB view")
		case cfg.LocalPref == 0:
			return nil, errors.New("inbound: inject mode requires local_pref")
		case cfg.Community == "":
			return nil, errors.New("inbound: inject mode requires a community")
		case cfg.MaxImprovements < 1:
			return nil, errors.New("inbound: max_improvements must be positive")
		case len(cfg.Allowlist) == 0:
			return nil, errors.New("inbound: inject mode requires an allowlist")
		}
	}
	if cfg.ReleasePct <= 0 || cfg.ReleasePct > 100 {
		cfg.ReleasePct = config.DefaultInboundReleasePct
	}
	if log == nil {
		log = slog.Default()
	}
	prefixes := make([]netip.Prefix, 0, len(cfg.Prefixes))
	for _, p := range cfg.Prefixes {
		prefixes = append(prefixes, p.Masked())
	}
	sortPrefixes(prefixes)
	cfg.Prefixes = prefixes
	return &Controller{
		cfg: cfg, ann: ann, rib: rib, log: log,
		steers: map[string]Steer{}, cooldown: map[string]time.Time{}, active: map[netip.Prefix]Route{},
	}, nil
}

// Reserved reports whether p is an inbound prefix. The outbound announcer
// refuses these so the two never publish the same prefix.
func (c *Controller) Reserved(p netip.Prefix) bool {
	if c == nil {
		return false
	}
	return slices.Contains(c.cfg.Prefixes, p.Masked())
}

// Active is the number of steer routes on the wire.
func (c *Controller) Active() int {
	if c == nil {
		return 0
	}
	return int(c.onWire.Load())
}

func (c *Controller) action(provider string) (plugin.InboundAction, bool) {
	if c.ann == nil {
		return plugin.InboundAction{Provider: provider}, true
	}
	return c.ann.Action(provider)
}

// Evaluate updates the steer set from telemetry and returns what changed.
// It does not announce; Sync does, and only in inject.
func (c *Controller) Evaluate(now time.Time, usage []plugin.Usage) []Change {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evaluated = now
	fresh := map[string]plugin.Usage{}
	for _, u := range usage {
		if !slices.Contains(c.cfg.Providers, u.Provider) || u.Error != "" {
			continue
		}
		if _, ok := u.InboundMbps(); !ok {
			continue
		}
		// Telemetry is read after the decision clock, so a row may be
		// stamped slightly ahead of now. Far ahead is a bad clock.
		age := now.Sub(u.Updated)
		if u.Updated.IsZero() || age < -maxFutureSkew || (c.cfg.MaxAge > 0 && age > c.cfg.MaxAge) {
			continue
		}
		fresh[u.Provider] = u
	}

	var changes []Change
	released := map[string]bool{}
	release := func(s Steer, reason string, cool bool) {
		delete(c.steers, s.Provider)
		released[s.Provider] = true
		if cool && c.cfg.HoldTime > 0 {
			c.cooldown[s.Provider] = now.Add(c.cfg.HoldTime)
		}
		changes = append(changes, Change{Action: ActionRelease, Steer: s, Reason: reason})
	}
	for _, p := range sortedKeys(c.steers) {
		s := c.steers[p]
		u, ok := fresh[p]
		if !ok {
			release(s, "inbound telemetry is stale or missing", true)
			continue
		}
		in95, _ := u.InboundMbps()
		s.InMbps95, s.CommitMbps = in95, u.CommitMbps
		held := now.Sub(s.Since) >= c.cfg.HoldTime
		switch {
		case c.cfg.TTL > 0 && now.Sub(s.Since) >= c.cfg.TTL:
			release(s, "improvement_ttl reached", false)
		case held && in95 <= u.CommitMbps*c.cfg.ReleasePct/100:
			release(s, fmt.Sprintf("inbound 95th %.1f Mbps is at or below %.0f%% of the %.1f Mbps commit", in95, c.cfg.ReleasePct, u.CommitMbps), true)
		default:
			c.steers[p] = s
		}
	}

	type cand struct {
		u     plugin.Usage
		in95  float64
		ratio float64
	}
	var cands []cand
	for _, u := range fresh {
		if _, on := c.steers[u.Provider]; on || released[u.Provider] {
			continue
		}
		in95, _ := u.InboundMbps()
		if in95 > u.CommitMbps {
			cands = append(cands, cand{u: u, in95: in95, ratio: in95 / u.CommitMbps})
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].ratio != cands[j].ratio {
			return cands[i].ratio > cands[j].ratio
		}
		return cands[i].u.Provider < cands[j].u.Provider
	})
	c.blocked = nil
	for _, cd := range cands {
		p := cd.u.Provider
		if until, ok := c.cooldown[p]; ok && now.Before(until) {
			c.blocked = append(c.blocked, Blocked{Provider: p, Reason: "released recently; waiting hold_time"})
			continue
		}
		delete(c.cooldown, p)
		act, ok := c.action(p)
		if !ok {
			c.blocked = append(c.blocked, Blocked{Provider: p, Reason: "no catalog action for this provider"})
			continue
		}
		if len(c.steers)+1 >= len(c.cfg.Providers) {
			c.blocked = append(c.blocked, Blocked{Provider: p, Reason: "would steer away from every provider"})
			continue
		}
		s := Steer{Provider: p, Since: now, InMbps95: cd.in95, CommitMbps: cd.u.CommitMbps, Action: act}
		c.steers[p] = s
		changes = append(changes, Change{Action: ActionSteer, Steer: s,
			Reason: fmt.Sprintf("inbound 95th %.1f Mbps is above the %.1f Mbps commit", cd.in95, cd.u.CommitMbps)})
	}
	return changes
}

// Sync makes the steer routes on the wire match the steer set. Outside
// inject it returns at once. When the RIB is not ready every steer route
// is withdrawn.
func (c *Controller) Sync(ctx context.Context) error {
	if c == nil || c.cfg.Mode != config.ModeInject {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.storeActive()
	if !c.rib.Ready() {
		if len(c.active) > 0 {
			c.log.Warn("rib not ready; withdrawing inbound steer routes")
		}
		return c.withdrawAllLocked(ctx)
	}
	away := sortedKeys(c.steers)
	if len(away) == 0 {
		return c.withdrawAllLocked(ctx)
	}
	key := strings.Join(away, ",")
	var errs []error
	for _, p := range c.cfg.Prefixes {
		cur, on := c.active[p]
		if on && strings.Join(cur.Away, ",") == key {
			continue
		}
		if !coveredBy(c.cfg.Allowlist, p) {
			if on {
				errs = append(errs, c.withdrawLocked(ctx, p))
			}
			errs = append(errs, fmt.Errorf("inbound: %s is not allowlisted", p))
			continue
		}
		nh := cur.NextHop
		if !on {
			learned, ok := c.rib.NextHop(p)
			if !ok {
				errs = append(errs, fmt.Errorf("inbound: %s is not in the RIB", p))
				continue
			}
			if len(c.active) >= c.cfg.MaxImprovements {
				errs = append(errs, fmt.Errorf("inbound: max_improvements (%d) reached", c.cfg.MaxImprovements))
				continue
			}
			if c.cfg.SharedCap > 0 && c.cfg.Others != nil && len(c.active)+c.cfg.Others() >= c.cfg.SharedCap {
				errs = append(errs, fmt.Errorf("inbound: shared max_improvements (%d) reached", c.cfg.SharedCap))
				continue
			}
			nh = learned
		}
		r := plugin.InboundRoute{Prefix: p, NextHop: nh, LocalPref: c.cfg.LocalPref, Community: c.cfg.Community, Away: away}
		if err := c.ann.Announce(ctx, r); err != nil {
			errs = append(errs, err)
			continue
		}
		c.active[p] = Route{Prefix: p, NextHop: nh, Away: away}
		c.log.Info("inbound steer announced", "prefix", p, "away", key, "next_hop", nh)
	}
	return errors.Join(errs...)
}

// WithdrawAll removes every steer route. It is safe to call more than once
// and in every mode.
func (c *Controller) WithdrawAll(ctx context.Context) error {
	if c == nil || c.ann == nil || c.cfg.Mode != config.ModeInject {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.storeActive()
	return c.withdrawAllLocked(ctx)
}

// storeActive publishes the route count. The caller holds mu.
func (c *Controller) storeActive() { c.onWire.Store(int64(len(c.active))) }

func (c *Controller) withdrawAllLocked(ctx context.Context) error {
	if len(c.active) == 0 {
		return nil
	}
	if err := c.ann.WithdrawAll(ctx); err != nil {
		return err
	}
	c.active = map[netip.Prefix]Route{}
	c.log.Info("inbound steer routes withdrawn")
	return nil
}

func (c *Controller) withdrawLocked(ctx context.Context, p netip.Prefix) error {
	if err := c.ann.Withdraw(ctx, p); err != nil {
		return err
	}
	delete(c.active, p)
	return nil
}

// Status copies the current state.
func (c *Controller) Status() Status {
	if c == nil {
		return Status{Steers: []Steer{}, Announced: []Route{}, Blocked: []Blocked{}, Prefixes: []string{}}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st := Status{Mode: c.cfg.Mode, Evaluated: c.evaluated, Prefixes: []string{}, Steers: []Steer{}, Announced: []Route{}, Blocked: []Blocked{}}
	for _, p := range c.cfg.Prefixes {
		st.Prefixes = append(st.Prefixes, p.String())
	}
	for _, k := range sortedKeys(c.steers) {
		st.Steers = append(st.Steers, c.steers[k])
	}
	order := make([]netip.Prefix, 0, len(c.active))
	for p := range c.active {
		order = append(order, p)
	}
	sortPrefixes(order)
	for _, p := range order {
		st.Announced = append(st.Announced, c.active[p])
	}
	st.Blocked = append(st.Blocked, c.blocked...)
	return st
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortPrefixes(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool {
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
}

func coveredBy(list []netip.Prefix, p netip.Prefix) bool {
	for _, a := range list {
		if a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
			return true
		}
	}
	return false
}
