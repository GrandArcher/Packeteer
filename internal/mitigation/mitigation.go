// Package mitigation is threat mitigation (#28): RTBH (blackhole) and BGP
// redirect routes for prefixes under attack, added and removed through the
// ops API.
//
// A rule names an exact prefix, an action (blackhole, or redirect to a
// target in the mitigation announcer's catalog), and a TTL. Every rule
// expires; rules live in memory only, so a restart drops them and nothing
// is re-announced from stale intent. The mitigation allowlist and the
// max_rules cap are checked when a rule is added and again, by the
// announcer itself, on every announce.
//
// Only inject announces. observe accepts and lists rules as a dry run. A
// mitigation route is announced only for a prefix that is in the learned
// RIB, and it stays while the rule holds even after the edge stops sending
// the prefix (its best path is then the mitigation route). While a rule
// holds a prefix, or its route is still on the wire, outbound improvements
// and inbound steers leave that prefix alone, so the speaker never has two
// Packeteer paths for one prefix. When the RIB is not ready every
// mitigation route is withdrawn.
package mitigation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// RIB is the slice of the RIB view mitigation needs. Contains reports an
// exact prefix a configured neighbor is advertising.
type RIB interface {
	Ready() bool
	Contains(netip.Prefix) bool
}

// Config is the mitigation policy (see config.Mitigation).
type Config struct {
	Mode       string
	Allowlist  []netip.Prefix
	MaxRules   int
	DefaultTTL time.Duration
	MaxTTL     time.Duration
	LocalPref  uint32
	Community  string
}

// Request asks for one rule. A zero TTL means the default.
type Request struct {
	Prefix netip.Prefix
	Action string
	Target string
	TTL    time.Duration
	Reason string
}

// Rule is one mitigation rule.
type Rule struct {
	ID      string       `json:"id"`
	Prefix  netip.Prefix `json:"prefix"`
	Action  string       `json:"action"`
	Target  string       `json:"target,omitempty"`
	NextHop netip.Addr   `json:"next_hop,omitzero"`
	Reason  string       `json:"reason,omitempty"`
	Created time.Time    `json:"created"`
	Expires time.Time    `json:"expires"`
	// Announced is true while the route is on the wire.
	Announced bool `json:"announced"`
	// Pending says why an inject rule is not on the wire yet.
	Pending string `json:"pending,omitempty"`
}

// Status is the API view.
type Status struct {
	Mode      string                   `json:"mitigation_mode"`
	MaxRules  int                      `json:"max_rules"`
	Allowlist []string                 `json:"allowlist"`
	Catalog   plugin.MitigationCatalog `json:"catalog"`
	Rules     []Rule                   `json:"rules"`
}

// Errors from Add. ErrInvalid is a bad request; ErrFull is the cap.
var (
	ErrInvalid = errors.New("invalid mitigation rule")
	ErrFull    = errors.New("mitigation max_rules reached")
)

// Controller holds the rules and syncs them to the announcer.
type Controller struct {
	cfg     Config
	ann     plugin.MitigationAnnouncer
	catalog plugin.MitigationCatalog
	rib     RIB
	log     *slog.Logger

	mu    sync.Mutex
	rules map[netip.Prefix]*Rule
	// wire is what the announcer has for each prefix.
	wire   map[netip.Prefix]Rule
	onWire atomic.Int64
}

// New validates the policy. ann may be nil outside inject; redirect rules
// then cannot be added (there is no catalog to name a target from). The
// RIB view is given later with SetRIB.
func New(cfg Config, ann plugin.MitigationAnnouncer, log *slog.Logger) (*Controller, error) {
	if len(cfg.Allowlist) == 0 {
		return nil, errors.New("mitigation: allowlist is empty")
	}
	if cfg.MaxRules < 1 {
		return nil, errors.New("mitigation: max_rules must be positive")
	}
	if cfg.MaxTTL <= 0 || cfg.DefaultTTL <= 0 || cfg.DefaultTTL > cfg.MaxTTL {
		return nil, errors.New("mitigation: default_ttl must be positive and at most max_ttl")
	}
	if cfg.Mode == config.ModeInject {
		if ann == nil {
			return nil, errors.New("mitigation: inject mode requires mitigation.announcer")
		}
		if cfg.LocalPref == 0 || cfg.Community == "" {
			return nil, errors.New("mitigation: inject mode requires local_pref and packeteer_community")
		}
	}
	if log == nil {
		log = slog.Default()
	}
	c := &Controller{cfg: cfg, ann: ann, log: log, rules: map[netip.Prefix]*Rule{}, wire: map[netip.Prefix]Rule{}}
	c.catalog.Targets = []plugin.MitigationTarget{}
	if ann != nil {
		c.catalog = ann.Catalog()
	}
	return c, nil
}

// SetRIB gives the controller the RIB view. Inject needs one; Sync
// withdraws everything and announces nothing without it.
func (c *Controller) SetRIB(rib RIB) error {
	if c.cfg.Mode == config.ModeInject && rib == nil {
		return errors.New("mitigation: inject mode requires a RIB view")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rib = rib
	return nil
}

// Catalog is the announcer's catalog (empty without an announcer).
func (c *Controller) Catalog() plugin.MitigationCatalog { return c.catalog }

// Active is the number of mitigation routes on the wire.
func (c *Controller) Active() int {
	if c == nil {
		return 0
	}
	return int(c.onWire.Load())
}

// Holds reports whether a rule holds p or its route is still on the wire.
// Outbound improvements and inbound steers skip such a prefix. Outside
// inject it is always false: observe is a dry run and changes nothing.
func (c *Controller) Holds(p netip.Prefix) bool {
	if c == nil || c.cfg.Mode != config.ModeInject {
		return false
	}
	p = p.Masked()
	c.mu.Lock()
	defer c.mu.Unlock()
	_, r := c.rules[p]
	_, w := c.wire[p]
	return r || w
}

// Add validates req and holds it as a rule. A rule for the same prefix is
// replaced (and keeps counting once toward max_rules).
func (c *Controller) Add(req Request, now time.Time) (Rule, error) {
	p := req.Prefix
	bad := func(format string, a ...any) (Rule, error) {
		return Rule{}, fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
	}
	if !p.IsValid() {
		return bad("prefix is required")
	}
	if p != p.Masked() {
		return bad("prefix %s has host bits set (did you mean %s?)", p, p.Masked())
	}
	if p.Bits() == 0 {
		return bad("a default route is never mitigated")
	}
	if !coveredBy(c.cfg.Allowlist, p) {
		return bad("%s is not in mitigation.allowlist", p)
	}
	if len(req.Reason) > 256 {
		return bad("reason is longer than 256 characters")
	}
	ttl := req.TTL
	if ttl == 0 {
		ttl = c.cfg.DefaultTTL
	}
	if ttl < config.MinMitigationTTL || ttl > c.cfg.MaxTTL {
		return bad("ttl %s must be between %s and max_ttl (%s)", ttl, config.MinMitigationTTL, c.cfg.MaxTTL)
	}
	var nh netip.Addr
	switch req.Action {
	case plugin.MitigationBlackhole:
		if req.Target != "" {
			return bad("blackhole takes no target")
		}
		if c.ann != nil {
			if !c.catalog.Blackhole {
				return bad("blackhole is not configured on the mitigation announcer")
			}
			for _, h := range c.catalog.BlackholeNextHops {
				if h.Is4() == p.Addr().Is4() {
					nh = h
				}
			}
			if !nh.IsValid() {
				return bad("no blackhole next hop for the address family of %s", p)
			}
		}
	case plugin.MitigationRedirect:
		if c.ann == nil {
			return bad("redirect needs mitigation.announcer (its catalog names the targets)")
		}
		t, ok := c.catalog.Target(req.Target)
		if !ok {
			return bad("unknown redirect target %q", req.Target)
		}
		if t.NextHop.Is4() != p.Addr().Is4() {
			return bad("redirect target %q has no next hop for the address family of %s", req.Target, p)
		}
		nh = t.NextHop
	default:
		return bad("action %q is invalid (want %s or %s)", req.Action, plugin.MitigationBlackhole, plugin.MitigationRedirect)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, replace := c.rules[p]; !replace && len(c.rules) >= c.cfg.MaxRules {
		return Rule{}, fmt.Errorf("%w (%d)", ErrFull, c.cfg.MaxRules)
	}
	r := &Rule{ID: newID(), Prefix: p, Action: req.Action, Target: req.Target, NextHop: nh, Reason: req.Reason, Created: now, Expires: now.Add(ttl)}
	c.rules[p] = r
	c.log.Info("mitigation rule added", "id", r.ID, "prefix", p, "action", r.Action, "target", r.Target, "ttl", ttl, "mode", c.cfg.Mode, "reason", r.Reason)
	return c.view(r), nil
}

// Remove drops the rule with id. Its route is withdrawn on the next Sync.
func (c *Controller) Remove(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for p, r := range c.rules {
		if r.ID == id {
			delete(c.rules, p)
			c.log.Info("mitigation rule removed", "id", id, "prefix", p)
			return true
		}
	}
	return false
}

// Sync expires rules and, in inject, makes the routes on the wire match
// the rules. Outside inject it only expires rules.
func (c *Controller) Sync(ctx context.Context, now time.Time) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() { c.onWire.Store(int64(len(c.wire))) }()
	for p, r := range c.rules {
		if !now.Before(r.Expires) {
			delete(c.rules, p)
			c.log.Info("mitigation rule expired", "id", r.ID, "prefix", p, "action", r.Action)
		}
	}
	if c.cfg.Mode != config.ModeInject {
		return nil
	}
	if c.rib == nil || !c.rib.Ready() {
		if len(c.wire) > 0 {
			c.log.Warn("rib not ready; withdrawing mitigation routes")
		}
		return c.withdrawAllLocked(ctx)
	}
	var errs []error
	for p := range c.wire {
		if _, ok := c.rules[p]; !ok {
			errs = append(errs, c.withdrawLocked(ctx, p))
		}
	}
	order := make([]netip.Prefix, 0, len(c.rules))
	for p := range c.rules {
		order = append(order, p)
	}
	sortPrefixes(order)
	for _, p := range order {
		r := c.rules[p]
		cur, on := c.wire[p]
		if on && cur.Action == r.Action && cur.Target == r.Target {
			r.Pending = ""
			continue
		}
		if !coveredBy(c.cfg.Allowlist, p) {
			r.Pending = "not in mitigation.allowlist"
			if on {
				errs = append(errs, c.withdrawLocked(ctx, p))
			}
			continue
		}
		// A new announcement needs the exact prefix in the learned RIB.
		// Replacing the action of a route already on the wire does not:
		// the edge stops sending a prefix once the mitigation route wins.
		if !on && !c.rib.Contains(p) {
			if r.Pending == "" {
				c.log.Warn("mitigation rule waits: prefix is not in the learned RIB", "id", r.ID, "prefix", p)
			}
			r.Pending = "not in the learned RIB"
			continue
		}
		mr := plugin.MitigationRoute{Prefix: p, Action: r.Action, Target: r.Target, LocalPref: c.cfg.LocalPref, Community: c.cfg.Community}
		if err := c.ann.Announce(ctx, mr); err != nil {
			r.Pending = err.Error()
			errs = append(errs, err)
			continue
		}
		r.Pending = ""
		c.wire[p] = *r
		c.log.Info("mitigation announced", "id", r.ID, "prefix", p, "action", r.Action, "target", r.Target, "next_hop", r.NextHop, "expires", r.Expires.UTC().Format(time.RFC3339))
	}
	return errors.Join(errs...)
}

// WithdrawAll removes every mitigation route and keeps the rules. It is
// safe to call more than once and in every mode.
func (c *Controller) WithdrawAll(ctx context.Context) error {
	if c == nil || c.ann == nil || c.cfg.Mode != config.ModeInject {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() { c.onWire.Store(int64(len(c.wire))) }()
	return c.withdrawAllLocked(ctx)
}

func (c *Controller) withdrawAllLocked(ctx context.Context) error {
	if len(c.wire) == 0 {
		return nil
	}
	if err := c.ann.WithdrawAll(ctx); err != nil {
		return err
	}
	n := len(c.wire)
	c.wire = map[netip.Prefix]Rule{}
	c.log.Info("mitigation routes withdrawn", "routes", n)
	return nil
}

func (c *Controller) withdrawLocked(ctx context.Context, p netip.Prefix) error {
	if err := c.ann.Withdraw(ctx, p); err != nil {
		return err
	}
	delete(c.wire, p)
	c.log.Info("mitigation withdrawn", "prefix", p)
	return nil
}

// Status copies the rules, sorted by prefix.
func (c *Controller) Status() Status {
	if c == nil {
		return Status{Allowlist: []string{}, Rules: []Rule{}, Catalog: plugin.MitigationCatalog{Targets: []plugin.MitigationTarget{}}}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st := Status{Mode: c.cfg.Mode, MaxRules: c.cfg.MaxRules, Allowlist: []string{}, Catalog: c.catalog, Rules: []Rule{}}
	for _, p := range c.cfg.Allowlist {
		st.Allowlist = append(st.Allowlist, p.String())
	}
	order := make([]netip.Prefix, 0, len(c.rules))
	for p := range c.rules {
		order = append(order, p)
	}
	sortPrefixes(order)
	for _, p := range order {
		st.Rules = append(st.Rules, c.view(c.rules[p]))
	}
	return st
}

// view copies r with its wire state. The caller holds mu.
func (c *Controller) view(r *Rule) Rule {
	out := *r
	w, on := c.wire[r.Prefix]
	out.Announced = on && w.Action == r.Action && w.Target == r.Target
	if c.cfg.Mode != config.ModeInject {
		out.Pending = "mitigation.mode is " + c.cfg.Mode + " (dry run, never announced)"
	}
	return out
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
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
