// Package mitigation is threat mitigation (#28): RTBH (blackhole), BGP
// redirect, and FlowSpec (drop, rate-limit, redirect) for prefixes under
// attack, added and removed through the ops API.
//
// A rule names an exact prefix, an action, and a TTL. RTBH and redirect
// rules announce the prefix itself with the action's next hop; there is
// at most one per prefix. A FlowSpec rule matches traffic toward the
// prefix, optionally narrowed by source, protocol, ports, or source
// countries (expanded to networks from a mounted GeoIP database), and
// tells the edge to drop, rate-limit, or redirect it into a VRF; several
// FlowSpec rules may share a prefix. Every rule expires; rules live in
// memory only, so a restart drops them and nothing is re-announced from
// stale intent. The mitigation allowlist and the max_rules cap (counted in
// routes: a country rule counts once per source network) are checked when
// a rule is added and again, by the announcer itself, on every announce.
//
// Only inject announces. observe accepts and lists rules as a dry run. A
// mitigation route is announced only for a prefix that is in the learned
// RIB, and it stays while the rule holds even after the edge stops sending
// the prefix (its best path is then the mitigation route). While an RTBH
// or redirect rule holds a prefix, or its route is still on the wire,
// outbound improvements and inbound steers leave that prefix alone, so the
// speaker never has two Packeteer paths for one prefix. FlowSpec rules do
// not change the unicast route and do not hold the prefix. When the RIB
// is not ready every mitigation route is withdrawn.
//
// Every change to a rule (added, replaced, announced, withdrawn, expired,
// removed) goes to a bounded in-memory feed for the API and to Changes for
// notifier events and stored history.
package mitigation

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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/geoip"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// RIB is the slice of the RIB view mitigation needs. Contains reports an
// exact prefix a configured neighbor is advertising.
type RIB interface {
	Ready() bool
	Contains(netip.Prefix) bool
}

// GeoIP lists a country's networks in one address family.
type GeoIP interface {
	Networks(country string, v4 bool) ([]netip.Prefix, error)
}

// Bounds on a FlowSpec country rule.
const (
	MaxCountries = 8
	// FeedSize is how many changes the in-memory feed keeps.
	FeedSize = 200
)

// Config is the mitigation policy (see config.Mitigation).
type Config struct {
	Mode       string
	Allowlist  []netip.Prefix
	MaxRules   int
	DefaultTTL time.Duration
	MaxTTL     time.Duration
	LocalPref  uint32
	Community  string
	// Geo turns FlowSpec source countries into networks. Nil refuses
	// rules with countries.
	Geo GeoIP
	// Leader reports whether this instance is the active one of an HA
	// pair (#31). Nil is a single instance, always active. While it is
	// false, Sync withdraws everything and announces nothing; it is
	// checked under the controller's lock on every Sync.
	Leader func() bool
}

// Request asks for one rule. A zero TTL means the default. Match,
// Countries, and RateMbps are for FlowSpec actions only.
type Request struct {
	Prefix    netip.Prefix
	Action    string
	Target    string
	TTL       time.Duration
	Reason    string
	Match     plugin.FlowSpecMatch
	Countries []string
	RateMbps  float64
}

// Rule is one mitigation rule.
type Rule struct {
	ID      string       `json:"id"`
	Prefix  netip.Prefix `json:"prefix"`
	Action  string       `json:"action"`
	Target  string       `json:"target,omitempty"`
	NextHop netip.Addr   `json:"next_hop,omitzero"`
	// RouteTarget is a FlowSpec redirect's route target.
	RouteTarget string `json:"route_target,omitempty"`
	// Match narrows a FlowSpec rule; Countries are its source countries
	// and Sources the networks they expanded to when the rule was added.
	Match     *plugin.FlowSpecMatch `json:"match,omitempty"`
	Countries []string              `json:"source_countries,omitempty"`
	Sources   []netip.Prefix        `json:"country_sources,omitempty"`
	RateMbps  float64               `json:"rate_mbps,omitempty"`
	// Routes is how many routes the rule stands for; they count toward
	// max_rules.
	Routes  int       `json:"routes"`
	Reason  string    `json:"reason,omitempty"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
	// Announced is true while every route of the rule is on the wire.
	Announced bool `json:"announced"`
	// FirstAnnounced is when the rule first went on the wire.
	FirstAnnounced time.Time `json:"first_announced,omitzero"`
	// Pending says why an inject rule is not on the wire yet.
	Pending string `json:"pending,omitempty"`

	key  string
	live bool
}

// FlowSpec reports whether the rule is a FlowSpec rule.
func (r Rule) FlowSpec() bool { return plugin.IsFlowSpec(r.Action) }

// MatchText is the FlowSpec match in text form ("" for RTBH/redirect).
func (r Rule) MatchText() string {
	if r.Match == nil {
		return ""
	}
	return r.Match.Key()
}

// Change kinds, in the feed and in Changes.
const (
	ChangeAdded     = "added"
	ChangeReplaced  = "replaced"
	ChangeAnnounced = "announced"
	ChangeWithdrawn = "withdrawn"
	ChangeExpired   = "expired"
	ChangeRemoved   = "removed"
)

// Change is one entry of the feed.
type Change struct {
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"`
	Mode   string    `json:"mode"`
	Detail string    `json:"detail,omitempty"`
	Rule   Rule      `json:"rule"`
}

// Ends reports whether the change ends the rule.
func (c Change) Ends() bool {
	return c.Kind == ChangeExpired || c.Kind == ChangeRemoved || c.Kind == ChangeReplaced
}

// Status is the API view.
type Status struct {
	Mode      string                   `json:"mitigation_mode"`
	MaxRules  int                      `json:"max_rules"`
	Routes    int                      `json:"routes_held"`
	OnWire    int                      `json:"routes_announced"`
	Allowlist []string                 `json:"allowlist"`
	Catalog   plugin.MitigationCatalog `json:"catalog"`
	FlowSpec  plugin.FlowSpecCatalog   `json:"flowspec"`
	GeoIP     bool                     `json:"geoip"`
	Rules     []Rule                   `json:"rules"`
	// Feed is the most recent changes, newest first.
	Feed []Change `json:"feed"`
}

// Errors from Add. ErrInvalid is a bad request; ErrFull is the cap;
// ErrConflict is a FlowSpec rule that would send a route another rule
// already sends.
var (
	ErrInvalid  = errors.New("invalid mitigation rule")
	ErrFull     = errors.New("mitigation max_rules reached")
	ErrConflict = errors.New("mitigation rule conflicts with a held rule")
)

// fsWire is one FlowSpec route on the wire.
type fsWire struct {
	rule  string // rule key
	route plugin.FlowSpecRoute
}

// Controller holds the rules and syncs them to the announcer.
type Controller struct {
	cfg     Config
	ann     plugin.MitigationAnnouncer
	fs      plugin.FlowSpecAnnouncer
	catalog plugin.MitigationCatalog
	fsCat   plugin.FlowSpecCatalog
	rib     RIB
	log     *slog.Logger

	mu    sync.Mutex
	rules map[string]*Rule
	// wire is what the announcer has for each RTBH/redirect prefix, fwire
	// its FlowSpec routes by route key.
	wire    map[netip.Prefix]Rule
	fwire   map[string]fsWire
	feed    []Change
	pending []Change
	onWire  atomic.Int64
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
	c := &Controller{cfg: cfg, ann: ann, log: log, rules: map[string]*Rule{}, wire: map[netip.Prefix]Rule{}, fwire: map[string]fsWire{}}
	c.catalog.Targets = []plugin.MitigationTarget{}
	c.fsCat.Targets = []plugin.FlowSpecTarget{}
	if ann != nil {
		c.catalog = ann.Catalog()
		if fs, ok := ann.(plugin.FlowSpecAnnouncer); ok {
			if cat := fs.FlowSpecCatalog(); cat.Enabled {
				c.fs, c.fsCat = fs, cat
			}
		}
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

// FlowSpecCatalog is the announcer's FlowSpec catalog (disabled without
// one).
func (c *Controller) FlowSpecCatalog() plugin.FlowSpecCatalog { return c.fsCat }

// Active is the number of mitigation routes on the wire, FlowSpec
// included.
func (c *Controller) Active() int {
	if c == nil {
		return 0
	}
	return int(c.onWire.Load())
}

// pendingRIB is Rule.Pending while a rule waits for its prefix in the RIB.
const pendingRIB = "not in the learned RIB"

func unicastKey(p netip.Prefix) string { return "route " + p.String() }

// Holds reports whether an RTBH or redirect rule holds p or its route is
// still on the wire. Outbound improvements and inbound steers skip such a
// prefix. FlowSpec rules never hold a prefix. Outside inject it is always
// false: observe is a dry run and changes nothing.
func (c *Controller) Holds(p netip.Prefix) bool {
	if c == nil || c.cfg.Mode != config.ModeInject {
		return false
	}
	p = p.Masked()
	c.mu.Lock()
	defer c.mu.Unlock()
	_, r := c.rules[unicastKey(p)]
	_, w := c.wire[p]
	return r || w
}

// Add validates req and holds it as a rule. A rule with the same key (the
// same prefix for RTBH/redirect; the same prefix, match, and countries for
// FlowSpec) is replaced and keeps counting once toward max_rules.
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
	r := &Rule{ID: newID(), Prefix: p, Action: req.Action, Target: req.Target, Reason: req.Reason, Created: now, Expires: now.Add(ttl), Routes: 1}
	if plugin.IsFlowSpec(req.Action) {
		if err := c.flowSpecRule(r, req); err != nil {
			return bad("%s", err.Error())
		}
		r.key = "flowspec dst=" + p.String() + " " + r.MatchText() + " countries=" + strings.Join(r.Countries, ",")
	} else {
		if req.Match.Key() != "" || len(req.Countries) > 0 || req.RateMbps != 0 {
			return bad("match, source_countries, and rate_mbps are for flowspec actions only")
		}
		nh, err := c.unicastNextHop(req)
		if err != nil {
			return bad("%s", err.Error())
		}
		r.NextHop = nh
		r.key = unicastKey(p)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.FlowSpec() {
		if other, route := c.flowConflictLocked(r); other != nil {
			return Rule{}, fmt.Errorf("%w: rule %s (%s) already sends the flowspec route %s; remove it first or use the same match and source_countries to replace it",
				ErrConflict, other.ID, other.Action, route)
		}
	}
	old, replace := c.rules[r.key]
	held := 0
	for k, x := range c.rules {
		if k != r.key {
			held += x.Routes
		}
	}
	if held+r.Routes > c.cfg.MaxRules {
		if r.Routes > 1 {
			return Rule{}, fmt.Errorf("%w (%d routes; this rule needs %d, %d are held)", ErrFull, c.cfg.MaxRules, r.Routes, held)
		}
		return Rule{}, fmt.Errorf("%w (%d)", ErrFull, c.cfg.MaxRules)
	}
	if replace {
		c.changeLocked(now, ChangeReplaced, old, "replaced by "+r.ID)
	}
	c.rules[r.key] = r
	c.changeLocked(now, ChangeAdded, r, "")
	c.log.Info("mitigation rule added", "id", r.ID, "prefix", p, "action", r.Action, "target", r.Target, "match", r.MatchText(),
		"countries", strings.Join(r.Countries, ","), "routes", r.Routes, "rate_mbps", r.RateMbps, "ttl", ttl, "mode", c.cfg.Mode, "reason", r.Reason)
	return c.view(r), nil
}

// unicastNextHop checks an RTBH or redirect request against the catalog.
func (c *Controller) unicastNextHop(req Request) (netip.Addr, error) {
	p := req.Prefix
	var nh netip.Addr
	switch req.Action {
	case plugin.MitigationBlackhole:
		if req.Target != "" {
			return nh, errors.New("blackhole takes no target")
		}
		if c.ann != nil {
			if !c.catalog.Blackhole {
				return nh, errors.New("blackhole is not configured on the mitigation announcer")
			}
			for _, h := range c.catalog.BlackholeNextHops {
				if h.Is4() == p.Addr().Is4() {
					nh = h
				}
			}
			if !nh.IsValid() {
				return nh, fmt.Errorf("no blackhole next hop for the address family of %s", p)
			}
		}
	case plugin.MitigationRedirect:
		if c.ann == nil {
			return nh, errors.New("redirect needs mitigation.announcer (its catalog names the targets)")
		}
		t, ok := c.catalog.Target(req.Target)
		if !ok {
			return nh, fmt.Errorf("unknown redirect target %q", req.Target)
		}
		if t.NextHop.Is4() != p.Addr().Is4() {
			return nh, fmt.Errorf("redirect target %q has no next hop for the address family of %s", req.Target, p)
		}
		nh = t.NextHop
	default:
		return nh, fmt.Errorf("action %q is invalid (want %s, %s, %s, %s, or %s)", req.Action, plugin.MitigationBlackhole, plugin.MitigationRedirect,
			plugin.MitigationFlowSpecDrop, plugin.MitigationFlowSpecRateLimit, plugin.MitigationFlowSpecRedirect)
	}
	return nh, nil
}

// flowSpecRule checks a FlowSpec request and fills r: the normalized
// match, the countries and their networks, the rate, and the route count.
func (c *Controller) flowSpecRule(r *Rule, req Request) error {
	p := req.Prefix
	if c.ann != nil && !c.fsCat.Enabled {
		return errors.New("flowspec is not configured on the mitigation announcer")
	}
	switch req.Action {
	case plugin.MitigationFlowSpecRedirect:
		if c.ann == nil {
			return errors.New("flowspec_redirect needs mitigation.announcer (its catalog names the targets)")
		}
		t, ok := c.fsCat.Target(req.Target)
		if !ok {
			return fmt.Errorf("unknown flowspec redirect target %q", req.Target)
		}
		r.RouteTarget = t.RouteTarget
		if req.RateMbps != 0 {
			return errors.New("flowspec_redirect takes no rate_mbps")
		}
	case plugin.MitigationFlowSpecRateLimit:
		if req.Target != "" {
			return errors.New("flowspec_rate_limit takes no target")
		}
		if !(req.RateMbps > 0 && req.RateMbps <= plugin.MaxFlowSpecRateMbps) {
			return fmt.Errorf("rate_mbps %v must be above 0 and at most %d", req.RateMbps, plugin.MaxFlowSpecRateMbps)
		}
		r.RateMbps = req.RateMbps
	default: // drop
		if req.Target != "" || req.RateMbps != 0 {
			return errors.New("flowspec_drop takes no target or rate_mbps")
		}
	}
	m := req.Match.Normalize()
	if err := m.Validate(p); err != nil {
		return err
	}
	if len(req.Countries) > 0 {
		if m.Source.IsValid() {
			return errors.New("give match.source or source_countries, not both")
		}
		if len(req.Countries) > MaxCountries {
			return fmt.Errorf("at most %d source_countries", MaxCountries)
		}
		if c.cfg.Geo == nil {
			return errors.New("source_countries needs mitigation.geoip_db")
		}
		var nets []netip.Prefix
		seen := map[string]bool{}
		for _, cc := range req.Countries {
			if !geoip.ValidCountry(cc) {
				return fmt.Errorf("country %q is not a two-letter upper-case ISO code", cc)
			}
			if seen[cc] {
				return fmt.Errorf("country %s is listed twice", cc)
			}
			seen[cc] = true
			n, err := c.cfg.Geo.Networks(cc, p.Addr().Is4())
			if err != nil {
				return fmt.Errorf("country %s: %w", cc, err)
			}
			nets = append(nets, n...)
		}
		nets = geoip.Aggregate(nets)
		if len(nets) == 0 {
			return fmt.Errorf("geoip_db has no IPv%d networks for %s", map[bool]int{true: 4, false: 6}[p.Addr().Is4()], strings.Join(req.Countries, ", "))
		}
		if len(nets) > c.cfg.MaxRules {
			return fmt.Errorf("source_countries expand to %d networks, more than max_rules (%d)", len(nets), c.cfg.MaxRules)
		}
		r.Countries = slices.Sorted(slices.Values(req.Countries))
		r.Sources = nets
		r.Routes = len(nets)
	}
	r.Match = &m
	return nil
}

// flowRoutes is every FlowSpec route of r: one, or one per source network.
func (c *Controller) flowRoutes(r *Rule) []plugin.FlowSpecRoute {
	base := plugin.FlowSpecRoute{Destination: r.Prefix, Action: r.Action, Target: r.Target, RateMbps: r.RateMbps,
		LocalPref: c.cfg.LocalPref, Community: c.cfg.Community}
	if r.Match != nil {
		base.Match = *r.Match
	}
	if len(r.Sources) == 0 {
		return []plugin.FlowSpecRoute{base}
	}
	out := make([]plugin.FlowSpecRoute, 0, len(r.Sources))
	for _, s := range r.Sources {
		rt := base
		rt.Match.Source = s
		out = append(out, rt)
	}
	return out
}

// flowConflictLocked returns the held FlowSpec rule with another key that
// shares a route with r (the one with the lowest key), and that route.
// Different rules can expand to one route: a country rule and a rule whose
// match.source is one of the country's networks, or [XA] and [XA, XB] with
// the same match. The caller holds mu.
func (c *Controller) flowConflictLocked(r *Rule) (*Rule, string) {
	mine := map[string]bool{}
	for _, rt := range c.flowRoutes(r) {
		mine[rt.Key()] = true
	}
	var best *Rule
	var route string
	for k, x := range c.rules {
		if k == r.key || !x.FlowSpec() || (best != nil && k > best.key) {
			continue
		}
		for _, rt := range c.flowRoutes(x) {
			if mine[rt.Key()] {
				best, route = x, rt.Key()
				break
			}
		}
	}
	return best, route
}

// Remove drops the rule with id. Its routes are withdrawn on the next Sync.
func (c *Controller) Remove(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, r := range c.rules {
		if r.ID == id {
			delete(c.rules, k)
			c.changeLocked(time.Now(), ChangeRemoved, r, "")
			c.log.Info("mitigation rule removed", "id", id, "prefix", r.Prefix, "action", r.Action)
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
	defer c.settleLocked(now)
	for k, r := range c.rules {
		if !now.Before(r.Expires) {
			delete(c.rules, k)
			c.changeLocked(now, ChangeExpired, r, "")
			c.log.Info("mitigation rule expired", "id", r.ID, "prefix", r.Prefix, "action", r.Action)
		}
	}
	if c.cfg.Mode != config.ModeInject {
		return nil
	}
	if c.cfg.Leader != nil && !c.cfg.Leader() {
		if len(c.wire)+len(c.fwire) > 0 {
			c.log.Warn("ha standby; withdrawing mitigation routes")
		}
		return c.withdrawAllLocked(ctx)
	}
	if c.rib == nil || !c.rib.Ready() {
		if len(c.wire)+len(c.fwire) > 0 {
			c.log.Warn("rib not ready; withdrawing mitigation routes")
		}
		return c.withdrawAllLocked(ctx)
	}
	return errors.Join(c.syncUnicastLocked(ctx), c.syncFlowSpecLocked(ctx))
}

func (c *Controller) syncUnicastLocked(ctx context.Context) error {
	uni := map[netip.Prefix]*Rule{}
	for _, r := range c.rules {
		if !r.FlowSpec() {
			uni[r.Prefix] = r
		}
	}
	var errs []error
	for p := range c.wire {
		if _, ok := uni[p]; !ok {
			errs = append(errs, c.withdrawLocked(ctx, p))
		}
	}
	order := make([]netip.Prefix, 0, len(uni))
	for p := range uni {
		order = append(order, p)
	}
	sortPrefixes(order)
	for _, p := range order {
		r := uni[p]
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
			r.Pending = pendingRIB
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

func (c *Controller) syncFlowSpecLocked(ctx context.Context) error {
	type want struct {
		rule  *Rule
		route plugin.FlowSpecRoute
	}
	// Add refuses a rule that shares a route with another. Should two
	// ever share one, the rule with the lowest key owns it every round,
	// so the route never flaps between them.
	var rules []*Rule
	for _, r := range c.rules {
		if r.FlowSpec() {
			rules = append(rules, r)
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].key < rules[j].key })
	desired := map[string]want{}
	var keys []string
	// waited is the rules that already waited for the RIB, so the warning
	// is logged once per wait and not every round.
	waited := map[*Rule]bool{}
	for _, r := range rules {
		waited[r] = r.Pending == pendingRIB
		r.Pending = ""
		for _, rt := range c.flowRoutes(r) {
			k := rt.Key()
			if d, dup := desired[k]; dup {
				r.Pending = "route " + k + " is sent by rule " + d.rule.ID
				continue
			}
			keys = append(keys, k)
			desired[k] = want{rule: r, route: rt}
		}
	}
	var errs []error
	for k, w := range c.fwire {
		if d, ok := desired[k]; !ok || d.rule.key != w.rule {
			errs = append(errs, c.withdrawFlowSpecLocked(ctx, k))
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		d := desired[k]
		r, rt := d.rule, d.route
		cur, on := c.fwire[k]
		if on && cur.route.Action == rt.Action && cur.route.Target == rt.Target && cur.route.RateMbps == rt.RateMbps {
			continue
		}
		if c.fs == nil {
			r.Pending = "flowspec is not configured on the mitigation announcer"
			continue
		}
		if !coveredBy(c.cfg.Allowlist, r.Prefix) {
			r.Pending = "not in mitigation.allowlist"
			if on {
				errs = append(errs, c.withdrawFlowSpecLocked(ctx, k))
			}
			continue
		}
		// The destination must be the exact learned prefix. A route
		// already on the wire keeps its place when only the action
		// changes, as for RTBH.
		if !on && !c.rib.Contains(r.Prefix) {
			if !waited[r] {
				c.log.Warn("mitigation flowspec rule waits: prefix is not in the learned RIB", "id", r.ID, "prefix", r.Prefix)
				waited[r] = true
			}
			r.Pending = pendingRIB
			continue
		}
		if err := c.fs.AnnounceFlowSpec(ctx, rt); err != nil {
			r.Pending = err.Error()
			errs = append(errs, err)
			continue
		}
		c.fwire[k] = fsWire{rule: r.key, route: rt}
		c.log.Info("mitigation flowspec announced", "id", r.ID, "rule", k, "action", r.Action, "target", r.Target,
			"rate_mbps", r.RateMbps, "expires", r.Expires.UTC().Format(time.RFC3339))
	}
	return errors.Join(errs...)
}

// settleLocked records announced/withdrawn transitions and the wire
// count. The caller holds mu.
func (c *Controller) settleLocked(now time.Time) {
	c.onWire.Store(int64(len(c.wire) + len(c.fwire)))
	keys := make([]string, 0, len(c.rules))
	for k := range c.rules {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		r := c.rules[k]
		on := c.announcedLocked(r)
		if on == r.live {
			continue
		}
		r.live = on
		if on {
			if r.FirstAnnounced.IsZero() {
				r.FirstAnnounced = now
			}
			c.changeLocked(now, ChangeAnnounced, r, "")
		} else {
			c.changeLocked(now, ChangeWithdrawn, r, r.Pending)
		}
	}
}

// announcedLocked reports whether every route of r is on the wire with
// r's action.
func (c *Controller) announcedLocked(r *Rule) bool {
	if !r.FlowSpec() {
		w, on := c.wire[r.Prefix]
		return on && w.Action == r.Action && w.Target == r.Target
	}
	for _, rt := range c.flowRoutes(r) {
		w, on := c.fwire[rt.Key()]
		if !on || w.rule != r.key || w.route.Action != rt.Action || w.route.Target != rt.Target || w.route.RateMbps != rt.RateMbps {
			return false
		}
	}
	return true
}

// WithdrawAll removes every mitigation route and keeps the rules. It is
// safe to call more than once and in every mode.
func (c *Controller) WithdrawAll(ctx context.Context) error {
	if c == nil || c.ann == nil || c.cfg.Mode != config.ModeInject {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.settleLocked(time.Now())
	return c.withdrawAllLocked(ctx)
}

func (c *Controller) withdrawAllLocked(ctx context.Context) error {
	if len(c.wire)+len(c.fwire) == 0 {
		return nil
	}
	if err := c.ann.WithdrawAll(ctx); err != nil {
		return err
	}
	n := len(c.wire) + len(c.fwire)
	c.wire = map[netip.Prefix]Rule{}
	c.fwire = map[string]fsWire{}
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

func (c *Controller) withdrawFlowSpecLocked(ctx context.Context, key string) error {
	if c.fs == nil {
		return errors.New("mitigation: flowspec route on the wire without a flowspec announcer")
	}
	if err := c.fs.WithdrawFlowSpec(ctx, key); err != nil {
		return err
	}
	delete(c.fwire, key)
	c.log.Info("mitigation flowspec withdrawn", "rule", key)
	return nil
}

// changeLocked appends a change to the feed and to the pending changes.
// The caller holds mu.
func (c *Controller) changeLocked(now time.Time, kind string, r *Rule, detail string) {
	ch := Change{Time: now, Kind: kind, Mode: c.cfg.Mode, Detail: detail, Rule: c.view(r)}
	c.feed = append(c.feed, ch)
	if len(c.feed) > FeedSize {
		c.feed = slices.Clone(c.feed[len(c.feed)-FeedSize:])
	}
	c.pending = append(c.pending, ch)
	if len(c.pending) > 10*FeedSize {
		// Nobody is taking changes; keep the newest.
		c.pending = slices.Clone(c.pending[len(c.pending)-FeedSize:])
	}
}

// Changes returns and clears the changes since the last call, oldest
// first. The decision loop turns them into events and history.
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

// Status copies the rules (sorted by prefix, then action and match) and
// the feed (newest first).
func (c *Controller) Status() Status {
	if c == nil {
		return Status{Allowlist: []string{}, Rules: []Rule{}, Feed: []Change{},
			Catalog: plugin.MitigationCatalog{Targets: []plugin.MitigationTarget{}}, FlowSpec: plugin.FlowSpecCatalog{Targets: []plugin.FlowSpecTarget{}}}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st := Status{Mode: c.cfg.Mode, MaxRules: c.cfg.MaxRules, OnWire: len(c.wire) + len(c.fwire), Allowlist: []string{},
		Catalog: c.catalog, FlowSpec: c.fsCat, GeoIP: c.cfg.Geo != nil, Rules: []Rule{}, Feed: []Change{}}
	for _, p := range c.cfg.Allowlist {
		st.Allowlist = append(st.Allowlist, p.String())
	}
	rules := make([]*Rule, 0, len(c.rules))
	for _, r := range c.rules {
		rules = append(rules, r)
		st.Routes += r.Routes
	}
	sort.Slice(rules, func(i, j int) bool {
		a, b := rules[i], rules[j]
		if a.Prefix != b.Prefix {
			return lessPrefix(a.Prefix, b.Prefix)
		}
		return a.key < b.key
	})
	for _, r := range rules {
		st.Rules = append(st.Rules, c.view(r))
	}
	for i := len(c.feed) - 1; i >= 0; i-- {
		st.Feed = append(st.Feed, c.feed[i])
	}
	return st
}

// view copies r with its wire state. The caller holds mu.
func (c *Controller) view(r *Rule) Rule {
	out := *r
	if r.Match != nil {
		m := *r.Match
		out.Match = &m
	}
	out.Countries = slices.Clone(r.Countries)
	out.Sources = slices.Clone(r.Sources)
	out.Announced = c.announcedLocked(r)
	if c.cfg.Mode != config.ModeInject {
		out.Pending = "mitigation.mode is " + c.cfg.Mode + " (dry run, never announced)"
	}
	return out
}

// Record is the stored history row for a rule after change ch.
func Record(ch Change) plugin.MitigationRecord {
	r := ch.Rule
	rec := plugin.MitigationRecord{ID: r.ID, Prefix: r.Prefix, Action: r.Action, Target: r.Target, Match: r.MatchText(),
		Countries: strings.Join(r.Countries, ","), RateMbps: r.RateMbps, Routes: r.Routes, Reason: r.Reason, Mode: ch.Mode,
		Created: r.Created, Expires: r.Expires, Announced: r.FirstAnnounced}
	if ch.Ends() {
		rec.End, rec.EndReason = ch.Time, ch.Kind
		if ch.Detail != "" {
			rec.EndReason += ": " + ch.Detail
		}
	}
	return rec
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func lessPrefix(a, b netip.Prefix) bool {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c < 0
	}
	return a.Bits() < b.Bits()
}

func sortPrefixes(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool { return lessPrefix(ps[i], ps[j]) })
}

func coveredBy(list []netip.Prefix, p netip.Prefix) bool {
	for _, a := range list {
		if a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
			return true
		}
	}
	return false
}
