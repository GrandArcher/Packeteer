// Package inbound is inbound optimization (#25). It decides when to steer
// inbound traffic for the operator's own prefixes away from a provider, and
// in inject mode it re-announces those prefixes to the edge through an
// in-process inbound announcer that adds the provider's catalog prepend,
// withhold (selective announcement), and TE communities.
//
// Two triggers steer a provider. commit: its inbound 95th percentile is
// above its commit; released once it is at or below release_pct of the
// commit. performance: the probes rank it the single worst provider by mean
// loss or RTT over the prefixes every provider measured; released once both
// gaps are at or below the performance release_pct of their thresholds. A
// steer is held for its hold time, and a released provider waits that long
// before it can be steered again. Stale or missing telemetry or probe
// results release at once (fail closed). Packeteer never steers away from
// every configured provider.
//
// Damping keeps the edge from oscillating: a trigger must hold for confirm
// before a steer, a provider steered again within max_hold of its release
// has its hold time multiplied by backoff (up to max_hold), and a flapping
// commit steer learns how much inbound traffic came back on release
// (inertia) and is kept until the 95th plus that amount is under
// release_pct.
//
// Only inject announces, and only triggers that are not moderated. observe
// logs; suggest and moderated triggers log and publish the suggestion on
// the API and as events, so an operator can apply it by hand. A steer
// route is announced only for an inbound prefix that is allowlisted and
// present in the learned RIB, with the learned next hop, within the shared
// max_improvements cap. A route already announced stays while the steer is
// wanted even if the edge stops sending the prefix (its best path is then
// the steer route); improvement_ttl bounds that, and a new announcement
// always needs the prefix back in the RIB.
package inbound

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
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
	// Performance enables the performance trigger. Nil disables it.
	Performance *PerfConfig
	// PerfMaxAge is how old a probe result may be. Older results are left
	// out of the comparison.
	PerfMaxAge time.Duration
	Damping    Damping
	// Moderated triggers only suggest, even in inject.
	Moderated map[string]bool
	// Excluded reports prefixes threat mitigation holds (#28). Their
	// steer route is withdrawn and not announced again until it lets go,
	// so the speaker never has two Packeteer paths for one prefix.
	Excluded func(netip.Prefix) bool
	// Leader reports whether this instance is the active one of an HA
	// pair (#31). Nil is a single instance, always active. While it is
	// false, Sync withdraws everything and announces nothing; it is
	// checked under the controller's lock on every Sync.
	Leader func() bool
}

// PerfConfig is the performance trigger (see config.InboundPerformance).
// A negative threshold disables that check.
type PerfConfig struct {
	LossPct     float64
	LatencyMs   float64
	MinPrefixes int
	ReleasePct  float64
}

// Damping is inertia against oscillation (see config.InboundDamping).
type Damping struct {
	Disabled bool
	Confirm  time.Duration
	Backoff  float64
	MaxHold  time.Duration
}

// Input is what Plan reads each round.
type Input struct {
	Usage []plugin.Usage
	// Paths are the latest probe results that hold a measurement, from
	// providers whose probe source is up.
	Paths []Path
}

// Path is one provider's latest measurement toward one prefix.
type Path struct {
	Provider string
	Prefix   netip.Prefix
	LossPct  float64
	RTT      time.Duration
	Time     time.Time
}

// PerfGap is how a provider compares with the best other provider.
type PerfGap struct {
	LossPct  float64 `json:"loss_pct"`
	RTTMs    float64 `json:"rtt_ms"`
	LossGap  float64 `json:"loss_gap_pct"`
	RTTGapMs float64 `json:"rtt_gap_ms"`
	Prefixes int     `json:"prefixes"`
}

// Triggers.
const (
	TriggerCommit      = config.InboundTriggerCommit
	TriggerPerformance = config.InboundTriggerPerformance
)

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
	Provider string `json:"provider"`
	// Trigger is commit or performance.
	Trigger    string               `json:"trigger"`
	Since      time.Time            `json:"since"`
	InMbps95   float64              `json:"in_mbps_95"`
	CommitMbps float64              `json:"commit_mbps"`
	Action     plugin.InboundAction `json:"action"`
	// Perf is the comparison behind a performance steer.
	Perf *PerfGap `json:"performance,omitempty"`
	// Moderated steers are suggestions: never announced.
	Moderated bool `json:"moderated,omitempty"`
	// Hold is the minimum time the steer stays, and the cooldown after
	// it. Damping grows it for a flapping provider.
	Hold      time.Duration `json:"-"`
	HoldUntil time.Time     `json:"hold_until"`
	// Flaps counts steers of this provider inside the flap window.
	Flaps int `json:"flaps,omitempty"`
	// Shift is the inbound Mbps that came back the last time this
	// provider's commit steer was released (inertia).
	Shift float64 `json:"inertia_mbps,omitempty"`
}

// damping is the per-provider memory behind Steer.Flaps and Steer.Shift.
type damping struct {
	released    time.Time
	releaseIn95 float64
	trigger     string
	flaps       int
	shift       float64
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
	// pending is when each trigger was first seen (confirm).
	pending map[string]time.Time
	damp    map[string]*damping
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
	if pc := cfg.Performance; pc != nil {
		if pc.MinPrefixes < 1 {
			pc.MinPrefixes = 1
		}
		if pc.ReleasePct <= 0 || pc.ReleasePct > 100 {
			pc.ReleasePct = config.DefaultInboundPerfReleasePct
		}
	}
	if d := &cfg.Damping; d.Backoff < 1 {
		d.Backoff = 1
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
		pending: map[string]time.Time{}, damp: map[string]*damping{},
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

// Evaluate plans from telemetry alone. It is Plan without probe results.
func (c *Controller) Evaluate(now time.Time, usage []plugin.Usage) []Change {
	return c.Plan(now, Input{Usage: usage})
}

// Plan updates the steer set from telemetry and probe results and returns
// what changed. It does not announce; Sync does, and only in inject.
func (c *Controller) Plan(now time.Time, in Input) []Change {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evaluated = now
	fresh := map[string]plugin.Usage{}
	for _, u := range in.Usage {
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
	perf := c.performance(now, in.Paths)

	var changes []Change
	released := map[string]bool{}
	c.blocked = nil
	release := func(s Steer, reason string, cool bool) {
		delete(c.steers, s.Provider)
		released[s.Provider] = true
		if cool && s.Hold > 0 {
			c.cooldown[s.Provider] = now.Add(s.Hold)
		}
		d := c.damp[s.Provider]
		if d == nil {
			d = &damping{}
			c.damp[s.Provider] = d
		}
		d.released, d.releaseIn95, d.trigger = now, s.InMbps95, s.Trigger
		changes = append(changes, Change{Action: ActionRelease, Steer: s, Reason: reason})
	}
	for _, p := range sortedKeys(c.steers) {
		s := c.steers[p]
		held := now.Sub(s.Since) >= s.Hold
		ttl := c.cfg.TTL > 0 && now.Sub(s.Since) >= c.cfg.TTL
		if s.Trigger == TriggerPerformance {
			g, ok := perf.gaps[p]
			switch {
			case !ok:
				release(s, "performance data is stale or missing", true)
			case ttl:
				release(s, "improvement_ttl reached", false)
			case held && c.perfReleased(g):
				s.Perf = &g
				release(s, fmt.Sprintf("loss %.1f points and RTT %.1f ms above the best other provider are within release_pct", g.LossGap, g.RTTGapMs), true)
			default:
				s.Perf = &g
				c.steers[p] = s
			}
			continue
		}
		u, ok := fresh[p]
		if !ok {
			release(s, "inbound telemetry is stale or missing", true)
			continue
		}
		in95, _ := u.InboundMbps()
		s.InMbps95, s.CommitMbps = in95, u.CommitMbps
		limit := u.CommitMbps * c.cfg.ReleasePct / 100
		switch {
		case ttl:
			release(s, "improvement_ttl reached", false)
		case held && in95+s.Shift <= limit:
			release(s, fmt.Sprintf("inbound 95th %.1f Mbps is at or below %.0f%% of the %.1f Mbps commit", in95, c.cfg.ReleasePct, u.CommitMbps), true)
		default:
			if held && in95 <= limit {
				c.blocked = append(c.blocked, Blocked{Provider: p, Reason: fmt.Sprintf(
					"inertia: kept because releasing moved %.1f Mbps back last time", s.Shift)})
			}
			c.steers[p] = s
		}
	}

	type cand struct {
		trigger string
		p       string
		u       plugin.Usage
		in95    float64
		ratio   float64
		gap     *PerfGap
		reason  string
	}
	var cands []cand
	for _, u := range fresh {
		if _, on := c.steers[u.Provider]; on || released[u.Provider] {
			continue
		}
		in95, _ := u.InboundMbps()
		if in95 > u.CommitMbps {
			cands = append(cands, cand{trigger: TriggerCommit, p: u.Provider, u: u, in95: in95, ratio: in95 / u.CommitMbps,
				reason: fmt.Sprintf("inbound 95th %.1f Mbps is above the %.1f Mbps commit", in95, u.CommitMbps)})
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].ratio != cands[j].ratio {
			return cands[i].ratio > cands[j].ratio
		}
		return cands[i].p < cands[j].p
	})
	// At most one provider is steered for performance: the worst.
	if w := perf.worst; w != "" && !released[w] && !c.perfSteered() {
		if _, on := c.steers[w]; !on {
			g := perf.gaps[w]
			cands = append(cands, cand{trigger: TriggerPerformance, p: w, gap: &g,
				reason: fmt.Sprintf("worst-performing provider: loss %.1f points and RTT %.1f ms above the best other provider over %d prefixes", g.LossGap, g.RTTGapMs, g.Prefixes)})
		}
	}
	seen := map[string]bool{}
	for _, cd := range cands {
		p := cd.p
		if seen[p] {
			continue
		}
		seen[p] = true
		first, ok := c.pending[p]
		if !ok {
			first = now
			c.pending[p] = now
		}
		if c.cfg.Damping.Confirm > 0 && now.Sub(first) < c.cfg.Damping.Confirm {
			c.blocked = append(c.blocked, Blocked{Provider: p, Reason: fmt.Sprintf("%s: confirming for %s (damping)", cd.trigger, c.cfg.Damping.Confirm)})
			continue
		}
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
		s := Steer{Provider: p, Trigger: cd.trigger, Since: now, InMbps95: cd.in95, CommitMbps: cd.u.CommitMbps, Action: act,
			Perf: cd.gap, Moderated: c.cfg.Moderated[cd.trigger]}
		c.damped(&s, now)
		s.HoldUntil = now.Add(s.Hold)
		c.steers[p] = s
		delete(c.pending, p)
		changes = append(changes, Change{Action: ActionSteer, Steer: s, Reason: cd.reason})
	}
	for p := range c.pending {
		if !seen[p] {
			delete(c.pending, p)
		}
	}
	// A provider that stayed released for a whole flap window starts over.
	for p, d := range c.damp {
		if _, on := c.steers[p]; !on && now.Sub(d.released) > c.window() {
			delete(c.damp, p)
		}
	}
	return changes
}

// damped sets the hold time of a new steer. A provider steered again
// within the flap window of its release is flapping: its hold time (and so
// its next cooldown) grows by backoff per flap up to max_hold, and a commit
// steer learns how much inbound traffic came back when it was released.
// It then stays until the 95th plus that shift is under release_pct, which
// ends the steer/release loop an unchanged demand would otherwise cause.
func (c *Controller) damped(s *Steer, now time.Time) {
	s.Hold = c.cfg.HoldTime
	d := c.damp[s.Provider]
	if c.cfg.Damping.Disabled || d == nil || now.Sub(d.released) > c.window() {
		delete(c.damp, s.Provider)
		return
	}
	d.flaps++
	if s.Trigger == TriggerCommit && d.trigger == TriggerCommit {
		if back := s.InMbps95 - d.releaseIn95; back > d.shift {
			d.shift = back
		}
	}
	if s.Trigger == TriggerCommit {
		s.Shift = d.shift
	}
	s.Flaps = d.flaps
	hold := float64(c.cfg.HoldTime)
	for i := 0; i < d.flaps && hold < float64(c.cfg.Damping.MaxHold); i++ {
		hold *= c.cfg.Damping.Backoff
	}
	s.Hold = min(time.Duration(hold), max(c.cfg.Damping.MaxHold, c.cfg.HoldTime))
}

// window is the flap window: a release followed by a steer inside it is a
// flap.
func (c *Controller) window() time.Duration {
	if c.cfg.Damping.Disabled {
		return 0
	}
	return max(c.cfg.Damping.MaxHold, c.cfg.HoldTime)
}

func (c *Controller) perfSteered() bool {
	for _, s := range c.steers {
		if s.Trigger == TriggerPerformance {
			return true
		}
	}
	return false
}

// perfReleased reports whether both gaps are at or below release_pct of
// their thresholds.
func (c *Controller) perfReleased(g PerfGap) bool {
	pc := c.cfg.Performance
	f := pc.ReleasePct / 100
	if pc.LossPct >= 0 && g.LossGap > pc.LossPct*f {
		return false
	}
	if pc.LatencyMs >= 0 && g.RTTGapMs > pc.LatencyMs*f {
		return false
	}
	return true
}

type perfView struct {
	gaps  map[string]PerfGap
	worst string
}

// performance compares providers over the prefixes every one of them
// measured with a fresh result. A provider with no fresh result (its probe
// source is down, or it was not probed) is left out, so a steer on it is
// released.
func (c *Controller) performance(now time.Time, paths []Path) perfView {
	v := perfView{gaps: map[string]PerfGap{}}
	pc := c.cfg.Performance
	if pc == nil {
		return v
	}
	by := map[string]map[netip.Prefix]Path{}
	for _, r := range paths {
		if !slices.Contains(c.cfg.Providers, r.Provider) || !r.Prefix.IsValid() {
			continue
		}
		age := now.Sub(r.Time)
		if r.Time.IsZero() || age < -maxFutureSkew || (c.cfg.PerfMaxAge > 0 && age > c.cfg.PerfMaxAge) {
			continue
		}
		if by[r.Provider] == nil {
			by[r.Provider] = map[netip.Prefix]Path{}
		}
		by[r.Provider][r.Prefix.Masked()] = r
	}
	if len(by) < 2 {
		return v
	}
	provs := sortedKeys(by)
	var common []netip.Prefix
	for p := range by[provs[0]] {
		all := true
		for _, q := range provs[1:] {
			if _, ok := by[q][p]; !ok {
				all = false
				break
			}
		}
		if all {
			common = append(common, p)
		}
	}
	if len(common) < pc.MinPrefixes {
		return v
	}
	// RTT is averaged over the paths that answered: a path with total
	// loss has no RTT, and its loss already counts.
	loss, rtt := map[string]float64{}, map[string]float64{}
	for _, q := range provs {
		answered := 0
		for _, p := range common {
			r := by[q][p]
			loss[q] += r.LossPct
			if r.LossPct < 100 {
				rtt[q] += float64(r.RTT) / float64(time.Millisecond)
				answered++
			}
		}
		loss[q] /= float64(len(common))
		if answered > 0 {
			rtt[q] /= float64(answered)
		} else {
			delete(rtt, q)
		}
	}
	worstScore := 0.0
	for _, q := range provs {
		bestLoss, bestRTT := math.Inf(1), math.Inf(1)
		for _, o := range provs {
			if o == q {
				continue
			}
			bestLoss = min(bestLoss, loss[o])
			if v, ok := rtt[o]; ok {
				bestRTT = min(bestRTT, v)
			}
		}
		g := PerfGap{LossPct: loss[q], RTTMs: rtt[q], LossGap: loss[q] - bestLoss, Prefixes: len(common)}
		if v, ok := rtt[q]; ok && !math.IsInf(bestRTT, 1) {
			g.RTTGapMs = v - bestRTT
		}
		v.gaps[q] = g
		score := 0.0
		if pc.LossPct >= 0 && g.LossGap >= max(pc.LossPct, 1e-9) {
			score = max(score, g.LossGap/max(pc.LossPct, 1e-9))
		}
		if pc.LatencyMs >= 0 && g.RTTGapMs >= max(pc.LatencyMs, 1e-9) {
			score = max(score, g.RTTGapMs/max(pc.LatencyMs, 1e-9))
		}
		if score > worstScore {
			worstScore, v.worst = score, q
		}
	}
	return v
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
	if c.cfg.Leader != nil && !c.cfg.Leader() {
		if len(c.active) > 0 {
			c.log.Warn("ha standby; withdrawing inbound steer routes")
		}
		return c.withdrawAllLocked(ctx)
	}
	if !c.rib.Ready() {
		if len(c.active) > 0 {
			c.log.Warn("rib not ready; withdrawing inbound steer routes")
		}
		return c.withdrawAllLocked(ctx)
	}
	var away []string
	for _, p := range sortedKeys(c.steers) {
		if !c.steers[p].Moderated {
			away = append(away, p)
		}
	}
	if len(away) == 0 {
		return c.withdrawAllLocked(ctx)
	}
	key := strings.Join(away, ",")
	var errs []error
	for _, p := range c.cfg.Prefixes {
		cur, on := c.active[p]
		if c.cfg.Excluded != nil && c.cfg.Excluded(p) {
			if on {
				errs = append(errs, c.withdrawLocked(ctx, p))
			}
			continue
		}
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
