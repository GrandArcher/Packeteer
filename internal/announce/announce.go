// Package announce turns decision-engine changes into announcer calls.
//
// It runs only in inject mode. Observe and suggest never touch the
// announcer. A route is published only when the decided prefix is allowlisted
// and present in the RIB, the provider has a next hop, and the improvement
// cap has room. The announced prefix is that exact prefix. Packeteer does
// not synthesize more-specifics. Every Sync re-checks prefixes already on
// the wire, including provider switches. A route already on the wire stays
// while the decision engine still wants it, even if the neighbor stopped
// advertising the prefix: that is what the router does once Packeteer's
// route is best, and withdrawing it would flap. A real leave arrives as the
// improvement leaving the wanted set, and Sync withdraws it. Every route
// carries a local preference, the configured community, and any extra
// communities for the cause and the provider; the announcer adds NO_EXPORT.
// The local preference is the provider's, when that provider sets one,
// otherwise the improvement's cause, otherwise the global value. An empty
// cause is performance. Extra communities are added, not substituted: the
// configured community, then the cause's, then the provider's. A learned
// more-specific uses its improvement's resolved local preference and
// communities.
//
// With more-specific injection on (#56, docs/design/more-specific.md), an
// improvement also announces the more-specifics inside its prefix that a
// neighbor advertises in the learned RIB: each an exact learned prefix,
// never one Packeteer computed. MaxRoutes caps every route on the wire, and
// a new improvement is announced whole or not at all.
package announce

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
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// RIB is the slice of the RIB view the controller needs. Ready is false when
// no BGP session is up. Contains reports an exact prefix a configured
// neighbor is still advertising. It is false both when the prefix has left
// and when the router has stopped sending it because Packeteer's route won.
// Sync uses Contains to refuse a new announcement. It does not, by itself,
// withdraw an improvement the decision engine still wants.
type RIB interface {
	Ready() bool
	Contains(netip.Prefix) bool
}

// PathRIB is the RIB surface bgp.as_path reads (#27): the AS path of the
// learned (native) route for exactly p, and of a provider's learned path.
type PathRIB interface {
	NativePath(netip.Prefix) ([]uint32, bool)
	ProviderPath(p netip.Prefix, provider string) ([]uint32, bool)
}

// MoreSpecificRIB is the RIB surface more-specific injection reads (#56):
// the learned prefixes strictly inside any of parents. Each one is checked
// again with Contains before it is announced.
type MoreSpecificRIB interface {
	MoreSpecifics(parents []netip.Prefix) []netip.Prefix
}

// Config is the injection policy. It is ignored unless Mode is inject.
type Config struct {
	Mode      string
	LocalPref uint32
	// CauseLocalPref overrides LocalPref for an improvement cause
	// (performance, static, commit, cost). A missing cause uses LocalPref.
	// An empty cause is performance.
	CauseLocalPref map[string]uint32
	// ProviderLocalPref overrides the cause and the global value for routes
	// steered to that provider.
	ProviderLocalPref map[string]uint32
	Community         string
	// CauseCommunities are extra communities for an improvement cause.
	// An empty cause is performance. They are added after Community.
	CauseCommunities map[string][]string
	// ProviderCommunities are extra communities for routes steered to that
	// provider, added after the cause's.
	ProviderCommunities map[string][]string
	MaxImprovements     int
	Allowlist           []netip.Prefix
	NextHops            map[string]netip.Addr // provider name -> next hop
	// Reserved reports prefixes that inbound steering owns or threat
	// mitigation holds (#28). They are never announced as outbound
	// improvements, so no two of them share a prefix.
	Reserved func(netip.Prefix) bool
	// Others counts routes inbound steering has on the wire. They count
	// toward MaxImprovements too.
	Others func() int
	// Routers is per-router provider reachability (#27). Empty sends every
	// route to every neighbor. Set, the announcer must implement
	// plugin.RouterAnnouncer or Bind fails.
	Routers []plugin.RouterExport
	// ASPath is the AS path on injected routes (config.ASPath*): empty
	// (default), native, or provider. native and provider need the RIB to
	// implement PathRIB.
	ASPath string
	// MoreSpecific also announces, with each improvement, the learned
	// more-specifics inside its prefix (#56). The RIB must implement
	// MoreSpecificRIB. MaxRoutes caps the routes on the wire: improvements,
	// their more-specifics, and Others. Both are ignored when MoreSpecific
	// is false.
	MoreSpecific bool
	MaxRoutes    int
	// Now is the clock for the more-specific leave check. Nil is time.Now.
	Now func() time.Time
	// Leader reports whether this instance is the active one of an HA
	// pair (#31). Nil is a single instance, always active. While it is
	// false, Sync withdraws everything and announces nothing; it is
	// checked under the controller's lock on every Sync.
	Leader func() bool
}

// Controller applies decision changes to an announcer.
type Controller struct {
	cfg Config
	ann plugin.Announcer
	rib RIB
	log *slog.Logger

	mu     sync.Mutex
	active map[netip.Prefix]slot // exact learned prefix -> what is on the wire
	onWire atomic.Int64          // improvements on the wire
	routes atomic.Int64          // routes on the wire, more-specifics included
	// srv is the RIB view's speaker. bound is true after a successful
	// bind. RememberSpeaker stores srv before inject is on, so a later
	// mode change can bind without a restart (#128).
	srv   any
	bound bool
}

// Active is the number of improvements on the wire. It does not lock, so
// the inbound controller can read it while syncing. More-specifics
// announced with an improvement are not counted; Routes counts them.
func (c *Controller) Active() int {
	if c == nil {
		return 0
	}
	return int(c.onWire.Load())
}

// Routes is the number of outbound routes on the wire: improvements and
// the learned more-specifics announced with them.
func (c *Controller) Routes() int {
	if c == nil {
		return 0
	}
	return int(c.routes.Load())
}

// slot is the route published for one learned prefix.
type slot struct {
	provider    string
	asPath      []uint32
	localPref   uint32
	communities []string
	// parent is the improvement that owns a learned more-specific (#56).
	// It is the zero prefix on an improvement's own route.
	parent netip.Prefix
	// seen and held track a more-specific in the RIB the way the decision
	// engine tracks an improvement's prefix (policy.NativePathConfirm).
	seen time.Time
	held bool
}

func (s slot) moreSpecific() bool { return s.parent.IsValid() }

// store publishes the on-wire counts. Caller holds mu.
func (c *Controller) store() {
	c.onWire.Store(int64(c.improvementsLocked()))
	c.routes.Store(int64(len(c.active)))
}

// improvementsLocked counts improvements on the wire, not their
// more-specifics.
func (c *Controller) improvementsLocked() int {
	n := 0
	for _, s := range c.active {
		if !s.moreSpecific() {
			n++
		}
	}
	return n
}

// New validates inject settings and returns a controller. ann and rib may be
// nil when Mode is not inject; Apply is then a no-op.
func New(cfg Config, ann plugin.Announcer, rib RIB, log *slog.Logger) (*Controller, error) {
	if cfg.Mode == config.ModeInject {
		if ann == nil {
			return nil, errors.New("announce: inject mode requires an announcer")
		}
		if rib == nil {
			return nil, errors.New("announce: inject mode requires a RIB view")
		}
		if cfg.LocalPref == 0 {
			return nil, errors.New("announce: inject mode requires local_pref")
		}
		for cause, v := range cfg.CauseLocalPref {
			switch cause {
			case plugin.CausePerformance, plugin.CauseStatic, plugin.CauseCommit, plugin.CauseCost:
			default:
				return nil, fmt.Errorf("announce: local_pref cause %q is invalid", cause)
			}
			if v == 0 {
				return nil, fmt.Errorf("announce: local_pref for cause %s must be above the edge's native local preference (0 is rejected)", cause)
			}
		}
		for name, v := range cfg.ProviderLocalPref {
			if _, ok := cfg.NextHops[name]; !ok {
				return nil, fmt.Errorf("announce: local_pref for unknown provider %q", name)
			}
			if v == 0 {
				return nil, fmt.Errorf("announce: provider %s local_pref must be above the edge's native local preference (0 is rejected)", name)
			}
		}
		if cfg.Community == "" {
			return nil, errors.New("announce: inject mode requires a community")
		}
		text, err := config.CommunityText(cfg.Community)
		if err != nil {
			return nil, fmt.Errorf("announce: community: %w", err)
		}
		cfg.Community = text
		for cause, list := range cfg.CauseCommunities {
			switch cause {
			case plugin.CausePerformance, plugin.CauseStatic, plugin.CauseCommit, plugin.CauseCost:
			default:
				return nil, fmt.Errorf("announce: communities cause %q is invalid", cause)
			}
			canon, err := checkExtraCommunities(cause, list, cfg.Community)
			if err != nil {
				return nil, err
			}
			cfg.CauseCommunities[cause] = canon
		}
		for name, list := range cfg.ProviderCommunities {
			if _, ok := cfg.NextHops[name]; !ok {
				return nil, fmt.Errorf("announce: communities for unknown provider %q", name)
			}
			canon, err := checkExtraCommunities(name, list, cfg.Community)
			if err != nil {
				return nil, err
			}
			cfg.ProviderCommunities[name] = canon
		}
		if cfg.MaxImprovements < 0 {
			return nil, errors.New("announce: max_improvements must not be negative")
		}
		switch cfg.ASPath {
		case "", config.ASPathEmpty:
		case config.ASPathNative, config.ASPathProvider:
			if _, ok := rib.(PathRIB); !ok {
				return nil, fmt.Errorf("announce: as_path %s needs the learned AS paths", cfg.ASPath)
			}
		default:
			return nil, fmt.Errorf("announce: as_path %q is invalid", cfg.ASPath)
		}
		if cfg.MoreSpecific {
			if cfg.MaxRoutes < 1 {
				return nil, errors.New("announce: more_specific.max_routes must be positive")
			}
			if _, ok := rib.(MoreSpecificRIB); !ok {
				return nil, errors.New("announce: more_specific needs the learned more-specifics from the RIB")
			}
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	if cfg.NextHops == nil {
		cfg.NextHops = map[string]netip.Addr{}
	}
	return &Controller{cfg: cfg, ann: ann, rib: rib, log: log, active: map[netip.Prefix]slot{}}, nil
}

// Bind attaches an announcer that publishes on an existing speaker. srv is
// the RIB view's GoBGP server. Inject mode refuses to start when the
// announcer cannot bind. The speaker is remembered either way, so a later
// change to inject can bind without a restart.
func (c *Controller) Bind(srv any) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if srv != nil {
		c.srv = srv
	}
	if c.cfg.Mode != config.ModeInject {
		return nil
	}
	return c.bindLocked()
}

// RememberSpeaker stores the RIB speaker without binding. Observe and
// suggest call it at start so a later mode change to inject can bind.
func (c *Controller) RememberSpeaker(srv any) {
	if c == nil || srv == nil {
		return
	}
	c.mu.Lock()
	c.srv = srv
	c.mu.Unlock()
}

// ApplyRuntime updates mode, the allowlist, and the improvement cap while
// running (#128). Leaving inject withdraws every route before the mode
// changes, under this lock, so a concurrent Sync cannot announce again.
// Entering inject binds the remembered speaker and, if that fails, leaves
// the previous mode in place. The caller has not changed BGP sessions yet.
func (c *Controller) ApplyRuntime(ctx context.Context, mode string, allow []netip.Prefix, max int) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	prevMode, prevAllow, prevMax := c.cfg.Mode, c.cfg.Allowlist, c.cfg.MaxImprovements
	if prevMode == config.ModeInject && mode != config.ModeInject {
		if err := c.withdrawAllLocked(ctx); err != nil {
			return err
		}
		c.store()
	}
	c.cfg.Mode = mode
	c.cfg.Allowlist = append([]netip.Prefix(nil), allow...)
	c.cfg.MaxImprovements = max
	if prevMode != config.ModeInject && mode == config.ModeInject {
		if err := c.bindLocked(); err != nil {
			c.cfg.Mode, c.cfg.Allowlist, c.cfg.MaxImprovements = prevMode, prevAllow, prevMax
			return err
		}
	}
	return nil
}

// bindLocked publishes on the remembered speaker. Caller holds mu.
func (c *Controller) bindLocked() error {
	if c.bound {
		return nil
	}
	if c.ann == nil {
		return errors.New("announce: inject mode requires an announcer")
	}
	if c.srv == nil {
		return errors.New("announce: inject needs an iBGP session")
	}
	var err error
	if len(c.cfg.Routers) > 0 {
		r, ok := c.ann.(plugin.RouterAnnouncer)
		if !ok {
			return fmt.Errorf("announce: announcer %T cannot send per-router routes (bgp.neighbors providers/next_hops)", c.ann)
		}
		err = r.BindRouters(c.srv, c.cfg.Community, c.cfg.Routers)
	} else {
		b, ok := c.ann.(interface {
			Bind(any, string) error
		})
		if !ok {
			return fmt.Errorf("announce: announcer %T cannot publish on the embedded iBGP speaker", c.ann)
		}
		err = b.Bind(c.srv, c.cfg.Community)
	}
	if err != nil {
		return err
	}
	c.bound = true
	return nil
}

// Sync makes the announced set match imps, the decision engine's active
// improvements. In observe and suggest it returns immediately and does not
// call the announcer. When the RIB is not ready every announced route is
// withdrawn, even if imps is non-empty. Calling Sync again with the same
// improvements does not re-advertise. A prefix that is not in the RIB is not
// announced. One that is already announced is kept or moved while the
// improvement is still requested; a real RIB leave comes in as the
// improvement disappearing from imps. With MoreSpecific, each improvement's
// learned more-specifics follow it (syncMoreSpecificsLocked).
func (c *Controller) Sync(ctx context.Context, imps []policy.Improvement) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.store()
	// Mode is read under the lock so a reload that leaves inject can
	// withdraw and clear the mode without a concurrent Sync announcing.
	if c.cfg.Mode != config.ModeInject {
		return nil
	}
	if c.cfg.Leader != nil && !c.cfg.Leader() {
		// HA standby (#31): nothing on the wire.
		if len(c.active) == 0 {
			return nil
		}
		c.log.Warn("ha standby; withdrawing announced routes", "routes", len(c.active))
		return c.withdrawAllLocked(ctx)
	}
	if !c.rib.Ready() {
		c.log.Warn("rib not ready; withdrawing announced routes")
		return c.withdrawAllLocked(ctx)
	}
	want := map[netip.Prefix]policy.Improvement{}
	for _, im := range imps {
		want[im.Prefix.Masked()] = im
	}
	var errs []error
	for p, s := range c.active {
		if _, ok := want[p]; ok {
			continue
		}
		if s.moreSpecific() {
			// Kept or withdrawn with its improvement below.
			if _, ok := want[s.parent]; ok {
				continue
			}
		}
		if err := c.withdrawLocked(ctx, p); err != nil {
			errs = append(errs, err)
		}
	}
	var kids map[netip.Prefix][]netip.Prefix
	var owner map[netip.Prefix]netip.Prefix
	visited := map[netip.Prefix]bool{}
	if c.cfg.MoreSpecific {
		kids, owner = c.learnedMoreSpecifics(want)
	}
	order := make([]netip.Prefix, 0, len(want))
	for p := range want {
		order = append(order, p)
	}
	sortPrefixes(order)
	for _, p := range order {
		if err := c.syncImprovementLocked(ctx, want[p], kids[p]); err != nil {
			errs = append(errs, err)
		}
		if s, on := c.active[p]; c.cfg.MoreSpecific && on && !s.moreSpecific() {
			errs = append(errs, c.syncMoreSpecificsLocked(ctx, p, kids[p], owner, visited)...)
		}
	}
	// A more-specific no improvement on the wire claimed this round (its
	// improvement did not make it, or a new improvement that owns it did
	// not) is withdrawn rather than left without its leave check.
	for p, s := range c.active {
		if s.moreSpecific() && !visited[p] {
			if err := c.withdrawLocked(ctx, p); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// syncImprovementLocked announces, moves, keeps, or refuses the route for
// one improvement. learned is its more-specifics in the RIB when
// MoreSpecific is on; a new improvement is announced only when it and all
// of them fit under MaxRoutes.
func (c *Controller) syncImprovementLocked(ctx context.Context, im policy.Improvement, learned []netip.Prefix) error {
	p := im.Prefix.Masked()
	s, on := c.active[p]
	if c.cfg.Reserved != nil && c.cfg.Reserved(p) {
		var err error
		if on {
			err = c.withdrawLocked(ctx, p)
		}
		return errors.Join(err, fmt.Errorf("announce: %s is reserved for inbound steering or threat mitigation", p))
	}
	if !on && !c.rib.Contains(p) {
		return fmt.Errorf("announce: %s is not in the RIB", p)
	}
	// A cause change can keep the provider and the AS path and still need a
	// new local preference or a new community list on the wire.
	lp := c.localPref(im.Provider, im.Cause)
	comms := c.communities(im.Provider, im.Cause)
	if on && !s.moreSpecific() && s.provider == im.Provider && s.localPref == lp && slices.Equal(s.communities, comms) && slices.Equal(s.asPath, c.asPath(p, im.Provider)) {
		return nil
	}
	if !allowed(c.cfg.Allowlist, p) {
		var err error
		if on {
			err = c.withdrawLocked(ctx, p)
		}
		return errors.Join(err, fmt.Errorf("announce: %s is not allowlisted", p))
	}
	if c.cfg.MoreSpecific && !on {
		need := 1
		for _, m := range learned {
			if _, ok := c.active[m]; !ok {
				need++
			}
		}
		if used := c.usedRoutesLocked(); used+need > c.cfg.MaxRoutes {
			return fmt.Errorf("announce: more_specific.max_routes (%d) reached: %s needs %d routes, %d in use", c.cfg.MaxRoutes, p, need, used)
		}
	}
	return c.announceLocked(ctx, im)
}

// usedRoutesLocked is the routes that count toward MaxRoutes: every route
// this controller has on the wire plus Others.
func (c *Controller) usedRoutesLocked() int {
	n := len(c.active)
	if c.cfg.Others != nil {
		n += c.cfg.Others()
	}
	return n
}

// learnedMoreSpecifics assigns every learned more-specific inside a wanted
// improvement to the longest improvement that contains it. A prefix that is
// itself wanted, outside the allowlist, or reserved is not assigned. kids
// maps an improvement to its more-specifics in prefix order; owner maps a
// more-specific to its improvement.
func (c *Controller) learnedMoreSpecifics(want map[netip.Prefix]policy.Improvement) (kids map[netip.Prefix][]netip.Prefix, owner map[netip.Prefix]netip.Prefix) {
	kids, owner = map[netip.Prefix][]netip.Prefix{}, map[netip.Prefix]netip.Prefix{}
	if len(want) == 0 {
		return kids, owner
	}
	parents := make([]netip.Prefix, 0, len(want))
	for p := range want {
		parents = append(parents, p)
	}
	sortPrefixes(parents)
	seen := map[netip.Prefix]bool{}
	for _, m := range c.rib.(MoreSpecificRIB).MoreSpecifics(parents) {
		m = m.Masked()
		if seen[m] {
			continue
		}
		seen[m] = true
		if _, ok := want[m]; ok || !allowed(c.cfg.Allowlist, m) || (c.cfg.Reserved != nil && c.cfg.Reserved(m)) {
			continue
		}
		var best netip.Prefix
		for _, p := range parents {
			if p.Bits() < m.Bits() && p.Contains(m.Addr()) && (!best.IsValid() || p.Bits() > best.Bits()) {
				best = p
			}
		}
		if !best.IsValid() {
			continue
		}
		kids[best] = append(kids[best], m)
		owner[m] = best
	}
	for _, ms := range kids {
		sortPrefixes(ms)
	}
	return kids, owner
}

// syncMoreSpecificsLocked keeps the learned more-specifics of the
// improvement on p (already on the wire) in step with it and the RIB.
// learned is what the RIB has inside p now. A more-specific on the wire is
// withdrawn when it becomes reserved or leaves the allowlist, or on a real
// RIB leave: it was seen for policy.NativePathConfirm while announced and
// then stopped. A shorter gap is the router hiding the native path because
// Packeteer's route won, and it stays. New ones are announced while
// MaxRoutes has room.
func (c *Controller) syncMoreSpecificsLocked(ctx context.Context, p netip.Prefix, learned []netip.Prefix, owner map[netip.Prefix]netip.Prefix, visited map[netip.Prefix]bool) []error {
	var errs []error
	now := c.cfg.Now()
	par := c.active[p]
	inRIB := map[netip.Prefix]bool{}
	for _, m := range learned {
		inRIB[m] = true
	}
	var mine []netip.Prefix
	for m, s := range c.active {
		if s.moreSpecific() && s.parent == p {
			mine = append(mine, m)
		}
	}
	sortPrefixes(mine)
	for _, m := range mine {
		if o, ok := owner[m]; ok && o != p {
			continue // a longer improvement owns it now
		}
		s := c.active[m]
		if !allowed(c.cfg.Allowlist, m) || (c.cfg.Reserved != nil && c.cfg.Reserved(m)) {
			if err := c.withdrawLocked(ctx, m); err != nil {
				errs = append(errs, err)
				visited[m] = true
			}
			continue
		}
		switch {
		case inRIB[m]:
			if s.seen.IsZero() {
				s.seen = now
			}
			s.held = true
		case s.held && !s.seen.IsZero() && now.Sub(s.seen) >= policy.NativePathConfirm:
			if err := c.withdrawLocked(ctx, m); err != nil {
				errs = append(errs, err)
				visited[m] = true
				continue
			}
			c.log.Info("more-specific left the RIB; withdrawn", "prefix", m, "improvement", p)
			continue
		default:
			s.seen, s.held = time.Time{}, false
		}
		c.active[m] = s
		visited[m] = true
		if s.provider != par.provider || s.localPref != par.localPref || !slices.Equal(s.communities, par.communities) || !slices.Equal(s.asPath, c.asPath(m, par.provider)) {
			if err := c.announceMoreSpecificLocked(ctx, m, p, par.provider); err != nil {
				errs = append(errs, err)
			}
		}
	}
	capped := 0
	for _, m := range learned {
		if s, on := c.active[m]; on {
			if s.moreSpecific() && s.parent == p {
				continue
			}
			if s.moreSpecific() {
				// It moves from a shorter improvement to this one.
				visited[m] = true
				s.parent, s.seen, s.held = p, time.Time{}, false
				c.active[m] = s
				if s.provider != par.provider || s.localPref != par.localPref || !slices.Equal(s.communities, par.communities) || !slices.Equal(s.asPath, c.asPath(m, par.provider)) {
					if err := c.announceMoreSpecificLocked(ctx, m, p, par.provider); err != nil {
						errs = append(errs, err)
					}
				}
				continue
			}
			continue // an improvement's own route
		}
		if c.usedRoutesLocked()+1 > c.cfg.MaxRoutes {
			capped++
			continue
		}
		if err := c.announceMoreSpecificLocked(ctx, m, p, par.provider); err != nil {
			errs = append(errs, err)
			continue
		}
		visited[m] = true
	}
	if capped > 0 {
		errs = append(errs, fmt.Errorf("announce: more_specific.max_routes (%d) reached: %d learned more-specifics of %s not announced", c.cfg.MaxRoutes, capped, p))
	}
	return errs
}

// announceMoreSpecificLocked publishes the learned prefix m for the
// improvement on parent, toward provider. m must be inside the allowlist
// and, when it is not already on the wire, exactly in the RIB.
func (c *Controller) announceMoreSpecificLocked(ctx context.Context, m, parent netip.Prefix, provider string) error {
	m = m.Masked()
	if !allowed(c.cfg.Allowlist, m) {
		return fmt.Errorf("announce: %s is not allowlisted", m)
	}
	old, on := c.active[m]
	if !on && !c.rib.Contains(m) {
		return fmt.Errorf("announce: %s is not in the RIB", m)
	}
	nh, ok := c.cfg.NextHops[provider]
	if !ok || !nh.IsValid() {
		return fmt.Errorf("announce: provider %q has no next hop", provider)
	}
	lp := c.cfg.LocalPref
	comms := []string{c.cfg.Community}
	if par, ok := c.active[parent]; ok {
		if par.localPref != 0 {
			lp = par.localPref
		}
		if len(par.communities) > 0 {
			comms = slices.Clone(par.communities)
		}
	}
	rt := plugin.Route{
		Prefix:      m,
		NextHop:     nh,
		Provider:    provider,
		LocalPref:   lp,
		Communities: comms,
		ASPath:      c.asPath(m, provider),
	}
	if err := c.ann.Announce(ctx, rt); err != nil {
		return err
	}
	s := slot{provider: provider, asPath: rt.ASPath, localPref: lp, communities: comms, parent: parent}
	if on && old.moreSpecific() && old.parent == parent {
		s.seen, s.held = old.seen, old.held
	}
	c.active[m] = s
	c.log.Info("injected more-specific", "prefix", m, "improvement", parent, "provider", provider, "next_hop", nh, "local_pref", lp, "as_path", fmt.Sprint(rt.ASPath), "communities", strings.Join(comms, ","))
	return nil
}

// WithdrawAll removes every announced route. It is safe to call more than once.
func (c *Controller) WithdrawAll(ctx context.Context) error {
	if c == nil || c.cfg.Mode != config.ModeInject || c.ann == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.store()
	return c.withdrawAllLocked(ctx)
}

func (c *Controller) withdrawAllLocked(ctx context.Context) error {
	if err := c.ann.WithdrawAll(ctx); err != nil {
		return err
	}
	c.active = map[netip.Prefix]slot{}
	return nil
}

func (c *Controller) withdrawLocked(ctx context.Context, p netip.Prefix) error {
	p = p.Masked()
	if _, ok := c.active[p]; !ok {
		return nil
	}
	if err := c.ann.Withdraw(ctx, p); err != nil {
		return err
	}
	delete(c.active, p)
	return nil
}

func (c *Controller) announceLocked(ctx context.Context, imp policy.Improvement) error {
	p := imp.Prefix.Masked()
	if !allowed(c.cfg.Allowlist, p) {
		return fmt.Errorf("announce: %s is not allowlisted", p)
	}
	if _, on := c.active[p]; !on && !c.rib.Contains(p) {
		return fmt.Errorf("announce: %s is not in the RIB", p)
	}
	nh, ok := c.cfg.NextHops[imp.Provider]
	if !ok || !nh.IsValid() {
		return fmt.Errorf("announce: provider %q has no next hop", imp.Provider)
	}
	others := 0
	if c.cfg.Others != nil {
		others = c.cfg.Others()
	}
	// A learned more-specific becoming an improvement of its own is a new
	// improvement for this cap. More-specifics do not count here; MaxRoutes
	// bounds them.
	if s, exists := c.active[p]; (!exists || s.moreSpecific()) && c.improvementsLocked()+others >= c.cfg.MaxImprovements {
		return fmt.Errorf("announce: max_improvements (%d) reached", c.cfg.MaxImprovements)
	}
	lp := c.localPref(imp.Provider, imp.Cause)
	comms := c.communities(imp.Provider, imp.Cause)
	rt := plugin.Route{
		Prefix:      p,
		NextHop:     nh,
		Provider:    imp.Provider,
		LocalPref:   lp,
		Communities: comms,
		ASPath:      c.asPath(p, imp.Provider),
	}
	if err := c.ann.Announce(ctx, rt); err != nil {
		return err
	}
	c.active[p] = slot{provider: imp.Provider, asPath: rt.ASPath, localPref: lp, communities: comms}
	// cause stays after local_pref so the walkthrough's fixed substring
	// (provider, next_hop, local_pref) still matches. Communities follow.
	c.log.Info("injected", "prefix", p, "provider", imp.Provider, "next_hop", nh, "local_pref", lp, "as_path", fmt.Sprint(rt.ASPath), "cause", imp.Cause, "communities", strings.Join(comms, ","))
	return nil
}

// localPref is the local preference for a steer to provider for cause.
// The provider value wins, then the cause, then the global LocalPref.
// An empty cause is performance. Caller holds mu.
func (c *Controller) localPref(provider, cause string) uint32 {
	if v, ok := c.cfg.ProviderLocalPref[provider]; ok {
		return v
	}
	if cause == "" {
		cause = plugin.CausePerformance
	}
	if v, ok := c.cfg.CauseLocalPref[cause]; ok {
		return v
	}
	return c.cfg.LocalPref
}

// communities is packeteer_community, then the cause's extras, then the
// provider's. Duplicates are dropped. An empty cause is performance.
// Caller holds mu.
func (c *Controller) communities(provider, cause string) []string {
	out := []string{c.cfg.Community}
	seen := map[string]bool{c.cfg.Community: true}
	add := func(list []string) {
		for _, x := range list {
			if x == "" || seen[x] {
				continue
			}
			seen[x] = true
			out = append(out, x)
		}
	}
	if cause == "" {
		cause = plugin.CausePerformance
	}
	add(c.cfg.CauseCommunities[cause])
	add(c.cfg.ProviderCommunities[provider])
	return out
}

// checkExtraCommunities rejects a list the config loader would reject.
func checkExtraCommunities(where string, list []string, packeteer string) ([]string, error) {
	if len(list) > config.MaxExtraCommunities {
		return nil, fmt.Errorf("announce: %s: at most %d communities", where, config.MaxExtraCommunities)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(list))
	for _, s := range list {
		text, err := config.ExtraCommunityText(s, packeteer)
		if err != nil {
			return nil, fmt.Errorf("announce: %s community %q: %w", where, s, err)
		}
		if seen[text] {
			return nil, fmt.Errorf("announce: %s: duplicate community %s", where, text)
		}
		seen[text] = true
		out = append(out, text)
	}
	return out, nil
}

// asPath is the AS path for p toward provider under bgp.as_path. native
// is the learned route's path; provider is the provider's own learned
// path, else the native one. When the view no longer shows the path (the
// router stopped sending the native route once Packeteer's won), the path
// already on the wire for the same provider is kept, so that does not
// re-announce. Caller holds mu.
func (c *Controller) asPath(p netip.Prefix, provider string) []uint32 {
	mode := c.cfg.ASPath
	if mode == "" || mode == config.ASPathEmpty {
		return nil
	}
	r, ok := c.rib.(PathRIB)
	if !ok {
		return nil
	}
	if mode == config.ASPathProvider {
		if as, ok := r.ProviderPath(p, provider); ok {
			return as
		}
	}
	if as, ok := r.NativePath(p); ok {
		return as
	}
	if s, on := c.active[p]; on && s.provider == provider {
		return s.asPath
	}
	return nil
}

// SetRouters replaces the per-router table while the controller runs
// (online reconfiguration, #27). The announcer withdraws every outbound
// route first; the next Sync announces them again under the new table.
// Outside inject only the config is kept.
func (c *Controller) SetRouters(ctx context.Context, routers []plugin.RouterExport) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.store()
	if c.cfg.Mode != config.ModeInject {
		c.cfg.Routers = routers
		return nil
	}
	r, ok := c.ann.(plugin.RouterReloader)
	if !ok {
		return fmt.Errorf("announce: announcer %T cannot replace its per-router table while running; restart instead", c.ann)
	}
	err := r.SetRouters(ctx, routers)
	// Whatever the outcome, nothing is known to be on the wire any more;
	// the caller stops the controller on an error, which withdraws again.
	c.active = map[netip.Prefix]slot{}
	if err != nil {
		return err
	}
	c.cfg.Routers = routers
	return nil
}

// Routers is the per-router table in use.
func (c *Controller) Routers() []plugin.RouterExport {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg.Routers
}

func sortPrefixes(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool {
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
}

// allowed reports whether p is an allowlist entry or covered by one.
// Announce publishes p itself, and only when that exact prefix is in the RIB.
func allowed(list []netip.Prefix, p netip.Prefix) bool {
	p = p.Masked()
	for _, a := range list {
		if a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
			return true
		}
	}
	return false
}
