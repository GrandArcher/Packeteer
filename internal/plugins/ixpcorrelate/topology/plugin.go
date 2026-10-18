// Package topology is the ixp.correlate plugin (#163). It reads the fabric
// probe view, groups member measurements by switch, colo, and core bundle,
// and raises ixp.fabric_degraded when many members behind one group
// degrade together and ixp.member_degraded when one member does alone. It
// does not probe, does not announce, and is not an input to Decide.
package topology

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the config type.
const TypeName = "topology"

// Defaults and bounds. A zero value in config selects the default.
const (
	DefaultMinMembers  = 3
	minMinMembers      = 2
	maxMinMembers      = 1000
	DefaultDegradedPct = 50
	DefaultRounds      = 2
	maxRounds          = 10
	maxBundles         = 64
	maxBundleSwitches  = 256

	// pollEvery is how often the loop looks for a new fabric round. It is
	// not a config knob: the prober interval is at least 10 seconds.
	pollEvery = 5 * time.Second
	// maxASNsInEvent bounds the asns field of an event.
	maxASNsInEvent = 10
)

// Bundle names the switches that share one core link bundle. IX-F carries
// no core bundle, so the operator lists them. IXPID 0 matches any IXP.
type Bundle struct {
	Name     string `yaml:"name"`
	IXPID    int    `yaml:"ixp_id"`
	Switches []int  `yaml:"switches"`
}

func (b Bundle) has(ixp, sw int) bool {
	if b.IXPID != 0 && b.IXPID != ixp {
		return false
	}
	for _, id := range b.Switches {
		if id == sw {
			return true
		}
	}
	return false
}

// Config is the topology correlator's config block.
type Config struct {
	MinMembers  int      `yaml:"min_members"`
	DegradedPct int      `yaml:"degraded_pct"`
	Rounds      int      `yaml:"rounds"`
	Bundles     []Bundle `yaml:"bundles"`
}

func init() { plugin.FabricCorrelators.Register(TypeName, New) }

// The controller stores the correlator as a FabricCorrelator.
var _ plugin.FabricCorrelator = (*Correlator)(nil)

// flip is a state with hysteresis: it changes only after rounds
// consecutive observations that disagree with it.
type flip struct {
	active bool
	n      int
}

func (f *flip) step(cond bool, rounds int) bool {
	if cond == f.active {
		f.n = 0
		return false
	}
	f.n++
	if f.n < rounds {
		return false
	}
	f.active, f.n = cond, 0
	return true
}

func (f *flip) idle() bool { return !f.active && f.n == 0 }

type groupState struct {
	flip
	last group
}

type memberState struct {
	flip
	last member
}

// Correlator is the topology correlator.
type Correlator struct {
	th      thresholds
	rounds  int
	bundles []Bundle
	now     func() time.Time

	mu     sync.Mutex
	fabric func() plugin.FabricView
	sink   func(plugin.Event)
	groups map[groupKey]*groupState
	member map[uint32]*memberState
	seen   time.Time
	view   plugin.CorrelationView
	cancel context.CancelFunc
	done   chan struct{}
}

// New validates the config. It does not read the fabric view.
func New(c plugin.Config, _ plugin.Env) (plugin.FabricCorrelator, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if err := applyDefaults(&cfg); err != nil {
		return nil, err
	}
	return &Correlator{
		th:      thresholds{minMembers: cfg.MinMembers, pct: cfg.DegradedPct},
		rounds:  cfg.Rounds,
		bundles: cfg.Bundles,
		now:     time.Now,
		groups:  map[groupKey]*groupState{},
		member:  map[uint32]*memberState{},
		view: plugin.CorrelationView{
			Configured: true,
			Groups:     []plugin.CorrelationGroup{},
			Members:    []plugin.CorrelationMember{},
		},
	}, nil
}

func applyDefaults(cfg *Config) error {
	if cfg.MinMembers == 0 {
		cfg.MinMembers = DefaultMinMembers
	}
	if cfg.MinMembers < minMinMembers || cfg.MinMembers > maxMinMembers {
		return fmt.Errorf("min_members %d must be between %d and %d", cfg.MinMembers, minMinMembers, maxMinMembers)
	}
	if cfg.DegradedPct == 0 {
		cfg.DegradedPct = DefaultDegradedPct
	}
	if cfg.DegradedPct < 1 || cfg.DegradedPct > 100 {
		return fmt.Errorf("degraded_pct %d must be between 1 and 100", cfg.DegradedPct)
	}
	if cfg.Rounds == 0 {
		cfg.Rounds = DefaultRounds
	}
	if cfg.Rounds < 1 || cfg.Rounds > maxRounds {
		return fmt.Errorf("rounds %d must be between 1 and %d", cfg.Rounds, maxRounds)
	}
	return validateBundles(cfg.Bundles)
}

func validateBundles(bundles []Bundle) error {
	if len(bundles) > maxBundles {
		return fmt.Errorf("bundles: more than %d", maxBundles)
	}
	names := map[string]bool{}
	for i, b := range bundles {
		if !plugin.ValidLabel(b.Name) {
			return fmt.Errorf("bundles[%d].name is invalid", i)
		}
		if names[b.Name] {
			return fmt.Errorf("bundles[%d].name %q is duplicated", i, b.Name)
		}
		names[b.Name] = true
		if b.IXPID < 0 {
			return fmt.Errorf("bundles[%d].ixp_id is invalid", i)
		}
		if len(b.Switches) == 0 || len(b.Switches) > maxBundleSwitches {
			return fmt.Errorf("bundles[%d].switches needs 1 to %d switch ids", i, maxBundleSwitches)
		}
		for _, id := range b.Switches {
			if id < 1 {
				return fmt.Errorf("bundles[%d].switches has an invalid switch id %d", i, id)
			}
		}
	}
	return nil
}

// SetFabric records the fabric view to read. The controller calls it
// before Start.
func (c *Correlator) SetFabric(fn func() plugin.FabricView) {
	c.mu.Lock()
	c.fabric = fn
	c.mu.Unlock()
}

// SetEventSink records where events go. The controller calls it before
// Start.
func (c *Correlator) SetEventSink(fn func(plugin.Event)) {
	c.mu.Lock()
	c.sink = fn
	c.mu.Unlock()
}

// View returns the latest evaluated round.
func (c *Correlator) View() plugin.CorrelationView {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.view
}

// Start begins the loop. It does not block.
func (c *Correlator) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	c.mu.Lock()
	c.cancel, c.done = cancel, done
	c.mu.Unlock()
	go c.loop(ctx, done)
	return nil
}

// Stop cancels the loop and waits for it to leave.
func (c *Correlator) Stop(ctx context.Context) error {
	c.mu.Lock()
	cancel, done := c.cancel, c.done
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Correlator) loop(ctx context.Context, done chan struct{}) {
	defer close(done)
	t := time.NewTicker(pollEvery)
	defer t.Stop()
	for {
		c.poll()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// poll evaluates the fabric view when it holds a round not seen before.
func (c *Correlator) poll() {
	c.mu.Lock()
	fn := c.fabric
	c.mu.Unlock()
	if fn == nil {
		return
	}
	c.evaluate(fn())
}

// evaluate applies one fabric round. A stale round has no samples, so
// every open incident counts toward its resolving event.
func (c *Correlator) evaluate(fv plugin.FabricView) {
	if fv.Round.IsZero() {
		return
	}
	c.mu.Lock()
	if fv.Round.Equal(c.seen) {
		c.mu.Unlock()
		return
	}
	c.seen = fv.Round
	samples := fv.Samples
	if fv.Stale {
		samples = nil
	}
	obs := observe(samples, c.bundles, c.th)
	now := c.now()
	events := c.stepGroups(obs, now)
	events = append(events, c.stepMembers(obs, now)...)
	c.view = c.buildView(fv, obs)
	sink := c.sink
	c.mu.Unlock()
	if sink == nil {
		return
	}
	for _, e := range events {
		sink(e)
	}
}

func (c *Correlator) stepGroups(obs observation, now time.Time) []plugin.Event {
	var events []plugin.Event
	seen := map[groupKey]bool{}
	for _, g := range obs.groups {
		seen[g.key] = true
		st := c.groups[g.key]
		if st == nil {
			st = &groupState{}
			c.groups[g.key] = st
		}
		st.last = g
		if st.step(obs.firing[g.key], c.rounds) {
			events = append(events, groupEvent(st.active, g, now))
		}
	}
	for k, st := range c.groups {
		if !seen[k] && st.step(false, c.rounds) {
			events = append(events, groupEvent(false, st.last, now))
		}
	}
	for k, st := range c.groups {
		if st.idle() {
			delete(c.groups, k)
		}
	}
	return events
}

func (c *Correlator) stepMembers(obs observation, now time.Time) []plugin.Event {
	var events []plugin.Event
	seen := map[uint32]bool{}
	for _, m := range obs.alone {
		seen[m.asn] = true
		st := c.member[m.asn]
		if st == nil {
			st = &memberState{}
			c.member[m.asn] = st
		}
		st.last = m
		if st.step(true, c.rounds) {
			events = append(events, memberEvent(true, m, now))
		}
	}
	for asn, st := range c.member {
		if !seen[asn] && st.step(false, c.rounds) {
			events = append(events, memberEvent(false, st.last, now))
		}
		if st.idle() {
			delete(c.member, asn)
		}
	}
	return events
}

// buildView lists the groups and members of this round, plus those whose
// event is still open but that were not seen this round, so an open
// event is always visible in the view.
func (c *Correlator) buildView(fv plugin.FabricView, obs observation) plugin.CorrelationView {
	groups := slices.Clone(obs.groups)
	inRound := map[groupKey]bool{}
	for _, g := range obs.groups {
		inRound[g.key] = true
	}
	for k, st := range c.groups {
		if st.active && !inRound[k] {
			groups = append(groups, group{key: k, name: st.last.name})
		}
	}
	slices.SortFunc(groups, func(a, b group) int {
		switch {
		case lessKey(a.key, b.key):
			return -1
		case lessKey(b.key, a.key):
			return 1
		}
		return 0
	})
	members := slices.Clone(obs.alone)
	alone := map[uint32]bool{}
	for _, m := range obs.alone {
		alone[m.asn] = true
	}
	for asn, st := range c.member {
		if st.active && !alone[asn] {
			members = append(members, member{asn: asn, name: st.last.name})
		}
	}
	slices.SortFunc(members, func(a, b member) int { return cmp.Compare(a.asn, b.asn) })

	v := plugin.CorrelationView{
		Configured: true,
		Stale:      fv.Stale,
		Round:      fv.Round,
		Groups:     make([]plugin.CorrelationGroup, 0, len(groups)),
		Members:    make([]plugin.CorrelationMember, 0, len(members)),
	}
	for _, g := range groups {
		asns := g.degraded
		if asns == nil {
			asns = []uint32{}
		}
		active := false
		if st := c.groups[g.key]; st != nil {
			active = st.active
		}
		v.Groups = append(v.Groups, plugin.CorrelationGroup{
			Scope: g.key.scope, IXPID: g.key.ixp, Name: g.name,
			Members: g.members, Degraded: len(g.degraded),
			DegradedPct: float64(len(g.degraded)) * 100 / float64(max(g.members, 1)),
			Active:      active, ASNs: asns,
		})
	}
	for _, m := range members {
		active := false
		if st := c.member[m.asn]; st != nil {
			active = st.active
		}
		v.Members = append(v.Members, plugin.CorrelationMember{ASN: m.asn, Name: m.name, Addresses: m.addresses, Active: active})
	}
	return v
}

func groupEvent(degraded bool, g group, now time.Time) plugin.Event {
	fields := map[string]string{
		"scope": g.key.scope, "ixp_id": strconv.Itoa(g.key.ixp), "group": g.key.id, "name": g.name,
	}
	label := g.key.scope + " " + g.name
	if !degraded {
		return plugin.NewEvent(plugin.EventFabricRecovered, now, label+" is no longer degraded", fields)
	}
	fields["members"] = strconv.Itoa(g.members)
	fields["degraded"] = strconv.Itoa(len(g.degraded))
	fields["asns"] = asnList(g.degraded)
	return plugin.NewEvent(plugin.EventFabricDegraded, now,
		fmt.Sprintf("%s: %d of %d members degraded", label, len(g.degraded), g.members), fields)
}

func memberEvent(degraded bool, m member, now time.Time) plugin.Event {
	asn := strconv.FormatUint(uint64(m.asn), 10)
	fields := map[string]string{"asn": asn}
	if m.name != "" {
		fields["name"] = m.name
	}
	if degraded {
		fields["addresses"] = strconv.Itoa(m.addresses)
		return plugin.NewEvent(plugin.EventMemberDegraded, now,
			fmt.Sprintf("AS%s is degraded on all %d measured addresses and no switch, colo, or bundle behind it is degraded", asn, m.addresses), fields)
	}
	return plugin.NewEvent(plugin.EventMemberRecovered, now, "AS"+asn+" is no longer degraded on its own", fields)
}

func asnList(asns []uint32) string {
	n := min(len(asns), maxASNsInEvent)
	parts := make([]string, 0, n+1)
	for _, a := range asns[:n] {
		parts = append(parts, strconv.FormatUint(uint64(a), 10))
	}
	if len(asns) > n {
		parts = append(parts, "...")
	}
	return strings.Join(parts, ",")
}
