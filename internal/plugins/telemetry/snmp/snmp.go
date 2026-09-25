// Package snmp is the telemetry plugin that polls interface counters and
// tracks 95th-percentile usage for a billing period.
//
// It does not announce routes and it does not change decisions. A failed
// poll records an error and leaves the samples already stored. Credentials
// come from the environment named in the config. They are not logged.
package snmp

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "snmp"

func init() { plugin.Telemetries.Register(TypeName, New) }

// Collector polls SNMP and keeps one billing window per provider.
type Collector struct {
	plugin.Base

	log      *slog.Logger
	interval time.Duration
	timeout  time.Duration
	retries  int
	hosts    []hostSpec
	order    []string // provider names, config order
	states   map[string]*provState
	dial     func(context.Context, hostSpec) (session, error)

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

type provState struct {
	spec      bindingSpec
	ifIndex   int
	speedMbps float64
	bits      int
	haveBase  bool
	baseIn    uint64
	baseOut   uint64
	baseAt    time.Time
	baseTicks uint32
	haveTicks bool
	win       window
	lastIn    float64 // Mbps
	lastOut   float64
	updated   time.Time
	polled    time.Time
	err       string
}

type observation struct {
	idx       int
	speedMbps float64
	bits      int
	in        uint64
	out       uint64
	ticks     uint32
	haveTicks bool
}

// New validates config and reads credentials. It does not open a socket.
func New(c plugin.Config, e plugin.Env) (plugin.Telemetry, error) {
	getenv := e.Getenv
	interval, timeout, retries, maxSamples, hosts, bindings, err := decode(c, getenv, e.Providers)
	if err != nil {
		return nil, err
	}
	log := e.Logger
	if log == nil {
		log = slog.Default()
	}
	col := &Collector{
		log:      log,
		interval: interval,
		timeout:  timeout,
		retries:  retries,
		hosts:    hosts,
		states:   make(map[string]*provState, len(bindings)),
	}
	for _, b := range bindings {
		col.order = append(col.order, b.name)
		col.states[b.name] = &provState{
			spec: b,
			win:  window{billingDay: b.billingDay, mode: b.mode, maxSamples: maxSamples},
		}
	}
	col.dial = func(ctx context.Context, h hostSpec) (session, error) {
		return dialSNMP(ctx, h, col.timeout, col.retries)
	}
	return col, nil
}

// ProviderNames lists the providers this collector polls.
func (c *Collector) ProviderNames() []string {
	out := make([]string, len(c.order))
	copy(out, c.order)
	return out
}

// Start polls once, then on each interval, until ctx is cancelled.
func (c *Collector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.cancel != nil {
		c.mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.done = make(chan struct{})
	c.mu.Unlock()
	c.log.Info("snmp telemetry started", "interval", c.interval, "providers", len(c.order))
	go c.loop(ctx)
	return nil
}

// Stop waits for the poll loop to leave. An in-flight request is cut
// short because cancelling ctx closes its socket.
func (c *Collector) Stop(ctx context.Context) error {
	c.mu.Lock()
	cancel, done := c.cancel, c.done
	c.cancel = nil
	c.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Collector) loop(ctx context.Context) {
	defer close(c.done)
	c.poll(ctx, time.Now())
	timer := time.NewTimer(c.interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			c.poll(ctx, time.Now())
			timer.Reset(c.interval)
		}
	}
}

// Snapshot returns the latest usage. The order follows the config.
func (c *Collector) Snapshot(context.Context) ([]plugin.Usage, error) {
	now := time.Now().UTC()
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]plugin.Usage, 0, len(c.order))
	for _, name := range c.order {
		st := c.states[name]
		sum, start, end := st.win.summary(now)
		row := plugin.Usage{
			Provider:    st.spec.name,
			Host:        st.spec.host,
			Interface:   st.spec.iface,
			IfIndex:     st.ifIndex,
			CommitMbps:  st.spec.commitMbps,
			BillingDay:  st.spec.billingDay,
			Mode:        st.spec.mode,
			PeriodStart: start,
			PeriodEnd:   end,
			Samples:     sum.Samples,
			InMbps:      st.lastIn,
			OutMbps:     st.lastOut,
			InMbps95:    sum.In95,
			OutMbps95:   sum.Out95,
			UsageMbps:   sum.Usage,
			Single:      sum.Single,
			Updated:     st.updated,
			Polled:      st.polled,
			Error:       st.err,
		}
		out = append(out, row)
	}
	return out, nil
}

func (c *Collector) poll(ctx context.Context, now time.Time) {
	if ctx.Err() != nil {
		return
	}
	now = now.UTC()
	for _, h := range c.hosts {
		if ctx.Err() != nil {
			return
		}
		c.pollHost(ctx, h, now)
	}
}

func (c *Collector) pollHost(ctx context.Context, h hostSpec, now time.Time) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	states := c.statesFor(h.name)
	sess, err := c.dial(ctx, h)
	if err != nil {
		c.markErr(states, now, redact(err, h.secrets()...))
		c.log.Warn("snmp poll", "host", h.name, "err", redact(err, h.secrets()...))
		return
	}
	defer sess.Close()

	var todo []resolvedRow
	for _, st := range states {
		idx, speed, bits := c.cached(st)
		if idx != 0 {
			todo = append(todo, resolvedRow{st: st, idx: idx, speed: speed, bits: bits})
			continue
		}
		idx, speed, bits, err = resolveIface(sess, st.spec.iface)
		if err != nil {
			msg := redact(err, h.secrets()...)
			c.markErr([]*provState{st}, now, msg)
			c.log.Warn("snmp interface", "provider", st.spec.name, "err", msg)
			continue
		}
		todo = append(todo, resolvedRow{st: st, idx: idx, speed: speed, bits: bits})
	}
	if len(todo) == 0 {
		return
	}
	oids := []string{oidSysUpTime}
	for _, r := range todo {
		inOID, outOID := counterOIDs(r.idx, r.bits)
		oids = append(oids, inOID, outOID)
	}
	pdus, err := getMapped(sess, oids)
	if err != nil {
		msg := redact(err, h.secrets()...)
		c.markErr(statesOfResolved(todo), now, msg)
		c.log.Warn("snmp poll", "host", h.name, "err", msg)
		return
	}
	ticks, haveTicks := uint32(0), false
	if p, ok := pdus[normOID(oidSysUpTime)]; ok && !missing(p) {
		if n, ok := pduUint(p.Value); ok && n <= 0xffffffff {
			ticks, haveTicks = uint32(n), true
		}
	}
	for _, r := range todo {
		inOID, outOID := counterOIDs(r.idx, r.bits)
		inPDU, inOK := pdus[normOID(inOID)]
		outPDU, outOK := pdus[normOID(outOID)]
		if !inOK || !outOK || missing(inPDU) || missing(outPDU) {
			// The cached ifIndex is no longer the interface we resolved.
			// Drop it so the next poll walks again instead of repeating
			// a counter that will never return.
			c.clearIndex(r.st)
			c.markErr([]*provState{r.st}, now, "interface counters are not available")
			continue
		}
		inVal, ok1 := pduUint(inPDU.Value)
		outVal, ok2 := pduUint(outPDU.Value)
		if !ok1 || !ok2 {
			c.markErr([]*provState{r.st}, now, "interface counters are not numeric")
			continue
		}
		c.observe(r.st, now, observation{
			idx: r.idx, speedMbps: r.speed, bits: r.bits,
			in: inVal, out: outVal, ticks: ticks, haveTicks: haveTicks,
		})
	}
}

func (c *Collector) observe(st *provState, now time.Time, ob observation) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st.polled = now
	st.ifIndex = ob.idx
	st.speedMbps = ob.speedMbps
	st.bits = ob.bits
	if !st.haveBase {
		st.err = ""
		st.setBase(ob, now)
		return
	}
	if ob.haveTicks && st.haveTicks && ob.ticks < st.baseTicks {
		// sysUpTime wraps about every 497 days. A decrease inside the
		// poll gap is a reload, not a wrap. The counters start over.
		st.err = "sysUpTime went backwards; counters reset"
		st.setBase(ob, now)
		return
	}
	dt := now.Sub(st.baseAt)
	if dt <= 0 || dt > 2*c.interval {
		st.err = "poll gap is too large; baseline reset"
		st.setBase(ob, now)
		return
	}
	inBps := rateBps(counterDelta(st.baseIn, ob.in, ob.bits), dt)
	outBps := rateBps(counterDelta(st.baseOut, ob.out, ob.bits), dt)
	if !saneRate(inBps, ob.speedMbps) || !saneRate(outBps, ob.speedMbps) {
		st.err = "counter delta is not a plausible rate; baseline reset"
		st.setBase(ob, now)
		return
	}
	st.win.add(now, inBps, outBps)
	st.lastIn = inBps / 1e6
	st.lastOut = outBps / 1e6
	st.updated = now
	st.err = ""
	st.setBase(ob, now)
	c.log.Debug("snmp sample", "provider", st.spec.name, "ifindex", ob.idx, "in_mbps", st.lastIn, "out_mbps", st.lastOut)
}

func (st *provState) setBase(ob observation, now time.Time) {
	st.haveBase = true
	st.baseIn = ob.in
	st.baseOut = ob.out
	st.baseAt = now
	st.baseTicks = ob.ticks
	st.haveTicks = ob.haveTicks
}

func (c *Collector) statesFor(host string) []*provState {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*provState
	for _, name := range c.order {
		st := c.states[name]
		if st.spec.host == host {
			out = append(out, st)
		}
	}
	return out
}

func (c *Collector) cached(st *provState) (idx int, speed float64, bits int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return st.ifIndex, st.speedMbps, st.bits
}

func (c *Collector) clearIndex(st *provState) {
	c.mu.Lock()
	st.ifIndex = 0
	st.haveBase = false
	c.mu.Unlock()
}

func (c *Collector) markErr(states []*provState, now time.Time, msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, st := range states {
		st.polled = now
		st.err = msg
	}
}

type resolvedRow struct {
	st    *provState
	idx   int
	speed float64
	bits  int
}

func statesOfResolved(rs []resolvedRow) []*provState {
	out := make([]*provState, len(rs))
	for i := range rs {
		out[i] = rs[i].st
	}
	return out
}

func redact(err error, secrets ...string) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	// Longer secrets first so a short one does not cut through a longer one.
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	for _, sec := range secrets {
		if sec == "" {
			continue
		}
		s = strings.ReplaceAll(s, sec, "[redacted]")
	}
	return s
}
