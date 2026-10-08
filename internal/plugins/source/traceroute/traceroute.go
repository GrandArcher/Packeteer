// Package traceroute implements the "traceroute" target source.
//
// For each configured prefix it probes toward the host with increasing
// TTL. When that host answers, the probe target stays the host. When it
// does not, the source picks the highest-TTL hop that answered stably
// (the same address on at least min_replies probes, with no tie). A hop
// on an exchange peering LAN is not adopted (#145); the configured host
// is used when it is not itself on that LAN. A prefix or host inside a
// peering LAN is not traced and is not returned. The prefix on the target
// does not change: the discovered address is only where measurements are
// sent. Packeteer still announces only a prefix that is in the learned RIB.
//
// Discovery runs in the background. Targets returns the last cache
// immediately and never traces, so a slow hop cannot consume the probe
// round. One pass is capped by budget, which is below the default round
// deadline. The factory does no I/O.
package traceroute

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "traceroute"

// Defaults and bounds.
const (
	defaultMaxHops    = 16
	defaultProbes     = 3
	defaultTimeout    = 500 * time.Millisecond
	defaultPort       = 33434
	defaultInterval   = 5 * time.Minute
	defaultMinReplies = 2
	// defaultBudget is one discovery pass. It is under the default probe
	// round deadline (about 110s) so a trace cannot outlive a normal round
	// even if a caller waited for it. Targets does not wait.
	defaultBudget = 10 * time.Second
	maxBudget     = 30 * time.Second
	maxHopsLimit  = 64
	maxProbes     = 10
	maxTimeout    = 5 * time.Second
	minInterval   = time.Second
	maxInterval   = 24 * time.Hour
	// gapHops is how many silent TTLs after a stable hop end the trace.
	// A filtered hop in the middle does not hide a later responder, and
	// a dead destination does not walk max_hops on every discovery.
	gapHops = 3
)

func init() { plugin.Sources.Register(TypeName, New) }

// Config is the traceroute source's config block.
type Config struct {
	Targets    []targetSpec  `yaml:"targets"`
	MaxHops    int           `yaml:"max_hops"`
	Probes     int           `yaml:"probes"`
	MinReplies int           `yaml:"min_replies"`
	Timeout    time.Duration `yaml:"timeout"`
	Port       int           `yaml:"port"`
	Source     string        `yaml:"source"`
	Interval   time.Duration `yaml:"interval"`
	// Budget is the wall-clock cap for one discovery pass across every
	// target. Zero uses defaultBudget. Targets never blocks on it.
	Budget time.Duration `yaml:"budget"`
}

type targetSpec struct {
	Prefix string  `yaml:"prefix"`
	Host   string  `yaml:"host"`
	Weight float64 `yaml:"weight"`
}

// hopper sends one TTL-limited probe. reached means the reply is
// destination-unreachable or a payload from the destination.
type hopper interface {
	Probe(ctx context.Context, src, dst netip.Addr, ttl, port int, timeout time.Duration) (from netip.Addr, reached bool, err error)
}

// udpHopper is the built-in traceroute. The Linux implementation reads
// the socket error queue. Other systems compile a stub so a developer
// checkout still builds; the container image is Linux.
type udpHopper struct{}

// Source discovers probe hosts.
type Source struct {
	plugin.Base
	log        *slog.Logger
	targets    []plugin.Target
	maxHops    int
	probes     int
	minReplies int
	timeout    time.Duration
	port       int
	src        netip.Addr
	interval   time.Duration
	budget     time.Duration
	hop        hopper
	now        func() time.Time

	mu       sync.Mutex
	lans     []netip.Prefix
	cached   []plugin.Target
	cachedAt time.Time
	have     bool
	lastErr  error
	cancel   context.CancelFunc
	started  bool
	wg       sync.WaitGroup
}

// New is the plugin factory.
func New(c plugin.Config, env plugin.Env) (plugin.TargetSource, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if len(cfg.Targets) == 0 {
		return nil, fmt.Errorf("targets is required")
	}
	if cfg.MaxHops == 0 {
		cfg.MaxHops = defaultMaxHops
	}
	if cfg.MaxHops < 1 || cfg.MaxHops > maxHopsLimit {
		return nil, fmt.Errorf("max_hops %d must be between 1 and %d", cfg.MaxHops, maxHopsLimit)
	}
	if cfg.Probes == 0 {
		cfg.Probes = defaultProbes
	}
	if cfg.Probes < 1 || cfg.Probes > maxProbes {
		return nil, fmt.Errorf("probes %d must be between 1 and %d", cfg.Probes, maxProbes)
	}
	if cfg.MinReplies == 0 {
		cfg.MinReplies = defaultMinReplies
		if cfg.MinReplies > cfg.Probes {
			cfg.MinReplies = cfg.Probes
		}
	}
	if cfg.MinReplies < 1 || cfg.MinReplies > cfg.Probes {
		return nil, fmt.Errorf("min_replies %d must be between 1 and probes (%d)", cfg.MinReplies, cfg.Probes)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	} else if cfg.Timeout < time.Nanosecond || cfg.Timeout > maxTimeout {
		return nil, fmt.Errorf("timeout %s must be between 1ns and %s", cfg.Timeout, maxTimeout)
	}
	if cfg.Port == 0 {
		cfg.Port = defaultPort
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, fmt.Errorf("port %d must be between 1 and 65535", cfg.Port)
	}
	if cfg.Interval == 0 {
		cfg.Interval = defaultInterval
	}
	if cfg.Interval < minInterval || cfg.Interval > maxInterval {
		return nil, fmt.Errorf("interval %s must be between %s and %s", cfg.Interval, minInterval, maxInterval)
	}
	if cfg.Budget == 0 {
		cfg.Budget = defaultBudget
	}
	if cfg.Budget < cfg.Timeout || cfg.Budget > maxBudget {
		return nil, fmt.Errorf("budget %s must be between the per-probe timeout (%s) and %s", cfg.Budget, cfg.Timeout, maxBudget)
	}
	var src netip.Addr
	if cfg.Source != "" {
		a, err := netip.ParseAddr(cfg.Source)
		if err != nil {
			return nil, fmt.Errorf("source %q is not a valid IP address", cfg.Source)
		}
		src = a
	}
	seen := map[netip.Prefix]bool{}
	var targets []plugin.Target
	for i, t := range cfg.Targets {
		p, err := netip.ParsePrefix(t.Prefix)
		if err != nil {
			return nil, fmt.Errorf("targets[%d]: prefix %q is not a valid CIDR", i, t.Prefix)
		}
		if p != p.Masked() {
			return nil, fmt.Errorf("targets[%d]: prefix %q has host bits set (did you mean %s?)", i, t.Prefix, p.Masked())
		}
		if seen[p] {
			return nil, fmt.Errorf("targets[%d]: duplicate prefix %s", i, p)
		}
		seen[p] = true
		if t.Weight < 0 {
			return nil, fmt.Errorf("targets[%d]: weight must not be negative", i)
		}
		tg := plugin.Target{Prefix: p, Weight: t.Weight}
		if t.Host != "" {
			h, err := netip.ParseAddr(t.Host)
			if err != nil || !p.Contains(h) {
				return nil, fmt.Errorf("targets[%d]: host %q must be an address inside %s", i, t.Host, p)
			}
			tg.Host = h
		} else {
			tg.Host = defaultHost(p)
		}
		if src.IsValid() && src.Is4() != tg.Host.Is4() {
			return nil, fmt.Errorf("targets[%d]: source %s and host %s differ in address family", i, src, tg.Host)
		}
		targets = append(targets, tg)
	}
	if env.Logger == nil {
		env.Logger = slog.Default()
	}
	return &Source{
		log:        env.Logger,
		targets:    targets,
		maxHops:    cfg.MaxHops,
		probes:     cfg.Probes,
		minReplies: cfg.MinReplies,
		timeout:    cfg.Timeout,
		port:       cfg.Port,
		src:        src,
		interval:   cfg.Interval,
		budget:     cfg.Budget,
		now:        time.Now,
	}, nil
}

func defaultHost(p netip.Prefix) netip.Addr {
	p = p.Masked()
	a := p.Addr()
	if p.Bits() == a.BitLen() {
		return a
	}
	next := a.Next()
	if next.IsValid() && p.Contains(next) {
		return next
	}
	return a
}

// Start begins background discovery. Targets never waits for it.
func (s *Source) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil
	}
	s.started = true
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		s.loop(runCtx)
	}()
	return nil
}

// Stop cancels discovery and waits for the current pass to return.
func (s *Source) Stop(ctx context.Context) error {
	s.mu.Lock()
	cancel := s.cancel
	s.cancel = nil
	started := s.started
	s.started = false
	s.mu.Unlock()
	if !started || cancel == nil {
		return nil
	}
	cancel()
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SetExchangeLANs installs the peering LANs (#145). Discovery does not
// adopt a hop on one, and a prefix or configured host inside one is not
// traced. The controller calls this before Start.
func (s *Source) SetExchangeLANs(lans []netip.Prefix) {
	cp := append([]netip.Prefix(nil), lans...)
	s.mu.Lock()
	s.lans = cp
	s.mu.Unlock()
}

func (s *Source) lanSkip(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	s.mu.Lock()
	lans := s.lans
	s.mu.Unlock()
	return exchange.ContainsAddr(lans, a)
}

// Targets implements plugin.TargetSource. It returns the last discovery
// immediately. A pass that has not finished yet contributes nothing, so
// the probe round is not spent tracing. A bind failure with no cache
// fails the call so the engine logs it and keeps the other sources.
// A cached prefix or pinned host inside a peering LAN is omitted.
func (s *Source) Targets(context.Context) ([]plugin.Target, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.have && errors.Is(s.lastErr, plugin.ErrSourceUnavailable) {
		return nil, s.lastErr
	}
	return exchange.FilterTargets(s.lans, cloneTargets(s.cached)), nil
}

func (s *Source) loop(ctx context.Context) {
	if s.needsRefresh() {
		s.discover(ctx)
	}
	timer := time.NewTimer(s.interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if ctx.Err() != nil {
				return
			}
			s.discover(ctx)
			timer.Reset(s.interval)
		}
	}
}

func (s *Source) needsRefresh() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.have || s.lastErr != nil {
		return true
	}
	return s.now().Sub(s.cachedAt) >= s.interval
}

// discover traces every configured prefix under one budget. Each target
// gets an equal share so one silent hop cannot consume the rest. A pass
// that finishes no target leaves the previous cache in place.
func (s *Source) discover(ctx context.Context) {
	if len(s.targets) == 0 || ctx.Err() != nil {
		return
	}
	bctx, cancel := context.WithTimeout(ctx, s.budget)
	defer cancel()
	hop := s.hop
	if hop == nil {
		hop = udpHopper{}
	}
	share := s.budget / time.Duration(len(s.targets))
	if share < s.timeout {
		share = s.timeout
	}
	s.mu.Lock()
	lans := append([]netip.Prefix(nil), s.lans...)
	s.mu.Unlock()
	var found []plugin.Target
	var done []netip.Prefix
	dropped := 0
	for _, t := range s.targets {
		if bctx.Err() != nil || ctx.Err() != nil {
			break
		}
		if exchange.PrefixInside(lans, t.Prefix) || (t.Host.IsValid() && exchange.ContainsAddr(lans, t.Host)) {
			done = append(done, t.Prefix)
			dropped++
			s.log.Info("traceroute target inside an exchange LAN", "prefix", t.Prefix, "host", t.Host)
			continue
		}
		tctx, tcancel := context.WithTimeout(bctx, share)
		host, ok, err := s.trace(tctx, hop, t.Host)
		tcancel()
		if err != nil {
			if errors.Is(err, plugin.ErrSourceUnavailable) {
				exchange.NoteDrops(dropped)
				s.noteUnavailable(err)
				return
			}
			break
		}
		done = append(done, t.Prefix)
		if !ok {
			s.log.Info("traceroute found no stable hop", "prefix", t.Prefix, "dest", t.Host)
			continue
		}
		tg := t
		tg.Host = host
		found = append(found, tg)
	}
	exchange.NoteDrops(dropped)
	if len(done) == 0 {
		return
	}
	s.merge(done, found)
}

func (s *Source) noteUnavailable(err error) {
	s.mu.Lock()
	s.lastErr = err
	s.mu.Unlock()
	s.log.Error("traceroute source unavailable", "err", err)
}

// merge keeps a previous host for any prefix this pass did not finish.
func (s *Source) merge(done []netip.Prefix, found []plugin.Target) {
	finished := map[netip.Prefix]bool{}
	for _, p := range done {
		finished[p] = true
	}
	foundBy := map[netip.Prefix]plugin.Target{}
	for _, t := range found {
		foundBy[t.Prefix] = t
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := map[netip.Prefix]plugin.Target{}
	for _, t := range s.cached {
		prev[t.Prefix] = t
	}
	var out []plugin.Target
	for _, t := range s.targets {
		if finished[t.Prefix] {
			if tg, ok := foundBy[t.Prefix]; ok {
				out = append(out, tg)
			}
			continue
		}
		if tg, ok := prev[t.Prefix]; ok {
			out = append(out, tg)
		}
	}
	s.cached = out
	s.cachedAt = s.now()
	s.have = true
	s.lastErr = nil
}

func cloneTargets(in []plugin.Target) []plugin.Target {
	out := make([]plugin.Target, len(in))
	copy(out, in)
	return out
}

// trace walks TTL until the destination answers, a gap follows a stable
// hop, or max_hops is reached.
func (s *Source) trace(ctx context.Context, hop hopper, dest netip.Addr) (netip.Addr, bool, error) {
	t := Tracer{MaxHops: s.maxHops, Probes: s.probes, MinReplies: s.minReplies, Port: s.port,
		Timeout: s.timeout, Hop: hop.Probe, Skip: s.lanSkip}
	return t.Trace(ctx, s.src, dest, nil)
}

// HopFunc sends one TTL-limited probe. reached means the reply is
// destination-unreachable or a payload from the destination.
type HopFunc func(ctx context.Context, src, dst netip.Addr, ttl, port int, timeout time.Duration) (from netip.Addr, reached bool, err error)

// Tracer walks TTL from one source address toward a destination and picks
// the highest stable hop. The traceroute source and the probe engine's
// per-provider indirect probing (#123) share it. It announces nothing.
type Tracer struct {
	MaxHops    int
	Probes     int
	MinReplies int
	Port       int
	Timeout    time.Duration
	// Hop sends one probe. Nil uses the built-in Linux traceroute.
	Hop HopFunc
	// Skip, when non-nil, ignores a hop (an exchange peering LAN).
	Skip func(netip.Addr) bool
}

// Trace walks TTL until the destination answers, a gap follows a stable
// hop, or MaxHops is reached. wait, when non-nil, runs before every
// packet; the probe engine passes its global rate limit there. A wait
// error ends the trace like a deadline. ok is false when no hop was
// stable. A source that cannot be bound returns plugin.ErrSourceUnavailable.
func (t Tracer) Trace(ctx context.Context, src, dest netip.Addr, wait func(context.Context) error) (netip.Addr, bool, error) {
	hop := t.Hop
	if hop == nil {
		hop = udpHopper{}.Probe
	}
	var hops [][]sample
	silent := 0
	saw := false
	for ttl := 1; ttl <= t.MaxHops; ttl++ {
		if err := ctx.Err(); err != nil {
			return t.finish(hops, dest, err)
		}
		samples := make([]sample, 0, t.Probes)
		reached := false
		for n := 0; n < t.Probes; n++ {
			if err := ctx.Err(); err != nil {
				return t.finish(hops, dest, err)
			}
			if wait != nil {
				if err := wait(ctx); err != nil {
					return t.finish(hops, dest, err)
				}
			}
			from, hit, err := hop(ctx, src, dest, ttl, t.Port, t.Timeout)
			if err != nil {
				if errors.Is(err, plugin.ErrSourceUnavailable) {
					return netip.Addr{}, false, err
				}
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return t.finish(hops, dest, err)
				}
				samples = append(samples, sample{})
				continue
			}
			samples = append(samples, sample{from: from, reached: hit})
			if hit && from.IsValid() {
				reached = true
			}
		}
		hops = append(hops, samples)
		if _, n := stableHop(samples, t.MinReplies); n >= t.MinReplies {
			saw = true
			silent = 0
		} else {
			silent++
		}
		if reached || (saw && silent >= gapHops) {
			break
		}
	}
	host, ok := selectHost(hops, dest, t.MinReplies, t.Skip)
	return host, ok, nil
}

// finish keeps hops already collected when the budget expires. With
// nothing collected yet, the caller sees the context error and does not
// replace the cache.
func (t Tracer) finish(hops [][]sample, dest netip.Addr, err error) (netip.Addr, bool, error) {
	if len(hops) == 0 {
		return netip.Addr{}, false, err
	}
	host, ok := selectHost(hops, dest, t.MinReplies, t.Skip)
	return host, ok, nil
}

// Hop sends one TTL-limited UDP probe from src to dst with the built-in
// Linux traceroute. The troubleshooting API uses it for on-demand
// traces. It returns plugin.ErrSourceUnavailable when src cannot be bound.
func Hop(ctx context.Context, src, dst netip.Addr, ttl, port int, timeout time.Duration) (netip.Addr, bool, error) {
	return udpHopper{}.Probe(ctx, src, dst, ttl, port, timeout)
}
