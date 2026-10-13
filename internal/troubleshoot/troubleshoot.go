// Package troubleshoot holds Packeteer's operator tools: a looking glass
// over the learned RIB view, an on-demand probe of one address or hostname
// across every provider, a per-provider traceroute, and a whois/RDAP lookup.
//
// The tools never announce or withdraw, and on-demand probe results are
// returned to the caller and never stored as probe results. The one write is
// Optimize, which asks the probe engine to measure the learned prefix
// covering a target for a limited time. Any move still comes from the
// decision engine.
package troubleshoot

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Defaults and bounds.
const (
	DefaultRequestsPerMinute = 6
	MaxRequestsPerMinute     = 600
	DefaultMaxHops           = 30
	MaxHopsLimit             = 64
	DefaultHopTimeout        = time.Second
	maxMoreSpecifics         = 100
	tracePort                = 33434
	gapHops                  = 3
	reverseTimeout           = 3 * time.Second
	resolveTimeout           = 5 * time.Second
	maxHostnameLen           = 253
	maxLabelLen              = 63

	// OptimizeTTL is how long Optimize keeps a prefix in the probe set.
	OptimizeTTL = 10 * time.Minute
)

// ErrDisabled is returned by the active tools when they are not enabled.
var ErrDisabled = errors.New("troubleshooting tools are disabled (set troubleshoot.enabled: true)")

// ErrNoWhois is returned when no whois plugin is configured.
var ErrNoWhois = errors.New("no whois plugin configured (troubleshoot.whois)")

// ErrBusy is returned when the rate limit rejects a request.
var ErrBusy = errors.New("rate limited; try again shortly")

// RIB is the learned-route surface the looking glass reads. *rib.View
// implements it.
type RIB interface {
	Ready() bool
	Exact(p netip.Prefix) (rib.Route, bool)
	Covering(p netip.Prefix) (rib.Route, bool)
	Routes() []rib.Route
	// Paths lists every path held for exactly p (iBGP add-path and BMP
	// paths included), not only the published best.
	Paths(p netip.Prefix) []rib.Route
}

// Resolver looks up hostnames. *net.Resolver implements it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Queue asks the probe engine to measure a prefix for ttl. *probe.Engine
// implements it. A queued prefix is only measured; the decision engine
// decides whether any move follows.
type Queue interface {
	QueueManual(p netip.Prefix, ttl time.Duration) error
}

// HopFunc sends one TTL-limited probe. The traceroute source's Hop is the
// production implementation; tests pass a fake network.
type HopFunc func(ctx context.Context, src, dst netip.Addr, ttl, port int, timeout time.Duration) (netip.Addr, bool, error)

// Limiter admits one request. *rate.Limiter's Allow satisfies it.
type Limiter interface{ Allow() bool }

// PacketLimiter waits for the budget of n packets. *rate.Limiter's WaitN
// satisfies it.
type PacketLimiter interface {
	WaitN(ctx context.Context, n int) error
}

// Options configure Tools.
type Options struct {
	// Enabled turns on the active tools (probe, traceroute, whois). The
	// looking glass only reads the RIB and is always available.
	Enabled   bool
	Providers []probe.Provider
	Probers   []probe.NamedProber
	Packets   int
	Timeout   time.Duration
	MaxHops   int
	Hop       HopFunc
	// Reverse names a hop address (a PTR lookup). Empty means no name.
	Reverse func(ctx context.Context, a netip.Addr) string
	Whois   plugin.Whois
	Limiter Limiter
	// PacketLimiter paces every indirect trace packet. Nil sends unpaced.
	PacketLimiter PacketLimiter
	Now           func() time.Time
	// Resolver resolves hostnames. Nil uses net.DefaultResolver.
	Resolver Resolver
	// Scorer ranks providers for the best exit in a probe answer. Nil
	// leaves Best empty.
	Scorer plugin.Scorer
	// Indirect traces from a provider's source toward a target that
	// answered no probe there, and probes the highest stable hop instead
	// (#123). Nil disables the fallback.
	Indirect probe.Tracer
}

// Tools is safe for concurrent use.
type Tools struct {
	opt Options

	mu    sync.RWMutex
	rib   RIB
	queue Queue
}

// New returns Tools. The RIB is attached later with SetRIB because the
// HTTP server starts before the BGP view exists.
func New(opt Options) *Tools {
	if opt.Packets <= 0 {
		opt.Packets = 5
	}
	if opt.Timeout <= 0 {
		opt.Timeout = DefaultHopTimeout
	}
	if opt.MaxHops <= 0 {
		opt.MaxHops = DefaultMaxHops
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Resolver == nil {
		opt.Resolver = net.DefaultResolver
	}
	return &Tools{opt: opt}
}

// SetRIB attaches the learned RIB view. Nil means no BGP is configured.
func (t *Tools) SetRIB(r RIB) {
	t.mu.Lock()
	t.rib = r
	t.mu.Unlock()
}

// SetQueue attaches the probe engine's manual queue. Nil leaves Optimize
// unavailable.
func (t *Tools) SetQueue(q Queue) {
	t.mu.Lock()
	t.queue = q
	t.mu.Unlock()
}

func (t *Tools) manualQueue() Queue {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.queue
}

func (t *Tools) view() RIB {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.rib
}

// Status describes which tools are usable.
type Status struct {
	LookingGlass bool     `json:"looking_glass"`
	Enabled      bool     `json:"enabled"`
	Probe        bool     `json:"probe"`
	Traceroute   bool     `json:"traceroute"`
	Whois        bool     `json:"whois"`
	Optimize     bool     `json:"optimize"`
	Providers    []string `json:"providers"`
}

// Status reports tool availability.
func (t *Tools) Status() Status {
	names := make([]string, 0, len(t.opt.Providers))
	for _, p := range t.opt.Providers {
		names = append(names, p.Name)
	}
	return Status{
		LookingGlass: t.view() != nil,
		Enabled:      t.opt.Enabled,
		Probe:        t.opt.Enabled && len(t.opt.Probers) > 0 && len(t.opt.Providers) > 0,
		Traceroute:   t.opt.Enabled && t.opt.Hop != nil && len(t.opt.Providers) > 0,
		Whois:        t.opt.Enabled && t.opt.Whois != nil,
		Optimize:     t.opt.Enabled && t.manualQueue() != nil && t.view() != nil,
		Providers:    names,
	}
}

// Glass is a looking-glass answer for one prefix.
type Glass struct {
	Query    netip.Prefix `json:"query"`
	RIBReady bool         `json:"rib_ready"`
	Exact    *rib.Route   `json:"exact,omitempty"`
	// Paths are every learned path for exactly the query: with add-path
	// or BMP that includes the router's inactive and IX paths.
	Paths         []rib.Route `json:"paths,omitempty"`
	Covering      *rib.Route  `json:"covering,omitempty"`
	MoreSpecifics []rib.Route `json:"more_specifics"`
	Truncated     bool        `json:"truncated,omitempty"`
}

// ErrNoRIB is returned by the looking glass when BGP is not configured.
var ErrNoRIB = errors.New("no BGP RIB view configured")

// LookingGlass returns the learned best route for p, the longest covering
// route, and learned more-specifics inside p. It only reads.
func (t *Tools) LookingGlass(p netip.Prefix) (Glass, error) {
	v := t.view()
	if v == nil {
		return Glass{}, ErrNoRIB
	}
	p = p.Masked()
	g := Glass{Query: p, RIBReady: v.Ready(), MoreSpecifics: []rib.Route{}}
	if r, ok := v.Exact(p); ok {
		g.Exact = &r
	}
	g.Paths = v.Paths(p)
	if r, ok := v.Covering(p); ok {
		g.Covering = &r
	}
	for _, r := range v.Routes() {
		if r.Prefix.Bits() > p.Bits() && p.Contains(r.Prefix.Addr()) {
			if len(g.MoreSpecifics) == maxMoreSpecifics {
				g.Truncated = true
				break
			}
			g.MoreSpecifics = append(g.MoreSpecifics, r)
		}
	}
	return g, nil
}

// CheckTarget rejects addresses the active tools must never send to.
func CheckTarget(a netip.Addr) error {
	a = a.Unmap()
	switch {
	case !a.IsValid(), a.Zone() != "":
		return errors.New("target must be a plain IP address")
	case a.IsUnspecified(), a.IsLoopback(), a.IsMulticast(), a.IsLinkLocalUnicast(), a.IsInterfaceLocalMulticast():
		return fmt.Errorf("target %s is not a routable unicast address", a)
	case a.Is4() && a.As4()[0] == 255:
		return fmt.Errorf("target %s is not a routable unicast address", a)
	}
	return nil
}

func (t *Tools) admit() error {
	if !t.opt.Enabled {
		return ErrDisabled
	}
	if t.opt.Limiter != nil && !t.opt.Limiter.Allow() {
		return ErrBusy
	}
	return nil
}

// ProbeAnswer is one on-demand probe across every provider.
type ProbeAnswer struct {
	// Host is the hostname the caller gave, and Addresses is every routable
	// address it resolved to. Both are empty when the caller gave an IP.
	Host      string       `json:"host,omitempty"`
	Addresses []netip.Addr `json:"addresses,omitempty"`
	// Target is the address that was probed.
	Target netip.Addr `json:"target"`
	Route  *rib.Route `json:"route,omitempty"` // learned route covering Target
	// Current is the provider of Route: the exit the edge uses now. Best
	// is the provider with the lowest score from the configured scorer
	// among those that answered. Either is empty when unknown.
	Current string         `json:"current,omitempty"`
	Best    string         `json:"best,omitempty"`
	Results []probe.Result `json:"results"`
}

// Probe measures the target from every provider's source with the
// configured prober chain. input is an IP address or a hostname; a
// hostname is resolved and the first routable address is probed. A provider
// whose probes get no reply is traced and its highest stable hop probed
// when Options.Indirect is set. Results go to the caller only; they never
// reach the probe engine, the decision loop, or the announcer.
func (t *Tools) Probe(ctx context.Context, input string) (ProbeAnswer, error) {
	host, err := parseHostOrAddr(input)
	if err != nil {
		return ProbeAnswer{}, err
	}
	if err := t.admit(); err != nil {
		return ProbeAnswer{}, err
	}
	if len(t.opt.Probers) == 0 || len(t.opt.Providers) == 0 {
		return ProbeAnswer{}, errors.New("no probers or providers configured")
	}
	ans := ProbeAnswer{Host: host.name}
	if ans.Target, ans.Addresses, err = t.resolve(ctx, host); err != nil {
		return ProbeAnswer{}, err
	}
	target := ans.Target
	ans.Results = make([]probe.Result, len(t.opt.Providers))
	if v := t.view(); v != nil {
		if r, ok := v.Covering(netip.PrefixFrom(target, target.BitLen())); ok {
			ans.Route = &r
			ans.Current = r.Provider
		}
	}
	var wg sync.WaitGroup
	for i, p := range t.opt.Providers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ans.Results[i] = t.probeProvider(ctx, p, target)
		}()
	}
	wg.Wait()
	ans.Best = t.best(ans.Results)
	return ans, nil
}

// hostInput is a parsed Probe input: an address, or a hostname to resolve.
type hostInput struct {
	name string
	addr netip.Addr
}

// parseHostOrAddr accepts an IP address or a DNS name. A name needs a
// non-numeric last label so that forms such as 127.1 are never handed to
// the resolver as an address.
func parseHostOrAddr(input string) (hostInput, error) {
	input = strings.TrimSpace(input)
	if a, err := netip.ParseAddr(input); err == nil {
		a = a.Unmap()
		if err := CheckTarget(a); err != nil {
			return hostInput{}, err
		}
		return hostInput{addr: a}, nil
	}
	name := strings.TrimSuffix(input, ".")
	if err := checkHostname(name); err != nil {
		return hostInput{}, err
	}
	return hostInput{name: strings.ToLower(name)}, nil
}

func checkHostname(name string) error {
	if name == "" || len(name) > maxHostnameLen {
		return errors.New("target must be an IP address or a hostname")
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if l == "" || len(l) > maxLabelLen || l[0] == '-' || l[len(l)-1] == '-' {
			return errors.New("target must be an IP address or a hostname")
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return errors.New("target must be an IP address or a hostname")
			}
		}
	}
	if last := labels[len(labels)-1]; strings.Trim(last, "0123456789") == "" {
		return errors.New("target must be an IP address or a hostname")
	}
	return nil
}

// resolve returns the address to probe and, for a hostname, every routable
// address it resolved to. The first address whose family a provider source
// can use wins, else the first routable one.
func (t *Tools) resolve(ctx context.Context, h hostInput) (target netip.Addr, addrs []netip.Addr, err error) {
	if h.addr.IsValid() {
		return h.addr, nil, nil
	}
	rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	found, err := t.opt.Resolver.LookupNetIP(rctx, "ip", h.name)
	if err != nil {
		return netip.Addr{}, nil, fmt.Errorf("cannot resolve %s: %w", h.name, err)
	}
	for _, a := range found {
		if a = a.Unmap(); CheckTarget(a) == nil && !slices.Contains(addrs, a) {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		return netip.Addr{}, nil, fmt.Errorf("%s resolves to no routable address", h.name)
	}
	for _, a := range addrs {
		for _, p := range t.opt.Providers {
			if p.Source.Is4() == a.Is4() {
				return a, addrs, nil
			}
		}
	}
	return addrs[0], addrs, nil
}

// best is the answering provider with the lowest score. Equal scores keep
// the earlier provider.
func (t *Tools) best(rs []probe.Result) string {
	if t.opt.Scorer == nil {
		return ""
	}
	best, bestScore := "", 0.0
	for _, r := range rs {
		if !r.OK() || r.Stats.Received == 0 {
			continue
		}
		sc := t.opt.Scorer.Score(plugin.PathStats{Provider: r.Provider, LossPct: r.Stats.LossPct, RTTAvg: r.Stats.RTTAvg, Jitter: r.Stats.Jitter})
		if best == "" || sc < bestScore {
			best, bestScore = r.Provider, sc
		}
	}
	return best
}

// probeProvider probes target from one provider and, when nothing there
// answered, falls back to the highest stable traceroute hop. The hop is
// reported as the target with Indirect set, as the probe engine does.
func (t *Tools) probeProvider(ctx context.Context, p probe.Provider, target netip.Addr) probe.Result {
	res := t.probeOne(ctx, p, target)
	if t.opt.Indirect == nil || (res.OK() && res.Stats.Received > 0) || p.Source.Is4() != target.Is4() {
		return res
	}
	hop, ok, err := t.opt.Indirect.Trace(ctx, p.Source, target, t.waitPacket)
	if err != nil || !ok {
		return res
	}
	via := t.probeOne(ctx, p, hop)
	if !via.OK() || via.Stats.Received == 0 {
		return res
	}
	via.Prefix, via.Indirect = res.Prefix, true
	return via
}

// waitPacket takes one packet from the packet budget. One request can
// otherwise send max_hops × probes trace packets per silent provider on
// one request token.
func (t *Tools) waitPacket(ctx context.Context) error {
	if t.opt.PacketLimiter == nil {
		return nil
	}
	return t.opt.PacketLimiter.WaitN(ctx, 1)
}

func (t *Tools) probeOne(ctx context.Context, p probe.Provider, target netip.Addr) probe.Result {
	res := probe.Result{Provider: p.Name, Prefix: netip.PrefixFrom(target, target.BitLen()), Target: target}
	req := plugin.ProbeRequest{Provider: p.Name, Source: p.Source, Target: target, Count: t.opt.Packets, Timeout: t.opt.Timeout}
	var errs []error
	for _, pr := range t.opt.Probers {
		pctx, cancel := context.WithTimeout(ctx, time.Duration(t.opt.Packets)*t.opt.Timeout+time.Second)
		raw, err := pr.Prober.Probe(pctx, req)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", pr.Name, err))
			if errors.Is(err, plugin.ErrSourceUnavailable) {
				break
			}
			continue
		}
		res.Prober, res.Stats, res.Time = pr.Name, probe.Compute(raw), t.opt.Now()
		if res.Stats.Received > 0 {
			return res
		}
	}
	if res.Prober != "" {
		return res
	}
	res.Err, res.Time = errors.Join(errs...).Error(), t.opt.Now()
	return res
}

// ErrNoOptimize is returned by Optimize when the probe queue is not wired.
var ErrNoOptimize = errors.New("probe and optimize is not available")

// OptimizeAnswer names the prefix Optimize queued.
type OptimizeAnswer struct {
	Host      string       `json:"host,omitempty"`
	Addresses []netip.Addr `json:"addresses,omitempty"`
	Target    netip.Addr   `json:"target"`
	// Prefix is the learned route covering Target: the exact prefix the
	// decision engine would act on.
	Prefix  netip.Prefix `json:"prefix"`
	Expires time.Time    `json:"expires"`
}

// Optimize queues the learned prefix covering the target as an urgent
// probe target for OptimizeTTL. Only prefixes in the learned RIB view are
// queued, never the default route, and queuing only measures: the next
// decision round applies the usual rules (exact learned prefix, allowlist
// in inject mode, max_improvements, thresholds, hold time) to the result.
func (t *Tools) Optimize(ctx context.Context, input string) (OptimizeAnswer, error) {
	host, err := parseHostOrAddr(input)
	if err != nil {
		return OptimizeAnswer{}, err
	}
	// Setup checks come before admit so a refused request spends no token.
	if !t.opt.Enabled {
		return OptimizeAnswer{}, ErrDisabled
	}
	q := t.manualQueue()
	if q == nil {
		return OptimizeAnswer{}, ErrNoOptimize
	}
	v := t.view()
	if v == nil {
		return OptimizeAnswer{}, ErrNoRIB
	}
	if !v.Ready() {
		return OptimizeAnswer{}, errors.New("the learned RIB view is not ready")
	}
	if err := t.admit(); err != nil {
		return OptimizeAnswer{}, err
	}
	ans := OptimizeAnswer{Host: host.name}
	if ans.Target, ans.Addresses, err = t.resolve(ctx, host); err != nil {
		return OptimizeAnswer{}, err
	}
	r, ok := v.Covering(netip.PrefixFrom(ans.Target, ans.Target.BitLen()))
	if !ok || r.Prefix.Bits() == 0 {
		return OptimizeAnswer{}, fmt.Errorf("no learned prefix covers %s", ans.Target)
	}
	ans.Prefix = r.Prefix
	if err := q.QueueManual(r.Prefix, OptimizeTTL); err != nil {
		return OptimizeAnswer{}, err
	}
	ans.Expires = t.opt.Now().Add(OptimizeTTL)
	return ans, nil
}

// TraceHop is one TTL of a trace.
type TraceHop struct {
	TTL     int        `json:"ttl"`
	Address netip.Addr `json:"address,omitzero"`
	RTTMs   float64    `json:"rtt_ms,omitempty"`
	Reached bool       `json:"reached,omitempty"`
	Error   string     `json:"error,omitempty"`
	// Name is the reverse name of Address when Options.Reverse knows one.
	Name string `json:"name,omitempty"`
	// OriginAS is the last ASN on the longest learned route covering
	// Address. It comes from the learned RIB only; 0 means none.
	OriginAS uint32 `json:"origin_as,omitempty"`
}

// Trace is one provider's traceroute.
type Trace struct {
	Provider string     `json:"provider"`
	Source   netip.Addr `json:"source"`
	Hops     []TraceHop `json:"hops"`
	Reached  bool       `json:"reached"`
	Error    string     `json:"error,omitempty"`
}

// TraceAnswer is a traceroute from each selected provider.
type TraceAnswer struct {
	Target netip.Addr `json:"target"`
	Traces []Trace    `json:"traces"`
}

// Traceroute traces target from each provider's source address, or only
// from provider when it is not empty. One probe per TTL.
func (t *Tools) Traceroute(ctx context.Context, target netip.Addr, provider string) (TraceAnswer, error) {
	target = target.Unmap()
	if err := CheckTarget(target); err != nil {
		return TraceAnswer{}, err
	}
	var provs []probe.Provider
	for _, p := range t.opt.Providers {
		if provider == "" || p.Name == provider {
			provs = append(provs, p)
		}
	}
	if len(provs) == 0 {
		return TraceAnswer{}, fmt.Errorf("unknown provider %q", provider)
	}
	if err := t.admit(); err != nil {
		return TraceAnswer{}, err
	}
	if t.opt.Hop == nil {
		return TraceAnswer{}, errors.New("traceroute is not available")
	}
	ans := TraceAnswer{Target: target, Traces: make([]Trace, len(provs))}
	var wg sync.WaitGroup
	for i, p := range provs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ans.Traces[i] = t.traceOne(ctx, p, target)
		}()
	}
	wg.Wait()
	t.annotate(ctx, ans.Traces)
	return ans, nil
}

// annotate fills each hop's origin AS from the learned RIB and, with
// Options.Reverse, its reverse name. Lookups run together and share one
// deadline so a slow resolver cannot stretch the answer.
func (t *Tools) annotate(ctx context.Context, traces []Trace) {
	v := t.view()
	var wg sync.WaitGroup
	rctx, cancel := context.WithTimeout(ctx, reverseTimeout)
	defer cancel()
	for i := range traces {
		for j := range traces[i].Hops {
			h := &traces[i].Hops[j]
			if !h.Address.IsValid() {
				continue
			}
			if v != nil {
				h.OriginAS = originAS(v, h.Address)
			}
			if t.opt.Reverse != nil {
				wg.Add(1)
				go func() {
					defer wg.Done()
					h.Name = t.opt.Reverse(rctx, h.Address)
				}()
			}
		}
	}
	wg.Wait()
}

// originAS is the last non-zero ASN of the longest learned route covering
// a. A default route is not a match.
func originAS(v RIB, a netip.Addr) uint32 {
	r, ok := v.Covering(netip.PrefixFrom(a, a.BitLen()))
	if !ok || r.Prefix.Bits() == 0 {
		return 0
	}
	for i := len(r.ASPath) - 1; i >= 0; i-- {
		if r.ASPath[i] != 0 {
			return r.ASPath[i]
		}
	}
	return 0
}

func (t *Tools) traceOne(ctx context.Context, p probe.Provider, target netip.Addr) Trace {
	tr := Trace{Provider: p.Name, Source: p.Source, Hops: []TraceHop{}}
	if p.Source.Is4() != target.Is4() {
		tr.Error = "source and target address families differ"
		return tr
	}
	silent := 0
	for ttl := 1; ttl <= t.opt.MaxHops; ttl++ {
		if err := ctx.Err(); err != nil {
			tr.Error = err.Error()
			return tr
		}
		start := time.Now()
		from, reached, err := t.opt.Hop(ctx, p.Source, target, ttl, tracePort+ttl-1, t.opt.Timeout)
		h := TraceHop{TTL: ttl}
		if err != nil {
			if errors.Is(err, plugin.ErrSourceUnavailable) {
				tr.Error = err.Error()
				return tr
			}
			h.Error = err.Error()
		} else if from.IsValid() {
			h.Address = from
			h.RTTMs = float64(time.Since(start).Microseconds()) / 1000
			h.Reached = reached
		}
		tr.Hops = append(tr.Hops, h)
		if h.Reached {
			tr.Reached = true
			break
		}
		if h.Address.IsValid() {
			silent = 0
		} else if silent++; silent >= 2*gapHops {
			break // a long run of silence: the rest is filtered
		}
	}
	return tr
}

// Whois looks q up with the configured whois plugin.
func (t *Tools) Whois(ctx context.Context, q string) (plugin.WhoisResult, error) {
	if !t.opt.Enabled {
		return plugin.WhoisResult{}, ErrDisabled
	}
	if t.opt.Whois == nil {
		return plugin.WhoisResult{}, ErrNoWhois
	}
	if err := CheckWhoisQuery(q); err != nil {
		return plugin.WhoisResult{}, err
	}
	if err := t.admit(); err != nil {
		return plugin.WhoisResult{}, err
	}
	return t.opt.Whois.Lookup(ctx, q)
}

// CheckWhoisQuery accepts an IP address, a prefix, or an ASN (with or
// without the AS prefix) and nothing else, so a plugin never sees a
// hostname, URL, or path.
func CheckWhoisQuery(q string) error {
	if s, ok := strings.CutPrefix(strings.ToUpper(q), "AS"); ok || q != "" {
		if _, err := strconv.ParseUint(s, 10, 32); err == nil {
			return nil
		}
	}
	if _, err := netip.ParsePrefix(q); err == nil {
		return nil
	}
	if a, err := netip.ParseAddr(q); err == nil && a.Zone() == "" {
		return nil
	}
	return fmt.Errorf("query %q is not an IP address, prefix, or ASN", q)
}
