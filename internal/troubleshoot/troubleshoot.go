// Package troubleshoot holds Packeteer's operator tools: a looking glass
// over the learned RIB view, an on-demand probe of one address across every
// provider, a per-provider traceroute, and a whois/RDAP lookup.
//
// Every tool is read-only. Nothing here announces, withdraws, or feeds
// the decision engine: on-demand probe results are returned to the caller
// and never stored as probe results.
package troubleshoot

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
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
}

// HopFunc sends one TTL-limited probe. The traceroute source's Hop is the
// production implementation; tests pass a fake network.
type HopFunc func(ctx context.Context, src, dst netip.Addr, ttl, port int, timeout time.Duration) (netip.Addr, bool, error)

// Limiter admits one request. *rate.Limiter's Allow satisfies it.
type Limiter interface{ Allow() bool }

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
	Whois     plugin.Whois
	Limiter   Limiter
	Now       func() time.Time
}

// Tools is safe for concurrent use.
type Tools struct {
	opt Options

	mu  sync.RWMutex
	rib RIB
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
	return &Tools{opt: opt}
}

// SetRIB attaches the learned RIB view. Nil means no BGP is configured.
func (t *Tools) SetRIB(r RIB) {
	t.mu.Lock()
	t.rib = r
	t.mu.Unlock()
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
		Providers:    names,
	}
}

// Glass is a looking-glass answer for one prefix.
type Glass struct {
	Query         netip.Prefix `json:"query"`
	RIBReady      bool         `json:"rib_ready"`
	Exact         *rib.Route   `json:"exact,omitempty"`
	Covering      *rib.Route   `json:"covering,omitempty"`
	MoreSpecifics []rib.Route  `json:"more_specifics"`
	Truncated     bool         `json:"truncated,omitempty"`
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
	Target  netip.Addr     `json:"target"`
	Route   *rib.Route     `json:"route,omitempty"` // learned route covering Target
	Results []probe.Result `json:"results"`
}

// Probe measures target from every provider's source with the configured
// prober chain. Results go to the caller only; they never reach the probe
// engine, the decision loop, or the announcer.
func (t *Tools) Probe(ctx context.Context, target netip.Addr) (ProbeAnswer, error) {
	target = target.Unmap()
	if err := CheckTarget(target); err != nil {
		return ProbeAnswer{}, err
	}
	if err := t.admit(); err != nil {
		return ProbeAnswer{}, err
	}
	if len(t.opt.Probers) == 0 || len(t.opt.Providers) == 0 {
		return ProbeAnswer{}, errors.New("no probers or providers configured")
	}
	ans := ProbeAnswer{Target: target, Results: make([]probe.Result, len(t.opt.Providers))}
	if v := t.view(); v != nil {
		if r, ok := v.Covering(netip.PrefixFrom(target, target.BitLen())); ok {
			ans.Route = &r
		}
	}
	var wg sync.WaitGroup
	for i, p := range t.opt.Providers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ans.Results[i] = t.probeOne(ctx, p, target)
		}()
	}
	wg.Wait()
	return ans, nil
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

// TraceHop is one TTL of a trace.
type TraceHop struct {
	TTL     int        `json:"ttl"`
	Address netip.Addr `json:"address,omitzero"`
	RTTMs   float64    `json:"rtt_ms,omitempty"`
	Reached bool       `json:"reached,omitempty"`
	Error   string     `json:"error,omitempty"`
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
	return ans, nil
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
