package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/all"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/flow"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/outage"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/vip"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// prefixLookup is implemented by target sources that map a destination
// onto the learned RIB (the flow source). A default route is not a target,
// and a view that is not ready must not contribute prefixes.
type prefixLookup interface {
	SetPrefixLookup(func(netip.Addr) (netip.Prefix, bool))
}

// learnedView is the RIB surface VIP expansion reads. *rib.View implements it.
type learnedView interface {
	Ready() bool
	Generation() uint64
	Routes() []rib.Route
}

// routeSnapshotter is implemented by *rib.View. Outage correlation reads
// the other providers' AS paths from the same generation as the selected
// routes (#124).
type routeSnapshotter interface {
	RouteSnapshot() (routes []rib.Route, paths []rib.AltPath)
}

// routeSnapshotSetter is implemented by the vip source.
type routeSnapshotSetter interface {
	SetRouteSnapshot(func() (uint64, []vip.LearnedRoute))
}

// learnedSnap caches the copied RIB for one generation. A VIP interval as
// short as a second must not copy every AS path on every wake.
type learnedSnap struct {
	mu  sync.Mutex
	gen uint64
	ok  bool
	out []vip.LearnedRoute
}

func (s *learnedSnap) get(view learnedView) (uint64, []vip.LearnedRoute) {
	if view == nil || !view.Ready() {
		return 0, nil
	}
	g := view.Generation()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ok && s.gen == g {
		return g, s.out
	}
	routes := view.Routes()
	out := make([]vip.LearnedRoute, 0, len(routes))
	for _, rt := range routes {
		if !rt.Prefix.IsValid() || rt.Prefix.Bits() == 0 {
			continue
		}
		out = append(out, vip.LearnedRoute{Prefix: rt.Prefix, ASPath: append([]uint32(nil), rt.ASPath...)})
	}
	s.gen, s.ok, s.out = g, true, out
	return g, out
}

// wireLearnedRoutes gives the vip source the current RIB. The callback
// returns nothing while the view is missing or not ready, and it drops
// default routes, so an ASN list cannot invent targets from stale state.
// The copy is rebuilt only when the view's generation changes.
func wireLearnedRoutes(plugins *pluginhost.Set, view *rib.View) {
	if plugins == nil {
		return
	}
	var snap learnedSnap
	fn := func() (uint64, []vip.LearnedRoute) { return snap.get(view) }
	for _, src := range plugins.SourcesSnapshot() {
		if s, ok := src.Plugin.(routeSnapshotSetter); ok {
			s.SetRouteSnapshot(fn)
		}
	}
}

// noteOutages correlates the round that just finished. A new incident
// wakes the probe loop so the re-queued prefixes are measured without
// waiting out probe.interval. Observe and inject both call this; the
// source only adds probe targets.
func noteOutages(plugins *pluginhost.Set, engine *probe.Engine) {
	if plugins == nil || engine == nil {
		return
	}
	now := time.Now()
	for _, src := range plugins.SourcesSnapshot() {
		s, ok := src.Plugin.(*outage.Source)
		if !ok {
			continue
		}
		if s.Evaluate(now) {
			engine.Wake()
		}
	}
}

// outageSnap caches the copied RIB for one generation. Evaluate runs once
// per completed round and must not copy every AS path when nothing changed.
type outageSnap struct {
	mu  sync.Mutex
	gen uint64
	ok  bool
	out []outage.Route
}

func (s *outageSnap) get(view learnedView) []outage.Route {
	if view == nil || !view.Ready() {
		return nil
	}
	g := view.Generation()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ok && s.gen == g {
		return s.out
	}
	var routes []rib.Route
	var paths []rib.AltPath
	if snap, ok := view.(routeSnapshotter); ok {
		routes, paths = snap.RouteSnapshot()
	} else {
		routes = view.Routes()
	}
	alt := map[netip.Prefix][]outage.Alt{}
	for _, pp := range paths {
		alt[pp.Prefix] = append(alt[pp.Prefix], outage.Alt{
			Provider: pp.Provider,
			ASPath:   append([]uint32(nil), pp.ASPath...),
		})
	}
	out := make([]outage.Route, 0, len(routes))
	for _, rt := range routes {
		if !rt.Prefix.IsValid() || rt.Prefix.Bits() == 0 {
			continue
		}
		out = append(out, outage.Route{
			Prefix:   rt.Prefix,
			Provider: rt.Provider,
			ASPath:   append([]uint32(nil), rt.ASPath...),
			Alts:     alt[rt.Prefix],
		})
	}
	s.gen, s.ok, s.out = g, true, out
	return out
}

// wireOutage gives the outage source the probe results and the learned
// RIB, and sends its events to the notifiers. A missing or unready RIB
// yields no routes, so AS correlation stays quiet. The dispatcher queues
// events, so a slow notifier cannot hold the probe loop.
func wireOutage(plugins *pluginhost.Set, engine *probe.Engine, view *rib.View, out emitter) {
	if plugins == nil {
		return
	}
	var snap outageSnap
	samples := func() []outage.Sample {
		if engine == nil {
			return nil
		}
		return outageSamples(engine.Results())
	}
	routes := func() []outage.Route { return snap.get(view) }
	send := func(ev plugin.Event) {
		if out != nil {
			out.Emit(ev)
		}
	}
	for _, src := range plugins.SourcesSnapshot() {
		s, ok := src.Plugin.(*outage.Source)
		if !ok {
			continue
		}
		s.SetSnapshots(samples, routes)
		s.SetNotify(send)
	}
}

func outageSamples(rs []probe.Result) []outage.Sample {
	out := make([]outage.Sample, len(rs))
	for i, r := range rs {
		var hops []netip.Addr
		if len(r.Hops) > 0 {
			hops = append([]netip.Addr(nil), r.Hops...)
		}
		out[i] = outage.Sample{
			Provider: r.Provider,
			Prefix:   r.Prefix,
			LossPct:  r.Stats.LossPct,
			RTT:      r.Stats.RTTAvg,
			Failed:   !r.OK(),
			Time:     r.Time,
			Hops:     hops,
		}
	}
	return out
}

// providerNamer is implemented by telemetry plugins that bind providers.
type providerNamer interface {
	ProviderNames() []string
}

// checkTelemetryProviders rejects the same provider on two telemetry
// plugins. Each plugin already rejects a name that is not configured.
func checkTelemetryProviders(plugins *pluginhost.Set) error {
	if plugins == nil {
		return nil
	}
	seen := map[string]string{}
	for _, t := range plugins.Telemetry {
		namer, ok := t.Plugin.(providerNamer)
		if !ok {
			continue
		}
		for _, name := range namer.ProviderNames() {
			if prev, ok := seen[name]; ok {
				return fmt.Errorf("telemetry: provider %q is listed on both %s and %s", name, prev, t.Name)
			}
			seen[name] = t.Name
		}
	}
	return nil
}

// flowTracked sums the flow sources' passive prefix estimates (#125).
// Other sources do not implement it. The figure is not a probe target.
func flowTracked(plugins *pluginhost.Set) int {
	if plugins == nil {
		return 0
	}
	n := 0
	for _, src := range plugins.Sources {
		t, ok := src.Plugin.(interface{ Tracked() int })
		if !ok {
			continue
		}
		n += t.Tracked()
	}
	return n
}

// truncated sums what the flow and span sources' caps turned away, by
// config key (packeteer_truncated_total).
func truncated(plugins *pluginhost.Set) map[string]uint64 {
	out := map[string]uint64{}
	if plugins == nil {
		return out
	}
	for _, src := range plugins.Sources {
		t, ok := src.Plugin.(interface{ Truncated() map[string]uint64 })
		if !ok {
			continue
		}
		for k, n := range t.Truncated() {
			out[k] += n
		}
	}
	return out
}

func collectTelemetry(ctx context.Context, plugins *pluginhost.Set) []plugin.Usage {
	if plugins == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var out []plugin.Usage
	for _, t := range plugins.Telemetry {
		if ctx.Err() != nil {
			return out
		}
		rows, err := t.Plugin.Snapshot(ctx)
		if err != nil {
			continue
		}
		out = append(out, rows...)
	}
	return out
}

// checkOutageIntervals rejects a reprobe cadence that is not faster than
// the normal probe interval, or that is outside the staleness window. A
// longer interval would leave the re-queued prefixes stale, and the
// controller would withdraw any improvement on them.
func checkOutageIntervals(cfg *config.Config, plugins *pluginhost.Set) error {
	if plugins == nil {
		return nil
	}
	return checkOutageSourceIntervals(cfg, plugins.Sources)
}

func checkOutageSourceIntervals(cfg *config.Config, sources []pluginhost.Instance[plugin.TargetSource]) error {
	if cfg == nil {
		return nil
	}
	window := maxResultAge(cfg)
	var errs []error
	for _, src := range sources {
		s, ok := src.Plugin.(*outage.Source)
		if !ok {
			continue
		}
		iv := s.Interval()
		if iv >= cfg.Probe.Interval {
			errs = append(errs, fmt.Errorf("source %s: interval %s must be shorter than probe.interval %s", src.Name, iv, cfg.Probe.Interval))
		}
		if iv >= window {
			errs = append(errs, fmt.Errorf("source %s: interval %s must be shorter than the staleness window %s (3*probe.interval + packets*timeout, plus retry packets when retry is on)", src.Name, iv, window))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

// checkFlowTailIntervals rejects a tail cadence that is not slower than
// the normal probe interval, or that is outside the staleness window.
// A shorter interval would probe the tail more often than the priority
// tier. A longer one leaves those prefixes stale, and the controller
// would withdraw any improvement on them. The default has no tail.
func checkFlowTailIntervals(cfg *config.Config, plugins *pluginhost.Set) error {
	if plugins == nil {
		return nil
	}
	return checkFlowTailSourceIntervals(cfg, plugins.Sources)
}

func checkFlowTailSourceIntervals(cfg *config.Config, sources []pluginhost.Instance[plugin.TargetSource]) error {
	if cfg == nil {
		return nil
	}
	window := maxResultAge(cfg)
	var errs []error
	for _, src := range sources {
		s, ok := src.Plugin.(*flow.Source)
		if !ok {
			continue
		}
		iv := s.TailInterval()
		if iv == 0 {
			continue
		}
		if iv <= cfg.Probe.Interval {
			errs = append(errs, fmt.Errorf("source %s: tail_interval %s must be longer than probe.interval %s", src.Name, iv, cfg.Probe.Interval))
		}
		if iv >= window {
			errs = append(errs, fmt.Errorf("source %s: tail_interval %s must be shorter than the staleness window %s (3*probe.interval + packets*timeout, plus retry packets when retry is on)", src.Name, iv, window))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

// checkVIPIntervals rejects a VIP cadence that is not inside the staleness
// window. A longer interval leaves that prefix permanently stale, and the
// controller withdraws any improvement on it.
func checkVIPIntervals(cfg *config.Config, plugins *pluginhost.Set) error {
	if plugins == nil {
		return nil
	}
	return checkVIPSourceIntervals(cfg, plugins.Sources)
}

func checkVIPSourceIntervals(cfg *config.Config, sources []pluginhost.Instance[plugin.TargetSource]) error {
	if cfg == nil {
		return nil
	}
	window := maxResultAge(cfg)
	var errs []error
	for _, src := range sources {
		v, ok := src.Plugin.(*vip.Source)
		if !ok {
			continue
		}
		if v.Interval() >= window {
			errs = append(errs, fmt.Errorf("source %s: interval %s must be shorter than the staleness window %s (3*probe.interval + packets*timeout, plus retry packets when retry is on)", src.Name, v.Interval(), window))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

// exchangeLANSetter is implemented by target sources that must not probe
// an exchange peering LAN (#145).
type exchangeLANSetter interface {
	SetExchangeLANs([]netip.Prefix)
}

// wireExchangeLANs copies every exchange's peering LAN onto the sources
// that implement it, before they start, so a destination on that LAN is
// never aggregated into a probe prefix.
func wireExchangeLANs(cfg *config.Config, plugins *pluginhost.Set) {
	if cfg == nil || plugins == nil {
		return
	}
	lans := exchangeLANPrefixes(cfg)
	for _, src := range plugins.SourcesSnapshot() {
		if s, ok := src.Plugin.(exchangeLANSetter); ok {
			s.SetExchangeLANs(lans)
		}
	}
}

// probeExcludeSetter is implemented by target sources that send packets of
// their own and must honor probe.exclude (#203).
type probeExcludeSetter interface {
	SetExcluded(func(prefix netip.Prefix, host netip.Addr) bool)
}

// wireProbeExclusion hands probe.exclude to the sources that trace on their
// own, before they start. The probe engine filters every source's targets
// itself; this keeps the discovery packets off excluded destinations too.
func wireProbeExclusion(cfg *config.Config, plugins *pluginhost.Set, view *rib.View) {
	if cfg == nil || plugins == nil {
		return
	}
	x := probeExclusion(cfg, func() *rib.View { return view })
	if x == nil {
		return
	}
	fn := func(p netip.Prefix, host netip.Addr) bool { return x.Prefix(p) || x.Addr(host) }
	for _, src := range plugins.SourcesSnapshot() {
		if s, ok := src.Plugin.(probeExcludeSetter); ok {
			s.SetExcluded(fn)
		}
	}
}

// packetWaitSetter is implemented by target sources that send packets of
// their own toward a destination and must count them against
// probe.per_asn_pps (#203).
type packetWaitSetter interface {
	SetPacketWait(func(ctx context.Context, dest netip.Addr) error)
}

// wirePacketWait hands the engine's per-ASN cap to the sources that trace
// on their own, before they start.
func wirePacketWait(plugins *pluginhost.Set, perASN *probe.ASNLimits) {
	if plugins == nil || perASN == nil {
		return
	}
	wait := func(ctx context.Context, dest netip.Addr) error { return perASN.Wait(ctx, dest, 1) }
	for _, src := range plugins.SourcesSnapshot() {
		if s, ok := src.Plugin.(packetWaitSetter); ok {
			s.SetPacketWait(wait)
		}
	}
}

func exchangeLANPrefixes(cfg *config.Config) []netip.Prefix {
	if cfg == nil {
		return nil
	}
	var out []netip.Prefix
	for _, ex := range cfg.Exchanges {
		out = append(out, ex.ExchangeLANs()...)
	}
	return out
}

func wirePrefixLookup(plugins *pluginhost.Set, view *rib.View) {
	if plugins == nil || view == nil {
		return
	}
	fn := func(addr netip.Addr) (netip.Prefix, bool) {
		if !view.Ready() {
			return netip.Prefix{}, false
		}
		rt, ok := view.Lookup(addr)
		if !ok || !rt.Prefix.IsValid() || rt.Prefix.Bits() == 0 || !rt.Prefix.Contains(addr) {
			return netip.Prefix{}, false
		}
		return rt.Prefix, true
	}
	for _, src := range plugins.SourcesSnapshot() {
		if s, ok := src.Plugin.(prefixLookup); ok {
			s.SetPrefixLookup(fn)
		}
	}
}
