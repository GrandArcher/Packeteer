package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/GrandArcher/Packeteer/internal/announce"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/internal/inbound"
	"github.com/GrandArcher/Packeteer/internal/irr"
	"github.com/GrandArcher/Packeteer/internal/mitigation"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/all"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/internal/rpki"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// decideLoop evaluates on kick (a finished probe round or a RIB change)
// and on a staleness ticker. The ticker is what withdraws improvements
// when no round ever completes.
func decideLoop(ctx context.Context, interval func() time.Duration, kick <-chan struct{}, eval func(now time.Time)) {
	every := time.Second
	if interval != nil {
		if d := interval(); d > 0 {
			every = d
		}
	}
	staleness := time.NewTicker(every)
	defer staleness.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-kick:
		case <-staleness.C:
		}
		if ctx.Err() != nil {
			return
		}
		eval(time.Now())
		if interval == nil {
			continue
		}
		if d := interval(); d > 0 && d != every {
			every = d
			staleness.Reset(every)
		}
	}
}

// runDecision applies one evaluation to the announcer and returns the
// decision changes and the sync error for the event watcher. engine, when
// set, is told which prefixes still have an improvement before the sync,
// so the next probe round keeps them even if that sync is slow (#116).
func runDecision(now time.Time, decider *policy.Engine, in policy.Input, ctl *announce.Controller, log *slog.Logger, mode string, engine *probe.Engine) ([]policy.Change, error) {
	changes := decider.Evaluate(in, now)
	retainImprovedPrefixes(engine, decider.Improvements())
	// A prefix whose confirm streak compared this round is probed again
	// after a quarter of its interval. SetUrgent does not wake when the
	// list is empty or that gap has not elapsed. Every probe still waits
	// on probe.rate_limit_pps.
	if engine != nil {
		engine.SetUrgent(decider.Urgent())
	}
	logChanges(log, mode, changes)
	logQuarantines(log, decider.QuarantineChanges())
	actx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := ctl.Sync(actx, decider.Improvements())
	if err != nil {
		log.Error("announce", "err", err)
	}
	return changes, err
}

// standbyRound is a decision round on an HA standby (#31): no decision,
// and the gated syncs withdraw anything still on the wire. Mitigation
// rules still expire.
func standbyRound(now time.Time, ctl *announce.Controller, inb *inbound.Controller, mit *mitigation.Controller, log *slog.Logger) ([]mitigation.Change, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := errors.Join(ctl.Sync(ctx, nil), inb.Sync(ctx))
	if err != nil {
		log.Error("ha standby withdraw", "err", err)
	}
	mitChanges, mitErr := runMitigation(now, mit, log)
	return mitChanges, errors.Join(err, mitErr)
}

// policyConfig is the decision config for cfg. A reload builds a fresh one
// and installs it with SetConfig; the next Decide uses it. Prefixes here
// were already validated by config.Load.
func policyConfig(cfg *config.Config) (policy.Config, error) {
	if cfg == nil {
		return policy.Config{}, errors.New("no config")
	}
	max := 0
	if cfg.MaxImprovements != nil {
		max = *cfg.MaxImprovements
	}
	pc := policy.Config{
		Mode:            cfg.Mode,
		MinLossDeltaPct: cfg.Thresholds.MinLossDeltaPct,
		MinRTTDelta:     time.Duration(cfg.Thresholds.MinRTTDeltaMs * float64(time.Millisecond)),
		MinRTTDeltaPct:  cfg.Thresholds.MinRTTDeltaPct,
		ConfirmRounds:   cfg.Thresholds.ConfirmRounds,
		HoldTime:        cfg.HoldTime,
		MaxImprovements: max,
		// A result older than ~3 rounds is stale. The decision loop
		// re-checks this on a ticker even when no round completes.
		MaxResultAge:        maxResultAge(cfg),
		Excluded:            map[string]bool{},
		RPKIAvoidInvalid:    cfg.RPKIOn() && cfg.RPKI.AvoidInvalid,
		IRRPreferRegistered: cfg.IRROn() && cfg.IRR.PreferRegistered,
		RequireEvidence:     cfg.Thresholds.RequireEvidence,
	}
	if cfg.ImprovementTTL > 0 {
		pc.ImprovementTTL = cfg.ImprovementTTL
	}
	if f := cfg.FlapQuarantine; !f.Disabled {
		pc.Flap = policy.FlapConfig{MaxFlips: f.MaxFlips, Window: f.Window, Cooldown: f.Cooldown, MaxCooldown: f.MaxCooldown}
	}
	ported := map[string]bool{}
	for _, ex := range cfg.Exchanges {
		if ex.Port != nil {
			ported[ex.Name] = true
			pc.Ports = append(pc.Ports, policy.PortPolicy{Name: ex.Name, CapacityMbps: ex.Port.CapacityMbps, CommitMbps: ex.Port.CommitMbps})
		}
	}
	for _, p := range cfg.Providers {
		if p.Exclude {
			pc.Excluded[p.Name] = true
		}
		pp := policy.ProviderPolicy{
			Name: p.Name, Group: p.Group, Precedence: p.Precedence, CCDisable: p.CCDisable,
			CapacityThresholdPct: p.InterfaceCapacityThresholdPct,
		}
		if ported[p.Exchange] {
			pp.Port = p.Exchange
		}
		if p.Cost != nil {
			pp.Cost, pp.HasCost = *p.Cost, true
		}
		pc.Providers = append(pc.Providers, pp)
	}
	for _, s := range cfg.Allowlist.Prefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return policy.Config{}, err
		}
		pc.Allowlist = append(pc.Allowlist, p)
	}
	return pc, nil
}

func newDecider(cfg *config.Config, plugins *pluginhost.Set) (*policy.Engine, error) {
	if plugins.Scorer == nil {
		return nil, fmt.Errorf("no scorer configured")
	}
	pc, err := policyConfig(cfg)
	if err != nil {
		return nil, err
	}
	return policy.NewEngine(pc, plugins.Scorer.Plugin), nil
}

// newRPKISet wraps the configured origin-validation sources in order and
// the display-only fallback (#200). An empty set is RPKI off.
func newRPKISet(plugins *pluginhost.Set) *rpki.Set {
	if plugins == nil {
		return rpki.NewSet(nil)
	}
	out := make([]plugin.RPKI, 0, len(plugins.RPKISources))
	for _, s := range plugins.RPKISources {
		out = append(out, s.Plugin)
	}
	set := rpki.NewSet(out)
	if d := plugins.RPKIDisplay; d != nil {
		if a, ok := d.Plugin.(rpki.Answerer); ok {
			set.SetDisplay(a)
		}
	}
	return set
}

// newIRRChecker wraps the irr.sources in order with the cache timers and
// the per-provider as-sets (#214). With irr off it has no sources and
// every lookup is unknown.
func newIRRChecker(cfg *config.Config, plugins *pluginhost.Set) *irr.Checker {
	if plugins == nil || !cfg.IRROn() {
		return irr.NewChecker(nil, irr.Options{})
	}
	srcs := make([]irr.Source, 0, len(plugins.IRRSources))
	for _, s := range plugins.IRRSources {
		srcs = append(srcs, irr.Source{Name: s.Name, Type: s.Type, IRR: s.Plugin})
	}
	return irr.NewChecker(srcs, irr.Options{Refresh: cfg.IRR.Refresh, Staleness: cfg.IRR.Staleness, ASSets: cfg.IRR.ASSets})
}

// rpkiStatuses is the health of every rpki.sources entry, in order.
func rpkiStatuses(plugins *pluginhost.Set) []plugin.RPKIStatus {
	if plugins == nil {
		return nil
	}
	out := make([]plugin.RPKIStatus, 0, len(plugins.RPKISources))
	for _, s := range plugins.RPKISources {
		out = append(out, s.Plugin.Status())
	}
	return out
}

// decisionInput snapshots probe results, provider health, the RIB view,
// and, when the scorer plans commit moves, telemetry and flow volumes.
// A weighted scorer does not implement planning, so those reads are skipped.
// With federation (#30), fresh peers' paths through providers in other
// domains are merged in and global commits are applied to the usage.
// The RPKI answers the round used are returned too, so history records
// what Decide saw.
func decisionInput(ctx context.Context, now time.Time, engine *probe.Engine, view *rib.View, plugins *pluginhost.Set, fed *fedState, origins *rpki.Set, registry *irr.Checker) (policy.Input, []history.RPKIRoute) {
	in := policy.Input{Results: engine.Results(), ProviderUp: map[string]bool{}, Native: map[netip.Prefix]string{}}
	for _, p := range engine.Providers() {
		in.ProviderUp[p.Name] = p.Up
	}
	var routes []history.RPKIRoute
	if view != nil {
		in.RIBEnabled, in.RIBReady = true, view.Ready()
		for _, r := range in.Results {
			if rt, ok := view.Exact(r.Prefix); ok {
				in.Native[r.Prefix] = rt.Provider
			}
		}
		fillRouteChecks(&in, view)
		routes = rpkiRoutes(view, in.Results, origins)
		fillRPKI(&in, routes)
		fillIRR(&in, view, registry)
		in.EgressDown = view.EgressDown()
	}
	fed.merge(&in, now)
	in.Passive = collectPassive(plugins)
	var lookup routeLookup
	if view != nil {
		lookup = view
	}
	applyPolicies(&in, now, lookup, plugins, collectTraffic(ctx, plugins))
	fillPlannerInputs(ctx, &in, plugins)
	fed.commit(ctx, &in, plugins)
	return in, routes
}

// routeChecker is the RIB surface the route check (BMP or add-path) reads. *rib.View
// implements it.
type routeChecker interface {
	RouteCheck(netip.Prefix, string) (checked, ok bool)
}

// fillRouteChecks marks, per probed prefix, the providers the route check
// (bmp prefer or only, or add_path) found without a path for that exact prefix. Decide
// does not use them for that prefix.
func fillRouteChecks(in *policy.Input, view routeChecker) {
	for _, r := range in.Results {
		checked, ok := view.RouteCheck(r.Prefix, r.Provider)
		if !checked || ok {
			continue
		}
		if in.NoRoute == nil {
			in.NoRoute = map[netip.Prefix]map[string]bool{}
		}
		if in.NoRoute[r.Prefix] == nil {
			in.NoRoute[r.Prefix] = map[string]bool{}
		}
		in.NoRoute[r.Prefix][r.Provider] = true
	}
}

// providerPaths is the RIB surface fillRPKI reads. *rib.View implements it.
type providerPaths interface {
	ProviderPaths(netip.Prefix, string) [][]uint32
}

// rpkiRank orders validity from best to worst for a provider with several
// learned paths.
var rpkiRank = map[plugin.RPKIValidity]int{
	plugin.RPKIValid:    0,
	plugin.RPKINotFound: 1,
	plugin.RPKIUnknown:  2,
	plugin.RPKIInvalid:  3,
}

// eachPathOrigin calls fn once per probed prefix, provider, and distinct
// origin (the last AS) of that provider's learned paths.
func eachPathOrigin(view providerPaths, results []probe.Result, fn func(prefix netip.Prefix, provider string, origin uint32)) {
	type pair struct {
		prefix   netip.Prefix
		provider string
	}
	done := map[pair]bool{}
	for _, r := range results {
		k := pair{r.Prefix, r.Provider}
		if done[k] {
			continue
		}
		done[k] = true
		seen := map[uint32]bool{}
		for _, path := range view.ProviderPaths(r.Prefix, r.Provider) {
			if len(path) == 0 || seen[path[len(path)-1]] {
				continue
			}
			origin := path[len(path)-1]
			seen[origin] = true
			fn(r.Prefix, r.Provider, origin)
		}
	}
}

// rpkiRoutes validates the origin of every learned path of each probed
// prefix and provider, once per distinct origin (#200). It uses the
// decision sources only, never the display fallback. Nil when RPKI is off.
func rpkiRoutes(view providerPaths, results []probe.Result, origins *rpki.Set) []history.RPKIRoute {
	if view == nil || !origins.Enabled() {
		return nil
	}
	var out []history.RPKIRoute
	eachPathOrigin(view, results, func(prefix netip.Prefix, provider string, origin uint32) {
		out = append(out, history.RPKIRoute{Prefix: prefix, Provider: provider, Origin: origin, Answer: origins.Lookup(prefix, origin)})
	})
	return out
}

// fillRPKI labels each probed prefix and provider with the RFC 6811 state
// of that provider's learned paths (#158) and the source that answered. A
// provider with several paths (add-path, or BMP from several routers) gets
// the worst state among them: Decide cannot tell which one the provider
// forwards on, so one invalid path makes the provider invalid for
// rpki.avoid_invalid. It is display-only input to Decide unless
// avoid_invalid is set; it never changes the learned RIB.
func fillRPKI(in *policy.Input, routes []history.RPKIRoute) {
	for _, rt := range routes {
		cur, ok := in.RPKI[rt.Prefix][rt.Provider]
		if ok && rpkiRank[rt.Answer.State] <= rpkiRank[cur.State] {
			continue
		}
		if in.RPKI == nil {
			in.RPKI = map[netip.Prefix]map[string]plugin.RPKIAnswer{}
		}
		if in.RPKI[rt.Prefix] == nil {
			in.RPKI[rt.Prefix] = map[string]plugin.RPKIAnswer{}
		}
		in.RPKI[rt.Prefix][rt.Provider] = rt.Answer
	}
}

// irrRank orders IRR states from best to worst for a provider with several
// learned paths.
var irrRank = map[plugin.IRRState]int{
	plugin.IRRRegistered:    0,
	plugin.IRRUnknown:       1,
	plugin.IRRNotRegistered: 2,
}

// fillIRR labels each probed prefix and provider with the IRR state of
// that provider's learned paths (#214), the worst among several, as
// fillRPKI does. It is display-only input to Decide unless
// irr.prefer_registered is set. Nothing when IRR is off.
func fillIRR(in *policy.Input, view providerPaths, registry *irr.Checker) {
	if view == nil || !registry.Enabled() {
		return
	}
	eachPathOrigin(view, in.Results, func(prefix netip.Prefix, provider string, origin uint32) {
		a := registry.Lookup(prefix, origin, provider)
		cur, ok := in.IRR[prefix][provider]
		if ok && irrRank[a.State] <= irrRank[cur.State] {
			return
		}
		if in.IRR == nil {
			in.IRR = map[netip.Prefix]map[string]plugin.IRRAnswer{}
		}
		if in.IRR[prefix] == nil {
			in.IRR[prefix] = map[string]plugin.IRRAnswer{}
		}
		in.IRR[prefix][provider] = a
	})
}

// routeLookup is the RIB surface policies read. *rib.View implements it.
type routeLookup interface {
	Ready() bool
	Exact(netip.Prefix) (rib.Route, bool)
}

// applyPolicies asks the policy chain about every probed prefix and
// collects the providers in open maintenance windows. The first policy that
// matches a prefix decides it. ASN rules see the learned AS path only while
// the RIB view is ready, and traffic rules see the prefix's class from
// traffic (nil when no source classifies). Policies do not announce; Decide
// applies them.
func applyPolicies(in *policy.Input, now time.Time, routes routeLookup, plugins *pluginhost.Set, traffic map[netip.Prefix]string) {
	if in == nil || plugins == nil {
		return
	}
	pols := plugins.PoliciesSnapshot()
	if len(pols) == 0 {
		return
	}
	seen := map[string]bool{}
	for _, pol := range pols {
		m, ok := pol.Plugin.(plugin.Maintenance)
		if !ok {
			continue
		}
		for _, w := range m.Active(now) {
			for _, name := range w.Providers {
				if !seen[name] {
					seen[name] = true
					in.Maintenance = append(in.Maintenance, name)
				}
			}
		}
	}
	ready := routes != nil && routes.Ready()
	for _, r := range in.Results {
		if _, done := in.Policies[r.Prefix]; done || !r.Prefix.IsValid() {
			continue
		}
		subj := plugin.PolicySubject{Prefix: r.Prefix, Traffic: traffic[r.Prefix]}
		if ready {
			if rt, ok := routes.Exact(r.Prefix); ok {
				subj.ASPath = rt.ASPath
			}
		}
		for _, pol := range pols {
			if v, ok := pol.Plugin.Match(subj); ok {
				if in.Policies == nil {
					in.Policies = map[netip.Prefix]plugin.PolicyVerdict{}
				}
				in.Policies[r.Prefix] = v
				break
			}
		}
	}
}

// scorerPlans reports whether commit control is on for this process.
func scorerPlans(plugins *pluginhost.Set) bool {
	if plugins == nil || plugins.Scorer == nil || plugins.Scorer.Plugin == nil {
		return false
	}
	_, ok := plugins.Scorer.Plugin.(plugin.Planner)
	return ok
}

// fillPlannerInputs reads telemetry and per-prefix volume only for a scorer
// that implements plugin.Planner. The weighted scorer does not, and summing
// the flow window on every decision is wasted work. ctx is the decision
// loop's context, so shutdown cancels the read.
func fillPlannerInputs(ctx context.Context, in *policy.Input, plugins *pluginhost.Set) {
	if in == nil {
		return
	}
	if !scorerPlans(plugins) {
		// Improvement weights with a volume term (#34) need volumes too,
		// for the weights only: cost annotations stay as they were.
		if scorerWeighsVolume(plugins) {
			in.WeightVolumeMbps = collectVolumes(ctx, plugins)
		}
		return
	}
	in.Usage = collectTelemetry(ctx, plugins)
	in.VolumeMbps = collectVolumes(ctx, plugins)
}

// scorerWeighsVolume reports whether the scorer's improvement weights
// (#34) read per-prefix volume.
func scorerWeighsVolume(plugins *pluginhost.Set) bool {
	if plugins == nil || plugins.Scorer == nil || plugins.Scorer.Plugin == nil {
		return false
	}
	wg, ok := plugins.Scorer.Plugin.(plugin.ImprovementWeigher)
	if !ok {
		return false
	}
	_, vol := wg.ImprovementWeights()
	return vol
}

// collectTraffic reads the traffic class of each prefix from target sources
// that classify flow data (#29). The first source listed that classifies a
// prefix wins. It is nil when no policy is configured or no source
// classifies. This does not announce.
func collectTraffic(ctx context.Context, plugins *pluginhost.Set) map[netip.Prefix]string {
	if plugins == nil || len(plugins.PoliciesSnapshot()) == 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var out map[netip.Prefix]string
	for _, src := range plugins.SourcesSnapshot() {
		if ctx.Err() != nil {
			return out
		}
		tc, ok := src.Plugin.(plugin.TrafficClassifier)
		if !ok {
			continue
		}
		rows, err := tc.TrafficMix(ctx)
		if err != nil {
			continue
		}
		for _, row := range rows {
			if !row.Prefix.IsValid() || row.Class == "" {
				continue
			}
			if out == nil {
				out = map[netip.Prefix]string{}
			}
			if _, done := out[row.Prefix]; !done {
				out[row.Prefix] = row.Class
			}
		}
	}
	return out
}

// collectPassive reads the span and flow sources' passive view of the
// prefixes with TCP traffic in their window (#202): true when that traffic
// is over the source's problem thresholds. A problem in any source counts.
// Decide uses it to rate the confidence of the sample on the path that
// carries the traffic. This does not announce.
func collectPassive(plugins *pluginhost.Set) map[netip.Prefix]bool {
	if plugins == nil {
		return nil
	}
	var out map[netip.Prefix]bool
	for _, src := range plugins.SourcesSnapshot() {
		po, ok := src.Plugin.(plugin.PassiveObserver)
		if !ok {
			continue
		}
		for p, problem := range po.PassiveSignals() {
			if out == nil {
				out = map[netip.Prefix]bool{}
			}
			out[p] = out[p] || problem
		}
	}
	return out
}

// collectVolumes reads optional volume reports from target sources. The
// largest rate wins when two sources name one prefix. A source that does
// not implement VolumeSource is skipped. This does not announce.
func collectVolumes(ctx context.Context, plugins *pluginhost.Set) map[netip.Prefix]float64 {
	var out map[netip.Prefix]float64
	for p, v := range collectVolumeRows(ctx, plugins) {
		if out == nil {
			out = map[netip.Prefix]float64{}
		}
		out[p] = v.Mbps()
	}
	return out
}

// collectVolumeRows is collectVolumes with the bytes and window kept. A
// prefix with no rate is left out.
func collectVolumeRows(ctx context.Context, plugins *pluginhost.Set) map[netip.Prefix]plugin.PrefixVolume {
	if plugins == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var out map[netip.Prefix]plugin.PrefixVolume
	for _, src := range plugins.SourcesSnapshot() {
		if ctx.Err() != nil {
			return out
		}
		vs, ok := src.Plugin.(plugin.VolumeSource)
		if !ok {
			continue
		}
		rows, err := vs.Volumes(ctx)
		if err != nil {
			continue
		}
		for _, row := range rows {
			mbps := row.Mbps()
			if mbps <= 0 || !row.Prefix.IsValid() {
				continue
			}
			if out == nil {
				out = map[netip.Prefix]plugin.PrefixVolume{}
			}
			if mbps > out[row.Prefix].Mbps() {
				out[row.Prefix] = row
			}
		}
	}
	return out
}

func logChanges(log *slog.Logger, mode string, changes []policy.Change) {
	for _, c := range changes {
		switch c.Action {
		case policy.ActionRetire:
			log.Info("improvement retired", "mode", mode, "prefix", c.Old.Prefix, "provider", c.Old.Provider, "native", c.Old.Native, "cause", c.Old.Cause, "reason", c.Old.Reason)
		default:
			log.Info("improvement "+c.Action, "mode", mode, "prefix", c.New.Prefix, "provider", c.New.Provider, "native", c.New.Native, "cause", c.New.Cause, "reason", c.New.Reason)
		}
	}
}
