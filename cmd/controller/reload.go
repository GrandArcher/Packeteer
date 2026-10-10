package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Online reconfiguration (#27, #128). On SIGHUP, and on PUT /api/config
// when every change can apply online, the controller reads the config file
// again. Thresholds, hold_time, improvement_ttl, max_improvements, policies,
// sources, probe timing, mode, allowlist, and bgp.neighbors are applied.
// The next Decide uses the new values; nothing on the wire changes except
// what Decide (or a mode change off inject) withdraws. A key that cannot
// apply online is refused by name and the running config stays. An invalid
// file is refused the same way. If applying fails after the BGP speaker
// changed, the controller stops, which withdraws every Packeteer route.

// neighborView is the RIB surface a reload changes. *rib.View implements it.
type neighborView interface {
	RemoveNeighbors(context.Context, []netip.Addr) error
	AddNeighbors(context.Context, []rib.Neighbor) error
	SetEgress(map[string][]netip.Addr) error
}

// announcerCtl is the announce surface a reload changes.
// *announce.Controller implements it.
type announcerCtl interface {
	SetRouters(context.Context, []plugin.RouterExport) error
	Routers() []plugin.RouterExport
	ApplyRuntime(context.Context, string, []netip.Prefix, int) error
}

// reloadPlan is what a new config changes on the running speaker, plus the
// keys that apply without touching sessions.
type reloadPlan struct {
	remove  []netip.Addr   // sessions to close (removed or changed)
	add     []rib.Neighbor // sessions to open (new or changed)
	egress  map[string][]netip.Addr
	routers []plugin.RouterExport
	// newTable is set when the per-router table differs from the one in use.
	newTable bool
	online   []string
}

func (p reloadPlan) empty() bool {
	return len(p.remove) == 0 && len(p.add) == 0 && !p.newTable && len(p.online) == 0
}

func (p reloadPlan) sessions() bool {
	return len(p.remove) > 0 || len(p.add) > 0 || p.newTable
}

// planReload compares a freshly loaded config with the running one. It
// fails, naming the keys, when a key that cannot apply online changed.
func planReload(cur, next *config.Config, table []plugin.RouterExport) (reloadPlan, error) {
	var plan reloadPlan
	restart, online := classify(cur, next)
	if len(restart) > 0 {
		return plan, fmt.Errorf("restart required: changed %s (these keys do not reload online)", strings.Join(restart, ", "))
	}
	plan.online = online
	if len(cur.BGP.Neighbors) == 0 && len(next.BGP.Neighbors) == 0 {
		return plan, nil
	}
	if len(next.BGP.Neighbors) == 0 {
		return plan, errors.New("restart required: bgp.neighbors cannot become empty while running")
	}
	sessions, err := neighborPlan(cur, next, table)
	if err != nil {
		return plan, err
	}
	plan.remove, plan.add, plan.egress, plan.routers, plan.newTable = sessions.remove, sessions.add, sessions.egress, sessions.routers, sessions.newTable
	return plan, nil
}

// neighborPlan is the session and per-router-table diff. It does not look
// at other keys.
func neighborPlan(cur, next *config.Config, table []plugin.RouterExport) (reloadPlan, error) {
	var plan reloadPlan
	old, _, err := ribNeighbors(cur)
	if err != nil {
		return plan, err
	}
	nbrs, egress, err := ribNeighbors(next)
	if err != nil {
		return plan, err
	}
	before := map[netip.Addr]rib.Neighbor{}
	for _, n := range old {
		before[n.Address] = n
	}
	after := map[netip.Addr]bool{}
	for _, n := range nbrs {
		after[n.Address] = true
		o, ok := before[n.Address]
		if ok && o == n {
			continue
		}
		if ok {
			plan.remove = append(plan.remove, n.Address)
		}
		plan.add = append(plan.add, n)
	}
	for _, n := range old {
		if !after[n.Address] {
			plan.remove = append(plan.remove, n.Address)
		}
	}
	plan.egress = egress
	routers, err := routerExports(next)
	if err != nil {
		return plan, err
	}
	plan.routers = routers
	plan.newTable = !reflect.DeepEqual(normTable(routers), normTable(table))
	return plan, nil
}

// normTable makes two tables comparable: nil and empty are the same, and
// order does not matter.
func normTable(t []plugin.RouterExport) []plugin.RouterExport {
	out := make([]plugin.RouterExport, 0, len(t))
	for _, r := range t {
		c := plugin.RouterExport{Neighbor: r.Neighbor, Blocked: slices.Clone(r.Blocked)}
		if len(r.Via) > 0 {
			c.Via = r.Via
		}
		if len(c.Blocked) == 0 {
			c.Blocked = nil
		}
		slices.SortFunc(c.Blocked, netip.Addr.Compare)
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b plugin.RouterExport) int { return a.Neighbor.Compare(b.Neighbor) })
	return out
}

// onlineTop are top-level keys a reload applies. probe and bgp are split
// below: only some of their fields apply online.
var onlineTop = map[string]bool{
	"mode": true, "thresholds": true, "hold_time": true, "improvement_ttl": true,
	"max_improvements": true, "policies": true, "sources": true, "allowlist": true,
}

// classify lists restart keys and online keys. A probe timing change is
// online only when no restart-only probe field changed; the caller refuses
// the whole reload when any restart key is set, so timing is not applied
// on its own in that case.
func classify(a, b *config.Config) (restart, online []string) {
	if a == nil || b == nil {
		return []string{"config"}, nil
	}
	av, bv := reflect.ValueOf(*a), reflect.ValueOf(*b)
	t := av.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "" || name == "-" {
			continue
		}
		x, y := av.Field(i).Interface(), bv.Field(i).Interface()
		switch name {
		case "bgp":
			ab, bb := x.(config.BGP), y.(config.BGP)
			if !sameYAML(ab.Neighbors, bb.Neighbors) {
				online = append(online, "bgp.neighbors")
			}
			ab.Neighbors, bb.Neighbors = nil, nil
			if !sameYAML(ab.ListenPort, bb.ListenPort) {
				restart = append(restart, "bgp.listen_port")
			}
			if !sameYAML(ab.ListenAddresses, bb.ListenAddresses) {
				restart = append(restart, "bgp.listen_addresses")
			}
			if !sameYAML(ab.ASPath, bb.ASPath) {
				restart = append(restart, "bgp.as_path")
			}
			if !sameYAML(ab, bb) && !slices.ContainsFunc(restart, func(k string) bool { return strings.HasPrefix(k, "bgp.") }) {
				restart = append(restart, "bgp")
			}
		case "probe":
			pr, po := probeKeys(x.(config.Probe), y.(config.Probe))
			restart = append(restart, pr...)
			online = append(online, po...)
		default:
			if sameYAML(x, y) {
				continue
			}
			if onlineTop[name] {
				online = append(online, name)
			} else {
				restart = append(restart, name)
			}
		}
	}
	slices.Sort(online)
	return restart, online
}

// probeKeys splits a probe change into restart-only fields and timing
// fields. indirect and the worker, rate, and dispersion fields stay
// restart-only: they change how packets are sent, not only when.
func probeKeys(a, b config.Probe) (restart, online []string) {
	pair := func(name string, x, y any, live bool) {
		if sameYAML(x, y) {
			return
		}
		if live {
			online = append(online, "probe."+name)
		} else {
			restart = append(restart, "probe."+name)
		}
	}
	pair("interval", a.Interval, b.Interval, true)
	pair("timeout", a.Timeout, b.Timeout, true)
	pair("packets", a.Packets, b.Packets, true)
	pair("retry_loss_pct", a.RetryLossPct, b.RetryLossPct, true)
	pair("retry_packets", a.RetryPackets, b.RetryPackets, true)
	pair("workers", a.Workers, b.Workers, false)
	pair("rate_limit_pps", a.RateLimitPPS, b.RateLimitPPS, false)
	pair("per_target_concurrency", a.PerTargetConcurrency, b.PerTargetConcurrency, false)
	pair("min_replies", a.MinReplies, b.MinReplies, false)
	pair("dispersion_ms", a.DispersionMS, b.DispersionMS, false)
	pair("prober_recheck_rounds", a.ProberRecheckRounds, b.ProberRecheckRounds, false)
	pair("prober_memory", a.ProberMemory, b.ProberMemory, false)
	pair("indirect", a.Indirect, b.Indirect, false)
	return restart, online
}

// sameYAML compares two values by their YAML data: comments and flow or
// block style in plugin config nodes do not count.
func sameYAML(a, b any) bool {
	return reflect.DeepEqual(yamlData(a), yamlData(b))
}

func yamlData(v any) any {
	raw, err := yaml.Marshal(v)
	if err != nil {
		return fmt.Sprintf("unmarshalable: %v", err)
	}
	var out any
	if err := yaml.Unmarshal(raw, &out); err != nil {
		return fmt.Sprintf("unparsable: %v", err)
	}
	return out
}

func sameSpec(a, b config.PluginSpec) bool {
	return a.Type == b.Type && a.Name == b.Name && sameYAML(a.Config, b.Config)
}

// liveConfig is the config the decision loop reads. A reload replaces it
// under the lock after the new values are installed.
type liveConfig struct {
	mu  sync.RWMutex
	cfg *config.Config
}

func (l *liveConfig) snapshot() *config.Config {
	if l == nil {
		return nil
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.cfg
}

func (l *liveConfig) set(cfg *config.Config) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.cfg = cfg
	l.mu.Unlock()
}

// reloader applies SIGHUP and PUT reloads. SIGHUP and PUT share mu.
type reloader struct {
	mu     sync.Mutex
	path   string
	getenv func(string) string
	log    *slog.Logger
	cur    *config.Config
	view   neighborView
	rib    *rib.View
	ctl    announcerCtl
	poke   func()
	// applied, when set, is told each config the reload now runs with
	// (the config editor diffs against it).
	applied func(*config.Config)

	plugins  *pluginhost.Set
	engine   *probe.Engine
	decider  *policy.Engine
	fed      *fedState
	col      *httpapi.Collector
	watch    *eventWatch
	live     *liveConfig
	dispatch emitter
	hist     *history.Recorder
	opts     pluginhost.Options
}

func (r *reloader) setCur(next *config.Config) {
	r.cur = next
	if r.live != nil {
		r.live.set(next)
	}
	if r.applied != nil {
		r.applied(next)
	}
}

// reload reads the file and applies what can change online. applied are
// the keys now running. refused is a config that was not applied (the
// running one stays). fatal is a failure after the speaker was changed:
// the caller must stop, which withdraws.
func (r *reloader) reload(ctx context.Context) (applied []string, refused, fatal error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	next, err := config.Load(r.path)
	if err == nil {
		err = applyRuntimeEnv(next, r.getenv)
	}
	if err != nil {
		return nil, err, nil
	}
	restart, online := classify(r.cur, next)
	if r.view == nil {
		// No speaker: a restart-only key is still refused by name. A
		// neighbor change cannot open a session until BGP is on.
		if len(restart) > 0 {
			return nil, fmt.Errorf("restart required: changed %s (these keys do not reload online)", strings.Join(restart, ", ")), nil
		}
		if !sameYAML(r.cur.BGP.Neighbors, next.BGP.Neighbors) {
			return nil, errors.New("restart required: bgp is off in the running config"), nil
		}
		if len(online) == 0 {
			r.log.Info("config reloaded: no change")
			r.setCur(next)
			return nil, nil, nil
		}
		if err := r.applyOnline(ctx, next, online); err != nil {
			return nil, err, nil
		}
		r.setCur(next)
		r.log.Info("config reloaded", "applied", strings.Join(online, ","))
		if r.poke != nil {
			r.poke()
		}
		return online, nil, nil
	}
	var table []plugin.RouterExport
	if r.ctl != nil {
		table = r.ctl.Routers()
	}
	plan, err := planReload(r.cur, next, table)
	if err != nil {
		return nil, err, nil
	}
	if plan.empty() {
		r.log.Info("config reloaded: no change")
		r.setCur(next)
		return nil, nil, nil
	}
	if err := r.applyOnline(ctx, next, plan.online); err != nil {
		return nil, err, nil
	}
	// Close removed sessions first, so a router leaving the table never
	// sees routes without it; then swap the table (the announcer withdraws
	// and the next sync announces again); then open new sessions, so a
	// new router's first routes already follow the new table.
	if plan.sessions() {
		if err := r.view.RemoveNeighbors(ctx, plan.remove); err != nil {
			return plan.online, nil, err
		}
		if plan.newTable && r.ctl != nil {
			if err := r.ctl.SetRouters(ctx, plan.routers); err != nil {
				return plan.online, nil, err
			}
		}
		if err := r.view.AddNeighbors(ctx, plan.add); err != nil {
			return plan.online, nil, err
		}
		if err := r.view.SetEgress(plan.egress); err != nil {
			return plan.online, nil, err
		}
	}
	r.setCur(next)
	added := make([]string, 0, len(plan.add))
	for _, n := range plan.add {
		added = append(added, n.Address.String())
	}
	removed := make([]string, 0, len(plan.remove))
	for _, a := range plan.remove {
		removed = append(removed, a.String())
	}
	r.log.Info("config reloaded", "applied", strings.Join(plan.online, ","),
		"neighbors_added", strings.Join(added, ","), "neighbors_removed", strings.Join(removed, ","),
		"router_table_replaced", plan.newTable)
	if r.poke != nil {
		r.poke()
	}
	return plan.online, nil, nil
}

// applyOnline installs every online key except BGP sessions. A failure
// leaves the previous sources, policies, announcer mode, and probe timing
// in place. The caller has not changed the speaker yet. New plugins are
// started only after the announcer accepts the new mode, allowlist, and
// cap, so a bind failure there does not stop a running source.
func (r *reloader) applyOnline(ctx context.Context, next *config.Config, online []string) error {
	if len(online) == 0 {
		return nil
	}
	pc, err := policyConfig(next)
	if err != nil {
		return err
	}
	sources, policies, toStart, toStop, err := r.preparePlugins(next, online)
	if err != nil {
		return err
	}
	runtime := r.ctl != nil && (slices.Contains(online, "mode") || slices.Contains(online, "allowlist") || slices.Contains(online, "max_improvements"))
	if runtime {
		if err := r.ctl.ApplyRuntime(ctx, next.Mode, pc.Allowlist, pc.MaxImprovements); err != nil {
			return err
		}
	}
	pluginChange := r.plugins != nil && (slices.Contains(online, "sources") || slices.Contains(online, "policies"))
	var started []startedPlugin
	if pluginChange && (len(toStart) > 0 || len(toStop) > 0) {
		var preempted []plugin.Lifecycle
		started, preempted, err = r.swapPlugins(ctx, toStart, toStop)
		if err != nil {
			r.rollbackRuntime(ctx, runtime)
			r.stopStarted(ctx, started)
			if restartErr := r.restartStopped(ctx, preempted); restartErr != nil {
				return fmt.Errorf("%w (restarting the previous plugin failed: %v)", err, restartErr)
			}
			return err
		}
	}
	if pluginChange {
		if slices.Contains(online, "sources") {
			r.plugins.SetSources(sources)
			if r.engine != nil {
				ns := make([]probe.NamedSource, 0, len(sources))
				for _, s := range sources {
					ns = append(ns, probe.NamedSource{Name: s.Name, Source: s.Plugin})
				}
				r.engine.SetSources(ns)
			}
			wirePrefixLookup(r.plugins, r.rib)
			wireExchangeLANs(next, r.plugins)
			wireLearnedRoutes(r.plugins, r.rib)
			wireOutage(r.plugins, r.engine, r.rib, r.dispatch)
		}
		if slices.Contains(online, "policies") {
			r.plugins.SetPolicies(policies)
		}
		for _, s := range started {
			r.plugins.TrackStart(s.kind, s.name, s.lc)
		}
		for _, lc := range toStop {
			r.plugins.Untrack(lc)
			if err := lc.Stop(ctx); err != nil && r.log != nil {
				r.log.Warn("stop removed plugin", "err", err)
			}
		}
	}
	if r.engine != nil && probeTiming(online) {
		r.engine.SetTiming(probe.Timing{
			Interval: next.Probe.Interval, Timeout: next.Probe.Timeout, Packets: next.Probe.Packets,
			RetryLossPct: next.Probe.RetryLossPct, RetryPackets: next.Probe.RetryPackets,
			RoundTimeout: maxResultAge(next),
		})
	}
	if r.decider != nil {
		r.decider.SetConfig(pc)
	}
	if r.fed != nil {
		max := 0
		if next.MaxImprovements != nil {
			max = *next.MaxImprovements
		}
		r.fed.setRuntime(next.Mode, max, maxResultAge(next))
	}
	if r.col != nil {
		r.col.SetMode(next.Mode)
	}
	if r.watch != nil {
		r.watch.SetMode(next.Mode)
	}
	if r.hist != nil {
		r.hist.SetMode(next.Mode)
	}
	return nil
}

// rollbackRuntime puts the announcer's mode, allowlist, and cap back when
// a later step of the reload fails. The speaker has not changed.
func (r *reloader) rollbackRuntime(ctx context.Context, applied bool) {
	if !applied || r.ctl == nil || r.cur == nil {
		return
	}
	old, err := policyConfig(r.cur)
	if err != nil {
		if r.log != nil {
			r.log.Error("reload rollback could not rebuild the policy config", "err", err)
		}
		return
	}
	if err := r.ctl.ApplyRuntime(ctx, r.cur.Mode, old.Allowlist, old.MaxImprovements); err != nil && r.log != nil {
		r.log.Error("reload rollback of mode, allowlist, and cap failed", "err", err)
	}
}

func (r *reloader) stopStarted(ctx context.Context, started []startedPlugin) {
	for i := len(started) - 1; i >= 0; i-- {
		if err := started[i].lc.Stop(ctx); err != nil && r.log != nil {
			r.log.Warn("stop new plugin after refused reload", "plugin", started[i].label, "err", err)
		}
	}
}

func (r *reloader) restartStopped(ctx context.Context, preempted []plugin.Lifecycle) error {
	var errs []error
	for _, lc := range preempted {
		if err := lc.Start(ctx); err != nil {
			errs = append(errs, err)
			if r.log != nil {
				r.log.Error("restart plugin after refused reload", "err", err)
			}
		}
	}
	return errors.Join(errs...)
}

// swapPlugins starts plugins the new config adds or replaces, then stops
// the ones it removes. A flow source binds its UDP port in Start, so a
// first start that fails is retried once after the plugins being replaced
// are stopped. On failure, started are the new plugins that did start
// (the caller stops them) and preempted are the old plugins that were
// stopped (the caller starts them again). On success preempted is nil.
func (r *reloader) swapPlugins(ctx context.Context, toStart []startedPlugin, toStop []plugin.Lifecycle) (started []startedPlugin, preempted []plugin.Lifecycle, err error) {
	var failed error
	for _, s := range toStart {
		if startErr := s.lc.Start(ctx); startErr != nil {
			failed = fmt.Errorf("start %s: %w", s.label, startErr)
			break
		}
		started = append(started, s)
	}
	if failed == nil {
		for _, lc := range toStop {
			if stopErr := lc.Stop(ctx); stopErr != nil && r.log != nil {
				r.log.Warn("stop replaced plugin", "err", stopErr)
			}
		}
		return started, nil, nil
	}
	for _, lc := range toStop {
		if stopErr := lc.Stop(ctx); stopErr != nil && r.log != nil {
			r.log.Warn("stop plugin before retrying start", "err", stopErr)
		}
		preempted = append(preempted, lc)
	}
	for _, s := range toStart[len(started):] {
		if startErr := s.lc.Start(ctx); startErr != nil {
			return started, preempted, fmt.Errorf("start %s: %w", s.label, startErr)
		}
		started = append(started, s)
	}
	return started, nil, nil
}

type startedPlugin struct {
	kind  plugin.Kind
	name  string
	label string
	lc    plugin.Lifecycle
}

// preparePlugins builds the sources and policies that changed and checks
// probe-interval rules against the candidate list. It does not start
// them. toStart are the new instances; toStop are the ones the caller
// stops after the new ones are running. On error nothing was started.
func (r *reloader) preparePlugins(next *config.Config, online []string) (sources []pluginhost.Instance[plugin.TargetSource], policies []pluginhost.Instance[plugin.Policy], toStart []startedPlugin, toStop []plugin.Lifecycle, err error) {
	wantSources := slices.Contains(online, "sources") || probeTiming(online)
	wantPolicies := slices.Contains(online, "policies")
	if r.plugins == nil || (!wantSources && !wantPolicies) {
		return nil, nil, nil, nil, nil
	}
	if wantSources {
		var stop []plugin.Lifecycle
		var fresh []startedPlugin
		sources, stop, fresh, err = reconcileSources(next, r.cur.Sources, r.plugins.SourcesSnapshot(), r.opts)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if name := anomalySourceName(r.cur, r.plugins.SourcesSnapshot()); name != "" && stopsNamed(stop, r.plugins.SourcesSnapshot(), name) {
			return nil, nil, nil, nil, fmt.Errorf("restart required: the anomaly source %s changed", name)
		}
		if err := errors.Join(
			checkOutageSourceIntervals(next, sources),
			checkFlowTailSourceIntervals(next, sources),
			checkVIPSourceIntervals(next, sources),
		); err != nil {
			return nil, nil, nil, nil, err
		}
		toStop = append(toStop, stop...)
		toStart = append(toStart, fresh...)
	}
	if wantPolicies {
		var stop []plugin.Lifecycle
		var fresh []startedPlugin
		policies, stop, fresh, err = reconcilePolicies(next, r.cur.Policies, r.plugins.PoliciesSnapshot(), r.opts)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		toStop = append(toStop, stop...)
		toStart = append(toStart, fresh...)
	}
	return sources, policies, toStart, toStop, nil
}

func probeTiming(keys []string) bool {
	for _, k := range keys {
		if strings.HasPrefix(k, "probe.") {
			return true
		}
	}
	return false
}

func specIndex(specs []config.PluginSpec) map[string]config.PluginSpec {
	out := make(map[string]config.PluginSpec, len(specs))
	for _, sp := range specs {
		out[sp.InstanceName()] = sp
	}
	return out
}

func reconcileSources(next *config.Config, oldSpecs []config.PluginSpec, have []pluginhost.Instance[plugin.TargetSource], opts pluginhost.Options) ([]pluginhost.Instance[plugin.TargetSource], []plugin.Lifecycle, []startedPlugin, error) {
	old := specIndex(oldSpecs)
	byName := map[string]pluginhost.Instance[plugin.TargetSource]{}
	for _, inst := range have {
		byName[inst.Name] = inst
	}
	var nextList []pluginhost.Instance[plugin.TargetSource]
	var start []startedPlugin
	seen := map[string]bool{}
	for _, sp := range next.Sources {
		name := sp.InstanceName()
		seen[name] = true
		if prev, ok := old[name]; ok && sameSpec(prev, sp) {
			if inst, ok := byName[name]; ok {
				nextList = append(nextList, inst)
				continue
			}
		}
		built, err := pluginhost.BuildSources(next, []config.PluginSpec{sp}, opts)
		if err != nil {
			return nil, nil, nil, err
		}
		if len(built) != 1 {
			return nil, nil, nil, fmt.Errorf("sources: %s was not built", name)
		}
		nextList = append(nextList, built[0])
		start = append(start, startedPlugin{kind: plugin.KindSource, name: name, label: "source " + name, lc: built[0].Plugin})
	}
	var stop []plugin.Lifecycle
	for _, inst := range have {
		if !seen[inst.Name] {
			stop = append(stop, inst.Plugin)
			continue
		}
		kept := false
		for _, n := range nextList {
			if n.Plugin == inst.Plugin {
				kept = true
				break
			}
		}
		if !kept {
			stop = append(stop, inst.Plugin)
		}
	}
	return nextList, stop, start, nil
}

func reconcilePolicies(next *config.Config, oldSpecs []config.PluginSpec, have []pluginhost.Instance[plugin.Policy], opts pluginhost.Options) ([]pluginhost.Instance[plugin.Policy], []plugin.Lifecycle, []startedPlugin, error) {
	old := specIndex(oldSpecs)
	byName := map[string]pluginhost.Instance[plugin.Policy]{}
	for _, inst := range have {
		byName[inst.Name] = inst
	}
	var nextList []pluginhost.Instance[plugin.Policy]
	var start []startedPlugin
	seen := map[string]bool{}
	for _, sp := range next.Policies {
		name := sp.InstanceName()
		seen[name] = true
		if prev, ok := old[name]; ok && sameSpec(prev, sp) {
			if inst, ok := byName[name]; ok {
				nextList = append(nextList, inst)
				continue
			}
		}
		built, err := pluginhost.BuildPolicies(next, []config.PluginSpec{sp}, opts)
		if err != nil {
			return nil, nil, nil, err
		}
		if len(built) != 1 {
			return nil, nil, nil, fmt.Errorf("policies: %s was not built", name)
		}
		nextList = append(nextList, built[0])
		start = append(start, startedPlugin{kind: plugin.KindPolicy, name: name, label: "policy " + name, lc: built[0].Plugin})
	}
	var stop []plugin.Lifecycle
	for _, inst := range have {
		if !seen[inst.Name] {
			stop = append(stop, inst.Plugin)
			continue
		}
		kept := false
		for _, n := range nextList {
			if n.Plugin == inst.Plugin {
				kept = true
				break
			}
		}
		if !kept {
			stop = append(stop, inst.Plugin)
		}
	}
	return nextList, stop, start, nil
}

// anomalySourceName is the flow source the detector was built with. An
// empty name means anomaly detection is off. Replacing that source is
// refused: the detector keeps the instance it started with.
func anomalySourceName(cfg *config.Config, sources []pluginhost.Instance[plugin.TargetSource]) string {
	if cfg == nil || cfg.Anomaly == nil {
		return ""
	}
	if cfg.Anomaly.Source != "" {
		return cfg.Anomaly.Source
	}
	var name string
	n := 0
	for _, s := range sources {
		if _, ok := s.Plugin.(plugin.FlowCounterSource); ok {
			name, n = s.Name, n+1
		}
	}
	if n == 1 {
		return name
	}
	return ""
}

func stopsNamed(stop []plugin.Lifecycle, have []pluginhost.Instance[plugin.TargetSource], name string) bool {
	for _, inst := range have {
		if inst.Name != name {
			continue
		}
		for _, lc := range stop {
			if lc == inst.Plugin {
				return true
			}
		}
	}
	return false
}
