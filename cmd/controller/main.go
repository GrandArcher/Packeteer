// Command controller is the Packeteer entrypoint.
//
// It loads and validates the config and plugins, then runs the probe engine.
// In inject mode, improvements from the decision engine are announced on the
// existing iBGP session. Observe and suggest announce nothing.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/time/rate"

	"github.com/GrandArcher/Packeteer/internal/announce"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/all"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/outage"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/vip"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// DefaultConfigPath is where the container image expects the mounted config.
const DefaultConfigPath = "/etc/packeteer/config.yaml"

// Environment variables.
const (
	ConfigEnv     = "PACKETEER_CONFIG"      // config path when -config is not given
	PluginDirEnv  = "PACKETEER_PLUGIN_DIR"  // overrides plugin_dir
	LogLevelEnv   = "PACKETEER_LOG_LEVEL"   // debug, info, warn, error; overrides log.level
	LogFormatEnv  = "PACKETEER_LOG_FORMAT"  // text or json; overrides log.format
	HTTPListenEnv = "PACKETEER_HTTP_LISTEN" // overrides http.listen; "off" disables
	HTTPUserEnv   = "PACKETEER_HTTP_USER"
	HTTPPassEnv   = "PACKETEER_HTTP_PASSWORD"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func newLogger(w io.Writer, level, format string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn", "warning":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	opt := &slog.HandlerOptions{Level: l}
	var h slog.Handler
	if strings.ToLower(format) == "json" {
		h = slog.NewJSONHandler(w, opt)
	} else {
		h = slog.NewTextHandler(w, opt)
	}
	return slog.New(h)
}

// applyRuntimeEnv overlays process environment on an already-validated
// config and validates again. An empty PACKETEER_HTTP_LISTEN does not
// change the file (unset and empty look the same); "off" disables HTTP.
func applyRuntimeEnv(cfg *config.Config, getenv func(string) string) error {
	if v := strings.TrimSpace(getenv(LogLevelEnv)); v != "" {
		cfg.Log.Level = v
	}
	if v := strings.TrimSpace(getenv(LogFormatEnv)); v != "" {
		cfg.Log.Format = v
	}
	if v := strings.TrimSpace(getenv(HTTPListenEnv)); v != "" {
		if strings.EqualFold(v, "off") {
			empty := ""
			cfg.HTTP.Listen = &empty
		} else {
			cfg.HTTP.Listen = &v
		}
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("environment: %w", err)
	}
	return nil
}

func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("controller", flag.ContinueOnError)
	fs.SetOutput(stderr)
	defaultPath := DefaultConfigPath
	if p := getenv(ConfigEnv); p != "" {
		defaultPath = p
	}
	path := fs.String("config", defaultPath, "path to the YAML config file (env "+ConfigEnv+")")
	check := fs.Bool("check", false, "validate config and plugins, print a summary, and exit")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "packeteer %s\n", version)
		return 0
	}

	cfg, err := config.Load(*path)
	if err != nil {
		fmt.Fprintf(stderr, "packeteer: refusing to start: %v\n", err)
		return 1
	}
	if err := applyRuntimeEnv(cfg, getenv); err != nil {
		fmt.Fprintf(stderr, "packeteer: refusing to start: %v\n", err)
		return 1
	}
	httpUser, httpPass := getenv(HTTPUserEnv), getenv(HTTPPassEnv)
	if (httpUser == "") != (httpPass == "") {
		fmt.Fprintf(stderr, "packeteer: refusing to start: set both %s and %s, or neither\n", HTTPUserEnv, HTTPPassEnv)
		return 1
	}
	log := newLogger(stderr, cfg.Log.Level, cfg.Log.Format)
	plugins, err := pluginhost.Build(cfg, pluginhost.Options{Logger: log, Getenv: getenv, PluginDir: getenv(PluginDirEnv)})
	if err != nil {
		fmt.Fprintf(stderr, "packeteer: refusing to start: plugins: %v\n", err)
		return 1
	}
	if err := checkVIPIntervals(cfg, plugins); err != nil {
		fmt.Fprintf(stderr, "packeteer: refusing to start: %v\n", err)
		return 1
	}
	if err := checkOutageIntervals(cfg, plugins); err != nil {
		fmt.Fprintf(stderr, "packeteer: refusing to start: %v\n", err)
		return 1
	}
	if err := checkTelemetryProviders(plugins); err != nil {
		fmt.Fprintf(stderr, "packeteer: refusing to start: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "packeteer %s: config %s loaded\n", version, *path)
	fmt.Fprintf(stdout, "mode: %s\n", cfg.Mode)
	fmt.Fprintf(stdout, "max_improvements: %d\n", *cfg.MaxImprovements)
	fmt.Fprintf(stdout, "providers (%d):\n", len(cfg.Providers))
	for _, p := range cfg.Providers {
		fmt.Fprintf(stdout, "  - %s source_ip=%s next_hop=%s\n", p.Name, p.SourceIP, p.NextHop)
	}
	if len(cfg.BGP.Neighbors) == 0 {
		fmt.Fprintln(stdout, "bgp: disabled (no bgp.neighbors)")
	} else {
		fmt.Fprintf(stdout, "bgp neighbors (%d, learn-only):\n", len(cfg.BGP.Neighbors))
		for _, n := range cfg.BGP.Neighbors {
			fmt.Fprintf(stdout, "  - %s %s\n", n.Address, n.Description)
		}
	}
	fmt.Fprintf(stdout, "plugins (%d):\n", len(plugins.Summary()))
	for _, line := range plugins.Summary() {
		fmt.Fprintf(stdout, "  - %s\n", line)
	}
	switch {
	case cfg.Mode == config.ModeInject:
		fmt.Fprintf(stdout, "announce: %s local_pref=%d\n", plugins.Announcer.Type, cfg.LocalPref)
	case plugins.Announcer != nil:
		fmt.Fprintln(stdout, "announce: configured but inactive (mode is not inject)")
	default:
		fmt.Fprintln(stdout, "announce: disabled")
	}
	fmt.Fprintf(stdout, "log: %s %s\n", cfg.Log.Level, cfg.Log.Format)
	if cfg.HTTPListen() == "" {
		fmt.Fprintln(stdout, "http: disabled")
	} else {
		fmt.Fprintf(stdout, "http: %s\n", cfg.HTTPListen())
		if httpUser != "" {
			fmt.Fprintf(stdout, "http auth: basic (user %s)\n", httpUser)
		} else {
			fmt.Fprintln(stdout, "http auth: off")
		}
	}
	if *check {
		fmt.Fprintln(stdout, "check: ok (no probes sent, no BGP sessions opened)")
		return 0
	}
	return daemon(ctx, cfg, plugins, log, httpUser, httpPass)
}

func daemon(ctx context.Context, cfg *config.Config, plugins *pluginhost.Set, log *slog.Logger, httpUser, httpPass string) int {
	col := httpapi.NewCollector(version, cfg.Mode, cfg.Providers)
	if addr := cfg.HTTPListen(); addr != "" {
		srv, err := httpapi.New(httpapi.Options{
			Addr: addr, User: httpUser, Password: httpPass, Snapshot: col.Snapshot, Logger: log,
		})
		if err != nil {
			log.Error("refusing to start", "err", err)
			return 1
		}
		if err := srv.Start(); err != nil {
			log.Error("refusing to start", "err", err)
			return 1
		}
		defer func() {
			stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := srv.Shutdown(stopCtx); err != nil {
				log.Error("http shutdown", "err", err)
			}
		}()
	} else {
		log.Info("http disabled")
	}

	view, err := newRIB(cfg, log)
	if err != nil {
		log.Error("refusing to start", "err", err)
		return 1
	}
	decider, err := newDecider(cfg, plugins)
	if err != nil {
		log.Error("refusing to start", "err", err)
		return 1
	}
	ctl, err := newController(cfg, plugins, view, log)
	if err != nil {
		log.Error("refusing to start", "err", err)
		return 1
	}
	if view != nil {
		if err := view.Start(ctx); err != nil {
			log.Error("refusing to start", "err", err)
			return 1
		}
		defer func() { _ = view.Stop(context.Background()) }()
		go logRIB(ctx, view, log)
	}
	if cfg.Mode == config.ModeInject {
		if view == nil || view.Server() == nil {
			log.Error("refusing to start", "err", "inject mode requires an iBGP session")
			return 1
		}
		if err := ctl.Bind(view.Server()); err != nil {
			log.Error("refusing to start", "err", err)
			return 1
		}
	}

	kick := make(chan struct{}, 1)
	poke := func() {
		select {
		case kick <- struct{}{}:
		default:
		}
	}
	if view != nil {
		view.OnChange(poke)
	}
	var engine *probe.Engine
	onRound := func() {
		poke()
		noteOutages(plugins, engine)
	}
	engine, err = newEngine(cfg, plugins, log, onRound)
	if err != nil {
		log.Error("refusing to start", "err", err)
		return 1
	}
	wirePrefixLookup(plugins, view)
	wireLearnedRoutes(plugins, view)
	wireOutage(plugins, engine, view, log)
	col.SetTelemetry(func() []plugin.Usage { return collectTelemetry(context.Background(), plugins) })
	col.Attach(engine, decider, view)
	if err := plugins.Start(ctx); err != nil {
		log.Error("refusing to start", "err", err)
		return 1
	}
	col.SetStarted(true)
	defer col.SetStarted(false)
	if len(plugins.Sources) == 0 {
		log.Warn("no target sources configured; nothing to probe (add a `sources:` entry)")
	}

	loopCtx, loopCancel := context.WithCancel(ctx)
	var loopWG sync.WaitGroup
	loopWG.Add(1)
	go func() {
		defer loopWG.Done()
		// The ticker is independent of probe rounds and RIB updates. A round
		// that never completes (a prober or target source that ignores
		// cancellation) must still withdraw once measurements exceed
		// MaxResultAge.
		decideLoop(loopCtx, cfg.Probe.Interval, kick, func(now time.Time) {
			runDecision(now, decider, decisionInput(loopCtx, engine, view, plugins), ctl, log, cfg.Mode)
		})
	}()

	announcing := "disabled"
	if cfg.Mode == config.ModeInject {
		announcing = plugins.Announcer.Type
	}
	log.Info("packeteer running", "version", version, "mode", cfg.Mode, "bgp_neighbors", len(cfg.BGP.Neighbors), "announce", announcing)
	_ = engine.Run(ctx)

	log.Info("shutting down")
	loopCancel()
	loopWG.Wait()
	stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Withdraw while the session is still up, then stop plugins (the announcer
	// withdraws again) and finally drop the session. Graceful restart is never
	// enabled, so a missed withdraw still disappears with the session.
	if err := ctl.WithdrawAll(stopCtx); err != nil {
		log.Error("withdraw on shutdown", "err", err)
	}
	if err := plugins.Stop(stopCtx); err != nil {
		log.Error("plugin shutdown", "err", err)
		return 1
	}
	return 0
}

// ribGate is the RIB surface the announcer controller consults.
type ribGate struct{ v *rib.View }

func (g ribGate) Ready() bool { return g.v != nil && g.v.Ready() }

func (g ribGate) Contains(p netip.Prefix) bool {
	if g.v == nil {
		return false
	}
	_, ok := g.v.Exact(p)
	return ok
}

func newController(cfg *config.Config, plugins *pluginhost.Set, view *rib.View, log *slog.Logger) (*announce.Controller, error) {
	var ann plugin.Announcer
	if plugins.Announcer != nil {
		ann = plugins.Announcer.Plugin
	}
	ac := announce.Config{
		Mode:            cfg.Mode,
		LocalPref:       cfg.LocalPref,
		Community:       cfg.PacketeerCommunity,
		MaxImprovements: *cfg.MaxImprovements,
		NextHops:        map[string]netip.Addr{},
	}
	for _, p := range cfg.Providers {
		nh, err := parseAddr(p.NextHop)
		if err != nil {
			return nil, err
		}
		ac.NextHops[p.Name] = nh
	}
	for _, s := range cfg.Allowlist.Prefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		ac.Allowlist = append(ac.Allowlist, p)
	}
	return announce.New(ac, ann, ribGate{view}, log)
}

func newEngine(cfg *config.Config, plugins *pluginhost.Set, log *slog.Logger, onRound func()) (*probe.Engine, error) {
	var providers []probe.Provider
	for _, p := range cfg.Providers {
		src, err := parseAddr(p.SourceIP)
		if err != nil {
			return nil, err
		}
		providers = append(providers, probe.Provider{Name: p.Name, Source: src})
	}
	var probers []probe.NamedProber
	for _, p := range plugins.Probers {
		probers = append(probers, probe.NamedProber{Name: p.Name, Prober: p.Plugin})
	}
	var sources []probe.NamedSource
	for _, s := range plugins.Sources {
		sources = append(sources, probe.NamedSource{Name: s.Name, Source: s.Plugin})
	}
	burst := cfg.Probe.RateLimitPPS
	need := cfg.Probe.Packets
	if cfg.Probe.RetryPackets > need {
		need = cfg.Probe.RetryPackets
	}
	if burst < need {
		burst = need
	}
	return probe.New(providers, probers, sources, probe.Options{
		Interval:             cfg.Probe.Interval,
		Timeout:              cfg.Probe.Timeout,
		Packets:              cfg.Probe.Packets,
		Workers:              cfg.Probe.Workers,
		PerTargetConcurrency: cfg.Probe.PerTargetConcurrency,
		RoundTimeout:         maxResultAge(cfg),
		RetryLossPct:         cfg.Probe.RetryLossPct,
		RetryPackets:         cfg.Probe.RetryPackets,
		Limiter:              rate.NewLimiter(rate.Limit(cfg.Probe.RateLimitPPS), burst),
		Logger:               log,
		OnResult:             func(r probe.Result) { logResult(log, r) },
		OnRound:              onRound,
	})
}

// decideLoop evaluates on kick (a finished probe round or a RIB change)
// and on a staleness ticker. The ticker is what withdraws improvements
// when no round ever completes.
func decideLoop(ctx context.Context, interval time.Duration, kick <-chan struct{}, eval func(now time.Time)) {
	if interval <= 0 {
		interval = time.Second
	}
	staleness := time.NewTicker(interval)
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
	}
}

// runDecision applies one evaluation to the announcer.
func runDecision(now time.Time, decider *policy.Engine, in policy.Input, ctl *announce.Controller, log *slog.Logger, mode string) {
	changes := decider.Evaluate(in, now)
	logChanges(log, mode, changes)
	actx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := ctl.Sync(actx, decider.Improvements()); err != nil {
		log.Error("announce", "err", err)
	}
}

// maxResultAge is how old a measurement may be before Decide treats it as
// stale. It is also the overall probe-round deadline, so a stuck round
// cannot outlive the freshness window.
func maxResultAge(cfg *config.Config) time.Duration {
	pkts := cfg.Probe.Packets
	if cfg.Probe.RetryLossPct > 0 && cfg.Probe.RetryPackets > 0 {
		pkts += cfg.Probe.RetryPackets
	}
	return 3*cfg.Probe.Interval + time.Duration(pkts)*cfg.Probe.Timeout
}

func logResult(log *slog.Logger, r probe.Result) {
	if !r.OK() {
		log.Warn("probe failed", "provider", r.Provider, "prefix", r.Prefix, "target", r.Target, "err", r.Err)
		return
	}
	s := r.Stats
	log.Info("probe", "provider", r.Provider, "prefix", r.Prefix, "target", r.Target, "prober", r.Prober,
		"loss_pct", s.LossPct, "rtt_avg", s.RTTAvg, "rtt_min", s.RTTMin, "rtt_max", s.RTTMax, "jitter", s.Jitter,
		"sent", s.Sent, "received", s.Received)
}

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
	for _, src := range plugins.Sources {
		if s, ok := src.Plugin.(routeSnapshotSetter); ok {
			s.SetRouteSnapshot(fn)
		}
	}
}

// checkVIPIntervals rejects a VIP cadence that is not inside the staleness
// window. A longer interval leaves that prefix permanently stale, and the
// controller withdraws any improvement on it.
// noteOutages correlates the round that just finished. A new incident
// wakes the probe loop so the re-queued prefixes are measured without
// waiting out probe.interval. Observe and inject both call this; the
// source only adds probe targets.
func noteOutages(plugins *pluginhost.Set, engine *probe.Engine) {
	if plugins == nil || engine == nil {
		return
	}
	now := time.Now()
	for _, src := range plugins.Sources {
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
	routes := view.Routes()
	out := make([]outage.Route, 0, len(routes))
	for _, rt := range routes {
		if !rt.Prefix.IsValid() || rt.Prefix.Bits() == 0 {
			continue
		}
		out = append(out, outage.Route{
			Prefix:   rt.Prefix,
			Provider: rt.Provider,
			ASPath:   append([]uint32(nil), rt.ASPath...),
		})
	}
	s.gen, s.ok, s.out = g, true, out
	return out
}

// wireOutage gives the outage source the probe results and the learned
// RIB, and fans its events out to the configured notifiers. A missing or
// unready RIB yields no routes, so AS correlation stays quiet. Notifier
// delivery is asynchronous so a slow webhook cannot hold the probe loop.
func wireOutage(plugins *pluginhost.Set, engine *probe.Engine, view *rib.View, log *slog.Logger) {
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
	notify := func(ev plugin.Event) {
		if len(plugins.Notifiers) == 0 {
			return
		}
		go deliverOutage(plugins, log, ev)
	}
	for _, src := range plugins.Sources {
		s, ok := src.Plugin.(*outage.Source)
		if !ok {
			continue
		}
		s.SetSnapshots(samples, routes)
		s.SetNotify(notify)
	}
}

func deliverOutage(plugins *pluginhost.Set, log *slog.Logger, ev plugin.Event) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, n := range plugins.Notifiers {
		if err := n.Plugin.Notify(ctx, ev); err != nil && log != nil {
			log.Warn("notify", "notifier", n.Name, "kind", ev.Kind, "err", err)
		}
	}
}

func outageSamples(rs []probe.Result) []outage.Sample {
	out := make([]outage.Sample, len(rs))
	for i, r := range rs {
		out[i] = outage.Sample{
			Provider: r.Provider,
			Prefix:   r.Prefix,
			LossPct:  r.Stats.LossPct,
			RTT:      r.Stats.RTTAvg,
			Failed:   !r.OK(),
			Time:     r.Time,
		}
	}
	return out
}

// checkOutageIntervals rejects a reprobe cadence that is not faster than
// the normal probe interval, or that is outside the staleness window. A
// longer interval would leave the re-queued prefixes stale, and the
// controller would withdraw any improvement on them.
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

func checkOutageIntervals(cfg *config.Config, plugins *pluginhost.Set) error {
	if plugins == nil {
		return nil
	}
	window := maxResultAge(cfg)
	var errs []error
	for _, src := range plugins.Sources {
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

func checkVIPIntervals(cfg *config.Config, plugins *pluginhost.Set) error {
	if plugins == nil {
		return nil
	}
	window := maxResultAge(cfg)
	var errs []error
	for _, src := range plugins.Sources {
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
	for _, src := range plugins.Sources {
		if s, ok := src.Plugin.(prefixLookup); ok {
			s.SetPrefixLookup(fn)
		}
	}
}

// newRIB builds the learn-only RIB view, or returns nil when no BGP
// neighbors are configured.
func newRIB(cfg *config.Config, log *slog.Logger) (*rib.View, error) {
	if len(cfg.BGP.Neighbors) == 0 {
		return nil, nil
	}
	rid, err := parseAddr(cfg.RouterID)
	if err != nil {
		return nil, err
	}
	providers := map[netip.Addr]string{}
	for _, p := range cfg.Providers {
		nh, err := parseAddr(p.NextHop)
		if err != nil {
			return nil, err
		}
		providers[nh] = p.Name
	}
	var nbrs []rib.Neighbor
	for _, n := range cfg.BGP.Neighbors {
		a, err := parseAddr(n.Address)
		if err != nil {
			return nil, err
		}
		nb := rib.Neighbor{Address: a, Port: uint16(n.Port), Passive: n.Passive, Description: n.Description}
		if n.LocalAddress != "" {
			if nb.LocalAddress, err = parseAddr(n.LocalAddress); err != nil {
				return nil, err
			}
		}
		nbrs = append(nbrs, nb)
	}
	listen := int32(cfg.BGP.ListenPort)
	if listen == 0 {
		listen = -1
	}
	return rib.New(rib.Options{ASN: cfg.ASN, RouterID: rid, ListenPort: listen,
		ListenAddresses: cfg.BGP.ListenAddresses, Neighbors: nbrs, Providers: providers, Logger: log})
}

func logRIB(ctx context.Context, v *rib.View, log *slog.Logger) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			log.Info("rib", "ready", v.Ready(), "prefixes", v.Len())
		}
	}
}

func newDecider(cfg *config.Config, plugins *pluginhost.Set) (*policy.Engine, error) {
	if plugins.Scorer == nil {
		return nil, fmt.Errorf("no scorer configured")
	}
	pc := policy.Config{
		Mode:            cfg.Mode,
		MinLossDeltaPct: cfg.Thresholds.MinLossDeltaPct,
		MinRTTDelta:     time.Duration(cfg.Thresholds.MinRTTDeltaMs * float64(time.Millisecond)),
		HoldTime:        cfg.HoldTime,
		MaxImprovements: *cfg.MaxImprovements,
		// A result older than ~3 rounds is stale. The decision loop
		// re-checks this on a ticker even when no round completes.
		MaxResultAge: maxResultAge(cfg),
		Excluded:     map[string]bool{},
	}
	if cfg.ImprovementTTL > 0 {
		pc.ImprovementTTL = cfg.ImprovementTTL
	}
	for _, p := range cfg.Providers {
		if p.Exclude {
			pc.Excluded[p.Name] = true
		}
		pc.Providers = append(pc.Providers, policy.ProviderPolicy{
			Name: p.Name, Group: p.Group, Precedence: p.Precedence, CCDisable: p.CCDisable,
		})
	}
	for _, s := range cfg.Allowlist.Prefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		pc.Allowlist = append(pc.Allowlist, p)
	}
	return policy.NewEngine(pc, plugins.Scorer.Plugin), nil
}

// decisionInput snapshots probe results, provider health, the RIB view,
// and, when the scorer plans commit moves, telemetry and flow volumes.
// A weighted scorer does not implement planning, so those reads are skipped.
func decisionInput(ctx context.Context, engine *probe.Engine, view *rib.View, plugins *pluginhost.Set) policy.Input {
	in := policy.Input{Results: engine.Results(), ProviderUp: map[string]bool{}, Native: map[netip.Prefix]string{}}
	for _, p := range engine.Providers() {
		in.ProviderUp[p.Name] = p.Up
	}
	if view != nil {
		in.RIBEnabled, in.RIBReady = true, view.Ready()
		for _, r := range in.Results {
			if rt, ok := view.Exact(r.Prefix); ok {
				in.Native[r.Prefix] = rt.Provider
			}
		}
	}
	fillPlannerInputs(ctx, &in, plugins)
	return in
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
	if in == nil || !scorerPlans(plugins) {
		return
	}
	in.Usage = collectTelemetry(ctx, plugins)
	in.VolumeMbps = collectVolumes(ctx, plugins)
}

// collectVolumes reads optional volume reports from target sources. The
// largest rate wins when two sources name one prefix. A source that does
// not implement VolumeSource is skipped. This does not announce.
func collectVolumes(ctx context.Context, plugins *pluginhost.Set) map[netip.Prefix]float64 {
	if plugins == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var out map[netip.Prefix]float64
	for _, src := range plugins.Sources {
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
				out = map[netip.Prefix]float64{}
			}
			if mbps > out[row.Prefix] {
				out[row.Prefix] = mbps
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
