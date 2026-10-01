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
	"maps"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/time/rate"

	"github.com/GrandArcher/Packeteer/internal/announce"
	"github.com/GrandArcher/Packeteer/internal/anomaly"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/inbound"
	"github.com/GrandArcher/Packeteer/internal/mitigation"
	"github.com/GrandArcher/Packeteer/internal/notify"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/all"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/outage"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/traceroute"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/vip"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/internal/subscribe"
	"github.com/GrandArcher/Packeteer/internal/troubleshoot"
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
	// The first admin when auth is on (#32). Created only when no user
	// has that name; the user defaults to "admin".
	AdminUserEnv = "PACKETEER_ADMIN_USER"
	AdminPassEnv = "PACKETEER_ADMIN_PASSWORD"
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
	notifyTest := fs.Bool("notify-test", false, "send a notifier.test event to every configured notifier and exit (no probes, no BGP)")
	backup := fs.String("backup", "", "write the config and stored history to this archive and exit (no probes, no BGP; never overwrites)")
	restoreFrom := fs.String("restore", "", "restore stored history from this archive into its config's storage and exit (stop the controller first)")
	restoreConfig := fs.String("restore-config", "", "with -restore, also write the archived config to this path")
	force := fs.Bool("force", false, "with -restore, replace existing history and config files")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "packeteer %s\n", version)
		return 0
	}
	if *restoreFrom != "" {
		if *backup != "" {
			fmt.Fprintln(stderr, "packeteer: -backup and -restore are exclusive")
			return 2
		}
		return runRestore(ctx, *restoreFrom, *restoreConfig, *force, getenv, stdout, stderr)
	}
	if *restoreConfig != "" || *force {
		fmt.Fprintln(stderr, "packeteer: -restore-config and -force need -restore")
		return 2
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
	if *backup != "" {
		return runBackup(ctx, *path, cfg, *backup, getenv, stdout, stderr)
	}
	httpUser, httpPass := getenv(HTTPUserEnv), getenv(HTTPPassEnv)
	if (httpUser == "") != (httpPass == "") {
		fmt.Fprintf(stderr, "packeteer: refusing to start: set both %s and %s, or neither\n", HTTPUserEnv, HTTPPassEnv)
		return 1
	}
	log := newLogger(stderr, cfg.Log.Level, cfg.Log.Format)
	plugins, err := preflight(cfg, log, getenv, httpUser, false)
	if err != nil {
		fmt.Fprintf(stderr, "packeteer: refusing to start: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "packeteer %s: config %s loaded\n", version, *path)
	fmt.Fprintf(stdout, "mode: %s\n", cfg.Mode)
	fmt.Fprintf(stdout, "max_improvements: %d\n", *cfg.MaxImprovements)
	fmt.Fprintf(stdout, "providers (%d):\n", len(cfg.Providers))
	for _, p := range cfg.Providers {
		bmp := ""
		if p.BMP != "" && p.BMP != config.BMPOff {
			bmp = " bmp=" + p.BMP
		}
		ix := ""
		if p.Exchange != "" {
			ix = fmt.Sprintf(" exchange=%s asn=%d", p.Exchange, p.PeerASN)
		}
		if cfg.Remote(p) {
			fmt.Fprintf(stdout, "  - %s domain=%s next_hop=%s (measured by the peer there)\n", p.Name, p.Domain, p.NextHop)
			continue
		}
		fmt.Fprintf(stdout, "  - %s source_ip=%s next_hop=%s%s%s\n", p.Name, p.SourceIP, p.NextHop, bmp, ix)
	}
	for _, ex := range cfg.Exchanges {
		fmt.Fprintf(stdout, "exchange %s: lans=%s peers=%d (route-checked)\n", ex.Name, strings.Join(ex.LANs, ","), len(ex.Peers))
	}
	if len(cfg.BGP.Neighbors) == 0 {
		fmt.Fprintln(stdout, "bgp: disabled (no bgp.neighbors)")
	} else {
		fmt.Fprintf(stdout, "bgp neighbors (%d, learn-only):\n", len(cfg.BGP.Neighbors))
		for _, n := range cfg.BGP.Neighbors {
			fmt.Fprintf(stdout, "  - %s %s%s\n", n.Address, n.Description, routerSummary(n))
		}
		fmt.Fprintf(stdout, "bgp as_path: %s (neighbors reload online on SIGHUP)\n", cfg.BGP.ASPath)
	}
	fmt.Fprintf(stdout, "plugins (%d):\n", len(plugins.Summary()))
	for _, line := range plugins.Summary() {
		fmt.Fprintf(stdout, "  - %s\n", line)
	}
	switch {
	case cfg.Mode == config.ModeInject:
		fmt.Fprintf(stdout, "announce: %s local_pref=%d\n", plugins.Announcer.Type, cfg.LocalPref)
		if ms := cfg.MoreSpecific; ms != nil && ms.Enabled {
			fmt.Fprintf(stdout, "announce more_specific: learned more-specifics only, max_routes=%d\n", ms.MaxRoutes)
		}
	case plugins.Announcer != nil:
		fmt.Fprintln(stdout, "announce: configured but inactive (mode is not inject)")
	default:
		fmt.Fprintln(stdout, "announce: disabled")
	}
	if in := cfg.Inbound; in != nil {
		fmt.Fprintf(stdout, "inbound: %s prefixes=%d local_pref=%d release_pct=%g\n", in.Mode, len(in.Prefixes), in.LocalPref, in.ReleasePct)
		if pf := in.Performance; pf != nil {
			fmt.Fprintf(stdout, "inbound performance: loss_pct=%g latency_ms=%g min_prefixes=%d release_pct=%g\n", pf.LossPct, pf.LatencyMs, pf.MinPrefixes, pf.ReleasePct)
		}
		if d := in.Damping; d.Disabled {
			fmt.Fprintln(stdout, "inbound damping: off")
		} else {
			fmt.Fprintf(stdout, "inbound damping: confirm=%s backoff=%g max_hold=%s\n", d.Confirm, d.Backoff, d.MaxHold)
		}
		if len(in.Moderated) > 0 {
			fmt.Fprintf(stdout, "inbound moderated: %s\n", strings.Join(in.Moderated, ","))
		}
	}
	if m := cfg.Mitigation; m != nil {
		fmt.Fprintf(stdout, "mitigation: %s allowlist=%d max_rules=%d default_ttl=%s max_ttl=%s local_pref=%d\n",
			m.Mode, len(m.Allowlist), m.MaxRules, m.DefaultTTL, m.MaxTTL, m.LocalPref)
		if m.GeoIPDB != "" {
			fmt.Fprintf(stdout, "mitigation geoip_db: %s\n", m.GeoIPDB)
		}
	}
	if a := cfg.Anomaly; a != nil {
		fmt.Fprintf(stdout, "anomaly: detector=%s interval=%s rules=%d max_active=%d max_actions_per_hour=%d (acts only through mitigation, for an explicit rule)\n",
			a.Detector.Type, a.Interval, len(a.Rules), a.MaxActive, a.MaxActionsPerHour)
	}
	if el := plugins.Elector; el != nil {
		fmt.Fprintf(stdout, "ha: %s id=%s (standby until elected; only the active instance announces)\n", el.Type, el.Plugin.Status().ID)
	}
	fmt.Fprintf(stdout, "log: %s %s\n", cfg.Log.Level, cfg.Log.Format)
	if cfg.HTTPListen() == "" {
		fmt.Fprintln(stdout, "http: disabled")
	} else {
		fmt.Fprintf(stdout, "http: %s\n", cfg.HTTPListen())
		switch {
		case cfg.AuthEnabled():
			sso := "off"
			if plugins.SSO != nil {
				sso = plugins.SSO.Type
			}
			fmt.Fprintf(stdout, "http auth: rbac (users, tokens, and audit in storage %s; sso %s)\n", plugins.Storage.Type, sso)
		case httpUser != "":
			fmt.Fprintf(stdout, "http auth: basic (user %s)\n", httpUser)
		default:
			fmt.Fprintln(stdout, "http auth: off")
		}
		if len(cfg.HTTP.AllowFrom) > 0 {
			fmt.Fprintf(stdout, "http allow_from: %s\n", strings.Join(cfg.HTTP.AllowFrom, ","))
		}
		if cfg.HTTP.ConfigEditor {
			fmt.Fprintln(stdout, "http config_editor: on (admin only; writes this file after the start checks; applies on restart, or SIGHUP for bgp.neighbors)")
		}
	}
	for _, sub := range cfg.ReportSubscriptions {
		fmt.Fprintf(stdout, "report subscription %s: %s %s at %s UTC, %d days, notifier %s\n", sub.Name, sub.Report, sub.Schedule, sub.At, sub.Days, sub.Notifier)
	}
	if *notifyTest {
		return sendTestEvent(ctx, plugins, stdout)
	}
	if *check {
		fmt.Fprintln(stdout, "check: ok (no probes sent, no BGP sessions opened)")
		return 0
	}
	return daemon(ctx, cfg, plugins, log, httpUser, httpPass, *path, getenv)
}

// preflight builds the plugin set and runs every check the controller runs
// before it starts. It starts nothing. The config editor (#34) runs it on
// a candidate file too, with checkOnly set: no exec plugin command runs.
func preflight(cfg *config.Config, log *slog.Logger, getenv func(string) string, httpUser string, checkOnly bool) (*pluginhost.Set, error) {
	plugins, err := pluginhost.Build(cfg, pluginhost.Options{Logger: log, Getenv: getenv, PluginDir: getenv(PluginDirEnv), CheckOnly: checkOnly})
	if err != nil {
		return nil, fmt.Errorf("plugins: %w", err)
	}
	if err := checkVIPIntervals(cfg, plugins); err != nil {
		return nil, err
	}
	if err := checkOutageIntervals(cfg, plugins); err != nil {
		return nil, err
	}
	if a := cfg.Anomaly; a != nil {
		if _, _, err := anomalySource(a, plugins); err != nil {
			return nil, err
		}
	}
	if err := checkTelemetryProviders(plugins); err != nil {
		return nil, err
	}
	if err := checkAuth(cfg, plugins, httpUser, getenv); err != nil {
		return nil, err
	}
	if err := checkSubscriptions(cfg, plugins); err != nil {
		return nil, err
	}
	return plugins, nil
}

func daemon(ctx context.Context, cfg *config.Config, plugins *pluginhost.Set, log *slog.Logger, httpUser, httpPass, path string, getenv func(string) string) int {
	// SIGHUP reloads bgp.neighbors online (#27). Registered first: Go's
	// default for SIGHUP ends the process.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	ctx, stopDaemon := context.WithCancel(ctx)
	defer stopDaemon()
	kick := make(chan struct{}, 1)
	poke := func() {
		select {
		case kick <- struct{}{}:
		default:
		}
	}
	col := httpapi.NewCollector(version, cfg.Mode, cfg.Providers)
	maint := newMaintenanceControl(plugins, log, poke)
	if mc, ok := maint.(*maintenanceControl); ok {
		if mc.CanOpen() {
			log.Info("on-demand maintenance windows are kept in memory only; windows opened through the API before a restart are gone")
		}
		go watchMaintenance(ctx, mc.Active, maintenanceWatchInterval, log, poke)
	}
	// The recorder is built before the RIB view exists; describe reads it
	// through this variable once it is set.
	var view *rib.View
	rec := newRecorder(cfg, plugins, log, func() *rib.View { return view })
	var reports httpapi.ReportSource
	if rec != nil {
		reports = rec
	}
	// inb is built with the RIB view below; the API reads it through this
	// variable.
	var inb *inbound.Controller
	var inboundStatus func() inbound.Status
	if cfg.Inbound != nil {
		inboundStatus = func() inbound.Status { return inb.Status() }
	}
	// Threat mitigation (#28) is built before the HTTP server, which adds
	// and removes its rules. It needs the RIB view only to sync.
	mit, merr := newMitigation(cfg, plugins, log)
	if merr != nil {
		log.Error("refusing to start", "err", merr)
		return 1
	}
	var mitAPI httpapi.MitigationControl
	if mit != nil {
		mitAPI = mitigationControl{mit: mit, poke: poke}
	}
	// Anomaly detection (#33) acts only through mit, for explicit rules.
	anom, aerr := newAnomaly(cfg, plugins, mit, poke, log)
	if aerr != nil {
		log.Error("refusing to start", "err", aerr)
		return 1
	}
	var anomAPI func() anomaly.Status
	if anom != nil {
		anomAPI = anom.Status
	}
	tools, terr := newTools(cfg, plugins)
	if terr != nil {
		log.Error("refusing to start", "err", terr)
		return 1
	}
	fed := newFedState(cfg, plugins)
	var haStatus func() plugin.ElectorStatus
	if el := plugins.Elector; el != nil {
		haStatus = func() plugin.ElectorStatus {
			st := el.Plugin.Status()
			st.Type = el.Type
			return st
		}
	}
	// Built before the HTTP server: the audit log goes to the notifiers.
	dispatch := newDispatcher(plugins, notify.Options{Logger: log})
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = dispatch.Close(closeCtx)
	}()
	audit := newAuditor(plugins, dispatch, log)
	authSvc, aerr := newAuthService(cfg, plugins, log)
	if aerr != nil {
		log.Error("refusing to start", "err", aerr)
		return 1
	}
	// Remaining UI parity (#34). None of these announces.
	var subs *subscribe.Scheduler
	if rec != nil {
		var serr error
		if subs, serr = newSubscriptions(cfg, plugins, rec, log); serr != nil {
			log.Error("refusing to start", "err", serr)
			return 1
		}
	}
	var subsAPI httpapi.Subscriptions
	if subs != nil {
		subsAPI = subs
	}
	editor, eerr := newConfigEditor(cfg, path, getenv, httpUser)
	if eerr != nil {
		log.Error("refusing to start", "err", eerr)
		return 1
	}
	var editorAPI httpapi.ConfigEditor
	if editor != nil {
		editorAPI = editor
		if httpUser == "" && authSvc == nil {
			log.Warn("http.config_editor is on but neither auth nor basic auth is: the editor stays off")
		}
	}
	if addr := cfg.HTTPListen(); addr != "" {
		srv, err := httpapi.New(httpapi.Options{
			Addr: addr, User: httpUser, Password: httpPass, Snapshot: col.Snapshot, Logger: log,
			Auth: authSvc, Audit: audit, AllowFrom: cfg.HTTPAllowFrom(),
			Maintenance: maint, Reports: reports, Tools: tools, Inbound: inboundStatus, Mitigation: mitAPI, Anomaly: anomAPI,
			Federation: fed.status, HA: haStatus,
			ConfigEditor: editorAPI, Dashboards: dashboardStore(plugins), Subscriptions: subsAPI,
			Setup: setupInfo(cfg, plugins),
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
	if view != nil && mitigationFlowSpec(cfg, plugins) {
		// Before Start: the sessions offer the FlowSpec families (#28).
		view.EnableFlowSpec()
	}
	decider, err := newDecider(cfg, plugins)
	if err != nil {
		log.Error("refusing to start", "err", err)
		return 1
	}
	// The two controllers share max_improvements, so each reads the other's
	// count. ctl is assigned right below; Active is nil-safe until then.
	var ctl *announce.Controller
	if err := setMitigationRIB(mit, view); err != nil {
		log.Error("refusing to start", "err", err)
		return 1
	}
	setAnomalyRIB(anom, view)
	inb, err = newInbound(cfg, plugins, view, func() int { return ctl.Active() }, mit, log)
	if err != nil {
		log.Error("refusing to start", "err", err)
		return 1
	}
	ctl, err = newController(cfg, plugins, view, inb, mit, log)
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
		if err := bindInbound(cfg, plugins, view.Server()); err != nil {
			log.Error("refusing to start", "err", err)
			return 1
		}
		if err := bindMitigation(cfg, plugins, view.Server()); err != nil {
			log.Error("refusing to start", "err", err)
			return 1
		}
	}

	if view != nil {
		view.OnChange(poke)
		tools.SetRIB(view)
	}
	var engine *probe.Engine
	onRound := func() {
		poke()
		noteOutages(plugins, engine)
	}
	// rec is read here, not captured by value: a recorder that fails to
	// start below is dropped before the first probe.
	onProbe := func(r probe.Result) {
		if rec != nil {
			rec.Probe(r)
		}
	}
	engine, err = newEngine(cfg, plugins, log, onRound, onProbe)
	if err != nil {
		log.Error("refusing to start", "err", err)
		return 1
	}
	watch := newEventWatch(dispatch, cfg.Mode)
	if err := wireRIBSources(plugins, view); err != nil {
		log.Error("refusing to start", "err", err)
		return 1
	}
	wirePrefixLookup(plugins, view)
	wireLearnedRoutes(plugins, view)
	wireOutage(plugins, engine, view, dispatch)
	col.SetTelemetry(func() []plugin.Usage { return collectTelemetry(context.Background(), plugins) })
	col.Attach(engine, decider, view)
	wireExchanges(cfg, col, view)
	// Active/standby (#31): registered before the elector starts. A
	// standby withdraws everything, runs no decisions, and announces
	// nothing; the announce controllers check the same gate.
	var haView haRIB
	if view != nil {
		haView = view
	}
	ha := newHAControl(plugins, log, haView, func(ctx context.Context) error {
		return errors.Join(mit.WithdrawAll(ctx), inb.WithdrawAll(ctx), ctl.WithdrawAll(ctx))
	}, poke, watch.emit)
	if err := plugins.Start(ctx); err != nil {
		log.Error("refusing to start", "err", err)
		return 1
	}
	bootstrapAdmin(ctx, authSvc, audit, getenv, log)
	if rec != nil {
		// History is optional: a store that cannot be read leaves the core
		// loop running without reports.
		if err := rec.Start(ctx); err != nil {
			log.Error("history disabled", "err", err)
			rec = nil
		}
	}
	if subs != nil && rec != nil {
		go subs.Run(ctx)
	}
	col.SetStarted(true)
	defer col.SetStarted(false)
	watch.emit(time.Now(), plugin.EventControllerStarted, "packeteer "+version+" started in "+cfg.Mode+" mode",
		map[string]string{"mode": cfg.Mode, "version": version})
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
		leading := false
		decideLoop(loopCtx, cfg.Probe.Interval, kick, func(now time.Time) {
			if !ha.active() {
				if leading {
					// Stepped down: no intent survives into a later
					// takeover.
					decider.Reset()
					leading = false
				}
				mitChanges, err := standbyRound(now, ctl, inb, mit, log)
				anomChanges := anom.Changes()
				if rec != nil {
					recordMitigations(rec, mitChanges)
					recordAnomalies(rec, anomChanges)
				}
				if dispatch.Enabled() {
					watch.anomaly(anomChanges)
					watch.mitigation(mitChanges)
					watch.announce(now, err)
				}
				return
			}
			leading = true
			in := decisionInput(loopCtx, now, engine, view, plugins, fed)
			changes, err := runDecision(now, decider, in, ctl, log, cfg.Mode)
			fed.publish(now, in, decider.Improvements())
			if rec != nil {
				rec.Decision(now, changes, in.Results)
			}
			inChanges, inErr := runInbound(loopCtx, now, inb, plugins, log, cfg.InboundMode(), in)
			mitChanges, mitErr := runMitigation(now, mit, log)
			anomChanges := anom.Changes()
			if rec != nil {
				recordMitigations(rec, mitChanges)
				recordAnomalies(rec, anomChanges)
			}
			if !dispatch.Enabled() {
				return
			}
			watch.anomaly(anomChanges)
			watch.mitigation(mitChanges)
			watch.improvements(now, changes)
			watch.inbound(now, cfg.InboundMode(), inChanges)
			watch.announce(now, errors.Join(err, inErr, mitErr))
			watch.providerStatus(now, engine.Providers())
			if view != nil {
				watch.peerStatus(now, view.Peers())
			}
			if len(plugins.Telemetry) > 0 && watch.commitDue(now) {
				watch.commit(now, collectTelemetry(loopCtx, plugins))
			}
		})
	}()
	if anom != nil {
		// Its own interval, independent of probe rounds. Stopped with the
		// decision loop, before the shutdown withdraw, so it cannot add a
		// rule after it.
		loopWG.Add(1)
		go func() {
			defer loopWG.Done()
			anom.Run(loopCtx)
		}()
	}

	rl := &reloader{path: path, getenv: getenv, log: log, cur: cfg, ctl: ctl, poke: poke}
	if editor != nil {
		rl.applied = editor.SetRunning
	}
	if view != nil {
		rl.view = view
	}
	var reloadFailed atomic.Bool
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
			}
			refused, fatal := rl.reload(ctx)
			auditReload(ctx, audit, path, refused, fatal)
			switch {
			case fatal != nil:
				log.Error("config reload failed after changing the BGP speaker; stopping (Packeteer routes are withdrawn)", "err", fatal)
				reloadFailed.Store(true)
				stopDaemon()
				return
			case refused != nil:
				log.Error("config reload refused; the running config stays", "err", refused)
			}
		}
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
	// Peers stop using this POP's providers at their next poll (#30).
	fed.publishDown(time.Now())
	stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Withdraw while the session is still up, then stop plugins (the announcer
	// withdraws again) and finally drop the session. Graceful restart is never
	// enabled, so a missed withdraw still disappears with the session.
	withdrawErr := errors.Join(mit.WithdrawAll(stopCtx), inb.WithdrawAll(stopCtx), ctl.WithdrawAll(stopCtx))
	if withdrawErr != nil {
		log.Error("withdraw on shutdown", "err", withdrawErr)
	}
	// Only after the withdraw: the standby may announce once this lease
	// is released (#31).
	ha.shutdown(stopCtx, withdrawErr)
	// Mitigation routes withdrawn above are in the feed as withdrawn;
	// the recorder ends their rules as stopped on Close.
	if mitChanges := mit.Changes(); len(mitChanges) > 0 {
		if rec != nil {
			recordMitigations(rec, mitChanges)
		}
		watch.mitigation(mitChanges)
	}
	if anomChanges := anom.Changes(); len(anomChanges) > 0 {
		if rec != nil {
			recordAnomalies(rec, anomChanges)
		}
		watch.anomaly(anomChanges)
	}
	// Tell notifiers after the withdraw, and give them a bounded moment
	// before they stop. Notification never delays the withdraw.
	stopFields := map[string]string{"mode": cfg.Mode, "withdrawn": "true"}
	if withdrawErr != nil {
		stopFields["withdrawn"] = "false"
		stopFields["error"] = withdrawErr.Error()
	}
	watch.emit(time.Now(), plugin.EventControllerStopping, "packeteer is shutting down; Packeteer routes withdrawn", stopFields)
	if rec != nil {
		// After the withdraw: open improvement records end here. The store
		// is stopped with the other plugins below.
		histCtx, histCancel := context.WithTimeout(stopCtx, 5*time.Second)
		if err := rec.Close(histCtx); err != nil {
			log.Warn("history flush on shutdown", "err", err)
		}
		histCancel()
	}
	notifyCtx, notifyCancel := context.WithTimeout(stopCtx, 5*time.Second)
	_ = dispatch.Close(notifyCtx)
	notifyCancel()
	if err := plugins.Stop(stopCtx); err != nil {
		log.Error("plugin shutdown", "err", err)
		return 1
	}
	if reloadFailed.Load() {
		return 1
	}
	return 0
}

// wireExchanges gives the ops API the exchange statistics (#27). The next
// hop counts walk every learned path, so they are rebuilt only when the
// RIB generation changes.
func wireExchanges(cfg *config.Config, col *httpapi.Collector, view *rib.View) {
	if len(cfg.Exchanges) == 0 || view == nil {
		return
	}
	var exs []exchange.Exchange
	for _, ex := range cfg.Exchanges {
		e := exchange.Exchange{Name: ex.Name, LANs: ex.ExchangeLANs()}
		for _, p := range ex.Peers {
			nh, err := netip.ParseAddr(p.NextHop)
			if err != nil {
				continue
			}
			e.Peers = append(e.Peers, exchange.Peer{Name: p.Name, ASN: p.ASN, NextHop: nh})
		}
		exs = append(exs, e)
	}
	lans := exchange.LANs(exs)
	var mu sync.Mutex
	var gen uint64
	var cached []rib.NextHopCount
	built := false
	col.SetExchanges(exs, func() []rib.NextHopCount {
		g := view.Generation()
		mu.Lock()
		defer mu.Unlock()
		if !built || g != gen {
			cached, gen, built = view.NextHops(lans), g, true
		}
		return cached
	})
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

// MoreSpecifics lists learned prefixes inside improvements, for
// more_specific (#56).
func (g ribGate) MoreSpecifics(parents []netip.Prefix) []netip.Prefix {
	if g.v == nil {
		return nil
	}
	return g.v.MoreSpecifics(parents)
}

// NextHop is the learned next hop of an exact prefix, for inbound steers.
func (g ribGate) NextHop(p netip.Prefix) (netip.Addr, bool) {
	if g.v == nil {
		return netip.Addr{}, false
	}
	rt, ok := g.v.Exact(p)
	return rt.NextHop, ok && rt.NextHop.IsValid()
}

// NativePath is the learned route's AS path, for bgp.as_path native.
func (g ribGate) NativePath(p netip.Prefix) ([]uint32, bool) {
	if g.v == nil {
		return nil, false
	}
	rt, ok := g.v.Exact(p)
	return rt.ASPath, ok
}

// ProviderPath is a provider's learned AS path, for bgp.as_path provider.
func (g ribGate) ProviderPath(p netip.Prefix, provider string) ([]uint32, bool) {
	if g.v == nil {
		return nil, false
	}
	return g.v.ProviderPath(p, provider)
}

// inboundInput is telemetry plus the probe results that hold a measurement
// from providers whose probe source is up.
func inboundInput(ctx context.Context, plugins *pluginhost.Set, in policy.Input) inbound.Input {
	out := inbound.Input{Usage: collectTelemetry(ctx, plugins)}
	for _, r := range in.Results {
		if !r.OK() || !in.ProviderUp[r.Provider] || r.Stats.Sent == 0 {
			continue
		}
		out.Paths = append(out.Paths, inbound.Path{Provider: r.Provider, Prefix: r.Prefix, LossPct: r.Stats.LossPct, RTT: r.Stats.RTTAvg, Time: r.Time})
	}
	return out
}

// newInbound returns nil when inbound is not configured. others counts
// outbound improvements on the wire for the shared cap.
func newInbound(cfg *config.Config, plugins *pluginhost.Set, view *rib.View, others func() int, mit *mitigation.Controller, log *slog.Logger) (*inbound.Controller, error) {
	in := cfg.Inbound
	if in == nil {
		return nil, nil
	}
	var ann plugin.InboundAnnouncer
	if plugins.Inbound != nil {
		ann = plugins.Inbound.Plugin
	}
	ic := inbound.Config{
		Mode:            in.Mode,
		Community:       cfg.PacketeerCommunity,
		LocalPref:       in.LocalPref,
		MaxImprovements: in.MaxImprovements,
		SharedCap:       *cfg.MaxImprovements,
		Others:          others,
		HoldTime:        cfg.HoldTime,
		TTL:             cfg.ImprovementTTL,
		ReleasePct:      in.ReleasePct,
		MaxAge:          inbound.DefaultMaxAge,
		PerfMaxAge:      maxResultAge(cfg),
		Damping: inbound.Damping{
			Disabled: in.Damping.Disabled, Confirm: in.Damping.Confirm,
			Backoff: in.Damping.Backoff, MaxHold: in.Damping.MaxHold,
		},
		Moderated: map[string]bool{},
		Excluded:  mit.Holds,
		Leader:    haLeader(plugins),
	}
	if pf := in.Performance; pf != nil {
		ic.Performance = &inbound.PerfConfig{LossPct: pf.LossPct, LatencyMs: pf.LatencyMs, MinPrefixes: pf.MinPrefixes, ReleasePct: pf.ReleasePct}
	}
	for _, t := range in.Moderated {
		ic.Moderated[t] = true
	}
	for _, p := range cfg.Providers {
		if !p.Exclude {
			ic.Providers = append(ic.Providers, p.Name)
		}
	}
	for _, s := range in.Prefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		ic.Prefixes = append(ic.Prefixes, p)
	}
	for _, s := range cfg.Allowlist.Prefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		ic.Allowlist = append(ic.Allowlist, p)
	}
	var gate inbound.RIB
	if view != nil {
		gate = ribGate{view}
	}
	return inbound.New(ic, ann, gate, log.With("component", "inbound"))
}

// bindInbound attaches the inbound announcer to the speaker when inbound
// injects. It runs after the gobgp announcer has installed its export
// policy.
func bindInbound(cfg *config.Config, plugins *pluginhost.Set, srv any) error {
	if cfg.InboundMode() != config.ModeInject {
		return nil
	}
	if plugins.Inbound == nil {
		return errors.New("inbound: inject requires inbound.announcer")
	}
	b, ok := plugins.Inbound.Plugin.(interface {
		Bind(any, string, []netip.Prefix) error
	})
	if !ok {
		return fmt.Errorf("inbound: announcer %T cannot publish on the embedded iBGP speaker", plugins.Inbound.Plugin)
	}
	var prefixes []netip.Prefix
	for _, s := range cfg.Inbound.Prefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return err
		}
		prefixes = append(prefixes, p)
	}
	return b.Bind(srv, cfg.PacketeerCommunity, prefixes)
}

// runInbound plans inbound steers and syncs them. Sync is a no-op outside
// inject. results are the probe results the decision round used.
func runInbound(ctx context.Context, now time.Time, inb *inbound.Controller, plugins *pluginhost.Set, log *slog.Logger, mode string, in policy.Input) ([]inbound.Change, error) {
	if inb == nil {
		return nil, nil
	}
	changes := inb.Plan(now, inboundInput(ctx, plugins, in))
	for _, c := range changes {
		act := c.Steer.Action
		log.Info("inbound "+c.Action, "mode", mode, "trigger", c.Steer.Trigger, "moderated", c.Steer.Moderated,
			"provider", c.Steer.Provider, "in_mbps_95", c.Steer.InMbps95, "commit_mbps", c.Steer.CommitMbps,
			"hold", c.Steer.Hold, "flaps", c.Steer.Flaps, "inertia_mbps", c.Steer.Shift,
			"action", act.Name, "prepend", act.Prepend, "withhold", act.Withhold, "communities", strings.Join(act.Communities, " "), "reason", c.Reason)
	}
	actx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := inb.Sync(actx)
	if err != nil {
		log.Error("inbound announce", "err", err)
	}
	return changes, err
}

func newController(cfg *config.Config, plugins *pluginhost.Set, view *rib.View, inb *inbound.Controller, mit *mitigation.Controller, log *slog.Logger) (*announce.Controller, error) {
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
		ASPath:          cfg.BGP.ASPath,
		Leader:          haLeader(plugins),
	}
	if ms := cfg.MoreSpecific; ms != nil && ms.Enabled {
		ac.MoreSpecific, ac.MaxRoutes = true, ms.MaxRoutes
	}
	if inb != nil {
		ac.Others = inb.Active
	}
	// A prefix is reserved while inbound steering owns it or a mitigation
	// rule holds it (#28). Both are nil-safe.
	ac.Reserved = func(p netip.Prefix) bool { return inb.Reserved(p) || mit.Holds(p) }
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
	routers, err := routerExports(cfg)
	if err != nil {
		return nil, err
	}
	ac.Routers = routers
	return announce.New(ac, ann, ribGate{view}, log)
}

// routerSummary is a neighbor's provider reachability for -check, or ""
// when it reaches every provider.
func routerSummary(n config.BGPNeighbor) string {
	if !n.Routed() {
		return ""
	}
	out := " providers=" + strings.Join(n.Providers, ",")
	for _, name := range slices.Sorted(maps.Keys(n.NextHops)) {
		out += " " + name + "_via=" + n.NextHops[name]
	}
	return out
}

// routerExports is per-router provider reachability for the announcer
// (#27), or nil when no neighbor restricts providers. A router with no
// providers or next_hops of its own still reaches every provider directly.
func routerExports(cfg *config.Config) ([]plugin.RouterExport, error) {
	if !slices.ContainsFunc(cfg.BGP.Neighbors, config.BGPNeighbor.Routed) {
		return nil, nil
	}
	provNH := map[string]netip.Addr{}
	for _, p := range cfg.Providers {
		nh, err := parseAddr(p.NextHop)
		if err != nil {
			return nil, err
		}
		provNH[p.Name] = nh
	}
	var out []plugin.RouterExport
	for _, n := range cfg.BGP.Neighbors {
		a, err := parseAddr(n.Address)
		if err != nil {
			return nil, err
		}
		re := plugin.RouterExport{Neighbor: a}
		if n.Routed() {
			re.Via = map[netip.Addr]netip.Addr{}
			for name, s := range n.NextHops {
				nh, err := parseAddr(s)
				if err != nil {
					return nil, err
				}
				re.Via[provNH[name]] = nh
			}
			for _, p := range cfg.Providers {
				_, via := n.NextHops[p.Name]
				if !via && !slices.Contains(n.Providers, p.Name) {
					re.Blocked = append(re.Blocked, provNH[p.Name])
				}
			}
		}
		out = append(out, re)
	}
	return out, nil
}

// newTools builds the read-only troubleshooting tools. They share the
// provider sources and prober chain with the engine but never feed it:
// on-demand results go back to the HTTP caller only.
func newTools(cfg *config.Config, plugins *pluginhost.Set) (*troubleshoot.Tools, error) {
	var providers []probe.Provider
	for _, p := range cfg.Providers {
		if cfg.Remote(p) {
			// Measured by the peer in its domain (#30), never probed here.
			continue
		}
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
	rpm := cfg.Troubleshoot.RequestsPerMinute
	opt := troubleshoot.Options{
		Enabled:   cfg.Troubleshoot.Enabled,
		Providers: providers,
		Probers:   probers,
		Packets:   cfg.Probe.Packets,
		Timeout:   cfg.Probe.Timeout,
		MaxHops:   cfg.Troubleshoot.MaxHops,
		Hop:       traceroute.Hop,
		Limiter:   rate.NewLimiter(rate.Every(time.Minute/time.Duration(rpm)), min(rpm, 3)),
	}
	if plugins.Whois != nil {
		opt.Whois = plugins.Whois.Plugin
	}
	return troubleshoot.New(opt), nil
}

func newEngine(cfg *config.Config, plugins *pluginhost.Set, log *slog.Logger, onRound func(), onProbe func(probe.Result)) (*probe.Engine, error) {
	var providers []probe.Provider
	for _, p := range cfg.Providers {
		if cfg.Remote(p) {
			// Measured by the peer in its domain (#30), never probed here.
			continue
		}
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
	onResult := func(r probe.Result) {
		logResult(log, r)
		if onProbe != nil {
			onProbe(r)
		}
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
		OnResult:             onResult,
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

// runDecision applies one evaluation to the announcer and returns the
// decision changes and the sync error for the event watcher.
func runDecision(now time.Time, decider *policy.Engine, in policy.Input, ctl *announce.Controller, log *slog.Logger, mode string) ([]policy.Change, error) {
	changes := decider.Evaluate(in, now)
	logChanges(log, mode, changes)
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
	for _, src := range plugins.Sources {
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
	usage := map[string]string{}
	addPath := map[string]bool{}
	var peerASN map[string]uint32
	for _, p := range cfg.Providers {
		nh, err := parseAddr(p.NextHop)
		if err != nil {
			return nil, err
		}
		providers[nh] = p.Name
		if p.Exchange != "" {
			if peerASN == nil {
				peerASN = map[string]uint32{}
			}
			peerASN[p.Name] = p.PeerASN
		}
		if p.BMP != "" {
			usage[p.Name] = p.BMP
		}
		if p.AddPath {
			addPath[p.Name] = true
		}
	}
	nbrs, egress, err := ribNeighbors(cfg)
	if err != nil {
		return nil, err
	}
	listen := int32(cfg.BGP.ListenPort)
	if listen == 0 {
		listen = -1
	}
	own, err := ownCommunity(cfg.PacketeerCommunity)
	if err != nil {
		return nil, err
	}
	warnBMPSelfFilter(log, usage, own)
	return rib.New(rib.Options{ASN: cfg.ASN, RouterID: rid, ListenPort: listen,
		ListenAddresses: cfg.BGP.ListenAddresses, Neighbors: nbrs, Providers: providers, BMP: usage,
		AddPath: addPath, OwnCommunity: own, Egress: egress, PeerASN: peerASN, Logger: log})
}

// ribNeighbors is the iBGP sessions and, from each neighbor's providers,
// every provider's egress routers.
func ribNeighbors(cfg *config.Config) ([]rib.Neighbor, map[string][]netip.Addr, error) {
	var nbrs []rib.Neighbor
	egress := map[string][]netip.Addr{}
	for _, n := range cfg.BGP.Neighbors {
		a, err := parseAddr(n.Address)
		if err != nil {
			return nil, nil, err
		}
		for _, name := range n.Providers {
			egress[name] = append(egress[name], a)
		}
		nb := rib.Neighbor{Address: a, Port: uint16(n.Port), Passive: n.Passive, Description: n.Description, AddPath: n.AddPath}
		if n.LocalAddress != "" {
			if nb.LocalAddress, err = parseAddr(n.LocalAddress); err != nil {
				return nil, nil, err
			}
		}
		nbrs = append(nbrs, nb)
	}
	return nbrs, egress, nil
}

// warnBMPSelfFilter warns at startup that, with BMP in use, Packeteer's own
// routes are recognised in Loc-RIB (and in Adj-RIB-In reflected by another
// router) only by packeteer_community. A router or route reflector that
// strips it would let an injected route keep its prefix learned.
func warnBMPSelfFilter(log *slog.Logger, usage map[string]string, own uint32) {
	if log == nil {
		return
	}
	for _, u := range usage {
		if u != config.BMPPrefer && u != config.BMPOnly {
			continue
		}
		if own == 0 {
			log.Warn("bmp: packeteer_community is unset, so Packeteer's own routes reported over BMP Loc-RIB cannot be recognised; set it before mode: inject")
			return
		}
		log.Warn("bmp: Packeteer's own routes are recognised over BMP by packeteer_community (and on its own session by BGP ID); make sure no import policy or route reflector on the monitored routers strips that community")
		return
	}
}

// ownCommunity turns packeteer_community ("asn:value") into asn<<16|value,
// or 0 when it is unset.
func ownCommunity(s string) (uint32, error) {
	if s == "" {
		return 0, nil
	}
	hi, lo, _ := strings.Cut(s, ":")
	a, err := strconv.ParseUint(hi, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("packeteer_community %q: %w", s, err)
	}
	b, err := strconv.ParseUint(lo, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("packeteer_community %q: %w", s, err)
	}
	return uint32(a)<<16 | uint32(b), nil
}

// wireRIBSources points every RIB source (BMP) at the view. It runs before
// the plugins start, so no event is lost.
func wireRIBSources(plugins *pluginhost.Set, view *rib.View) error {
	if len(plugins.RIBSources) == 0 {
		return nil
	}
	if view == nil {
		return errors.New("rib_sources require bgp.neighbors")
	}
	for _, s := range plugins.RIBSources {
		s.Plugin.SetRIBSink(view.ApplyRIB)
	}
	return nil
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
		pp := policy.ProviderPolicy{
			Name: p.Name, Group: p.Group, Precedence: p.Precedence, CCDisable: p.CCDisable,
		}
		if p.Cost != nil {
			pp.Cost, pp.HasCost = *p.Cost, true
		}
		pc.Providers = append(pc.Providers, pp)
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
// With federation (#30), fresh peers' paths through providers in other
// domains are merged in and global commits are applied to the usage.
func decisionInput(ctx context.Context, now time.Time, engine *probe.Engine, view *rib.View, plugins *pluginhost.Set, fed *fedState) policy.Input {
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
		fillRouteChecks(&in, view)
		in.EgressDown = view.EgressDown()
	}
	fed.merge(&in, now)
	var routes routeLookup
	if view != nil {
		routes = view
	}
	applyPolicies(&in, now, routes, plugins, collectTraffic(ctx, plugins))
	fillPlannerInputs(ctx, &in, plugins)
	fed.commit(ctx, &in, plugins)
	return in
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
	if in == nil || plugins == nil || len(plugins.Policies) == 0 {
		return
	}
	seen := map[string]bool{}
	for _, pol := range plugins.Policies {
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
		for _, pol := range plugins.Policies {
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

// maintenanceOpener is implemented by the maintenance policy.
type maintenanceOpener interface {
	plugin.Maintenance
	Open(providers []string, d time.Duration, reason string, now time.Time) (plugin.MaintenanceWindow, error)
	Close(id string) bool
}

// maintenanceControl lists windows from every maintenance policy and opens
// on-demand windows on the first one. A change wakes the decision loop so
// improvements move off the provider without waiting for a probe round.
type maintenanceControl struct {
	all    []plugin.Maintenance
	opener maintenanceOpener
	log    *slog.Logger
	poke   func()
}

func newMaintenanceControl(plugins *pluginhost.Set, log *slog.Logger, poke func()) httpapi.MaintenanceControl {
	if plugins == nil {
		return nil
	}
	mc := &maintenanceControl{log: log, poke: poke}
	for _, pol := range plugins.Policies {
		if m, ok := pol.Plugin.(plugin.Maintenance); ok {
			mc.all = append(mc.all, m)
		}
		if o, ok := pol.Plugin.(maintenanceOpener); ok && mc.opener == nil {
			mc.opener = o
		}
	}
	if len(mc.all) == 0 {
		return nil
	}
	return mc
}

func (mc *maintenanceControl) Active(now time.Time) []plugin.MaintenanceWindow {
	var out []plugin.MaintenanceWindow
	for _, m := range mc.all {
		out = append(out, m.Active(now)...)
	}
	return out
}

func (mc *maintenanceControl) CanOpen() bool { return mc.opener != nil }

func (mc *maintenanceControl) Open(providers []string, d time.Duration, reason string, now time.Time) (plugin.MaintenanceWindow, error) {
	if mc.opener == nil {
		return plugin.MaintenanceWindow{}, errors.New("no maintenance policy configured")
	}
	w, err := mc.opener.Open(providers, d, reason, now)
	if err != nil {
		return w, err
	}
	if mc.log != nil {
		mc.log.Info("maintenance window opened", "id", w.ID, "providers", strings.Join(w.Providers, ","), "end", w.End, "reason", w.Reason)
	}
	if mc.poke != nil {
		mc.poke()
	}
	return w, nil
}

func (mc *maintenanceControl) Close(id string) bool {
	if mc.opener == nil || !mc.opener.Close(id) {
		return false
	}
	if mc.log != nil {
		mc.log.Info("maintenance window closed", "id", id)
	}
	if mc.poke != nil {
		mc.poke()
	}
	return true
}

// maintenanceWatchInterval is how often scheduled windows are checked.
const maintenanceWatchInterval = 15 * time.Second

// watchMaintenance wakes the decision loop when the set of providers in
// maintenance changes, so a scheduled window that opens or closes takes
// effect without waiting for the next probe round.
func watchMaintenance(ctx context.Context, active func(time.Time) []plugin.MaintenanceWindow, every time.Duration, log *slog.Logger, poke func()) {
	key := func(now time.Time) string {
		var names []string
		for _, w := range active(now) {
			names = append(names, w.Providers...)
		}
		slices.Sort(names)
		return strings.Join(slices.Compact(names), ",")
	}
	last := key(time.Now())
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if k := key(now); k != last {
				if log != nil {
					log.Info("providers in maintenance changed", "providers", k)
				}
				last = k
				poke()
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
	if plugins == nil || len(plugins.Policies) == 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var out map[netip.Prefix]string
	for _, src := range plugins.Sources {
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

// newRecorder returns nil when no storage plugin is configured. It reads
// the RIB view for origin ASNs and asks policy plugins that have a GeoIP
// database for countries. History never announces or changes a decision.
func newRecorder(cfg *config.Config, plugins *pluginhost.Set, log *slog.Logger, view func() *rib.View) *history.Recorder {
	if plugins == nil || plugins.Storage == nil {
		return nil
	}
	var geo []plugin.CountryLookup
	for _, pol := range plugins.Policies {
		if g, ok := pol.Plugin.(plugin.CountryLookup); ok {
			geo = append(geo, g)
		}
	}
	describe := func(p netip.Prefix) (uint32, string) {
		var asn uint32
		if v := view(); v != nil && v.Ready() {
			if rt, ok := v.Exact(p); ok && len(rt.ASPath) > 0 {
				asn = rt.ASPath[len(rt.ASPath)-1]
			}
		}
		for _, g := range geo {
			if c := g.Country(p.Addr()); c != "" {
				return asn, c
			}
		}
		return asn, ""
	}
	return history.New(history.Options{
		Store:    plugins.Storage.Plugin,
		Mode:     cfg.Mode,
		Logger:   log.With("component", "history"),
		Describe: describe,
		Volumes:  func(ctx context.Context) map[netip.Prefix]float64 { return collectVolumes(ctx, plugins) },
	})
}
