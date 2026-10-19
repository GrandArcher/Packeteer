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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/GrandArcher/Packeteer/internal/announce"
	"github.com/GrandArcher/Packeteer/internal/anomaly"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/herd"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/inbound"
	"github.com/GrandArcher/Packeteer/internal/linkout"
	"github.com/GrandArcher/Packeteer/internal/notify"
	"github.com/GrandArcher/Packeteer/internal/pbr"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/all"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/internal/subscribe"
	"github.com/GrandArcher/Packeteer/internal/syshealth"
	"github.com/GrandArcher/Packeteer/internal/upgrade"
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
	tuneGC(os.Getenv)
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
	if len(args) > 0 && args[0] == "herd" {
		return runHerd(args[1:], getenv, stdout, stderr)
	}
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
	pbrFormat := fs.String("pbr", "", "print the probe policy routing for the configured providers ("+strings.Join(pbr.Formats, ", ")+") and exit; generation only, nothing is applied or sent to a router")
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
	if *pbrFormat != "" {
		text, err := pbr.Generate(*pbrFormat, pbr.Entries(cfg))
		if err != nil {
			fmt.Fprintf(stderr, "packeteer: -pbr: %v\n", err)
			return 1
		}
		fmt.Fprint(stdout, text)
		return 0
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
	// A staged version (#196) takes over before anything starts. -check
	// and -notify-test run as the installed binary.
	if !*check && !*notifyTest {
		if code, switched := launchStaged(cfg, args, getenv, log); switched {
			return code
		}
	}
	plugins, err := preflight(cfg, log, getenv, httpUser, false)
	if err != nil {
		fmt.Fprintf(stderr, "packeteer: refusing to start: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "packeteer %s: config %s loaded\n", version, *path)
	fmt.Fprintf(stdout, "mode: %s\n", cfg.Mode)
	if cfg.IXP != nil {
		fmt.Fprintln(stdout, "ixp: on (observe-only, never announces)")
		if cfg.IXP.Members != nil {
			fmt.Fprintf(stdout, "ixp members: %s (read-only, never announces)\n", cfg.IXP.Members.Type)
		}
		if cfg.IXP.Fabric != nil {
			fmt.Fprintf(stdout, "ixp fabric: %s (%d vantages, observe-only, never announces)\n", cfg.IXP.Fabric.Type, len(cfg.IXP.Vantages))
		}
		if cfg.IXP.RouteServers != nil {
			fmt.Fprintf(stdout, "ixp routeservers: %s (read-only, never announces)\n", cfg.IXP.RouteServers.Type)
		}
		if cfg.IXP.Correlate != nil {
			fmt.Fprintf(stdout, "ixp correlate: %s (reads the fabric probes, never announces)\n", cfg.IXP.Correlate.Type)
		}
		if cfg.IXP.Core != nil {
			fmt.Fprintf(stdout, "ixp core: %s (%d links to other sites, observe-only, never announces)\n", cfg.IXP.Core.Type, len(cfg.IXP.CoreLinks))
		}
	}
	if cfg.Lookup != nil {
		fmt.Fprintf(stdout, "lookup: %s (read-only, never announces)\n", cfg.Lookup.Type)
	}
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
		tag := ""
		if p.FwMark != 0 {
			tag += fmt.Sprintf(" fwmark=%d", p.FwMark)
		}
		if p.DSCP != 0 {
			tag += fmt.Sprintf(" dscp=%d", p.DSCP)
		}
		fmt.Fprintf(stdout, "  - %s source_ip=%s next_hop=%s%s%s%s\n", p.Name, p.SourceIP, p.NextHop, tag, bmp, ix)
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
		fmt.Fprintf(stdout, "bgp as_path: %s (neighbors reload online on SIGHUP; as_path needs a restart)\n", cfg.BGP.ASPath)
	}
	fmt.Fprintf(stdout, "plugins (%d):\n", len(plugins.Summary()))
	for _, line := range plugins.Summary() {
		fmt.Fprintf(stdout, "  - %s\n", line)
	}
	switch {
	case cfg.Mode == config.ModeInject:
		fmt.Fprintf(stdout, "announce: %s local_pref=%d%s%s\n", plugins.Announcer.Type, cfg.LocalPref, formatLocalPrefOverrides(cfg), formatCommunityOverrides(cfg))
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
	if cfg.LeakWatching() {
		fmt.Fprintf(stdout, "leak_watch: on sources=%d (withdraws a leaked injected route and holds it out until cleared)\n", len(plugins.LeakSources))
	}
	if h := cfg.Herd; cfg.HerdOn() {
		fmt.Fprintf(stdout, "herd: on granularity=%s classes=%s sources=%s peers=%d serving=%t (shares measurements only, never announces, never feeds a decision; changes need a restart)\n",
			h.Share.Granularity, strings.Join(h.Share.Classes, ","), strings.Join(h.Share.Sources, ","), len(h.Peers), h.Serving())
	}
	if el := plugins.Elector; el != nil {
		fmt.Fprintf(stdout, "ha: %s id=%s (standby until elected; only the active instance announces)\n", el.Type, el.Plugin.Status().ID)
	}
	if u := cfg.Upgrade; u != nil && u.Enabled {
		fmt.Fprintf(stdout, "upgrade: on (repo %s, dir %s; only an admin's confirmation upgrades, verified against upgrade.public_key)\n", u.Repo, u.Dir)
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
			fmt.Fprintln(stdout, "http config_editor: on (admin only; writes this file after the start checks; online keys apply on save, the rest on restart)")
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
	var upMgr *upgrade.Manager
	code := daemon(ctx, cfg, plugins, log, httpUser, httpPass, *path, getenv, &upMgr)
	// The daemon has withdrawn and stopped. A prepared upgrade or rollback
	// starts its binary now; the new process learns the RIB before it injects.
	return finishUpgrade(ctx, upMgr, code, args, log)
}

// preflight builds the plugin set and runs every check the controller runs
// before it starts. It starts nothing. The config editor (#34) runs it on
// a candidate file too, with checkOnly set: no exec plugin command runs.
func preflight(cfg *config.Config, log *slog.Logger, getenv func(string) string, httpUser string, checkOnly bool) (*pluginhost.Set, error) {
	cfg.DefaultAuth(httpUser != "")
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
	if err := checkFlowTailIntervals(cfg, plugins); err != nil {
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

func daemon(ctx context.Context, cfg *config.Config, plugins *pluginhost.Set, log *slog.Logger, httpUser, httpPass, path string, getenv func(string) string, upgradeOut **upgrade.Manager) int {
	// SIGHUP reloads online keys (#27, #128). Registered first: Go's
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
	health := syshealth.New(nil)
	rec := newRecorder(cfg, plugins, log, func() *rib.View { return view }, health)
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
	pktLimiter := packetLimiter(cfg)
	tools, terr := newTools(cfg, plugins, pktLimiter)
	if terr != nil {
		log.Error("refusing to start", "err", terr)
		return 1
	}
	fed := newFedState(cfg, plugins)
	// Herd (#260) is built once storage is open. The probe loop hands rounds
	// to it without waiting.
	var herdRef atomic.Pointer[herd.Herd]
	var haStatus func() plugin.ElectorStatus
	if el := plugins.Elector; el != nil {
		haStatus = func() plugin.ElectorStatus {
			st := el.Plugin.Status()
			st.Type = el.Type
			return st
		}
	}
	// Built before the HTTP server: the audit log goes to the notifiers.
	evlog := newEventLog(plugins, log, health)
	dispatch := newDispatcher(plugins, notify.Options{Logger: log, Recorder: evlog,
		Result: func(name string, err error) { health.Record(notifierKey(name), err) }})
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = dispatch.Close(closeCtx)
		_ = evlog.Close(closeCtx)
	}()
	audit := newAuditor(plugins, dispatch, log)
	// The leak watch (#199) reaches the outbound announcer through ctl,
	// which is assigned once the RIB view exists. Held and Injected are
	// nil-safe until then.
	var ctl *announce.Controller
	lw, lerr := newLeakWatch(cfg, plugins, dispatch,
		func(p netip.Prefix) bool { return ctl.Injected(p) },
		func(ctx context.Context, p netip.Prefix) error { return ctl.WithdrawPrefix(ctx, p) }, log)
	if lerr != nil {
		log.Error("refusing to start", "err", lerr)
		return 1
	}
	var leakAPI httpapi.LeakControl
	if lw != nil {
		leakAPI = leakControl{w: lw, poke: poke}
	}
	authSvc, aerr := newAuthService(cfg, plugins, log)
	if aerr != nil {
		log.Error("refusing to start", "err", aerr)
		return 1
	}
	warnAuthOff(cfg, httpUser, log)
	// Upgrade from the UI (#196). The stop is the SIGTERM path: the
	// shutdown below withdraws every route before the new version starts.
	upMgr, uerr := newUpgrade(cfg, path, stopDaemon, haStatus, audit, getenv, log)
	if uerr != nil {
		log.Error("refusing to start", "err", uerr)
		return 1
	}
	var upgradeAPI httpapi.UpgradeControl
	if upMgr != nil {
		upgradeAPI = upMgr
		*upgradeOut = upMgr
		if httpUser == "" && authSvc == nil {
			log.Warn("upgrade.enabled is on but neither auth nor basic auth is: upgrade and rollback stay off")
		}
		go upMgr.Run(ctx)
		confirmUpgrade(ctx, upMgr, getenv)
	}
	// Remaining UI features (#34). None of these announces.
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
	var sysEngine atomic.Pointer[probe.Engine]
	var httpSrv *httpapi.Server
	if addr := cfg.HTTPListen(); addr != "" {
		var err error
		httpSrv, err = httpapi.New(httpapi.Options{
			Addr: addr, User: httpUser, Password: httpPass, Snapshot: col.Snapshot, Logger: log,
			Auth: authSvc, Audit: audit, Events: evlog, AllowFrom: cfg.HTTPAllowFrom(),
			Maintenance: maint, Reports: reports, Tools: tools, Inbound: inboundStatus, Mitigation: mitAPI, Anomaly: anomAPI, Leaks: leakAPI,
			Federation: fed.status, HA: haStatus,
			ConfigEditor: editorAPI, Dashboards: dashboardStore(plugins), Subscriptions: subsAPI,
			Setup: setupInfo(cfg, plugins), Upgrade: upgradeAPI, Linkouts: linkout.New(cfg.Linkouts),
			System: systemFacts(plugins, &sysEngine, health), Usage: usageReader(plugins),
		})
		if err != nil {
			log.Error("refusing to start", "err", err)
			return 1
		}
		if err := httpSrv.Start(); err != nil {
			log.Error("refusing to start", "err", err)
			return 1
		}
		defer func() {
			stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := httpSrv.Shutdown(stopCtx); err != nil {
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
	rpkiSet := newRPKISet(plugins)
	// The two controllers share max_improvements, so each reads the other's
	// count. ctl is assigned right below; Active is nil-safe until then.
	if err := setMitigationRIB(mit, view); err != nil {
		log.Error("refusing to start", "err", err)
		return 1
	}
	setAnomalyRIB(anom, view)
	inb, err = newInbound(cfg, plugins, view, func() int { return ctl.Active() }, mit, lw.Held, log)
	if err != nil {
		log.Error("refusing to start", "err", err)
		return 1
	}
	ctl, err = newController(cfg, plugins, view, inb, mit, lw.Held, log)
	if err != nil {
		log.Error("refusing to start", "err", err)
		return 1
	}
	mit.SetOutbound(ctl.Injected)
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
	} else if view != nil && view.Server() != nil {
		// A later change to inject binds this speaker, after the
		// controller runs the inject checks New skipped. Community, local
		// preference, and the announcer are restart-only when they
		// change; the allowlist and the cap reload online.
		ctl.RememberSpeaker(view.Server())
	}

	if view != nil {
		view.OnChange(poke)
		tools.SetRIB(view)
		httpSrv.SetSearchRIB(view)
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
	engine, err = newEngine(cfg, plugins, log, onRound, onProbe, herdBatch(cfg, &herdRef), pktLimiter)
	if err != nil {
		log.Error("refusing to start", "err", err)
		return 1
	}
	tools.SetQueue(engine)
	sysEngine.Store(engine)
	watch := newEventWatch(dispatch, cfg.Mode)
	portCommits := exchange.PortCommits(exchangesFromConfig(cfg))
	peerMon := exchangePeerMonitor(cfg)
	col.SetPeerPrefixes(peerMon.Prefixes)
	if err := wireRIBSources(plugins, view, health, peerMon, dispatch.Emit); err != nil {
		log.Error("refusing to start", "err", err)
		return 1
	}
	wirePrefixLookup(plugins, view)
	wireExchangeLANs(cfg, plugins)
	wireLearnedRoutes(plugins, view)
	wireOutage(plugins, engine, view, dispatch)
	col.SetTelemetry(func() []plugin.Usage { return collectTelemetry(context.Background(), plugins) })
	col.SetFlowTracked(func() int { return flowTracked(plugins) })
	col.SetTruncated(func() map[string]uint64 { return truncated(plugins) })
	col.Attach(engine, decider, view)
	if rpkiSet.Enabled() {
		col.SetRPKI(rpkiSet.Validate)
	}
	httpSrv.SetQuarantine(quarantineControl{decider: decider, out: dispatch, poke: poke, now: time.Now})
	wireExchanges(ctx, cfg, col, httpSrv, view, plugins, decider, rpkiSet)
	hopTargets, ixHealth := exchangeHealth(cfg)
	col.SetExchangeHealth(ixHealth)
	wireSuggestions(cfg, httpSrv, view)
	wireMitigationCandidates(httpSrv, mit, view)
	wireLookup(plugins, httpSrv)
	wireIXPMembers(plugins, httpSrv, dispatch.Emit)
	wireIXPFabric(cfg, plugins, httpSrv)
	wireIXPRouteServers(plugins, httpSrv, dispatch.Emit)
	wireIXPCorrelate(plugins, httpSrv, dispatch.Emit)
	wireIXPSites(cfg, plugins, fed, httpSrv)
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
	bootstrapAdmin(ctx, authSvc, audit, plugins, getenv, log)
	hd, herr := startHerd(ctx, cfg, plugins, view, audit, dispatch.Emit, ha.active, log)
	if herr != nil {
		log.Error("refusing to start", "err", herr)
		return 1
	}
	if hd != nil {
		herdRef.Store(hd)
		httpSrv.SetHerd(hd)
	}
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
	if ixHealth != nil {
		go runExchangeHealth(ctx, engine, ixHealth, hopTargets, func() time.Duration { return engine.TimingNow().Interval },
			func(ev plugin.Event) { dispatch.Emit(ev) })
	}
	if pc := pathCheckerFor(cfg, engine, pktLimiter, log); pc != nil {
		go pc.run(ctx, cfg.Probe.PathCheck.Interval)
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
	live := &liveConfig{cfg: cfg}
	loopWG.Add(1)
	go func() {
		defer loopWG.Done()
		// The ticker is independent of probe rounds and RIB updates. A round
		// that never completes (a prober or target source that ignores
		// cancellation) must still withdraw once measurements exceed
		// MaxResultAge. A reload replaces the interval.
		leading := false
		decideLoop(loopCtx, func() time.Duration {
			c := live.snapshot()
			if c == nil || c.Probe.Interval <= 0 {
				return time.Second
			}
			return c.Probe.Interval
		}, kick, func(now time.Time) {
			snap := live.snapshot()
			if snap == nil {
				snap = cfg
			}
			if !ha.active() {
				if leading {
					// Stepped down: no intent survives into a later
					// takeover. Drop the retained probe targets with it.
					decider.Reset()
					retainImprovedPrefixes(engine, nil)
					if engine != nil {
						engine.SetUrgent(nil)
					}
					leading = false
				}
				mitChanges, err := standbyRound(now, ctl, inb, mit, log)
				anomChanges := anom.Changes()
				if rec != nil {
					recordMitigations(rec, mitChanges)
					recordAnomalies(rec, anomChanges)
				}
				watch.anomaly(anomChanges)
				watch.mitigation(mitChanges)
				watch.announce(now, err)
				return
			}
			leading = true
			in := decisionInput(loopCtx, now, engine, view, plugins, fed, rpkiSet)
			in.Held = lw.Held
			changes, err := runDecision(now, decider, in, ctl, log, snap.Mode, engine)
			fed.publish(now, in, decider.Improvements())
			if rec != nil {
				rec.Decision(now, changes, in.Results)
			}
			inChanges, inErr := runInbound(loopCtx, now, inb, plugins, log, snap.InboundMode(), in)
			mitChanges, mitErr := runMitigation(now, mit, log)
			anomChanges := anom.Changes()
			if rec != nil {
				recordMitigations(rec, mitChanges)
				recordAnomalies(rec, anomChanges)
			}
			watch.anomaly(anomChanges)
			watch.mitigation(mitChanges)
			watch.improvements(now, changes)
			qc := decider.QuarantineChanges()
			watch.quarantines(now, qc)
			auditQuarantines(audit, qc)
			watch.inbound(now, snap.InboundMode(), inChanges)
			watch.announce(now, errors.Join(err, inErr, mitErr))
			watch.providerStatus(now, engine.Providers(), in.Results, snap.Probe.DegradedLossPct, snap.Probe.DownLossPct)
			if view != nil {
				watch.peerStatus(now, view.Peers(), snap.BGP.NotEstablishedAfter)
			}
			if len(plugins.Telemetry) > 0 && watch.commitDue(now) {
				watch.commit(now, exchange.WithPortCommit(collectTelemetry(loopCtx, plugins), portCommits))
			}
		})
	}()
	if lw != nil {
		// Stopped before the shutdown withdraw, like the decision loop.
		loopWG.Add(1)
		go func() {
			defer loopWG.Done()
			lw.Run(loopCtx)
		}()
	}
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

	rl := &reloader{
		path: path, getenv: getenv, httpUser: httpUser, log: log, cur: cfg, ctl: ctl, poke: poke,
		plugins: plugins, engine: engine, decider: decider, fed: fed, col: col,
		watch: watch, live: live, dispatch: dispatch, hist: rec, inb: inb, mit: mit,
		flowSpecUp: view != nil && mitigationFlowSpec(cfg, plugins),
		opts:       pluginhost.Options{Logger: log, Getenv: getenv, PluginDir: getenv(PluginDirEnv)},
	}
	if editor != nil {
		rl.applied = editor.SetRunning
	}
	if httpSrv != nil {
		rl.setup = httpSrv.SetSetup
	}
	if view != nil {
		rl.view = view
		rl.rib = view
	}
	var reloadFailed atomic.Bool
	if httpSrv != nil {
		httpSrv.SetOnlineApply(onlineApplier(ctx, rl.reload, func(c context.Context, applied []string, refused, fatal error) {
			auditReload(c, audit, path, "PUT /api/config", applied, refused, fatal)
			if fatal != nil {
				log.Error("config reload failed after changing the BGP speaker; stopping (Packeteer routes are withdrawn)", "err", fatal)
				reloadFailed.Store(true)
				stopDaemon()
			}
		}))
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
			}
			applied, refused, fatal := rl.reload(ctx)
			auditReload(ctx, audit, path, "SIGHUP", applied, refused, fatal)
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
	if hd != nil {
		hd.Stop(stopCtx)
	}
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
	stopCfg := cfg
	if snap := live.snapshot(); snap != nil {
		stopCfg = snap
	}
	announces := stopCfg.Mode == "inject" || stopCfg.InboundMode() == "inject" || stopCfg.MitigationMode() == "inject"
	watch.stopping(time.Now(), stopCfg.Mode, announces, withdrawErr)
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
	// Its own bound: a slow notifier must not leave controller.stopping
	// unwritten when the store closes.
	evCtx, evCancel := context.WithTimeout(stopCtx, 5*time.Second)
	_ = evlog.Close(evCtx)
	evCancel()
	if err := plugins.Stop(stopCtx); err != nil {
		log.Error("plugin shutdown", "err", err)
		return 1
	}
	if reloadFailed.Load() {
		return 1
	}
	return 0
}
