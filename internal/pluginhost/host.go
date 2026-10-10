// Package pluginhost builds the configured plugin instances and manages
// their lifecycle. Building validates every plugin's config, so errors are
// reported at startup before anything touches the network.
package pluginhost

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Instance is one constructed plugin.
type Instance[T plugin.Lifecycle] struct {
	Name   string
	Type   string
	Plugin T
}

// Set holds every configured plugin instance.
type Set struct {
	Probers   []Instance[plugin.Prober]
	Sources   []Instance[plugin.TargetSource]
	Scorer    *Instance[plugin.Scorer]
	Announcer *Instance[plugin.Announcer]
	// Inbound is the inbound announcer (inbound.announcer). Nil when
	// inbound is off or has no announcer.
	Inbound *Instance[plugin.InboundAnnouncer]
	// Mitigation is the mitigation announcer (mitigation.announcer, #28).
	// Nil when mitigation is off or has no announcer.
	Mitigation *Instance[plugin.MitigationAnnouncer]
	Notifiers  []Instance[plugin.Notifier]
	Telemetry  []Instance[plugin.Telemetry]
	Policies   []Instance[plugin.Policy]
	Storage    *Instance[plugin.Storage]
	// Whois serves the troubleshooting API only. It never announces.
	Whois *Instance[plugin.Whois]
	// RIBSources feed the RIB view (BMP). They never announce.
	RIBSources []Instance[plugin.RIBSource]
	// Federation is the multi-POP transport (#30). It never announces.
	Federation *Instance[plugin.Federation]
	// Elector is the active/standby elector (#31). Nil runs a single
	// instance. It never announces; it gates the announcers.
	Elector *Instance[plugin.Elector]
	// SSO is single sign-on for the ops API (auth.sso, #32). It never
	// announces.
	SSO *Instance[plugin.SSO]
	// Detector is the traffic anomaly detector (anomaly.detector, #33).
	// It never announces; the core acts on its anomalies only through
	// threat mitigation and only for an explicit rule.
	Detector *Instance[plugin.Detector]

	mu      sync.RWMutex
	started []namedLifecycle
}

type namedLifecycle struct {
	kind  plugin.Kind
	label string
	lc    plugin.Lifecycle
}

// Options configure Build.
type Options struct {
	Logger    *slog.Logger
	Getenv    func(string) string
	PluginDir string // overrides cfg.PluginDir when set
	// CheckOnly builds instances only to validate them (plugin.Env
	// CheckOnly): no plugin starts a process. The set must not be started.
	CheckOnly bool
}

func build[T plugin.Lifecycle](reg *plugin.Registry[T], field string, specs []config.PluginSpec, base plugin.Env, errs *[]error) []Instance[T] {
	var out []Instance[T]
	for i, sp := range specs {
		env := base
		env.Name = sp.InstanceName()
		env.Logger = base.Logger.With("plugin", string(reg.Kind()), "name", env.Name, "type", sp.Type)
		node := sp.Config
		p, err := reg.New(sp.Type, plugin.NewConfig(&node), env)
		if err != nil {
			*errs = append(*errs, fmt.Errorf("%s[%d] (%s): %w", field, i, env.Name, err))
			continue
		}
		out = append(out, Instance[T]{Name: env.Name, Type: sp.Type, Plugin: p})
	}
	return out
}

// Build constructs all plugins named in cfg, returning every error found.
func Build(cfg *config.Config, opts Options) (*Set, error) {
	base := optionsEnv(cfg, opts)

	var errs []error
	s := &Set{
		Probers:   build(plugin.Probers, "probers", cfg.Probers, base, &errs),
		Sources:   build(plugin.Sources, "sources", cfg.Sources, base, &errs),
		Notifiers: build(plugin.Notifiers, "notifiers", cfg.Notifiers, base, &errs),
		Telemetry: build(plugin.Telemetries, "telemetry", cfg.Telemetry, base, &errs),
		Policies:  build(plugin.Policies, "policies", cfg.Policies, base, &errs),

		RIBSources: build(plugin.RIBSources, "rib_sources", cfg.RIBSources, base, &errs),
	}
	if cfg.Scorer != nil {
		if b := build(plugin.Scorers, "scorer", []config.PluginSpec{*cfg.Scorer}, base, &errs); len(b) == 1 {
			s.Scorer = &b[0]
		}
	}
	if cfg.Announcer != nil {
		if b := build(plugin.Announcers, "announcer", []config.PluginSpec{*cfg.Announcer}, base, &errs); len(b) == 1 {
			s.Announcer = &b[0]
		}
	}
	if cfg.Inbound != nil && cfg.Inbound.Announcer != nil {
		if b := build(plugin.InboundAnnouncers, "inbound.announcer", []config.PluginSpec{*cfg.Inbound.Announcer}, base, &errs); len(b) == 1 {
			s.Inbound = &b[0]
		}
	}
	if cfg.Mitigation != nil && cfg.Mitigation.Announcer != nil {
		if b := build(plugin.MitigationAnnouncers, "mitigation.announcer", []config.PluginSpec{*cfg.Mitigation.Announcer}, base, &errs); len(b) == 1 {
			s.Mitigation = &b[0]
		}
	}
	if cfg.Storage != nil {
		if b := build(plugin.Storages, "storage", []config.PluginSpec{*cfg.Storage}, base, &errs); len(b) == 1 {
			s.Storage = &b[0]
		}
	}
	if cfg.Federation != nil {
		if b := build(plugin.Federations, "federation", []config.PluginSpec{*cfg.Federation}, base, &errs); len(b) == 1 {
			s.Federation = &b[0]
		}
	}
	if cfg.HA != nil {
		if b := build(plugin.Electors, "ha", []config.PluginSpec{*cfg.HA}, base, &errs); len(b) == 1 {
			s.Elector = &b[0]
		}
	}
	if cfg.AuthEnabled() && cfg.Auth.SSO != nil {
		if b := build(plugin.SSOs, "auth.sso", []config.PluginSpec{*cfg.Auth.SSO}, base, &errs); len(b) == 1 {
			s.SSO = &b[0]
		}
	}
	if cfg.Anomaly != nil && cfg.Anomaly.Detector != nil {
		if b := build(plugin.Detectors, "anomaly.detector", []config.PluginSpec{*cfg.Anomaly.Detector}, base, &errs); len(b) == 1 {
			s.Detector = &b[0]
		}
	}
	if cfg.Troubleshoot.Whois != nil {
		if b := build(plugin.Whoises, "troubleshoot.whois", []config.PluginSpec{*cfg.Troubleshoot.Whois}, base, &errs); len(b) == 1 {
			s.Whois = &b[0]
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	s.attachSampleStore()
	return s, nil
}

// attachSampleStore gives telemetry plugins that keep a 95th-percentile
// window the storage plugin, when that store persists samples (#127).
// Storage starts first, so the window can load its open period in Start.
func (s *Set) attachSampleStore() {
	if s.Storage == nil {
		return
	}
	store, ok := s.Storage.Plugin.(plugin.SampleStore)
	if !ok {
		return
	}
	for _, t := range s.Telemetry {
		if k, ok := t.Plugin.(plugin.SampleKeeper); ok {
			k.UseSampleStore(store)
		}
	}
}

func (s *Set) all() []namedLifecycle {
	var out []namedLifecycle
	add := func(kind plugin.Kind, name string, lc plugin.Lifecycle) {
		out = append(out, namedLifecycle{kind, fmt.Sprintf("%s %s", kind, name), lc})
	}
	// Storage starts first and stops last, so history can be flushed
	// after the announcer has withdrawn.
	if s.Storage != nil {
		add(plugin.KindStorage, s.Storage.Name, s.Storage.Plugin)
	}
	if s.SSO != nil {
		add(plugin.KindSSO, s.SSO.Name, s.SSO.Plugin)
	}
	for _, p := range s.RIBSources {
		add(plugin.KindRIBSource, p.Name, p.Plugin)
	}
	for _, p := range s.Sources {
		add(plugin.KindSource, p.Name, p.Plugin)
	}
	if s.Detector != nil {
		add(plugin.KindDetector, s.Detector.Name, s.Detector.Plugin)
	}
	for _, p := range s.Probers {
		add(plugin.KindProber, p.Name, p.Plugin)
	}
	if s.Scorer != nil {
		add(plugin.KindScorer, s.Scorer.Name, s.Scorer.Plugin)
	}
	for _, p := range s.Policies {
		add(plugin.KindPolicy, p.Name, p.Plugin)
	}
	for _, p := range s.Telemetry {
		add(plugin.KindTelemetry, p.Name, p.Plugin)
	}
	for _, p := range s.Notifiers {
		add(plugin.KindNotifier, p.Name, p.Plugin)
	}
	if s.Federation != nil {
		add(plugin.KindFederation, s.Federation.Name, s.Federation.Plugin)
	}
	if s.Whois != nil {
		add(plugin.KindWhois, s.Whois.Name, s.Whois.Plugin)
	}
	// Before the announcers, so it stops after them. The core withdraws
	// and resigns before any plugin stops.
	if s.Elector != nil {
		add(plugin.KindElector, s.Elector.Name, s.Elector.Plugin)
	}
	if s.Announcer != nil {
		add(plugin.KindAnnouncer, s.Announcer.Name, s.Announcer.Plugin)
	}
	// Started after, and so stopped before, the outbound announcer.
	if s.Inbound != nil {
		add(plugin.KindAnnouncer, "inbound "+s.Inbound.Name, s.Inbound.Plugin)
	}
	// Last to start, first to stop: mitigation routes are withdrawn first.
	if s.Mitigation != nil {
		add(plugin.KindAnnouncer, "mitigation "+s.Mitigation.Name, s.Mitigation.Plugin)
	}
	return out
}

// Start starts every plugin. If one fails, the ones already started are
// stopped again and the error is returned.
func (s *Set) Start(ctx context.Context) error {
	for _, nl := range s.all() {
		if err := nl.lc.Start(ctx); err != nil {
			stopErr := s.Stop(ctx)
			return errors.Join(fmt.Errorf("start %s: %w", nl.label, err), stopErr)
		}
		s.track(nl)
	}
	return nil
}

// Stop stops started plugins in reverse order (the announcer, which is
// started last, is stopped first so routes are withdrawn early).
func (s *Set) Stop(ctx context.Context) error {
	s.mu.Lock()
	started := s.started
	s.started = nil
	s.mu.Unlock()
	var errs []error
	for i := len(started) - 1; i >= 0; i-- {
		nl := started[i]
		if err := nl.lc.Stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("stop %s: %w", nl.label, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Set) track(nl namedLifecycle) {
	s.mu.Lock()
	s.started = append(s.started, nl)
	s.mu.Unlock()
}

// TrackStart records a plugin started after the set's Start, so Stop
// stops it too. Online reload uses it for a source or policy it added. It
// goes before the first elector or announcer, so Stop still stops the
// announcers first.
func (s *Set) TrackStart(kind plugin.Kind, name string, lc plugin.Lifecycle) {
	if s == nil || lc == nil {
		return
	}
	nl := namedLifecycle{kind, fmt.Sprintf("%s %s", kind, name), lc}
	s.mu.Lock()
	defer s.mu.Unlock()
	at := slices.IndexFunc(s.started, func(n namedLifecycle) bool {
		return n.kind == plugin.KindElector || n.kind == plugin.KindAnnouncer
	})
	if at < 0 {
		s.started = append(s.started, nl)
		return
	}
	s.started = slices.Insert(s.started, at, nl)
}

// Untrack forgets a plugin that was stopped on its own, so Stop does not
// stop it again. Pointer identity matches the instance Start recorded.
func (s *Set) Untrack(lc plugin.Lifecycle) {
	if s == nil || lc == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started = slices.DeleteFunc(s.started, func(n namedLifecycle) bool { return n.lc == lc })
}

// SourcesSnapshot copies the source list. The plugins are shared.
func (s *Set) SourcesSnapshot() []Instance[plugin.TargetSource] {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.Sources)
}

// PoliciesSnapshot copies the policy list. The plugins are shared.
func (s *Set) PoliciesSnapshot() []Instance[plugin.Policy] {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.Policies)
}

// SetSources replaces the source list. The caller starts new plugins and
// stops removed ones.
func (s *Set) SetSources(v []Instance[plugin.TargetSource]) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.Sources = v
	s.mu.Unlock()
}

// SetPolicies replaces the policy list.
func (s *Set) SetPolicies(v []Instance[plugin.Policy]) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.Policies = v
	s.mu.Unlock()
}

// optionsEnv is the plugin environment Build and a reload share.
func optionsEnv(cfg *config.Config, opts Options) plugin.Env {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Getenv == nil {
		opts.Getenv = func(string) string { return "" }
	}
	dir := ""
	if cfg != nil {
		dir = cfg.PluginDir
	}
	if opts.PluginDir != "" {
		dir = opts.PluginDir
	}
	return plugin.Env{Logger: opts.Logger, PluginDir: dir, Getenv: opts.Getenv, Providers: providerNames(cfg), CheckOnly: opts.CheckOnly}
}

// BuildSources constructs the named target sources. They are not started.
func BuildSources(cfg *config.Config, specs []config.PluginSpec, opts Options) ([]Instance[plugin.TargetSource], error) {
	var errs []error
	out := build(plugin.Sources, "sources", specs, optionsEnv(cfg, opts), &errs)
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return out, nil
}

// BuildPolicies constructs the named policies. They are not started.
func BuildPolicies(cfg *config.Config, specs []config.PluginSpec, opts Options) ([]Instance[plugin.Policy], error) {
	var errs []error
	out := build(plugin.Policies, "policies", specs, optionsEnv(cfg, opts), &errs)
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return out, nil
}

func providerNames(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	out := make([]string, 0, len(cfg.Providers))
	for _, p := range cfg.Providers {
		if p.Name != "" {
			out = append(out, p.Name)
		}
	}
	return out
}

// Summary describes the plugin set, one line per instance.
func (s *Set) Summary() []string {
	var out []string
	for _, nl := range s.all() {
		out = append(out, nl.label)
	}
	return out
}
