// Package pluginhost builds the configured plugin instances and manages
// their lifecycle. Building validates every plugin's config, so errors are
// reported at startup before anything touches the network.
package pluginhost

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

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

	started []namedLifecycle
}

type namedLifecycle struct {
	label string
	lc    plugin.Lifecycle
}

// Options configure Build.
type Options struct {
	Logger    *slog.Logger
	Getenv    func(string) string
	PluginDir string // overrides cfg.PluginDir when set
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
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Getenv == nil {
		opts.Getenv = func(string) string { return "" }
	}
	dir := cfg.PluginDir
	if opts.PluginDir != "" {
		dir = opts.PluginDir
	}
	base := plugin.Env{Logger: opts.Logger, PluginDir: dir, Getenv: opts.Getenv, Providers: providerNames(cfg)}

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
	if cfg.Troubleshoot.Whois != nil {
		if b := build(plugin.Whoises, "troubleshoot.whois", []config.PluginSpec{*cfg.Troubleshoot.Whois}, base, &errs); len(b) == 1 {
			s.Whois = &b[0]
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Set) all() []namedLifecycle {
	var out []namedLifecycle
	add := func(kind plugin.Kind, name string, lc plugin.Lifecycle) {
		out = append(out, namedLifecycle{fmt.Sprintf("%s %s", kind, name), lc})
	}
	// Storage starts first and stops last, so history can be flushed
	// after the announcer has withdrawn.
	if s.Storage != nil {
		add(plugin.KindStorage, s.Storage.Name, s.Storage.Plugin)
	}
	for _, p := range s.RIBSources {
		add(plugin.KindRIBSource, p.Name, p.Plugin)
	}
	for _, p := range s.Sources {
		add(plugin.KindSource, p.Name, p.Plugin)
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
	if s.Whois != nil {
		add(plugin.KindWhois, s.Whois.Name, s.Whois.Plugin)
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
		s.started = append(s.started, nl)
	}
	return nil
}

// Stop stops started plugins in reverse order (the announcer, which is
// started last, is stopped first so routes are withdrawn early).
func (s *Set) Stop(ctx context.Context) error {
	var errs []error
	for i := len(s.started) - 1; i >= 0; i-- {
		nl := s.started[i]
		if err := nl.lc.Stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("stop %s: %w", nl.label, err))
		}
	}
	s.started = nil
	return errors.Join(errs...)
}

func providerNames(cfg *config.Config) []string {
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
