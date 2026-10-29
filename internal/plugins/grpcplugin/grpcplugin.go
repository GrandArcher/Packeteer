// Package grpcplugin implements the long-running out-of-process "grpc"
// plugin type for probers, target sources, and notifiers (hashicorp/
// go-plugin over gRPC; the contract is pkg/plugin/rpc). Unlike "exec" it
// keeps one process per plugin instance, checks it with the gRPC health
// service, restarts it with a growing delay when it dies or stops
// answering, and stops it with the controller.
//
// Like exec, a grpc plugin can never be an announcer.
package grpcplugin

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/oop"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
	"github.com/GrandArcher/Packeteer/pkg/plugin/rpc"
)

// TypeName is the plugin type used in config.
const TypeName = oop.GRPCType

// Defaults for the supervision knobs.
const (
	DefaultHealthInterval = 10 * time.Second
	DefaultRestartBackoff = time.Second
	// maxBackoffFactor caps the restart delay at this many times the
	// configured one.
	maxBackoffFactor = 60
)

func init() {
	plugin.Probers.Register(TypeName, func(c plugin.Config, e plugin.Env) (plugin.Prober, error) {
		s, err := newSupervisor(plugin.KindProber, c, e)
		if err != nil {
			return nil, err
		}
		return &Prober{s: s}, nil
	})
	plugin.Sources.Register(TypeName, func(c plugin.Config, e plugin.Env) (plugin.TargetSource, error) {
		s, err := newSupervisor(plugin.KindSource, c, e)
		if err != nil {
			return nil, err
		}
		return &Source{s: s}, nil
	})
	plugin.Notifiers.Register(TypeName, func(c plugin.Config, e plugin.Env) (plugin.Notifier, error) {
		s, err := newSupervisor(plugin.KindNotifier, c, e)
		if err != nil {
			return nil, err
		}
		return &Notifier{s: s}, nil
	})
}

// Config is the grpc plugin's config block.
type Config struct {
	oop.Launch `yaml:",inline"`
	// HealthInterval is the time between health checks of a running
	// plugin.
	HealthInterval time.Duration `yaml:"health_interval"`
	// RestartBackoff is the delay before the first restart of a plugin
	// that died. It doubles after each failed start and after a start that dies soon,
	// up to 60 times this.
	RestartBackoff time.Duration `yaml:"restart_backoff"`

	// EventFilter (events, min_severity, rate_limit, rate_window) is
	// accepted only for notifiers.
	plugin.EventFilter `yaml:",inline"`
}

func newSupervisor(kind plugin.Kind, c plugin.Config, e plugin.Env) (*supervisor, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	spec, err := oop.NewSpec(kind, e, cfg.Launch, cfg.EventFilter)
	if err != nil {
		return nil, err
	}
	if cfg.HealthInterval < 0 || cfg.RestartBackoff < 0 {
		return nil, fmt.Errorf("health_interval and restart_backoff must not be negative")
	}
	if cfg.HealthInterval == 0 {
		cfg.HealthInterval = DefaultHealthInterval
	}
	if cfg.RestartBackoff == 0 {
		cfg.RestartBackoff = DefaultRestartBackoff
	}
	logger := e.Logger
	if logger == nil {
		logger = slog.Default()
	}
	s := newSupervisorFrom(kind, e.Name, spec, cfg.HealthInterval, cfg.RestartBackoff, logger)
	if e.CheckOnly {
		// A config check (the config editor) never starts the program.
		s.checkOnly = true
		return s, nil
	}
	// The plugin validates its own config now, in a process that is gone
	// again before the factory returns; Start launches the long-running
	// one. Nothing stays running for a plugin that is built but not
	// started (-check, a refused reload).
	ctx, cancel := context.WithTimeout(context.Background(), spec.Timeout)
	defer cancel()
	l, err := s.launch(ctx)
	if err != nil {
		return nil, fmt.Errorf("init: %w", err)
	}
	l.stop()
	return s, nil
}

// ---- Prober ----

// Prober is a grpc-backed plugin.Prober.
type Prober struct{ s *supervisor }

// Start implements plugin.Lifecycle.
func (p *Prober) Start(ctx context.Context) error { return p.s.Start(ctx) }

// Stop implements plugin.Lifecycle.
func (p *Prober) Stop(ctx context.Context) error { return p.s.Stop(ctx) }

// Probe implements plugin.Prober.
func (p *Prober) Probe(ctx context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	return call(ctx, p.s, "probe", func(ctx context.Context, c *rpc.Client) (plugin.ProbeResult, error) {
		return c.Probe(ctx, req)
	})
}

// ---- Target source ----

// Source is a grpc-backed plugin.TargetSource.
type Source struct{ s *supervisor }

// Start implements plugin.Lifecycle.
func (s *Source) Start(ctx context.Context) error { return s.s.Start(ctx) }

// Stop implements plugin.Lifecycle.
func (s *Source) Stop(ctx context.Context) error { return s.s.Stop(ctx) }

// Targets implements plugin.TargetSource.
func (s *Source) Targets(ctx context.Context) ([]plugin.Target, error) {
	return call(ctx, s.s, "targets", func(ctx context.Context, c *rpc.Client) ([]plugin.Target, error) {
		return c.Targets(ctx)
	})
}

// ---- Notifier ----

// Notifier is a grpc-backed plugin.Notifier.
type Notifier struct{ s *supervisor }

// Start implements plugin.Lifecycle.
func (n *Notifier) Start(ctx context.Context) error { return n.s.Start(ctx) }

// Stop implements plugin.Lifecycle.
func (n *Notifier) Stop(ctx context.Context) error { return n.s.Stop(ctx) }

// EventGate implements plugin.Gated.
func (n *Notifier) EventGate() *plugin.EventGate { return n.s.spec.Gate }

// Notify implements plugin.Notifier.
func (n *Notifier) Notify(ctx context.Context, e plugin.Event) error {
	if !n.s.spec.Gate.Match(e) {
		return nil
	}
	_, err := call(ctx, n.s, "notify", func(ctx context.Context, c *rpc.Client) (struct{}, error) {
		return struct{}{}, c.Notify(ctx, e)
	})
	return err
}
