// Package outage implements the "outage" target source.
//
// It correlates probe results by learned AS path and by provider. When
// enough prefixes fail together it returns them as urgent probe targets
// and emits notifier events. It does not announce. Injection still
// requires the prefix in the learned RIB, the allowlist, the community,
// the improvement cap, and hold time.
package outage

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "outage"

// Incident kinds stored on Incident.Kind.
const (
	IncidentAS      = "as"
	IncidentCircuit = "circuit"
)

// Notifier event kinds.
const (
	EventAS      = "outage.as"
	EventCircuit = "outage.circuit"
	EventCleared = "outage.cleared"
)

// Defaults and bounds. A bare zero on min_prefixes, window, loss_pct,
// interval, and max_targets selects the default. rtt_ms zero disables
// the RTT check. min_prefixes cannot be set below 2, so one noisy prefix
// is never an incident.
const (
	DefaultMinPrefixes = 3
	DefaultWindow      = 2 * time.Minute
	DefaultLossPct     = 20
	DefaultInterval    = 5 * time.Second
	DefaultMaxTargets  = 100
	MaxTargetsLimit    = 10000
	MinInterval        = time.Second
	MaxWindow          = 24 * time.Hour
	MaxMinPrefixes     = 10000
)

func init() { plugin.Sources.Register(TypeName, New) }

// Config is the outage source's config block.
type Config struct {
	MinPrefixes int           `yaml:"min_prefixes"`
	Window      time.Duration `yaml:"window"`
	LossPct     float64       `yaml:"loss_pct"`
	RTTMs       float64       `yaml:"rtt_ms"`
	Interval    time.Duration `yaml:"interval"`
	MaxTargets  int           `yaml:"max_targets"`
	IgnoreASNs  []uint32      `yaml:"ignore_asns"`
}

func (c Config) normalized() Config {
	if c.MinPrefixes == 0 {
		c.MinPrefixes = DefaultMinPrefixes
	}
	if c.Window == 0 {
		c.Window = DefaultWindow
	}
	if c.LossPct == 0 {
		c.LossPct = DefaultLossPct
	}
	if c.Interval == 0 {
		c.Interval = DefaultInterval
	}
	if c.MaxTargets == 0 {
		c.MaxTargets = DefaultMaxTargets
	}
	return c
}

// Source re-queues prefixes while an AS or circuit incident is active.
type Source struct {
	plugin.Base
	log *slog.Logger
	cfg Config

	mu        sync.Mutex
	samples   func() []Sample
	routes    func() []Route
	notify    func(plugin.Event)
	active    map[string]Incident
	targets   []plugin.Target
	immediate bool
}

// New is the plugin factory. It does no I/O.
func New(c plugin.Config, env plugin.Env) (plugin.TargetSource, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	cfg = cfg.normalized()
	if cfg.MinPrefixes < 2 || cfg.MinPrefixes > MaxMinPrefixes {
		return nil, fmt.Errorf("min_prefixes %d must be between 2 and %d", cfg.MinPrefixes, MaxMinPrefixes)
	}
	if cfg.Window < MinInterval || cfg.Window > MaxWindow {
		return nil, fmt.Errorf("window %s must be between %s and %s", cfg.Window, MinInterval, MaxWindow)
	}
	if cfg.LossPct < 0 || cfg.LossPct > 100 {
		return nil, fmt.Errorf("loss_pct %v must be between 0 and 100", cfg.LossPct)
	}
	if cfg.RTTMs < 0 {
		return nil, fmt.Errorf("rtt_ms %v must not be negative", cfg.RTTMs)
	}
	if cfg.Interval < MinInterval || cfg.Interval > MaxWindow {
		return nil, fmt.Errorf("interval %s must be between %s and %s", cfg.Interval, MinInterval, MaxWindow)
	}
	if cfg.MaxTargets < 1 || cfg.MaxTargets > MaxTargetsLimit {
		return nil, fmt.Errorf("max_targets %d must be between 1 and %d", cfg.MaxTargets, MaxTargetsLimit)
	}
	seen := map[uint32]struct{}{}
	for i, asn := range cfg.IgnoreASNs {
		if asn == 0 {
			return nil, fmt.Errorf("ignore_asns[%d]: asn must be non-zero", i)
		}
		if _, dup := seen[asn]; dup {
			return nil, fmt.Errorf("ignore_asns[%d]: duplicate asn %d", i, asn)
		}
		seen[asn] = struct{}{}
	}
	if env.Logger == nil {
		env.Logger = slog.Default()
	}
	return &Source{log: env.Logger, cfg: cfg, active: map[string]Incident{}}, nil
}

// Interval is the reprobe cadence while an incident is active. The
// controller rejects a value that is not shorter than probe.interval and
// the staleness window.
func (s *Source) Interval() time.Duration { return s.cfg.Interval }

// Fresh reports that Targets changes after each probe round, so the probe
// engine must not cache this source for probe.interval.
func (s *Source) Fresh() bool { return true }

// SetSnapshots installs the probe and RIB reads. Either function may be
// nil. Routes must be empty unless the RIB view is ready; a default route
// must not be included. The controller copies AS paths.
func (s *Source) SetSnapshots(samples func() []Sample, routes func() []Route) {
	s.mu.Lock()
	s.samples, s.routes = samples, routes
	s.mu.Unlock()
}

// SetNotify installs the event hook. The controller fans the event out to
// the configured notifiers. Nil drops the hook; the source still logs.
func (s *Source) SetNotify(fn func(plugin.Event)) {
	s.mu.Lock()
	s.notify = fn
	s.mu.Unlock()
}

// Evaluate correlates the current snapshots. It returns true when the
// probe loop should wake immediately because the re-queue set gained
// prefixes. Events fire on transitions, not on every call.
func (s *Source) Evaluate(now time.Time) bool {
	s.mu.Lock()
	samplesFn, routesFn, cfg := s.samples, s.routes, s.cfg
	s.mu.Unlock()
	var samples []Sample
	var routes []Route
	if samplesFn != nil {
		samples = samplesFn()
	}
	if routesFn != nil {
		routes = routesFn()
	}
	events, wake := s.apply(now, Detect(now, samples, routes, cfg))
	for _, ev := range events {
		s.emit(ev)
	}
	return wake
}

// Targets implements plugin.TargetSource. While an incident is active the
// prefixes that cross the sick ASN, or that sit on the sick provider, are
// returned with Interval set. The first call after the set changes marks
// them Urgent so the probe engine measures them even if they were probed
// moments ago. Later calls leave Urgent clear and the interval applies,
// so the scheduler does not tight-loop.
func (s *Source) Targets(context.Context) ([]plugin.Target, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := cloneTargets(s.targets)
	if s.immediate {
		for i := range out {
			out[i].Urgent = true
		}
		s.immediate = false
	}
	return out, nil
}

func (s *Source) apply(now time.Time, out Outcome) (events []plugin.Event, wake bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := map[string]Incident{}
	for _, inc := range out.Incidents {
		next[incidentKey(inc)] = inc
	}
	var opened []string
	for k := range next {
		if _, ok := s.active[k]; !ok {
			opened = append(opened, k)
		}
	}
	sort.Strings(opened)
	for _, k := range opened {
		events = append(events, eventFor(now, next[k], false))
	}
	var closed []string
	for k := range s.active {
		if _, ok := next[k]; !ok {
			closed = append(closed, k)
		}
	}
	sort.Strings(closed)
	for _, k := range closed {
		events = append(events, eventFor(now, s.active[k], true))
	}
	s.active = next
	if !sameTargets(s.targets, out.Targets) {
		s.targets = cloneTargets(out.Targets)
		s.immediate = len(s.targets) > 0
		wake = s.immediate
		if out.Truncated && wake {
			s.log.Warn("outage target list truncated", "max_targets", s.cfg.MaxTargets, "returned", len(s.targets))
		}
	}
	return events, wake
}

func (s *Source) emit(ev plugin.Event) {
	if ev.Severity == plugin.SeverityCritical {
		s.log.Warn(ev.Message, "kind", ev.Kind)
	} else {
		s.log.Info(ev.Message, "kind", ev.Kind)
	}
	s.mu.Lock()
	fn := s.notify
	s.mu.Unlock()
	if fn != nil {
		fn(ev)
	}
}

func incidentKey(inc Incident) string {
	if inc.Kind == IncidentCircuit {
		return "circuit:" + inc.Provider
	}
	return "as:" + strconv.FormatUint(uint64(inc.ASN), 10)
}

func eventFor(now time.Time, inc Incident, cleared bool) plugin.Event {
	fields := map[string]string{
		"count":    strconv.Itoa(len(inc.Prefixes)),
		"prefixes": joinPrefixes(inc.Prefixes),
	}
	var kind, msg string
	if inc.Kind == IncidentCircuit {
		fields["provider"] = inc.Provider
		if cleared {
			kind, msg = EventCleared, "circuit "+inc.Provider+" recovered"
		} else {
			kind = EventCircuit
			msg = fmt.Sprintf("circuit %s degraded across %d prefixes", inc.Provider, len(inc.Prefixes))
		}
	} else {
		asn := strconv.FormatUint(uint64(inc.ASN), 10)
		fields["asn"] = asn
		if cleared {
			kind, msg = EventCleared, "AS "+asn+" recovered"
		} else {
			kind = EventAS
			msg = fmt.Sprintf("AS %s degraded across %d prefixes", asn, len(inc.Prefixes))
		}
	}
	if !cleared {
		fields["requeued"] = strconv.Itoa(inc.Requeued)
		if inc.Kind == IncidentAS && len(inc.Providers) > 0 {
			fields["providers"] = strings.Join(inc.Providers, ",")
		}
	}
	sev := plugin.SeverityCritical
	if cleared {
		sev = plugin.SeverityWarning
	}
	return plugin.Event{Time: now, Kind: kind, Severity: sev, Message: msg, Fields: fields}
}

func joinPrefixes(ps []netip.Prefix) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.String()
	}
	return strings.Join(parts, ",")
}

func sameTargets(a, b []plugin.Target) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Prefix != b[i].Prefix || a[i].Interval != b[i].Interval {
			return false
		}
	}
	return true
}

func cloneTargets(in []plugin.Target) []plugin.Target {
	if len(in) == 0 {
		return nil
	}
	out := make([]plugin.Target, len(in))
	copy(out, in)
	return out
}
