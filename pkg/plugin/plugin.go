// Package plugin defines Packeteer's extension points.
//
// Every capability that could reasonably vary between deployments (how to
// probe, where targets come from, how paths are scored, how routes reach the
// router, where alerts go) is a small interface here. Implementations register
// a Factory under a type name in the matching Registry, and the operator
// selects them in config by that name:
//
//	probers:
//	  - type: icmp
//	  - type: exec
//	    config: {command: my-prober}
//
// A Factory is the plugin's Init step: it decodes and validates its own
// config and returns an error if anything is wrong. Nothing may touch the
// network in a Factory. Start begins background work; Stop must release all
// resources and return promptly once its context is cancelled.
//
// This package is public so that external Go code can implement plugins
// and compile them into a custom build. Plugins that must work with the stock
// container image use the out-of-process "exec" type instead (docs/PLUGINS.md).
package plugin

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"time"
)

// Kind names an extension point.
type Kind string

// Extension points.
const (
	KindProber    Kind = "prober"
	KindSource    Kind = "source"
	KindScorer    Kind = "scorer"
	KindAnnouncer Kind = "announcer"
	KindNotifier  Kind = "notifier"
)

// Lifecycle is implemented by every plugin.
type Lifecycle interface {
	// Start begins any background work. It must not block; long-running
	// work should run in goroutines that stop when ctx is cancelled.
	Start(ctx context.Context) error
	// Stop releases resources. It must return by the time ctx expires.
	Stop(ctx context.Context) error
}

// Base provides no-op Start and Stop for plugins without background work.
type Base struct{}

// Start implements Lifecycle.
func (Base) Start(context.Context) error { return nil }

// Stop implements Lifecycle.
func (Base) Stop(context.Context) error { return nil }

// Env is what the host gives each plugin at construction time.
type Env struct {
	// Name is the instance name from config (defaults to the type).
	Name string
	// Logger is scoped to this plugin instance.
	Logger *slog.Logger
	// PluginDir is where out-of-process plugins live
	// (default /etc/packeteer/plugins).
	PluginDir string
	// Getenv reads the process environment (injectable for tests).
	Getenv func(string) string
}

// ---- Prober ----

// ProbeRequest asks a prober to measure one path.
type ProbeRequest struct {
	Provider string        // provider name from config
	Source   netip.Addr    // local source address that egresses via Provider
	Target   netip.Addr    // destination host
	Count    int           // packets to send
	Timeout  time.Duration // per-packet timeout
}

// ProbeResult is the raw outcome of one probe run. The core computes loss,
// RTT statistics, and jitter from it so every prober is measured the same way.
type ProbeResult struct {
	Sent int
	// RTTs holds one entry per reply received, in send order.
	RTTs []time.Duration
}

// Prober measures reachability and latency from a source to a target.
// Implementations must bind to req.Source and return an error (not a 100%
// loss result) if the source cannot be used, so the core can fail closed.
type Prober interface {
	Lifecycle
	Probe(ctx context.Context, req ProbeRequest) (ProbeResult, error)
}

// ---- Target source ----

// Target is a destination prefix to measure, with an optional
// representative host to probe inside it.
type Target struct {
	Prefix netip.Prefix
	Host   netip.Addr // zero value: the engine picks one inside Prefix
	Weight float64    // relative importance, e.g. bytes from flow data
	// Interval, when positive, overrides the engine probe interval for
	// this prefix. The vip source sets it so critical prefixes are
	// measured more often. Zero means the engine interval. Run honors
	// it; RunOnce still measures every target.
	Interval time.Duration
	// Urgent asks for a measurement on this round even when Interval has
	// not elapsed. The outage source sets it for one pass after a new
	// incident. Leaving it set on every call makes the scheduler spin.
	Urgent bool
}

// TargetSource supplies the set of prefixes to probe.
type TargetSource interface {
	Lifecycle
	Targets(ctx context.Context) ([]Target, error)
}

// ---- Scorer ----

// PathStats summarizes one provider's measurements toward one prefix.
type PathStats struct {
	Provider string
	LossPct  float64
	RTTAvg   time.Duration
	Jitter   time.Duration
}

// Scorer turns path statistics into a comparable score; lower is better.
type Scorer interface {
	Lifecycle
	Score(s PathStats) float64
}

// ---- Announcer ----

// Route is a route Packeteer wants the edge router to use.
type Route struct {
	Prefix      netip.Prefix
	NextHop     netip.Addr
	Provider    string
	LocalPref   uint32
	Communities []string // standard communities, "asn:value"
}

// Announcer is the router driver. Announcers run in-process only: an
// out-of-process plugin must never be able to inject routes.
// Implementations must withdraw everything on Stop and must not use
// graceful restart.
type Announcer interface {
	Lifecycle
	Announce(ctx context.Context, r Route) error
	Withdraw(ctx context.Context, p netip.Prefix) error
	WithdrawAll(ctx context.Context) error
}

// ---- Notifier ----

// Severity of an Event.
type Severity string

// Severities.
const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Event is something operators may want to be told about.
type Event struct {
	Time     time.Time         `json:"time"`
	Kind     string            `json:"kind"` // e.g. "improvement.added"
	Severity Severity          `json:"severity"`
	Message  string            `json:"message"`
	Fields   map[string]string `json:"fields,omitempty"`
}

// Notifier delivers events (webhook, email, chat, ...).
type Notifier interface {
	Lifecycle
	Notify(ctx context.Context, e Event) error
}

// ErrSourceUnavailable is returned (wrapped) by probers when the requested
// source address cannot be used, e.g. it is not configured on the host. The
// core treats it as "provider down" and fails closed instead of guessing.
var ErrSourceUnavailable = errors.New("probe source address unavailable")
