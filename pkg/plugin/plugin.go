// Package plugin defines Packeteer's extension points.
//
// Every capability that could reasonably vary between deployments (how to
// probe, where targets come from, how paths are scored, how routes reach the
// router, where alerts go, how interface usage is collected) is a small interface here. Implementations register
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
	KindTelemetry Kind = "telemetry"
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
	// Providers lists configured provider names. Telemetry plugins reject
	// a binding that is not in this list. Nil means the caller is not
	// asking for that check (unit tests). An empty non-nil slice rejects
	// every name.
	Providers []string
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

// Causes recorded on an improvement.
const (
	// CausePerformance is a move that cleared the loss or latency thresholds.
	CausePerformance = "performance"
	// CauseCommit is a move that keeps a provider under its commit or
	// balances a provider group. It is not a performance win.
	CauseCommit = "commit"
	// CauseCost is a move onto a cheaper provider whose path is inside the
	// cost scorer's performance floor. It is not a performance win.
	CauseCost = "cost"
)

// PrefixVolume is observed traffic for one prefix. Bytes is the total over
// Window. A source that cannot time the window leaves both zero.
type PrefixVolume struct {
	Prefix netip.Prefix
	Bytes  uint64
	Window time.Duration
}

// Mbps is the average rate over Window, in decimal megabits per second.
// It is zero when Bytes or Window is zero.
func (v PrefixVolume) Mbps() float64 {
	if v.Bytes == 0 || v.Window <= 0 {
		return 0
	}
	sec := v.Window.Seconds()
	if sec <= 0 {
		return 0
	}
	return float64(v.Bytes) * 8 / sec / 1e6
}

// VolumeSource is optional on a target source that sees traffic. The
// decision engine reads it when the scorer plans commit moves. Volumes
// must not announce routes.
type VolumeSource interface {
	Volumes(ctx context.Context) ([]PrefixVolume, error)
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

// ---- Telemetry ----

// PercentileMode selects how a billing period's interface samples become
// a usage figure. Rates are whatever unit the caller stored; the mode
// only combines them.
type PercentileMode string

// 95th-percentile billing modes.
const (
	// PercentileSeparate keeps inbound and outbound 95ths apart. There is
	// no single billable figure; compare each direction to the commit.
	PercentileSeparate PercentileMode = "separate"
	// PercentileGreater is the 95th percentile of max(in, out) at each sample.
	PercentileGreater PercentileMode = "greater"
	// PercentileGreaterSeparate is the greater of the inbound 95th and the
	// outbound 95th, each computed on its own.
	PercentileGreaterSeparate PercentileMode = "greater_separate"
)

// RateSample is one interface observation. In and Out are the same unit.
type RateSample struct {
	In  float64
	Out float64
}

// PercentileSummary is the 95th-percentile reading of one billing window.
// Single is false for PercentileSeparate and when Samples is 0: Usage is
// then not a billable figure.
type PercentileSummary struct {
	In95    float64
	Out95   float64
	Usage   float64
	Single  bool
	Samples int
}

// Usage is one provider's interface telemetry for the open billing period.
// Rates are decimal megabits per second (bits/1e6, not 1024^2). A telemetry
// plugin reports usage. It must not announce routes.
type Usage struct {
	Provider    string
	Host        string
	Interface   string
	IfIndex     int
	CommitMbps  float64
	BillingDay  int
	Mode        PercentileMode
	PeriodStart time.Time
	PeriodEnd   time.Time
	Samples     int
	// InMbps and OutMbps are the latest accepted sample. They stay set
	// after the billing period rolls until the next sample, so a reader
	// can see PeriodStart and Updated together.
	InMbps    float64
	OutMbps   float64
	InMbps95  float64
	OutMbps95 float64
	// UsageMbps is the single billable figure when Single is true.
	UsageMbps float64
	Single    bool
	Updated   time.Time
	Polled    time.Time
	// Error is the last poll error. Empty when the last poll succeeded.
	// A poll error does not drop samples already stored.
	Error string
}

// BillableMbps is the figure outbound commit control compares with
// CommitMbps. A single-figure percentile mode uses UsageMbps. separate
// keeps the two directions apart, so the outbound 95th is the figure:
// commit control steers traffic the edge sends. ok is false when no
// sample is stored or the commit is not positive.
func (u Usage) BillableMbps() (float64, bool) {
	if u.Samples <= 0 || u.CommitMbps <= 0 {
		return 0, false
	}
	if u.Single {
		return u.UsageMbps, true
	}
	return u.OutMbps95, true
}

// Telemetry collects per-provider interface usage. Implementations must
// not announce routes or change decisions.
type Telemetry interface {
	Lifecycle
	Snapshot(ctx context.Context) ([]Usage, error)
}

// ErrSourceUnavailable is returned (wrapped) by probers when the requested
// source address cannot be used, e.g. it is not configured on the host. The
// core treats it as "provider down" and fails closed instead of guessing.
var ErrSourceUnavailable = errors.New("probe source address unavailable")
