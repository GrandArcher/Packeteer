package verify

import (
	"slices"
	"time"
)

// Defaults and bounds for the verify block.
const (
	DefaultOutboundWindow = 5 * time.Minute
	DefaultInboundWindow  = 10 * time.Minute
	MinWindow             = 10 * time.Second
	MaxWindow             = time.Hour
	DefaultVerifiedPct    = 50
	DefaultMovedPct       = 10
	DefaultMinMbps        = 1
	DefaultBackoff        = 30 * time.Minute
	DefaultMaxBackoff     = 4 * time.Hour
)

// Config is the verify block (#305). Off by default. It never announces:
// a steer is checked against the interface counters and the flow volume,
// and only a back-out undoes one, through the controller that made it.
type Config struct {
	Enabled bool `yaml:"enabled"`
	// OutboundWindow is how long after an outbound improvement the
	// traffic has to show on the new provider (default 5m).
	OutboundWindow time.Duration `yaml:"outbound_window"`
	// InboundWindow is the same for an inbound steer. Inbound telemetry
	// lags more, so the default is 10m.
	InboundWindow time.Duration `yaml:"inbound_window"`
	// VerifiedPct is the share of the expected traffic that must have
	// moved for the steer to count as verified (default 50).
	VerifiedPct float64 `yaml:"verified_pct"`
	// MovedPct is the share below which nothing moved (default 10).
	// Between the two the steer is partial.
	MovedPct float64 `yaml:"moved_pct"`
	// MinMbps is the least traffic worth judging (default 1). With less
	// expected, the steer is unknown: counter noise would decide it.
	MinMbps float64 `yaml:"min_mbps"`
	// Backout lists the directions whose steer is undone when it did not
	// move traffic: "inbound", "outbound", both, or none. Unset is
	// ["inbound"]; the outbound steer is only reported by default.
	Backout []string `yaml:"backout"`
	// Backoff is how long a backed-out steer is held off. It doubles for
	// each consecutive back-out of the same target, up to MaxBackoff.
	Backoff    time.Duration `yaml:"backoff"`
	MaxBackoff time.Duration `yaml:"max_backoff"`
}

// WithDefaults fills unset keys.
func (c Config) WithDefaults() Config {
	if c.OutboundWindow == 0 {
		c.OutboundWindow = DefaultOutboundWindow
	}
	if c.InboundWindow == 0 {
		c.InboundWindow = DefaultInboundWindow
	}
	if c.VerifiedPct == 0 {
		c.VerifiedPct = DefaultVerifiedPct
	}
	if c.MovedPct == 0 {
		c.MovedPct = DefaultMovedPct
	}
	if c.MinMbps == 0 {
		c.MinMbps = DefaultMinMbps
	}
	if c.Backout == nil {
		c.Backout = []string{string(Inbound)}
	}
	if c.Backoff == 0 {
		c.Backoff = DefaultBackoff
	}
	if c.MaxBackoff == 0 {
		c.MaxBackoff = max(DefaultMaxBackoff, c.Backoff)
	}
	return c
}

func (c Config) backsOut(k Kind) bool { return slices.Contains(c.Backout, string(k)) }

// Validate reports every problem with the block.
func (c Config) Validate(add func(string, ...any)) {
	if !c.Enabled {
		if !c.isZero() {
			add("verify: set enabled: true to use windows, thresholds, backout, or backoff")
		}
		return
	}
	for name, w := range map[string]time.Duration{"outbound_window": c.OutboundWindow, "inbound_window": c.InboundWindow} {
		if w != 0 && (w < MinWindow || w > MaxWindow) {
			add("verify.%s: %s is out of range (%s to %s)", name, w, MinWindow, MaxWindow)
		}
	}
	d := c.WithDefaults()
	if d.VerifiedPct <= 0 || d.VerifiedPct > 100 {
		add("verify.verified_pct: %v is out of range (above 0, at most 100)", c.VerifiedPct)
	}
	if d.MovedPct <= 0 || d.MovedPct >= d.VerifiedPct {
		add("verify.moved_pct: %v must be above 0 and below verified_pct %v", c.MovedPct, d.VerifiedPct)
	}
	if c.MinMbps < 0 {
		add("verify.min_mbps: %v must not be negative", c.MinMbps)
	}
	for _, b := range c.Backout {
		if b != string(Inbound) && b != string(Outbound) {
			add("verify.backout: %q is invalid (want inbound or outbound)", b)
		}
	}
	if c.Backoff < 0 {
		add("verify.backoff: %s must not be negative", c.Backoff)
	}
	if d.MaxBackoff < d.Backoff {
		add("verify.max_backoff: %s must not be shorter than backoff %s", c.MaxBackoff, d.Backoff)
	}
}

func (c Config) isZero() bool {
	return c.OutboundWindow == 0 && c.InboundWindow == 0 && c.VerifiedPct == 0 && c.MovedPct == 0 &&
		c.MinMbps == 0 && c.Backout == nil && c.Backoff == 0 && c.MaxBackoff == 0
}
