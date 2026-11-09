package config

import "time"

// Probe path-check defaults and bounds (#150).
const (
	DefaultPathCheckInterval = 5 * time.Minute
	MinPathCheckInterval     = time.Second
	MaxPathCheckInterval     = 24 * time.Hour
)

// ProbePathCheck periodically verifies that probe packets from each
// provider's source_ip leave through that provider's next_hop (#150). A
// mis-routed source silently measures another provider's path, so a
// mismatch marks the provider down with reason "probe path mismatch" and
// its improvements are withdrawn. Measurement only: nothing is announced
// from it. On unless `enabled: false`; one provider also opts out with
// `path_check: false`.
type ProbePathCheck struct {
	// Enabled is true when omitted. false stops the checks.
	Enabled *bool `yaml:"enabled"`
	// Interval is how often every provider is checked.
	Interval time.Duration `yaml:"interval"`
}

// On reports whether the probe-path check runs.
func (p ProbePathCheck) On() bool { return p.Enabled == nil || *p.Enabled }

// PathCheckOn reports whether the first-hop probe-path check runs for
// this provider (#150). On unless the provider sets path_check: false.
// A provider whose traffic does not leave directly through next_hop (for
// example one reached across another router) opts out.
func (p Provider) PathCheckOn() bool { return p.PathCheck == nil || *p.PathCheck }

func (c *Config) defaultPathCheck() {
	if c.Probe.PathCheck.Interval == 0 {
		c.Probe.PathCheck.Interval = DefaultPathCheckInterval
	}
}

func (c *Config) validatePathCheck(add func(string, ...any)) {
	p := c.Probe.PathCheck
	if p.Interval < MinPathCheckInterval || p.Interval > MaxPathCheckInterval {
		add("probe.path_check.interval %s must be between %s and %s", p.Interval, MinPathCheckInterval, MaxPathCheckInterval)
	}
}
