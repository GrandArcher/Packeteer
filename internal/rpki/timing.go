package rpki

import (
	"fmt"
	"time"
)

// Timer defaults and bounds shared by the VRP cache sources.
const (
	DefaultRefresh   = 5 * time.Minute
	DefaultStaleness = time.Hour
	DefaultTimeout   = 30 * time.Second
	MinRefresh       = time.Second
	MaxRefresh       = 24 * time.Hour
	MinTimeout       = time.Second
	MaxTimeout       = 5 * time.Minute
	// MaxVRPs bounds the cache one source can grow, so a broken or hostile
	// server cannot exhaust memory. It is well above the public RPKI
	// table.
	MaxVRPs = 2_000_000
)

// Timing is a VRP cache source's timers.
type Timing struct {
	// Refresh is how often a healthy source is polled (default 5m).
	Refresh time.Duration `yaml:"refresh"`
	// Staleness is how long data is served past its data time (see
	// plugin.RPKIStatus.Updated); older or missing data is unknown
	// (default 1h).
	Staleness time.Duration `yaml:"staleness"`
	// Timeout bounds one dial, handshake, fetch, or read wait (default
	// 30s).
	Timeout time.Duration `yaml:"timeout"`
}

// Normalize fills the defaults and checks the bounds: staleness is at
// least refresh, so a healthy source never reads as stale between polls.
func (t *Timing) Normalize() error {
	if t.Refresh == 0 {
		t.Refresh = DefaultRefresh
	}
	if t.Refresh < MinRefresh || t.Refresh > MaxRefresh {
		return fmt.Errorf("refresh %s must be between %s and %s", t.Refresh, MinRefresh, MaxRefresh)
	}
	if t.Staleness == 0 {
		t.Staleness = max(DefaultStaleness, t.Refresh)
	}
	if t.Staleness < t.Refresh || t.Staleness > MaxRefresh {
		return fmt.Errorf("staleness %s must be between refresh (%s) and %s", t.Staleness, t.Refresh, MaxRefresh)
	}
	if t.Timeout == 0 {
		t.Timeout = DefaultTimeout
	}
	if t.Timeout < MinTimeout || t.Timeout > MaxTimeout {
		return fmt.Errorf("timeout %s must be between %s and %s", t.Timeout, MinTimeout, MaxTimeout)
	}
	return nil
}

// Stale reports whether data with data time updated is too old to use at
// now. No data yet is stale.
func (t Timing) Stale(updated, now time.Time) bool {
	return updated.IsZero() || now.Sub(updated) > t.Staleness
}
