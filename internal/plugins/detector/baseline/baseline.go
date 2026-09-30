// Package baseline implements the "baseline" anomaly detector (#33).
//
// For every destination prefix and IP protocol it keeps an exponentially
// weighted mean and variance of the rate seen each detection round. A key
// is anomalous in a round when its rate is at least min_mbps, at least
// min_ratio times its mean, and more than sensitivity standard deviations
// above its mean, once it has learned for warmup rounds; or, with max_mbps
// set, when the rate reaches that ceiling whatever the baseline. An
// anomaly opens after trigger_rounds anomalous rounds in a row and clears
// after clear_rounds normal rounds in a row. Anomalous rounds, and every
// round of an open anomaly, are not learned, so a long attack does not
// become the baseline.
//
// Baselines live in memory only: a restart learns again. The detector
// never announces and never adds a mitigation rule; the core does that
// only for an explicit anomaly rule.
package baseline

import (
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "baseline"

// Defaults and bounds.
const (
	DefaultSensitivity   = 3.0
	DefaultMinRatio      = 3.0
	DefaultMinMbps       = 10.0
	DefaultAlpha         = 0.05
	DefaultWarmup        = 30
	DefaultTriggerRounds = 2
	DefaultClearRounds   = 3
	DefaultMaxKeys       = 10000

	maxSensitivity = 100.0
	maxRatio       = 1000.0
	maxRateMbps    = 100000000.0
	maxWarmup      = 100000
	maxRounds      = 1000
	maxKeysLimit   = 100000

	// forgetMbps: an idle key whose mean decayed below this is dropped.
	forgetMbps = 0.001
)

func init() { plugin.Detectors.Register(TypeName, New) }

// Config is the detector's config block.
type Config struct {
	// Sensitivity is how many standard deviations above the mean a rate
	// must be. Lower is more sensitive. Default 3.
	Sensitivity float64 `yaml:"sensitivity"`
	// MinRatio is how many times the mean a rate must be. Default 3.
	MinRatio float64 `yaml:"min_ratio"`
	// MinMbps is the smallest rate that can be anomalous. Default 10.
	MinMbps float64 `yaml:"min_mbps"`
	// MaxMbps, when set, is a static ceiling: a rate at or above it is
	// anomalous even before the key has a baseline. Default off.
	MaxMbps float64 `yaml:"max_mbps"`
	// Alpha is the weight of each new round in the mean and variance
	// (0 < alpha <= 1). Default 0.05.
	Alpha float64 `yaml:"alpha"`
	// Warmup is how many rounds a key learns before the baseline test
	// applies. Default 30.
	Warmup int `yaml:"warmup"`
	// TriggerRounds and ClearRounds are the hysteresis. Defaults 2 and 3.
	TriggerRounds int `yaml:"trigger_rounds"`
	ClearRounds   int `yaml:"clear_rounds"`
	// MaxKeys caps tracked keys. New keys past it are not tracked.
	// Default 10000.
	MaxKeys int `yaml:"max_keys"`
}

// Validate fills defaults and checks bounds.
func (c *Config) Validate() error {
	if c.Sensitivity == 0 {
		c.Sensitivity = DefaultSensitivity
	}
	if c.MinRatio == 0 {
		c.MinRatio = DefaultMinRatio
	}
	if c.MinMbps == 0 {
		c.MinMbps = DefaultMinMbps
	}
	if c.Alpha == 0 {
		c.Alpha = DefaultAlpha
	}
	if c.Warmup == 0 {
		c.Warmup = DefaultWarmup
	}
	if c.TriggerRounds == 0 {
		c.TriggerRounds = DefaultTriggerRounds
	}
	if c.ClearRounds == 0 {
		c.ClearRounds = DefaultClearRounds
	}
	if c.MaxKeys == 0 {
		c.MaxKeys = DefaultMaxKeys
	}
	bad := func(ok bool) bool { return !ok } // NaN fails every comparison
	switch {
	case bad(c.Sensitivity > 0 && c.Sensitivity <= maxSensitivity):
		return fmt.Errorf("sensitivity %v must be above 0 and at most %v", c.Sensitivity, maxSensitivity)
	case bad(c.MinRatio >= 1 && c.MinRatio <= maxRatio):
		return fmt.Errorf("min_ratio %v must be between 1 and %v", c.MinRatio, maxRatio)
	case bad(c.MinMbps > 0 && c.MinMbps <= maxRateMbps):
		return fmt.Errorf("min_mbps %v must be above 0 and at most %v", c.MinMbps, maxRateMbps)
	case bad(c.MaxMbps == 0 || (c.MaxMbps >= c.MinMbps && c.MaxMbps <= maxRateMbps)):
		return fmt.Errorf("max_mbps %v must be 0 (off) or between min_mbps (%v) and %v", c.MaxMbps, c.MinMbps, maxRateMbps)
	case bad(c.Alpha > 0 && c.Alpha <= 1):
		return fmt.Errorf("alpha %v must be above 0 and at most 1", c.Alpha)
	case c.Warmup < 1 || c.Warmup > maxWarmup:
		return fmt.Errorf("warmup %d must be between 1 and %d", c.Warmup, maxWarmup)
	case c.TriggerRounds < 1 || c.TriggerRounds > maxRounds:
		return fmt.Errorf("trigger_rounds %d must be between 1 and %d", c.TriggerRounds, maxRounds)
	case c.ClearRounds < 1 || c.ClearRounds > maxRounds:
		return fmt.Errorf("clear_rounds %d must be between 1 and %d", c.ClearRounds, maxRounds)
	case c.MaxKeys < 1 || c.MaxKeys > maxKeysLimit:
		return fmt.Errorf("max_keys %d must be between 1 and %d", c.MaxKeys, maxKeysLimit)
	}
	return nil
}

// state is one key's baseline and anomaly state.
type state struct {
	mean, variance float64
	learned        int
	hot, cool      int
	active         bool
	since          time.Time
	last, peak     float64
	reason         string
}

// Detector is the baseline detector.
type Detector struct {
	plugin.Base
	cfg     Config
	keys    map[plugin.TrafficKey]*state
	skipped int
	env     plugin.Env
	warned  bool
}

var _ plugin.Detector = (*Detector)(nil)

// New is the plugin factory.
func New(c plugin.Config, env plugin.Env) (plugin.Detector, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return newDetector(cfg, env), nil
}

func newDetector(cfg Config, env plugin.Env) *Detector {
	return &Detector{cfg: cfg, keys: map[plugin.TrafficKey]*state{}, env: env}
}

// Tracked implements plugin.Detector.
func (d *Detector) Tracked() int { return len(d.keys) }

// Reset implements plugin.Detector.
func (d *Detector) Reset() { d.keys = map[plugin.TrafficKey]*state{} }

// Observe implements plugin.Detector.
func (d *Detector) Observe(now time.Time, samples []plugin.TrafficSample) []plugin.Anomaly {
	rates := make(map[plugin.TrafficKey]float64, len(samples))
	for _, s := range samples {
		if !s.Key.Prefix.IsValid() || !(s.Mbps >= 0) || math.IsInf(s.Mbps, 0) {
			continue
		}
		rates[s.Key] += s.Mbps
	}
	for k, x := range rates {
		if _, ok := d.keys[k]; ok || x <= 0 {
			continue
		}
		if len(d.keys) >= d.cfg.MaxKeys {
			d.skipped++
			if !d.warned && d.env.Logger != nil {
				d.env.Logger.Warn("anomaly detector: max_keys reached; new keys are not tracked", "max_keys", d.cfg.MaxKeys)
				d.warned = true
			}
			continue
		}
		d.keys[k] = &state{}
	}
	var out []plugin.Anomaly
	for k, st := range d.keys {
		x := rates[k]
		d.step(now, st, x)
		if !st.active && x == 0 && st.hot == 0 && st.mean < forgetMbps {
			delete(d.keys, k)
			continue
		}
		if st.active {
			out = append(out, plugin.Anomaly{Key: k, Mbps: st.last, PeakMbps: st.peak, BaselineMbps: st.mean, Reason: st.reason, Since: st.since})
		}
	}
	slices.SortFunc(out, func(a, b plugin.Anomaly) int { return compareKeys(a.Key, b.Key) })
	return out
}

// step feeds one round's rate x to st.
func (d *Detector) step(now time.Time, st *state, x float64) {
	st.last = x
	reason, hot := d.test(st, x)
	if hot {
		st.hot++
		st.cool = 0
		if st.active {
			st.peak = max(st.peak, x)
			st.reason = reason
		} else if st.hot >= d.cfg.TriggerRounds {
			st.active, st.since, st.peak, st.reason = true, now, x, reason
		}
		return
	}
	st.hot = 0
	if st.active {
		st.cool++
		if st.cool < d.cfg.ClearRounds {
			return
		}
		st.active, st.cool, st.peak, st.reason = false, 0, 0, ""
		return
	}
	d.learn(st, x)
}

// test reports whether x is anomalous for st, and why.
func (d *Detector) test(st *state, x float64) (string, bool) {
	c := d.cfg
	if c.MaxMbps > 0 && x >= c.MaxMbps {
		return fmt.Sprintf("%.1f Mbps is at or above max_mbps %g", x, c.MaxMbps), true
	}
	if st.learned < c.Warmup || x < c.MinMbps || x < c.MinRatio*st.mean {
		return "", false
	}
	sd := math.Sqrt(st.variance)
	if x <= st.mean+c.Sensitivity*sd {
		return "", false
	}
	var parts []string
	if sd > 0 {
		parts = append(parts, fmt.Sprintf("%.1f standard deviations", (x-st.mean)/sd))
	}
	if st.mean > 0 {
		parts = append(parts, fmt.Sprintf("%.1fx", x/st.mean))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%.1f Mbps on a key with no baseline traffic", x), true
	}
	return fmt.Sprintf("%.1f Mbps is %s above the %.2f Mbps baseline", x, strings.Join(parts, " and "), st.mean), true
}

// learn folds x into the exponentially weighted mean and variance.
func (d *Detector) learn(st *state, x float64) {
	if st.learned == 0 {
		st.mean, st.variance = x, 0
	} else {
		a := d.cfg.Alpha
		diff := x - st.mean
		inc := a * diff
		st.mean += inc
		st.variance = (1 - a) * (st.variance + diff*inc)
	}
	if st.learned < math.MaxInt32 {
		st.learned++
	}
}

func compareKeys(a, b plugin.TrafficKey) int {
	if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
		return c
	}
	if a.Prefix.Bits() != b.Prefix.Bits() {
		return a.Prefix.Bits() - b.Prefix.Bits()
	}
	return int(a.Protocol) - int(b.Protocol)
}
