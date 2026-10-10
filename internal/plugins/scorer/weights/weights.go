// Package weights is the improvement_weights block the built-in scorers
// (weighted, commit, cost) share (#34). It
// decides which new improvements take the last max_improvements slots:
//
//	weight = performance * gain + volume * volume_mbps
//
// where gain is the native path's score minus the chosen path's. It is
// not a plugin type of its own.
package weights

import (
	"fmt"
	"math"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Defaults when the block is present but a key is omitted.
const (
	DefaultPerformance = 1
	DefaultVolume      = 0
	// MaxWeight bounds each coefficient.
	MaxWeight = 1e6
)

// Config is the improvement_weights block.
type Config struct {
	// Performance multiplies the score gain (default 1).
	Performance *float64 `yaml:"performance"`
	// Volume multiplies the prefix's observed traffic in Mbps (default 0).
	// A source that reports volume (flow, or mbps on a static target) is
	// needed for it to matter.
	Volume *float64 `yaml:"volume"`
}

// Weights implements plugin.ImprovementWeigher. The zero value is off.
type Weights struct {
	on          bool
	performance float64
	volume      float64
}

var _ plugin.ImprovementWeigher = Weights{}

// New validates c. A nil c is off: moves rank by gain as before.
func New(c *Config) (Weights, error) {
	if c == nil {
		return Weights{}, nil
	}
	w := Weights{on: true, performance: DefaultPerformance, volume: DefaultVolume}
	for name, pair := range map[string]struct {
		in  *float64
		out *float64
	}{"performance": {c.Performance, &w.performance}, "volume": {c.Volume, &w.volume}} {
		if pair.in == nil {
			continue
		}
		v := *pair.in
		if math.IsNaN(v) || v < 0 || v > MaxWeight {
			return Weights{}, fmt.Errorf("improvement_weights.%s %v must be between 0 and %g", name, v, float64(MaxWeight))
		}
		*pair.out = v
	}
	if w.performance == 0 && w.volume == 0 {
		return Weights{}, fmt.Errorf("improvement_weights: performance or volume must be positive")
	}
	return w, nil
}

// ImprovementWeights implements plugin.ImprovementWeigher.
func (w Weights) ImprovementWeights() (on, volume bool) { return w.on, w.on && w.volume > 0 }

// ImprovementWeight implements plugin.ImprovementWeigher.
func (w Weights) ImprovementWeight(in plugin.WeightInput) float64 {
	vol := in.VolumeMbps
	if math.IsNaN(vol) || vol < 0 {
		vol = 0
	}
	return w.performance*in.Gain + w.volume*vol
}
