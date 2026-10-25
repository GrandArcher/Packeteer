// Package weighted implements the default "weighted" scorer:
//
//	score = loss_pct*loss_weight + rtt_ms*rtt_weight + jitter_ms*jitter_weight + reorder_pct*reorder_weight
//
// Lower is better. With the defaults (100, 1, 0.5, 0) one percent of loss
// costs as much as 100 ms of latency, so loss dominates, then latency, then
// jitter; reordering (#224) counts only when reorder_weight is set.
package weighted

import (
	"fmt"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weights"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "weighted"

// Defaults.
const (
	DefaultLossWeight   = 100
	DefaultRTTWeight    = 1
	DefaultJitterWeight = 0.5
	// DefaultReorderWeight is zero: reordering (#224) enters the score only when the
	// operator sets reorder_weight.
	DefaultReorderWeight = 0
)

func init() { plugin.Scorers.Register(TypeName, New) }

// Config is the weighted scorer's config block.
type Config struct {
	LossWeight   *float64 `yaml:"loss_weight"`
	RTTWeight    *float64 `yaml:"rtt_weight"`
	JitterWeight *float64 `yaml:"jitter_weight"`
	// ReorderWeight is the cost of one percent of reordered packets on the
	// provider path (#224). Default 0: off.
	ReorderWeight *float64 `yaml:"reorder_weight"`
	// ImprovementWeights orders new improvements for the
	// max_improvements cap (#34). Nil ranks by score gain.
	ImprovementWeights *weights.Config `yaml:"improvement_weights"`
}

// Scorer is a linear weighted scorer.
type Scorer struct {
	plugin.Base
	weights.Weights
	loss, rtt, jitter, reorder float64
}

// New is the plugin factory.
func New(c plugin.Config, _ plugin.Env) (plugin.Scorer, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	s := &Scorer{loss: DefaultLossWeight, rtt: DefaultRTTWeight, jitter: DefaultJitterWeight, reorder: DefaultReorderWeight}
	for name, pair := range map[string]struct {
		in  *float64
		out *float64
	}{"loss_weight": {cfg.LossWeight, &s.loss}, "rtt_weight": {cfg.RTTWeight, &s.rtt}, "jitter_weight": {cfg.JitterWeight, &s.jitter}, "reorder_weight": {cfg.ReorderWeight, &s.reorder}} {
		if pair.in == nil {
			continue
		}
		if *pair.in < 0 {
			return nil, fmt.Errorf("%s %v must not be negative", name, *pair.in)
		}
		*pair.out = *pair.in
	}
	if s.loss == 0 && s.rtt == 0 && s.jitter == 0 && s.reorder == 0 {
		return nil, fmt.Errorf("at least one weight must be positive")
	}
	w, err := weights.New(cfg.ImprovementWeights)
	if err != nil {
		return nil, err
	}
	s.Weights = w
	return s, nil
}

// Score implements plugin.Scorer.
func (s *Scorer) Score(p plugin.PathStats) float64 {
	ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
	return p.LossPct*s.loss + ms(p.RTTAvg)*s.rtt + ms(p.Jitter)*s.jitter + p.ReorderPct*s.reorder
}
