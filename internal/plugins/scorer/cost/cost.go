// Package cost is the "cost" scorer.
//
// Score matches the weighted scorer, so performance decisions stay the same
// when this scorer is selected. Plan, in addition, moves a prefix to the
// cheapest provider (providers[].cost, price per Mbps) whose path is inside
// a performance floor: at most floor.max_loss_pct above the lowest loss and
// floor.max_rtt above the lowest RTT among usable, non-excluded providers.
// A provider without a cost is never a destination, and a prefix whose
// native provider has no cost is not moved.
//
// precedence decides between performance and cost. performance (default)
// lets a performance move win: the planner only sees prefixes whose native
// path is already best within thresholds. cost offers every prefix to the
// planner, keeps a native path that is inside the floor, and replaces a
// performance move with a cheaper path inside the floor when there is one.
// Decide enforces the floor and the price check itself. Plan does not
// announce.
package cost

import (
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "cost"

// Precedence values.
const (
	PrecedencePerformance = "performance"
	PrecedenceCost        = "cost"
)

const (
	defaultLossWeight   = 100
	defaultRTTWeight    = 1
	defaultJitterWeight = 0.5

	// DefaultFloorRTT is the latency a cost move may add over the fastest path.
	DefaultFloorRTT = 10 * time.Millisecond
	maxFloorRTT     = 10 * time.Second
	costEps         = 1e-9
	lossEps         = 1e-6
)

func init() { plugin.Scorers.Register(TypeName, New) }

// Floor is the performance floor a cost move must stay inside.
type Floor struct {
	// MaxLossPct is the loss a cost path may carry above the lowest loss.
	// Nil means 0: no extra loss.
	MaxLossPct *float64 `yaml:"max_loss_pct"`
	// MaxRTT is the latency a cost path may add over the lowest RTT. Nil
	// means 10ms.
	MaxRTT *time.Duration `yaml:"max_rtt"`
}

// Config is the cost scorer's config block.
type Config struct {
	LossWeight   *float64 `yaml:"loss_weight"`
	RTTWeight    *float64 `yaml:"rtt_weight"`
	JitterWeight *float64 `yaml:"jitter_weight"`
	// Precedence is performance (default) or cost.
	Precedence string `yaml:"precedence"`
	Floor      Floor  `yaml:"floor"`
}

// Scorer scores performance and plans cost moves.
type Scorer struct {
	plugin.Base
	loss, rtt, jitter float64
	costFirst         bool
	floorLoss         float64
	floorRTT          time.Duration
}

// New is the plugin factory. It does no I/O.
func New(c plugin.Config, _ plugin.Env) (plugin.Scorer, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	s := &Scorer{
		loss: defaultLossWeight, rtt: defaultRTTWeight, jitter: defaultJitterWeight,
		floorRTT: DefaultFloorRTT,
	}
	for name, pair := range map[string]struct {
		in  *float64
		out *float64
	}{"loss_weight": {cfg.LossWeight, &s.loss}, "rtt_weight": {cfg.RTTWeight, &s.rtt}, "jitter_weight": {cfg.JitterWeight, &s.jitter}} {
		if pair.in == nil {
			continue
		}
		if *pair.in < 0 {
			return nil, fmt.Errorf("%s %v must not be negative", name, *pair.in)
		}
		*pair.out = *pair.in
	}
	if s.loss == 0 && s.rtt == 0 && s.jitter == 0 {
		return nil, fmt.Errorf("at least one weight must be positive")
	}
	switch cfg.Precedence {
	case "", PrecedencePerformance:
	case PrecedenceCost:
		s.costFirst = true
	default:
		return nil, fmt.Errorf("precedence %q is invalid (want performance or cost)", cfg.Precedence)
	}
	if v := cfg.Floor.MaxLossPct; v != nil {
		if *v < 0 || *v > 100 {
			return nil, fmt.Errorf("floor.max_loss_pct %v must be between 0 and 100", *v)
		}
		s.floorLoss = *v
	}
	if v := cfg.Floor.MaxRTT; v != nil {
		if *v < 0 || *v > maxFloorRTT {
			return nil, fmt.Errorf("floor.max_rtt %s must be between 0s and %s", *v, maxFloorRTT)
		}
		s.floorRTT = *v
	}
	return s, nil
}

// Score implements plugin.Scorer. Lower is better.
func (s *Scorer) Score(p plugin.PathStats) float64 {
	ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
	return p.LossPct*s.loss + ms(p.RTTAvg)*s.rtt + ms(p.Jitter)*s.jitter
}

// Floor implements plugin.CostPolicy.
func (s *Scorer) Floor() (float64, time.Duration) { return s.floorLoss, s.floorRTT }

// CostFirst implements plugin.CostPolicy.
func (s *Scorer) CostFirst() bool { return s.costFirst }

// Plan implements plugin.Planner. It returns the cost steers that should
// exist: an active cost steer (Reversible) is planned again from its
// native provider, and keeps its provider on a price tie.
func (s *Scorer) Plan(in plugin.PlanInput) []plugin.PlanMove {
	prices := map[string]float64{}
	excluded := map[string]bool{}
	for _, p := range in.Providers {
		if p.Name == "" {
			continue
		}
		if p.Excluded {
			excluded[p.Name] = true
		}
		if !p.HasCost || !p.Up || p.Excluded {
			continue
		}
		if _, dup := prices[p.Name]; dup {
			continue
		}
		prices[p.Name] = p.Cost
	}
	natCost := func(name string) (float64, bool) {
		for _, p := range in.Providers {
			if p.Name == name {
				return p.Cost, p.HasCost
			}
		}
		return 0, false
	}

	prefixes := append([]plugin.PlanPrefix(nil), in.Prefixes...)
	sort.SliceStable(prefixes, func(i, j int) bool { return lessPrefix(prefixes[i].Prefix, prefixes[j].Prefix) })
	var moves []plugin.PlanMove
	seen := map[netip.Prefix]bool{}
	for _, px := range prefixes {
		if !px.Prefix.IsValid() || px.Locked || px.Native == "" || seen[px.Prefix] {
			continue
		}
		seen[px.Prefix] = true
		nc, ok := natCost(px.Native)
		if !ok {
			continue
		}
		inside := s.inside(px.Paths, excluded)
		keep := ""
		if px.Reversible {
			keep = px.Current
		}
		best, bestCost, found := "", 0.0, false
		for _, name := range inside {
			c, ok := prices[name]
			if !ok {
				continue
			}
			if !found || c < bestCost-costEps ||
				(c <= bestCost+costEps && tieFirst(name, best, keep, px.Native)) {
				best, bestCost, found = name, c, true
			}
		}
		if !found || best == px.Native || bestCost >= nc-costEps {
			continue
		}
		delta := nc - bestCost
		savings := delta
		if px.VolumeMbps > 0 {
			savings = delta * px.VolumeMbps
		}
		moves = append(moves, plugin.PlanMove{
			Prefix: px.Prefix, Provider: best, Cause: plugin.CauseCost, Savings: savings,
			ReliefMbps: px.VolumeMbps,
			Reason:     fmt.Sprintf("cost: %s %.4g→%s %.4g per Mbps inside floor", px.Native, nc, best, bestCost),
		})
	}
	return moves
}

// inside lists providers whose path is usable and inside the floor. The
// floor is measured from the lowest loss and the lowest RTT among usable
// paths of providers that are not excluded; Decide uses the same rule.
func (s *Scorer) inside(paths []plugin.PlanPath, excluded map[string]bool) []string {
	found := false
	var minLoss float64
	var minRTT time.Duration
	for _, p := range paths {
		if !p.Usable || excluded[p.Provider] {
			continue
		}
		if !found || p.LossPct < minLoss {
			minLoss = p.LossPct
		}
		if !found || p.RTT < minRTT {
			minRTT = p.RTT
		}
		found = true
	}
	if !found {
		return nil
	}
	var out []string
	for _, p := range paths {
		if !p.Usable || excluded[p.Provider] {
			continue
		}
		if p.LossPct <= minLoss+s.floorLoss+lossEps && p.RTT <= minRTT+s.floorRTT {
			out = append(out, p.Provider)
		}
	}
	sort.Strings(out)
	return out
}

// tieFirst breaks an equal price: the provider already carrying the steer,
// then native, then name.
func tieFirst(a, b, keep, native string) bool {
	rank := func(n string) int {
		switch {
		case keep != "" && n == keep:
			return 0
		case n == native:
			return 1
		}
		return 2
	}
	if ra, rb := rank(a), rank(b); ra != rb {
		return ra < rb
	}
	return a < b
}

func lessPrefix(a, b netip.Prefix) bool {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c < 0
	}
	return a.Bits() < b.Bits()
}
