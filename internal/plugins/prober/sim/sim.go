// Package sim is a prober that answers from a seeded delay and loss model
// and never opens a socket, so no packet leaves the host. A lab uses it to
// give every learned prefix a measurement on every route without probing
// real addresses (#103). Every result is simulated: do not use it to
// measure a network.
//
// The answer for a (route, target, packet) is a pure function of the seed,
// so a run repeats exactly and the same destination reads the same on every
// round.
package sim

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"math"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "sim"

func init() { plugin.Probers.Register(TypeName, New) }

// Config is the sim prober's config block.
type Config struct {
	// Seed fixes every answer. The same seed and config give the same
	// results.
	Seed   uint64  `yaml:"seed"`
	Routes []Route `yaml:"routes"`
}

// Route is the model of one provider's path.
type Route struct {
	Provider string `yaml:"provider"`
	// RTTMs is the round-trip time a destination near the middle of the
	// spread sees.
	RTTMs float64 `yaml:"rtt_ms"`
	// SpreadPct moves each destination's RTT by up to this percent of
	// RTTMs either way, so routes win on different prefixes.
	SpreadPct float64 `yaml:"spread_pct"`
	// JitterMs moves each reply by up to this many milliseconds either
	// way.
	JitterMs float64 `yaml:"jitter_ms"`
	// LossPct is the chance, per packet, that no reply comes.
	LossPct float64 `yaml:"loss_pct"`
}

type route struct {
	Route
	salt uint64
}

// Prober answers from the model.
type Prober struct {
	plugin.Base
	seed   uint64
	routes map[string]route
}

// New is the plugin factory. It does no I/O.
func New(c plugin.Config, env plugin.Env) (plugin.Prober, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if len(cfg.Routes) == 0 {
		return nil, fmt.Errorf("sim prober: routes is required")
	}
	known := map[string]bool{}
	for _, n := range env.Providers {
		known[n] = true
	}
	p := &Prober{seed: cfg.Seed, routes: map[string]route{}}
	for i, r := range cfg.Routes {
		switch {
		case r.Provider == "":
			return nil, fmt.Errorf("routes[%d]: provider is required", i)
		case env.Providers != nil && !known[r.Provider]:
			return nil, fmt.Errorf("routes[%d]: provider %q is not configured", i, r.Provider)
		case p.routes[r.Provider].Provider != "":
			return nil, fmt.Errorf("routes[%d]: duplicate provider %q", i, r.Provider)
		case r.RTTMs <= 0 || math.IsNaN(r.RTTMs):
			return nil, fmt.Errorf("routes[%d]: rtt_ms %v must be positive", i, r.RTTMs)
		case r.SpreadPct < 0 || r.SpreadPct > 100:
			return nil, fmt.Errorf("routes[%d]: spread_pct %v must be between 0 and 100", i, r.SpreadPct)
		case r.JitterMs < 0 || math.IsNaN(r.JitterMs):
			return nil, fmt.Errorf("routes[%d]: jitter_ms %v must not be negative", i, r.JitterMs)
		case r.LossPct < 0 || r.LossPct > 100:
			return nil, fmt.Errorf("routes[%d]: loss_pct %v must be between 0 and 100", i, r.LossPct)
		}
		h := fnv.New64a()
		_, _ = h.Write([]byte(r.Provider))
		p.routes[r.Provider] = route{Route: r, salt: h.Sum64()}
	}
	return p, nil
}

// Probe implements plugin.Prober. It fails for a provider with no route in
// the model, as the fixed prober does.
func (p *Prober) Probe(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	r, ok := p.routes[req.Provider]
	if !ok {
		return plugin.ProbeResult{}, fmt.Errorf("sim prober: no route for provider %q", req.Provider)
	}
	a := req.Target.As16()
	dest := mix(mix(p.seed^r.salt^binary.BigEndian.Uint64(a[:8])) ^ binary.BigEndian.Uint64(a[8:]))
	base := r.RTTMs * (1 + r.SpreadPct/100*signed(mix(dest^1)))
	res := plugin.ProbeResult{Sent: req.Count}
	for i := range req.Count {
		pk := mix(dest + uint64(i+1)*0x9e3779b97f4a7c15)
		if unit(pk) < r.LossPct/100 {
			continue
		}
		ms := max(base+r.JitterMs*signed(mix(pk^2)), 0.05)
		res.RTTs = append(res.RTTs, time.Duration(ms*float64(time.Millisecond)))
	}
	return res, nil
}

// mix is the splitmix64 finalizer.
func mix(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ x>>30) * 0xbf58476d1ce4e5b9
	x = (x ^ x>>27) * 0x94d049bb133111eb
	return x ^ x>>31
}

// unit maps x to [0, 1).
func unit(x uint64) float64 { return float64(x>>11) / (1 << 53) }

// signed maps x to [-1, 1).
func signed(x uint64) float64 { return 2*unit(x) - 1 }
