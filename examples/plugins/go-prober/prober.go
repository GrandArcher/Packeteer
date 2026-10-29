// Package goprober is a skeleton for a compiled-in Packeteer prober
// (docs/PLUGIN_AUTHORING.md). It reports a configured round-trip time for
// every packet and sends nothing, so it is a template, not a measurement.
//
// To use it as a starting point, copy this package to
// internal/plugins/prober/<name>, rename the type, and add a blank import
// to internal/plugins/all/all.go.
package goprober

import (
	"context"
	"fmt"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the value of `type:` in the probers list.
const TypeName = "example-go"

func init() { plugin.Probers.Register(TypeName, New) }

// Config is decoded strictly: an unknown key refuses the start.
type Config struct {
	RTTMs float64 `yaml:"rtt_ms"`
}

// Prober embeds plugin.Base for no-op Start and Stop.
type Prober struct {
	plugin.Base
	rtt time.Duration
}

// New is the factory. It validates and does no I/O.
func New(c plugin.Config, _ plugin.Env) (plugin.Prober, error) {
	cfg := Config{RTTMs: 10}
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.RTTMs <= 0 {
		return nil, fmt.Errorf("rtt_ms %v must be positive", cfg.RTTMs)
	}
	return &Prober{rtt: time.Duration(cfg.RTTMs * float64(time.Millisecond))}, nil
}

// Probe fails closed: a source or tag it cannot honor is an error, never a
// 100% loss result, so the core can treat the probe source as down.
func (p *Prober) Probe(ctx context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	if !req.Source.IsValid() {
		return plugin.ProbeResult{}, fmt.Errorf("%w: no source address", plugin.ErrSourceUnavailable)
	}
	if req.Mark != 0 || req.DSCP != 0 {
		return plugin.ProbeResult{}, fmt.Errorf("%w: this prober cannot tag packets", plugin.ErrSourceUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return plugin.ProbeResult{}, err
	}
	res := plugin.ProbeResult{Sent: req.Count}
	for range req.Count {
		res.RTTs = append(res.RTTs, p.rtt)
	}
	return res, nil
}
