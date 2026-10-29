// Command grpc-example is a minimal long-running Packeteer plugin (type
// "grpc", docs/PLUGINS.md). One binary can run as a prober, a target source,
// or a notifier; the kind comes from the config list that names it.
//
// Build it static so it runs in the stock (alpine) image, and mount it
// into the plugin dir:
//
//	CGO_ENABLED=0 go build -o grpc-example ./examples/plugins/grpc-example
//
//	sources:
//	  - type: grpc
//	    name: example
//	    config:
//	      command: grpc-example
//	      config:
//	        targets:
//	          - {prefix: 198.51.100.0/24, host: 198.51.100.1}
//	          - {prefix: 203.0.113.0/24, weight: 2}
package main

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
	"github.com/GrandArcher/Packeteer/pkg/plugin/rpc"
)

type config struct {
	// RTTMs is the round-trip time the prober reports for every reply.
	RTTMs   float64 `json:"rtt_ms"`
	Targets []struct {
		Prefix netip.Prefix `json:"prefix"`
		Host   netip.Addr   `json:"host"`
		Weight float64      `json:"weight"`
	} `json:"targets"`
}

type example struct {
	cfg config
	// probes is state that lives as long as the process, which an exec
	// plugin could not keep between calls.
	probes atomic.Int64
}

func (e *example) Init(_ context.Context, req rpc.InitRequest) error {
	e.cfg.RTTMs = 10
	if err := req.DecodeConfig(&e.cfg); err != nil {
		return err
	}
	if e.cfg.RTTMs < 0 {
		return fmt.Errorf("rtt_ms must not be negative")
	}
	return nil
}

func (e *example) Probe(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	e.probes.Add(1)
	res := plugin.ProbeResult{Sent: req.Count}
	for range req.Count {
		res.RTTs = append(res.RTTs, time.Duration(e.cfg.RTTMs*float64(time.Millisecond)))
	}
	return res, nil
}

func (e *example) Targets(context.Context) ([]plugin.Target, error) {
	var out []plugin.Target
	for _, t := range e.cfg.Targets {
		out = append(out, plugin.Target{Prefix: t.Prefix, Host: t.Host, Weight: t.Weight})
	}
	return out, nil
}

func (e *example) Notify(_ context.Context, ev plugin.Event) error {
	// Stderr reaches Packeteer's debug log.
	log.Printf("%s %s: %s (%d probes so far)", ev.Severity, ev.Kind, ev.Message, e.probes.Load())
	return nil
}

func main() { rpc.Serve(&example{}) }
