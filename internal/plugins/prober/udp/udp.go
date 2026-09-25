// Package udp implements the "udp" prober: it sends one datagram per
// packet to a port (default 33434) from the provider's source address.
// A UDP reply or an ICMP port-unreachable both count as a reply. The
// kernel delivers the unreachable to the connected socket, so this
// prober does not need a raw socket.
package udp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "udp"

// Defaults.
const (
	DefaultPort           = 33434
	DefaultPacketInterval = 100 * time.Millisecond
)

func init() { plugin.Probers.Register(TypeName, New) }

// Config is the udp prober's config block.
type Config struct {
	Port           int           `yaml:"port"`
	PacketInterval time.Duration `yaml:"packet_interval"`
}

// Prober measures UDP reachability and the time until a reply or an
// ICMP port-unreachable.
type Prober struct {
	plugin.Base
	port     int
	interval time.Duration
}

// New is the plugin factory.
func New(c plugin.Config, _ plugin.Env) (plugin.Prober, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.Port == 0 {
		cfg.Port = DefaultPort
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, fmt.Errorf("port %d must be between 1 and 65535", cfg.Port)
	}
	if cfg.PacketInterval < 0 {
		return nil, fmt.Errorf("packet_interval %s must not be negative", cfg.PacketInterval)
	}
	if cfg.PacketInterval == 0 {
		cfg.PacketInterval = DefaultPacketInterval
	}
	return &Prober{port: cfg.Port, interval: cfg.PacketInterval}, nil
}

// Probe implements plugin.Prober.
func (p *Prober) Probe(ctx context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	if req.Source.Is4() != req.Target.Is4() {
		return plugin.ProbeResult{}, fmt.Errorf("source %s and target %s differ in address family", req.Source, req.Target)
	}
	network := "udp4"
	if !req.Source.Is4() {
		network = "udp6"
	}
	laddr := &net.UDPAddr{IP: req.Source.AsSlice()}
	raddr := &net.UDPAddr{IP: req.Target.AsSlice(), Port: p.port}
	res := plugin.ProbeResult{}
	for i := 0; i < req.Count; i++ {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		start := time.Now()
		res.Sent++
		if rtt, ok, err := onePacket(ctx, network, laddr, raddr, req.Timeout, start); err != nil {
			return res, err
		} else if ok {
			res.RTTs = append(res.RTTs, rtt)
		}
		if i < req.Count-1 {
			if wait := p.interval - time.Since(start); wait > 0 {
				select {
				case <-time.After(wait):
				case <-ctx.Done():
					return res, ctx.Err()
				}
			}
		}
	}
	return res, nil
}

// onePacket sends one datagram. ok is true when the host answered with
// a payload or with ICMP port-unreachable. A missing source address is
// an error so the engine can fail closed.
func onePacket(ctx context.Context, network string, laddr, raddr *net.UDPAddr, timeout time.Duration, start time.Time) (time.Duration, bool, error) {
	c, err := net.DialUDP(network, laddr, raddr)
	if err != nil {
		if errors.Is(err, syscall.EADDRNOTAVAIL) {
			return 0, false, fmt.Errorf("%w: %s: %v", plugin.ErrSourceUnavailable, laddr.IP, err)
		}
		return 0, false, nil
	}
	defer c.Close()
	deadline := start.Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	if _, err := c.Write([]byte{0}); err != nil {
		if errors.Is(err, syscall.EADDRNOTAVAIL) {
			return 0, false, fmt.Errorf("%w: %v", plugin.ErrSourceUnavailable, err)
		}
		if errors.Is(err, syscall.ECONNREFUSED) {
			return time.Since(start), true, nil
		}
		return 0, false, nil
	}
	buf := make([]byte, 64)
	_, err = c.Read(buf)
	if err == nil || errors.Is(err, syscall.ECONNREFUSED) {
		return time.Since(start), true, nil
	}
	if ctx.Err() != nil {
		return 0, false, ctx.Err()
	}
	return 0, false, nil
}
