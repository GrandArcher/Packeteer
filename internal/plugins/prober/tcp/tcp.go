// Package tcp implements the "tcp" prober: it times TCP handshakes to a
// port (default 443) from the provider's source address. A SYN-ACK or a RST
// both count as a reply; the handshake is aborted with RST right away.
//
// A middlebox RST is indistinguishable from the target's RST: the kernel
// reports both as ECONNREFUSED and the RST is often sourced from the
// destination address. A firewall that rejects with tcp-reset can therefore
// look like a healthy low-latency path. The UDP prober does not have this
// gap for ICMP, because the unreachable names the host that sent it.
package tcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "tcp"

// Defaults.
const (
	DefaultPort           = 443
	DefaultPacketInterval = 100 * time.Millisecond
)

func init() { plugin.Probers.Register(TypeName, New) }

// Config is the tcp prober's config block.
type Config struct {
	Port           int           `yaml:"port"`
	PacketInterval time.Duration `yaml:"packet_interval"`
}

// Prober measures TCP connect time.
type Prober struct {
	plugin.Base
	port     uint16
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
	return &Prober{port: uint16(cfg.Port), interval: cfg.PacketInterval}, nil
}

// Probe implements plugin.Prober.
func (p *Prober) Probe(ctx context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	if req.Source.Is4() != req.Target.Is4() {
		return plugin.ProbeResult{}, fmt.Errorf("source %s and target %s differ in address family", req.Source, req.Target)
	}
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: req.Source.AsSlice()}, Timeout: req.Timeout}
	addr := netip.AddrPortFrom(req.Target, p.port).String()
	res := plugin.ProbeResult{}
	for i := 0; i < req.Count; i++ {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		start := time.Now()
		res.Sent++
		c, err := d.DialContext(ctx, "tcp", addr)
		rtt := time.Since(start)
		switch {
		case err == nil:
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetLinger(0) // RST instead of FIN: no TIME_WAIT buildup
			}
			_ = c.Close()
			res.RTTs = append(res.RTTs, rtt)
		case errors.Is(err, syscall.ECONNREFUSED):
			res.RTTs = append(res.RTTs, rtt) // host answered with RST
		case errors.Is(err, syscall.EADDRNOTAVAIL):
			return res, fmt.Errorf("%w: %s: %v", plugin.ErrSourceUnavailable, req.Source, err)
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
