// Package twamp implements the "twamp" prober: a TWAMP-Light Session-Sender
// (RFC 5357, unauthenticated mode) that sends a train of sequence-numbered
// UDP test packets from the provider's source address to a
// Session-Reflector and reads the reflected packets. Every packet of one
// run leaves one socket, so the train keeps one 5-tuple and one ECMP
// member; a new run gets a new socket. The result carries the arrival
// order, which the reordering monitor (#224) turns into RFC 4737 metrics.
// It needs a reflector the operator runs (packeteer-reflector), so it is
// not part of the default prober chain.
package twamp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/prober/train"
	"github.com/GrandArcher/Packeteer/internal/sockmark"
	"github.com/GrandArcher/Packeteer/internal/twamp"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "twamp"

// Defaults and bounds.
const (
	DefaultPacketInterval = 20 * time.Millisecond
	// DefaultPadding makes the sender packet 41 octets, the size of the
	// reflector's fixed part, so the reply is not truncated.
	DefaultPadding = twamp.MinSenderPadding
	maxPadding     = 1400
)

func init() { plugin.Probers.Register(TypeName, New) }

// Config is the twamp prober's config block.
type Config struct {
	Port           int           `yaml:"port"`
	PacketInterval time.Duration `yaml:"packet_interval"`
	Padding        int           `yaml:"padding"`
}

// Prober sends TWAMP-Light test packets.
type Prober struct {
	plugin.Base
	port     int
	interval time.Duration
	padding  int
}

// New is the plugin factory.
func New(c plugin.Config, _ plugin.Env) (plugin.Prober, error) {
	cfg := Config{Port: twamp.DefaultPort, PacketInterval: DefaultPacketInterval, Padding: DefaultPadding}
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.Port == 0 {
		cfg.Port = twamp.DefaultPort
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
	if cfg.Padding < twamp.MinSenderPadding || cfg.Padding > maxPadding {
		return nil, fmt.Errorf("padding %d must be between %d and %d", cfg.Padding, twamp.MinSenderPadding, maxPadding)
	}
	return &Prober{port: cfg.Port, interval: cfg.PacketInterval, padding: cfg.Padding}, nil
}

// Probe implements plugin.Prober. Packets go out at the request's Spacing
// (or packet_interval) without waiting for replies; the run ends Timeout
// after the last send. RTTs are in send order and Order is the send
// index of each reply in arrival order.
func (p *Prober) Probe(ctx context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	if req.Source.Is4() != req.Target.Is4() {
		return plugin.ProbeResult{}, fmt.Errorf("source %s and target %s differ in address family", req.Source, req.Target)
	}
	port := p.port
	if req.Port != 0 {
		port = int(req.Port)
	}
	spacing := p.interval
	if req.Spacing > 0 {
		spacing = req.Spacing
	}
	network := "udp4"
	if !req.Target.Is4() {
		network = "udp6"
	}
	d := net.Dialer{
		LocalAddr: &net.UDPAddr{IP: req.Source.AsSlice()},
		Control:   sockmark.Control(sockmark.Marking{Mark: req.Mark, DSCP: req.DSCP}),
	}
	conn, err := d.DialContext(ctx, network, netip.AddrPortFrom(req.Target, uint16(port)).String())
	if err != nil {
		if errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EINVAL) || errors.Is(err, sockmark.ErrTag) {
			return plugin.ProbeResult{}, fmt.Errorf("%w: %s: %v", plugin.ErrSourceUnavailable, req.Source, err)
		}
		return plugin.ProbeResult{}, err
	}
	uc := conn.(*net.UDPConn)
	defer uc.Close()
	stop := context.AfterFunc(ctx, func() { _ = uc.SetReadDeadline(time.Now()) })
	defer stop()

	count := req.Count
	replies := make(chan train.Reply, count)
	refused := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		seen := make([]bool, count)
		buf := make([]byte, 1500)
		for {
			n, err := uc.Read(buf)
			if err != nil {
				if errors.Is(err, syscall.ECONNREFUSED) {
					select {
					case refused <- struct{}{}:
					default:
					}
					continue
				}
				return
			}
			rp, err := twamp.ParseReflector(buf[:n])
			if err != nil || rp.SenderSeq >= uint32(count) || seen[rp.SenderSeq] {
				continue
			}
			seen[rp.SenderSeq] = true
			replies <- train.Reply{Seq: int(rp.SenderSeq), At: time.Now()}
		}
	}()

	res := plugin.ProbeResult{}
	sentAt := make([]time.Time, count)
	start := time.Now()
	for seq := 0; seq < count; seq++ {
		if seq > 0 {
			if err := train.SleepUntil(ctx, start.Add(time.Duration(seq)*spacing)); err != nil {
				_ = uc.SetReadDeadline(time.Now())
				<-done
				return res, err
			}
		}
		pkt := twamp.SenderPacket{Seq: uint32(seq), Timestamp: time.Now(), ErrorEstimate: twamp.UnsyncedErrorEstimate, Padding: p.padding}
		sentAt[seq] = time.Now()
		res.Sent++
		if _, err := uc.Write(pkt.Marshal()); err != nil {
			if errors.Is(err, syscall.EADDRNOTAVAIL) {
				_ = uc.SetReadDeadline(time.Now())
				<-done
				return res, fmt.Errorf("%w: %v", plugin.ErrSourceUnavailable, err)
			}
			// Unreachable and refused: the packet is lost.
		}
	}
	if count < 1 {
		_ = uc.SetReadDeadline(time.Now())
		<-done
		return res, nil
	}
	deadline := sentAt[count-1].Add(req.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = uc.SetReadDeadline(deadline)
	<-done
	close(replies)
	res.RTTs, res.Order = train.Collect(sentAt, replies)
	if len(res.RTTs) == 0 {
		select {
		case <-refused:
			return res, fmt.Errorf("%s: connection refused (no reflector on port %d)", req.Target, port)
		default:
		}
	}
	return res, nil
}
