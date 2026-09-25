// Package icmp implements the "icmp" prober: ICMP echo sourced from the
// provider's source address. It uses a raw socket (needs CAP_NET_RAW, which
// the container gets with --cap-add NET_RAW) and falls back to an
// unprivileged datagram ICMP socket when allowed by net.ipv4.ping_group_range.
package icmp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	xicmp "golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "icmp"

// Socket modes.
const (
	SocketAuto = "auto" // raw, then unprivileged datagram
	SocketRaw  = "raw"
	SocketUDP  = "udp"
)

// DefaultPacketInterval spaces echo requests within one run.
const DefaultPacketInterval = 100 * time.Millisecond

func init() { plugin.Probers.Register(TypeName, New) }

// Config is the icmp prober's config block.
type Config struct {
	Socket         string        `yaml:"socket"`
	PacketInterval time.Duration `yaml:"packet_interval"`
}

// Prober sends ICMP echo requests.
type Prober struct {
	plugin.Base
	socket   string
	interval time.Duration
}

// New is the plugin factory.
func New(c plugin.Config, _ plugin.Env) (plugin.Prober, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	switch cfg.Socket {
	case "":
		cfg.Socket = SocketAuto
	case SocketAuto, SocketRaw, SocketUDP:
	default:
		return nil, fmt.Errorf("socket %q is invalid (want auto, raw, udp)", cfg.Socket)
	}
	if cfg.PacketInterval < 0 {
		return nil, fmt.Errorf("packet_interval %s must not be negative", cfg.PacketInterval)
	}
	if cfg.PacketInterval == 0 {
		cfg.PacketInterval = DefaultPacketInterval
	}
	return &Prober{socket: cfg.Socket, interval: cfg.PacketInterval}, nil
}

func isSourceErr(err error) bool {
	return errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EINVAL)
}

func isPermErr(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) ||
		errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPROTONOSUPPORT)
}

type conn struct {
	c     *xicmp.PacketConn
	udp   bool
	proto int
}

func (p *Prober) listen(src netip.Addr) (*conn, error) {
	v6 := src.Is6() && !src.Is4In6()
	raw, dgram, proto := "ip4:icmp", "udp4", 1
	if v6 {
		raw, dgram, proto = "ip6:ipv6-icmp", "udp6", 58
	}
	var modes []bool // udp?
	switch p.socket {
	case SocketRaw:
		modes = []bool{false}
	case SocketUDP:
		modes = []bool{true}
	default:
		modes = []bool{false, true}
	}
	var errs []error
	for _, udp := range modes {
		network := raw
		if udp {
			network = dgram
		}
		c, err := xicmp.ListenPacket(network, src.String())
		if err == nil {
			return &conn{c: c, udp: udp, proto: proto}, nil
		}
		if isSourceErr(err) {
			return nil, fmt.Errorf("%w: %s: %v", plugin.ErrSourceUnavailable, src, err)
		}
		errs = append(errs, fmt.Errorf("%s: %w", network, err))
		if !isPermErr(err) {
			break
		}
	}
	return nil, fmt.Errorf("icmp socket unavailable (need CAP_NET_RAW or ping_group_range): %w", errors.Join(errs...))
}

// Probe implements plugin.Prober.
func (p *Prober) Probe(ctx context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	if req.Source.Is4() != req.Target.Is4() {
		return plugin.ProbeResult{}, fmt.Errorf("source %s and target %s differ in address family", req.Source, req.Target)
	}
	c, err := p.listen(req.Source)
	if err != nil {
		return plugin.ProbeResult{}, err
	}
	defer c.c.Close()

	var token [8]byte
	if _, err := rand.Read(token[:]); err != nil {
		return plugin.ProbeResult{}, err
	}
	id := int(binary.BigEndian.Uint16(token[:2]))
	var dst net.Addr = &net.IPAddr{IP: req.Target.AsSlice()}
	if c.udp {
		dst = &net.UDPAddr{IP: req.Target.AsSlice()}
	}
	var reqType, replyType xicmp.Type = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
	if c.proto == 58 {
		reqType, replyType = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}

	res := plugin.ProbeResult{}
	buf := make([]byte, 1500)
	for seq := 1; seq <= req.Count; seq++ {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		payload := append(token[:], byte(seq>>8), byte(seq))
		msg := xicmp.Message{Type: reqType, Body: &xicmp.Echo{ID: id, Seq: seq, Data: payload}}
		wb, err := msg.Marshal(nil)
		if err != nil {
			return res, err
		}
		start := time.Now()
		res.Sent++
		if _, err := c.c.WriteTo(wb, dst); err != nil {
			if isSourceErr(err) {
				return res, fmt.Errorf("%w: %v", plugin.ErrSourceUnavailable, err)
			}
			// Unreachable etc.: count as loss.
		} else if rtt, ok := waitReply(ctx, c, buf, start.Add(req.Timeout), start, req.Target, replyType, id, seq, payload); ok {
			res.RTTs = append(res.RTTs, rtt)
		}
		if seq < req.Count {
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

func waitReply(ctx context.Context, c *conn, buf []byte, deadline, start time.Time, target netip.Addr,
	replyType xicmp.Type, id, seq int, payload []byte) (time.Duration, bool) {
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.c.SetReadDeadline(deadline)
	for {
		n, peer, err := c.c.ReadFrom(buf)
		if err != nil {
			return 0, false
		}
		rtt := time.Since(start)
		var pip net.IP
		switch a := peer.(type) {
		case *net.IPAddr:
			pip = a.IP
		case *net.UDPAddr:
			pip = a.IP
		}
		pa, ok := netip.AddrFromSlice(pip)
		if !ok || pa.Unmap() != target.Unmap() {
			continue
		}
		m, err := xicmp.ParseMessage(c.proto, buf[:n])
		if err != nil || m.Type != replyType {
			continue
		}
		echo, ok := m.Body.(*xicmp.Echo)
		if !ok || echo.Seq != seq || (!c.udp && echo.ID != id) || !bytes.Equal(echo.Data, payload) {
			continue
		}
		return rtt, true
	}
}
