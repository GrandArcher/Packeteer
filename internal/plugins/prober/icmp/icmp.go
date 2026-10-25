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

	"github.com/GrandArcher/Packeteer/internal/plugins/prober/train"
	"github.com/GrandArcher/Packeteer/internal/sockmark"
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

func (p *Prober) listen(src netip.Addr, m sockmark.Marking) (*conn, error) {
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
			if terr := tag(c, v6, m); terr != nil {
				c.Close()
				return nil, fmt.Errorf("%w: %s: %v", plugin.ErrSourceUnavailable, src, terr)
			}
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

// tag applies the probe tag to the socket behind c. x/net/icmp keeps the
// socket private, but the embedded net.PacketConn of its ipv4/ipv6 wrapper
// is exported.
func tag(c *xicmp.PacketConn, v6 bool, m sockmark.Marking) error {
	if m.IsZero() {
		return nil
	}
	var pc net.PacketConn
	if v6 {
		pc = c.IPv6PacketConn().PacketConn
	} else {
		pc = c.IPv4PacketConn().PacketConn
	}
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return fmt.Errorf("%w: socket has no raw access", sockmark.ErrTag)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return fmt.Errorf("%w: %v", sockmark.ErrTag, err)
	}
	return sockmark.ApplyConn(rc, v6, m)
}

// Probe implements plugin.Prober. Echo requests go out at the request's
// Spacing (or packet_interval) without waiting for the reply, so a run is
// one train; replies are matched by sequence number as they arrive. The
// run ends when every echo is answered, or Timeout after the last send.
// RTTs are in send order and Order is the send index of each reply in
// arrival order (#224).
func (p *Prober) Probe(ctx context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	if req.Source.Is4() != req.Target.Is4() {
		return plugin.ProbeResult{}, fmt.Errorf("source %s and target %s differ in address family", req.Source, req.Target)
	}
	c, err := p.listen(req.Source, sockmark.Marking{Mark: req.Mark, DSCP: req.DSCP})
	if err != nil {
		return plugin.ProbeResult{}, err
	}
	defer c.c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.c.SetReadDeadline(time.Now()) })
	defer stop()

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
	spacing := p.interval
	if req.Spacing > 0 {
		spacing = req.Spacing
	}

	count := req.Count
	replies := make(chan train.Reply, count)
	done := make(chan struct{})
	go func() {
		defer close(done)
		readReplies(c, req.Target, replyType, id, token, count, replies)
	}()

	res := plugin.ProbeResult{}
	sentAt := make([]time.Time, count)
	start := time.Now()
	// A run cut short keeps the replies already matched, as the loss of a
	// partial run.
	collect := func() {
		<-done
		close(replies)
		res.RTTs, res.Order = train.Collect(sentAt, replies)
	}
	finish := func() {
		_ = c.c.SetReadDeadline(time.Now())
		collect()
	}
	for seq := 1; seq <= count; seq++ {
		if seq > 1 {
			if err := train.SleepUntil(ctx, start.Add(time.Duration(seq-1)*spacing)); err != nil {
				finish()
				return res, err
			}
		}
		msg := xicmp.Message{Type: reqType, Body: &xicmp.Echo{ID: id, Seq: seq, Data: payloadFor(token, seq)}}
		wb, err := msg.Marshal(nil)
		if err != nil {
			finish()
			return res, err
		}
		sentAt[seq-1] = time.Now()
		res.Sent++
		if _, err := c.c.WriteTo(wb, dst); err != nil && isSourceErr(err) {
			finish()
			return res, fmt.Errorf("%w: %v", plugin.ErrSourceUnavailable, err)
		}
		// Any other write error (unreachable, ...) is loss.
	}
	if count < 1 {
		finish()
		return res, nil
	}
	train.EndReads(ctx, c.c.SetReadDeadline, sentAt[count-1].Add(req.Timeout))
	collect()
	return res, nil
}

// payloadFor is the echo data: the run's random token and the sequence
// number, so a reply to another run or another host is not matched.
func payloadFor(token [8]byte, seq int) []byte {
	return append(token[:], byte(seq>>8), byte(seq))
}

// readReplies reads echo replies from the target until all count are
// matched or the read deadline passes, and reports each matched sequence
// once, as a 0-based index, in arrival order. The id is checked on a raw
// socket only: the kernel rewrites it on an unprivileged datagram socket.
func readReplies(c *conn, target netip.Addr, replyType xicmp.Type, id int, token [8]byte, count int, out chan<- train.Reply) {
	buf := make([]byte, 1500)
	seen := make([]bool, count+1)
	for matched := 0; matched < count; {
		n, peer, err := c.c.ReadFrom(buf)
		if err != nil {
			return
		}
		at := time.Now()
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
		if !ok || echo.Seq < 1 || echo.Seq > count || seen[echo.Seq] || (!c.udp && echo.ID != id) ||
			!bytes.Equal(echo.Data, payloadFor(token, echo.Seq)) {
			continue
		}
		seen[echo.Seq] = true
		matched++
		out <- train.Reply{Seq: echo.Seq - 1, At: at}
	}
}
