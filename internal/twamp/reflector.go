package twamp

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Session bounds. A TWAMP-Light reflector has no control connection to
// tell it when a session ends, so sessions are keyed by the sender's
// address and port and dropped when idle or when the table is full.
const (
	DefaultMaxSessions = 1024
	sessionIdle        = 5 * time.Minute
)

// Reflector builds Session-Reflector packets. Each sender address and
// port is one session with its own reflector sequence numbers, starting
// at zero (RFC 5357 section 4.2.1).
type Reflector struct {
	maxSessions int
	mu          sync.Mutex
	sessions    map[netip.AddrPort]*session
}

type session struct {
	next uint32
	last time.Time
}

// NewReflector keeps at most maxSessions senders. A non-positive value
// uses DefaultMaxSessions.
func NewReflector(maxSessions int) *Reflector {
	if maxSessions <= 0 {
		maxSessions = DefaultMaxSessions
	}
	return &Reflector{maxSessions: maxSessions, sessions: map[netip.AddrPort]*session{}}
}

// Reply builds the reflected packet for in, received from the sender at
// from at time now with the IP TTL or hop limit ttl (UnknownTTL when not
// read). The reply is the same length as the sender's packet, and at
// least ReflectorMinLen. ok is false for a packet that is not a
// Session-Sender packet, which gets no reply.
func (r *Reflector) Reply(from netip.AddrPort, ttl uint8, in []byte, now time.Time) (out []byte, ok bool) {
	sp, err := ParseSender(in)
	if err != nil {
		return nil, false
	}
	seq := r.nextSeq(from, now)
	rp := ReflectorPacket{
		Seq:                 seq,
		Timestamp:           now,
		ErrorEstimate:       UnsyncedErrorEstimate,
		ReceiveTimestamp:    now,
		SenderSeq:           sp.Seq,
		SenderTimestamp:     sp.Timestamp,
		SenderErrorEstimate: sp.ErrorEstimate,
		SenderTTL:           ttl,
		Padding:             max(len(in)-ReflectorMinLen, 0),
	}
	return rp.Marshal(), true
}

func (r *Reflector) nextSeq(from netip.AddrPort, now time.Time) uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.sessions[from]
	if s == nil {
		if len(r.sessions) >= r.maxSessions {
			r.evict(now)
		}
		s = &session{}
		r.sessions[from] = s
	}
	s.last = now
	seq := s.next
	s.next++
	return seq
}

// evict drops idle sessions and, when none is idle, the least recently
// seen one, so a new sender always gets a slot.
func (r *Reflector) evict(now time.Time) {
	var oldest netip.AddrPort
	var oldestAt time.Time
	for k, s := range r.sessions {
		if now.Sub(s.last) >= sessionIdle {
			delete(r.sessions, k)
			continue
		}
		if oldestAt.IsZero() || s.last.Before(oldestAt) {
			oldest, oldestAt = k, s.last
		}
	}
	if len(r.sessions) >= r.maxSessions && oldest.IsValid() {
		delete(r.sessions, oldest)
	}
}

// Serve answers every Session-Sender packet on conn until ctx ends, then
// closes conn. The sender's TTL is read from the socket so the reply can
// carry it; a socket that does not deliver it gets UnknownTTL. Each reply
// leaves from the address the test packet was sent to: on a wildcard
// listen the kernel would otherwise pick the outgoing interface's
// address, and a sender's connected socket drops a reply from any
// address but the one it sent to.
func Serve(ctx context.Context, conn *net.UDPConn, r *Reflector, log *slog.Logger) error {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	local, _ := netip.ParseAddrPort(conn.LocalAddr().String())
	v6 := local.Addr().Is6() && !local.Addr().Is4In6()
	var (
		pc4 *ipv4.PacketConn
		pc6 *ipv6.PacketConn
	)
	if v6 {
		pc6 = ipv6.NewPacketConn(conn)
		if err := pc6.SetControlMessage(ipv6.FlagHopLimit, true); err != nil {
			log.Warn("hop limit not readable, replies carry 255", "err", err)
		}
		if err := pc6.SetControlMessage(ipv6.FlagDst, true); err != nil {
			log.Warn("destination not readable, replies leave from the kernel's source", "err", err)
		}
	} else {
		pc4 = ipv4.NewPacketConn(conn)
		if err := pc4.SetControlMessage(ipv4.FlagTTL, true); err != nil {
			log.Warn("ttl not readable, replies carry 255", "err", err)
		}
		if err := pc4.SetControlMessage(ipv4.FlagDst, true); err != nil {
			log.Warn("destination not readable, replies leave from the kernel's source", "err", err)
		}
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	buf := make([]byte, 65535)
	for {
		var (
			n    int
			ttl  = UnknownTTL
			dst  net.IP
			peer net.Addr
			err  error
		)
		if v6 {
			var cm *ipv6.ControlMessage
			n, cm, peer, err = pc6.ReadFrom(buf)
			if cm != nil {
				dst = cm.Dst
				if cm.HopLimit > 0 {
					ttl = uint8(cm.HopLimit)
				}
			}
		} else {
			var cm *ipv4.ControlMessage
			n, cm, peer, err = pc4.ReadFrom(buf)
			if cm != nil {
				dst = cm.Dst
				if cm.TTL > 0 {
					ttl = uint8(cm.TTL)
				}
			}
		}
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		from, perr := netip.ParseAddrPort(peer.String())
		if perr != nil {
			continue
		}
		out, ok := r.Reply(from, ttl, buf[:n], time.Now())
		if !ok {
			continue
		}
		var werr error
		if v6 {
			var cm *ipv6.ControlMessage
			if dst != nil {
				cm = &ipv6.ControlMessage{Src: dst}
			}
			_, werr = pc6.WriteTo(out, cm, peer)
		} else {
			var cm *ipv4.ControlMessage
			if dst != nil {
				cm = &ipv4.ControlMessage{Src: dst}
			}
			_, werr = pc4.WriteTo(out, cm, peer)
		}
		if werr != nil && ctx.Err() == nil {
			log.Debug("reply not sent", "to", from, "err", werr)
		}
	}
}
