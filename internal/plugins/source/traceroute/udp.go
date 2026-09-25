package traceroute

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
	"golang.org/x/sys/unix"
)

// udpHopper is a UDP traceroute. ICMP time-exceeded and destination-
// unreachable come back on the socket error queue (IP_RECVERR), so it
// does not open a raw socket. A UDP payload from the destination counts
// as the destination answering.
type udpHopper struct{}

// Probe implements hopper.
func (udpHopper) Probe(ctx context.Context, src, dst netip.Addr, ttl, port int, timeout time.Duration) (netip.Addr, bool, error) {
	if err := ctx.Err(); err != nil {
		return netip.Addr{}, false, err
	}
	if !dst.IsValid() || port < 1 || ttl < 1 {
		return netip.Addr{}, false, fmt.Errorf("traceroute: invalid probe dest=%s ttl=%d port=%d", dst, ttl, port)
	}
	if src.IsValid() && src.Is4() != dst.Is4() {
		return netip.Addr{}, false, fmt.Errorf("source %s and target %s differ in address family", src, dst)
	}
	domain := unix.AF_INET
	if !dst.Is4() {
		domain = unix.AF_INET6
	}
	fd, err := unix.Socket(domain, unix.SOCK_DGRAM, 0)
	if err != nil {
		return netip.Addr{}, false, err
	}
	defer unix.Close(fd)
	if src.IsValid() {
		sa, err := sockaddr(src, 0)
		if err != nil {
			return netip.Addr{}, false, err
		}
		if err := unix.Bind(fd, sa); err != nil {
			if errors.Is(err, unix.EADDRNOTAVAIL) {
				return netip.Addr{}, false, fmt.Errorf("%w: %s: %v", plugin.ErrSourceUnavailable, src, err)
			}
			return netip.Addr{}, false, err
		}
	}
	v6 := !dst.Is4()
	if v6 {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVERR, 1); err != nil {
			return netip.Addr{}, false, err
		}
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl); err != nil {
			return netip.Addr{}, false, err
		}
	} else {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1); err != nil {
			return netip.Addr{}, false, err
		}
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, ttl); err != nil {
			return netip.Addr{}, false, err
		}
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return netip.Addr{}, false, err
	}
	to, err := sockaddr(dst, port)
	if err != nil {
		return netip.Addr{}, false, err
	}
	if err := unix.Sendto(fd, []byte{0}, 0, to); err != nil {
		if errors.Is(err, unix.EADDRNOTAVAIL) {
			return netip.Addr{}, false, fmt.Errorf("%w: %v", plugin.ErrSourceUnavailable, err)
		}
		return netip.Addr{}, false, err
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	buf := make([]byte, 1500)
	oob := make([]byte, 512)
	for {
		if err := ctx.Err(); err != nil {
			return netip.Addr{}, false, err
		}
		remain := time.Until(deadline)
		if remain <= 0 {
			return netip.Addr{}, false, nil
		}
		ms := int(remain / time.Millisecond)
		if ms < 1 {
			ms = 1
		}
		if ms > 200 {
			ms = 200
		}
		n, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLERR}}, ms)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return netip.Addr{}, false, err
		}
		if n == 0 {
			continue
		}
		_, oobn, _, _, rerr := unix.Recvmsg(fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
		if rerr == nil && oobn > 0 {
			from, typ, ok := parseExtErr(oob[:oobn])
			if !ok || !from.IsValid() {
				continue
			}
			_, reached := classify(v6, typ)
			if !classifyHop(v6, typ) {
				continue
			}
			return from, reached, nil
		}
		if rerr != nil && !again(rerr) {
			return netip.Addr{}, false, rerr
		}
		nn, _, _, _, rerr := unix.Recvmsg(fd, buf, nil, unix.MSG_DONTWAIT)
		if rerr == nil && nn >= 0 {
			return dst, true, nil
		}
		if rerr != nil && !again(rerr) {
			return netip.Addr{}, false, rerr
		}
		// Poll woke up but neither queue had a datagram. Don't spin.
		time.Sleep(2 * time.Millisecond)
	}
}

func again(err error) bool {
	return errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK)
}

func sockaddr(addr netip.Addr, port int) (unix.Sockaddr, error) {
	if addr.Is4() {
		sa := &unix.SockaddrInet4{Port: port}
		copy(sa.Addr[:], addr.AsSlice())
		return sa, nil
	}
	if !addr.Is6() {
		return nil, fmt.Errorf("address %s is not IP", addr)
	}
	sa := &unix.SockaddrInet6{Port: port}
	copy(sa.Addr[:], addr.AsSlice())
	return sa, nil
}

// classifyHop reports whether typ is a traceroute reply, and whether it
// means the probe got as far as a host that will not forward it.
func classify(v6 bool, typ byte) (hop, reached bool) {
	if v6 {
		switch typ {
		case 3: // time exceeded
			return true, false
		case 1: // destination unreachable
			return true, true
		default:
			return false, false
		}
	}
	switch typ {
	case 11: // time exceeded
		return true, false
	case 3: // destination unreachable
		return true, true
	default:
		return false, false
	}
}

func classifyHop(v6 bool, typ byte) bool {
	hop, _ := classify(v6, typ)
	return hop
}

// parseExtErr reads one IP_RECVERR / IPV6_RECVERR control message.
// The kernel lays out sock_extended_err (16 bytes) and then the
// offender sockaddr. ok is false when the message is not ICMP.
func parseExtErr(oob []byte) (from netip.Addr, icmpType byte, ok bool) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	for _, m := range msgs {
		if int(m.Header.Type) != unix.IP_RECVERR && int(m.Header.Type) != unix.IPV6_RECVERR {
			continue
		}
		return parseExtErrData(m.Data)
	}
	return netip.Addr{}, 0, false
}

func parseExtErrData(data []byte) (from netip.Addr, icmpType byte, ok bool) {
	// sock_extended_err is 16 bytes. The offender sockaddr follows.
	if len(data) < 16+8 {
		return netip.Addr{}, 0, false
	}
	origin := data[4]
	if origin != unix.SO_EE_ORIGIN_ICMP && origin != unix.SO_EE_ORIGIN_ICMP6 {
		return netip.Addr{}, 0, false
	}
	icmpType = data[5]
	sa := data[16:]
	family := binary.LittleEndian.Uint16(sa[:2])
	switch family {
	case unix.AF_INET:
		if len(sa) < 8 {
			return netip.Addr{}, 0, false
		}
		addr, ok := netip.AddrFromSlice(sa[4:8])
		return addr, icmpType, ok
	case unix.AF_INET6:
		if len(sa) < 24 {
			return netip.Addr{}, 0, false
		}
		addr, ok := netip.AddrFromSlice(sa[8:24])
		return addr, icmpType, ok
	default:
		return netip.Addr{}, 0, false
	}
}
