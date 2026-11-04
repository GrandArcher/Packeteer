//go:build linux

package traceroute

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/GrandArcher/Packeteer/internal/sockerr"
	"github.com/GrandArcher/Packeteer/internal/sockmark"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
	"golang.org/x/sys/unix"
)

// Probe implements hopper. ICMP time-exceeded and destination-
// unreachable come back on the socket error queue (IP_RECVERR), so this
// does not open a raw socket. A UDP payload from the destination counts
// as the destination answering.
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
	if err := sockmark.Apply(fd, v6, sockmark.FromContext(ctx)); err != nil {
		return netip.Addr{}, false, fmt.Errorf("%w: %s: %v", plugin.ErrSourceUnavailable, src, err)
	}
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
			from, typ, ok := sockerr.Parse(oob[:oobn])
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
		_, peer, rerr := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT)
		if rerr == nil {
			// The socket is unconnected, so any host can write to the
			// ephemeral port. Only the destination ends the trace.
			if fromDestination(peer, dst, port) {
				return dst, true, nil
			}
			continue
		}
		if rerr != nil && !again(rerr) {
			return netip.Addr{}, false, rerr
		}
		// Poll woke up but neither queue had a datagram. Don't spin.
		time.Sleep(2 * time.Millisecond)
	}
}

// fromDestination reports whether a datagram came from dst:port.
func fromDestination(peer unix.Sockaddr, dst netip.Addr, port int) bool {
	var from netip.Addr
	var fromPort int
	switch sa := peer.(type) {
	case *unix.SockaddrInet4:
		from, fromPort = netip.AddrFrom4(sa.Addr), sa.Port
	case *unix.SockaddrInet6:
		from, fromPort = netip.AddrFrom16(sa.Addr), sa.Port
	default:
		return false
	}
	return from.Unmap() == dst.Unmap() && fromPort == port
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

// classify reports whether typ is a traceroute reply, and whether it
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
