//go:build linux

package udp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
	"golang.org/x/sys/unix"
)

// onePacket sends one datagram. A payload from the connected peer counts.
// An ICMP destination-unreachable counts only when the error-queue
// offender is the target. Anything else, including icmp-port-unreachable
// from a firewall, is loss. A missing source address fails closed.
func onePacket(ctx context.Context, network string, laddr, raddr *net.UDPAddr, timeout time.Duration, start time.Time) (time.Duration, bool, error) {
	c, err := net.DialUDP(network, laddr, raddr)
	if err != nil {
		if errors.Is(err, syscall.EADDRNOTAVAIL) {
			return 0, false, fmt.Errorf("%w: %s: %v", plugin.ErrSourceUnavailable, laddr.IP, err)
		}
		return 0, false, nil
	}
	defer c.Close()
	target, _ := netip.AddrFromSlice(raddr.IP)
	target = target.Unmap()
	v6 := !target.Is4()
	fd, err := dupRecvErr(c, v6)
	if err != nil {
		return 0, false, nil
	}
	defer unix.Close(fd)
	deadline := start.Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if _, err := c.Write([]byte{0}); err != nil {
		if errors.Is(err, syscall.EADDRNOTAVAIL) {
			return 0, false, fmt.Errorf("%w: %v", plugin.ErrSourceUnavailable, err)
		}
		if rtt, ok, _ := takeReply(fd, target, v6, start); ok {
			return rtt, true, nil
		}
		return 0, false, nil
	}
	buf := make([]byte, 1500)
	oob := make([]byte, 512)
	for {
		if err := ctx.Err(); err != nil {
			return 0, false, err
		}
		ready, err := waitFD(fd, ctx, deadline)
		if err != nil {
			return 0, false, err
		}
		rtt, ok, saw := readQueues(fd, buf, oob, target, v6, start)
		if ok {
			return rtt, true, nil
		}
		// A queued ICMP from someone else is loss. Keep waiting only when
		// the poll woke up and neither queue had a message yet.
		if saw || !ready || time.Until(deadline) <= 0 {
			return 0, false, nil
		}
	}
}

// dupRecvErr enables the error queue and returns a dup of the socket so
// poll can see POLLERR. Go's net poller does not wake on that event.
func dupRecvErr(c *net.UDPConn, v6 bool) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	var fd int
	var sockErr error
	err = raw.Control(func(f uintptr) {
		level, opt := unix.IPPROTO_IP, unix.IP_RECVERR
		if v6 {
			level, opt = unix.IPPROTO_IPV6, unix.IPV6_RECVERR
		}
		if sockErr = unix.SetsockoptInt(int(f), level, opt, 1); sockErr != nil {
			return
		}
		fd, sockErr = unix.Dup(int(f))
	})
	if err != nil {
		return -1, err
	}
	return fd, sockErr
}

// waitFD reports ready when the socket can be read or has an error queued.
// A timeout is ready=false and a nil error.
func waitFD(fd int, ctx context.Context, deadline time.Time) (bool, error) {
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		remain := time.Until(deadline)
		if remain <= 0 {
			return false, nil
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
			return false, nil
		}
		if n > 0 {
			return true, nil
		}
	}
}

func takeReply(fd int, target netip.Addr, v6 bool, start time.Time) (time.Duration, bool, bool) {
	buf := make([]byte, 256)
	oob := make([]byte, 512)
	return readQueues(fd, buf, oob, target, v6, start)
}

// readQueues drains one error-queue message or one payload. ok is true
// only for a payload or a destination-unreachable from the target. saw is
// true when a message was consumed, so the caller does not keep waiting.
func readQueues(fd int, buf, oob []byte, target netip.Addr, v6 bool, start time.Time) (rtt time.Duration, ok, saw bool) {
	_, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
	if err == nil && oobn > 0 {
		from, typ, parsed := parseExtErr(oob[:oobn])
		if parsed && unreachableFromTarget(from, target, typ, v6) {
			return time.Since(start), true, true
		}
		return 0, false, true
	}
	nn, _, _, _, err := unix.Recvmsg(fd, buf, nil, unix.MSG_DONTWAIT)
	if err == nil && nn >= 0 {
		return time.Since(start), true, true
	}
	return 0, false, false
}

// unreachableFromTarget is true for an ICMP destination-unreachable whose
// offender is the probed address. Time-exceeded and an unreachable from
// any other address are not a reply.
func unreachableFromTarget(from, target netip.Addr, icmpType byte, v6 bool) bool {
	if !from.IsValid() || from.Unmap() != target.Unmap() {
		return false
	}
	if v6 {
		return icmpType == 1
	}
	return icmpType == 3
}

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
