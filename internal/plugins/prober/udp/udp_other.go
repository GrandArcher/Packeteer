//go:build !linux

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

// onePacket is the non-Linux fallback. The production image is Linux,
// where an unreachable counts only when its source is the target
// (udp_linux.go). Other systems cannot read that address from the
// socket, so a connection refusal still counts as a reply.
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
