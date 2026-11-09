//go:build linux

package sockmark

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Apply sets the fwmark and DSCP on the socket fd. The DSCP occupies the
// upper six bits of the TOS byte and traffic class.
func Apply(fd int, v6 bool, m Marking) error {
	if m.Mark != 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(m.Mark)); err != nil {
			return fmt.Errorf("%w: fwmark %d (needs CAP_NET_ADMIN): %v", ErrTag, m.Mark, err)
		}
	}
	if m.DSCP != 0 {
		level, opt := unix.IPPROTO_IP, unix.IP_TOS
		if v6 {
			level, opt = unix.IPPROTO_IPV6, unix.IPV6_TCLASS
		}
		if err := unix.SetsockoptInt(fd, level, opt, int(m.DSCP)<<2); err != nil {
			return fmt.Errorf("%w: dscp %d: %v", ErrTag, m.DSCP, err)
		}
	}
	return nil
}
