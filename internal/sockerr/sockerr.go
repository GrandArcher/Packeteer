//go:build linux

// Package sockerr parses the IP_RECVERR / IPV6_RECVERR control messages
// that carry ICMP errors for the UDP prober and the traceroute source.
package sockerr

import (
	"encoding/binary"
	"net/netip"

	"golang.org/x/sys/unix"
)

// Parse reads one IP_RECVERR / IPV6_RECVERR control message. ok is false
// when there is none or it is not an ICMP error.
func Parse(oob []byte) (from netip.Addr, icmpType byte, ok bool) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	for _, m := range msgs {
		if int(m.Header.Type) != unix.IP_RECVERR && int(m.Header.Type) != unix.IPV6_RECVERR {
			continue
		}
		return ParseData(m.Data)
	}
	return netip.Addr{}, 0, false
}

// ParseData reads the payload of one such message: the kernel's
// sock_extended_err (16 bytes), then the offender sockaddr. from is the
// router that sent the ICMP message.
func ParseData(data []byte) (from netip.Addr, icmpType byte, ok bool) {
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
