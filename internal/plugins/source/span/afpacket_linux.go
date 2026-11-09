//go:build linux

package span

import (
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// afPacket is a raw AF_PACKET socket bound to one interface. It needs
// CAP_NET_RAW (docker run --cap-add NET_RAW). Promiscuous mode is a
// socket membership: the kernel drops it when the socket closes, so a
// crash leaves the interface as it was.
type afPacket struct {
	fd       int
	linkType int
	loopback bool
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func openCapture(name string, promisc bool, readTimeout time.Duration) (capture, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", name, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET socket (needs CAP_NET_RAW): %w", err)
	}
	c := &afPacket{fd: fd, linkType: linkEthernet, loopback: ifi.Flags&net.FlagLoopback != 0}
	if len(ifi.HardwareAddr) == 0 && !c.loopback {
		// tun and other layer-3 devices deliver bare IP packets.
		c.linkType = linkRaw
	}
	fail := func(what string, err error) (capture, error) {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%s on %s: %w", what, name, err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifi.Index}); err != nil {
		return fail("bind", err)
	}
	if promisc {
		mreq := unix.PacketMreq{Ifindex: int32(ifi.Index), Type: unix.PACKET_MR_PROMISC}
		if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq); err != nil {
			return fail("promiscuous mode", err)
		}
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, captureBuffer)
	tv := unix.NsecToTimeval(readTimeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return fail("receive timeout", err)
	}
	return c, nil
}

func (c *afPacket) link() int { return c.linkType }

// read returns one frame, truncated to len(buf). errReadTimeout means no
// frame arrived inside the read timeout.
func (c *afPacket) read(buf []byte) (int, error) {
	for {
		n, from, err := unix.Recvfrom(c.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				return 0, errReadTimeout
			}
			return 0, err
		}
		// Loopback shows every frame twice: once outgoing, once received.
		if ll, ok := from.(*unix.SockaddrLinklayer); ok && c.loopback && ll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		return n, nil
	}
}

func (c *afPacket) close() error { return unix.Close(c.fd) }
