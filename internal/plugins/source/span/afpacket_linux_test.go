//go:build linux

package span

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TestAFPacketLoopback captures synthetic frames written to lo with a
// second AF_PACKET socket. It needs root (CI runs it with sudo) and sends
// nothing beyond the loopback interface.
func TestAFPacketLoopback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for AF_PACKET")
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("no lo interface")
	}
	s := startSource(t, mustSource(t, "interface: lo\npromiscuous: false\nlocal: [192.0.2.0/24, \"2001:db8:1::/48\"]\n"))

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	to := &unix.SockaddrLinklayer{Ifindex: lo.Index, Halen: 6}
	copy(to.Addr[:], macB)
	// Only the retransmission scenario: its verdict does not depend on
	// handshake timeouts, so it holds at wall-clock speed.
	for _, f := range retransFrames() {
		if err := unix.Sendto(fd, f, 0, to); err != nil {
			t.Fatal(err)
		}
	}
	waitRetrans(t, s)
}
