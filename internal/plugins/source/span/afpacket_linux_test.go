//go:build linux

package span

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

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
	s := mustSource(t, "interface: lo\npromiscuous: false\nlocal: [192.0.2.0/24, \"2001:db8:1::/48\"]\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		stopCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		if err := s.Stop(stopCtx); err != nil {
			t.Errorf("stop: %v", err)
		}
	}()

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	to := &unix.SockaddrLinklayer{Ifindex: lo.Index, Halen: 6}
	copy(to.Addr[:], macB)
	for _, p := range fixturePackets() {
		// Only the retransmission scenario: its verdict does not depend
		// on handshake timeouts, so it holds at wall-clock speed.
		if p.dst.Addr() != retransV4 && p.src.Addr() != retransV4 {
			continue
		}
		p.vlan = 0
		if err := unix.Sendto(fd, frame(p), 0, to); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ps := s.Problems()
		if len(ps) == 1 && ps[0].Prefix.String() == "198.51.100.0/24" {
			c := ps[0].Counts
			if c.Segments == 276 && c.Retrans == 36 && c.Flows == 12 {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("problems = %+v", s.Problems())
}
