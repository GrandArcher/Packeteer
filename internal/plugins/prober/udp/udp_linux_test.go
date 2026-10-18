//go:build linux

package udp

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
	"golang.org/x/sys/unix"
)

func TestUnreachableFromTarget(t *testing.T) {
	target := netip.MustParseAddr("203.0.113.9")
	other := netip.MustParseAddr("192.0.2.1")
	if !unreachableFromTarget(target, target, 3, false) {
		t.Fatal("destination unreachable from the target must count")
	}
	if unreachableFromTarget(other, target, 3, false) {
		t.Fatal("icmp-port-unreachable from another hop must be loss")
	}
	if unreachableFromTarget(target, target, 11, false) {
		t.Fatal("time exceeded is not a UDP reply")
	}
	v6 := netip.MustParseAddr("2001:db8::9")
	if !unreachableFromTarget(v6, v6, 1, true) {
		t.Fatal("v6 destination unreachable from the target must count")
	}
	if unreachableFromTarget(v6, v6, 3, true) {
		t.Fatal("v6 time exceeded must not count")
	}
}

func TestParseExtErrOffender(t *testing.T) {
	data := make([]byte, 16+16)
	binary.LittleEndian.PutUint32(data[0:4], uint32(unix.ECONNREFUSED))
	data[4] = unix.SO_EE_ORIGIN_ICMP
	data[5] = 3
	binary.LittleEndian.PutUint16(data[16:18], unix.AF_INET)
	copy(data[20:24], []byte{203, 0, 113, 9})
	from, typ, ok := parseExtErrData(data)
	if !ok || typ != 3 || from.String() != "203.0.113.9" {
		t.Fatalf("from=%s typ=%d ok=%v", from, typ, ok)
	}
	if !unreachableFromTarget(from, netip.MustParseAddr("203.0.113.9"), typ, false) {
		t.Fatal("parsed offender should match the target")
	}
	if unreachableFromTarget(from, netip.MustParseAddr("198.51.100.1"), typ, false) {
		t.Fatal("parsed offender matched a different target")
	}
}

// The datagram a provider sharing its source_ip sends carries the DSCP its
// policy route matches (#157).
func TestProbeSendsDSCP(t *testing.T) {
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("udp listen: %v", err)
	}
	defer ln.Close()
	raw, err := ln.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var serr error
	_ = raw.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1) })
	if serr != nil {
		t.Skipf("IP_RECVTOS: %v", serr)
	}

	p := &Prober{port: ln.LocalAddr().(*net.UDPAddr).Port, interval: time.Millisecond}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = p.Probe(context.Background(), plugin.ProbeRequest{
			Source: netip.MustParseAddr("127.0.0.1"), Target: netip.MustParseAddr("127.0.0.1"),
			Count: 1, Timeout: 200 * time.Millisecond, DSCP: 46,
		})
	}()
	buf, oob := make([]byte, 16), make([]byte, 64)
	_ = ln.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, oobn, _, _, err := ln.ReadMsgUDP(buf, oob)
	if err != nil {
		t.Fatal(err)
	}
	<-done
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_TOS {
			if got := m.Data[0]; got != 46<<2 {
				t.Fatalf("TOS byte = %#x, want %#x", got, 46<<2)
			}
			return
		}
	}
	t.Fatalf("no TOS control message in %d messages", len(msgs))
}
