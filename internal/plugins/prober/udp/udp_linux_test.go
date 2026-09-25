//go:build linux

package udp

import (
	"encoding/binary"
	"net/netip"
	"testing"

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
