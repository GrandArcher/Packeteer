//go:build linux

package sockmark

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestContextRoundTrip(t *testing.T) {
	m := Marking{Mark: 7, DSCP: 10}
	if got := FromContext(WithContext(context.Background(), m)); got != m {
		t.Fatalf("FromContext = %+v, want %+v", got, m)
	}
	if got := FromContext(WithContext(context.Background(), Marking{})); !got.IsZero() {
		t.Fatalf("zero marking leaked: %+v", got)
	}
}

func TestControlNilWhenZero(t *testing.T) {
	if Control(Marking{}) != nil {
		t.Fatal("Control(zero) must be nil")
	}
}

func sockInt(t *testing.T, c net.Conn, level, opt int) int {
	t.Helper()
	rc, err := c.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var serr error
	if err := rc.Control(func(fd uintptr) { v, serr = unix.GetsockoptInt(int(fd), level, opt) }); err != nil || serr != nil {
		t.Fatalf("getsockopt: %v %v", err, serr)
	}
	return v
}

func TestDSCPOnDialedSockets(t *testing.T) {
	for _, tc := range []struct {
		network, addr string
		level, opt    int
	}{
		{"udp4", "127.0.0.1:9", unix.IPPROTO_IP, unix.IP_TOS},
		{"udp6", "[::1]:9", unix.IPPROTO_IPV6, unix.IPV6_TCLASS},
	} {
		d := net.Dialer{Control: Control(Marking{DSCP: 46})}
		c, err := d.Dial(tc.network, tc.addr)
		if err != nil {
			t.Skipf("%s unavailable: %v", tc.network, err)
		}
		if got := sockInt(t, c, tc.level, tc.opt); got != 46<<2 {
			t.Errorf("%s: tos/tclass = %d, want %d", tc.network, got, 46<<2)
		}
		c.Close()
	}
}

func TestMarkNeedsPrivilegeOrIsSet(t *testing.T) {
	d := net.Dialer{Control: Control(Marking{Mark: 0x65})}
	c, err := d.Dial("udp4", "127.0.0.1:9")
	if err != nil {
		if !errors.Is(err, ErrTag) {
			t.Fatalf("unexpected error %v", err)
		}
		return // unprivileged: the tag is refused, never silently dropped
	}
	defer c.Close()
	if got := sockInt(t, c, unix.SOL_SOCKET, unix.SO_MARK); got != 0x65 {
		t.Fatalf("SO_MARK = %d, want %d", got, 0x65)
	}
}
