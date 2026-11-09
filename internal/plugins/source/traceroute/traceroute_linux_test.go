//go:build linux

package traceroute

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
	"golang.org/x/sys/unix"
)

func TestClassifyICMP(t *testing.T) {
	hop, reached := classify(false, 11)
	if !hop || reached {
		t.Fatalf("classify time exceeded: hop=%v reached=%v", hop, reached)
	}
	hop, reached = classify(false, 3)
	if !hop || !reached {
		t.Fatalf("classify dest unreach: hop=%v reached=%v", hop, reached)
	}
}

func TestLoopbackDiscovery(t *testing.T) {
	s := must(t, `
timeout: 300ms
probes: 1
min_replies: 1
max_hops: 3
interval: 1s
port: 33434
targets:
  - {prefix: 127.0.0.1/32, host: 127.0.0.1}
`)
	s.now = time.Now
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		_ = s.Stop(stop)
	})
	deadline := time.Now().Add(2 * time.Second)
	var ts []plugin.Target
	var err error
	for time.Now().Before(deadline) {
		ts, err = s.Targets(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(ts) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(ts) != 1 || ts[0].Host.String() != "127.0.0.1" || ts[0].Prefix.String() != "127.0.0.1/32" {
		t.Fatalf("loopback trace = %+v", ts)
	}
}

func TestLoopbackV6(t *testing.T) {
	s := must(t, `
timeout: 300ms
probes: 1
min_replies: 1
max_hops: 3
interval: 1s
port: 33434
targets:
  - {prefix: "::1/128", host: "::1"}
`)
	s.now = time.Now
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		_ = s.Stop(stop)
	})
	deadline := time.Now().Add(2 * time.Second)
	var ts []plugin.Target
	for time.Now().Before(deadline) {
		var err error
		ts, err = s.Targets(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(ts) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(ts) != 1 || ts[0].Host.String() != "::1" {
		t.Fatalf("v6 loopback trace = %+v", ts)
	}
}

func TestBindMissingSource(t *testing.T) {
	_, _, err := udpHopper{}.Probe(context.Background(),
		a("192.0.2.99"), a("192.0.2.1"), 1, 33434, 200*time.Millisecond)
	if !errors.Is(err, plugin.ErrSourceUnavailable) {
		t.Fatalf("err = %v, want ErrSourceUnavailable", err)
	}
}

func TestFromDestination(t *testing.T) {
	dst := a("203.0.113.9")
	v4 := func(addr string, port int) unix.Sockaddr {
		return &unix.SockaddrInet4{Addr: a(addr).As4(), Port: port}
	}
	if !fromDestination(v4("203.0.113.9", 33434), dst, 33434) {
		t.Error("reply from the destination refused")
	}
	if fromDestination(v4("203.0.113.10", 33434), dst, 33434) {
		t.Error("datagram from another host accepted")
	}
	if fromDestination(v4("203.0.113.9", 40000), dst, 33434) {
		t.Error("datagram from another port accepted")
	}
	v6 := a("2001:db8::9")
	if !fromDestination(&unix.SockaddrInet6{Addr: v6.As16(), Port: 33434}, v6, 33434) {
		t.Error("v6 reply from the destination refused")
	}
	if fromDestination(&unix.SockaddrUnix{Name: "/x"}, dst, 33434) {
		t.Error("non-IP sender accepted")
	}
}

// replyFrom reads one probe on ln and answers it from reply's socket.
func replyFrom(t *testing.T, ln, reply *net.UDPConn) {
	t.Helper()
	go func() {
		buf := make([]byte, 16)
		_ = ln.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, peer, err := ln.ReadFromUDP(buf)
		if err != nil {
			return
		}
		_, _ = reply.WriteToUDP([]byte("x"), peer)
	}()
}

func listenLoopback(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("udp listen: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestProbeReachedOnlyByDestinationReply(t *testing.T) {
	dst := netip.MustParseAddr("127.0.0.1")
	ln := listenLoopback(t)
	port := ln.LocalAddr().(*net.UDPAddr).Port

	replyFrom(t, ln, ln)
	from, reached, err := udpHopper{}.Probe(context.Background(), netip.Addr{}, dst, 64, port, time.Second)
	if err != nil || !reached || from != dst {
		t.Fatalf("destination reply: from=%s reached=%v err=%v", from, reached, err)
	}

	// Same host, other port: unrelated traffic on the ephemeral port.
	stray := listenLoopback(t)
	replyFrom(t, ln, stray)
	from, reached, err = udpHopper{}.Probe(context.Background(), netip.Addr{}, dst, 64, port, 300*time.Millisecond)
	if err != nil || reached || from.IsValid() {
		t.Fatalf("stray datagram ended the trace: from=%s reached=%v err=%v", from, reached, err)
	}
}
