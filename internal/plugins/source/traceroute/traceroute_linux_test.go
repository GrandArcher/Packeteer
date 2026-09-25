//go:build linux

package traceroute

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
	"golang.org/x/sys/unix"
)

func TestParseExtErr(t *testing.T) {
	data := make([]byte, 16+16)
	binary.LittleEndian.PutUint32(data[0:4], uint32(unix.ECONNREFUSED))
	data[4] = unix.SO_EE_ORIGIN_ICMP
	data[5] = 11 // time exceeded
	data[6] = 0
	binary.LittleEndian.PutUint16(data[16:18], unix.AF_INET)
	copy(data[20:24], []byte{203, 0, 113, 1})
	from, typ, ok := parseExtErrData(data)
	if !ok || typ != 11 || from.String() != "203.0.113.1" {
		t.Fatalf("from=%s typ=%d ok=%v", from, typ, ok)
	}
	hop, reached := classify(false, typ)
	if !hop || reached {
		t.Fatalf("classify time exceeded: hop=%v reached=%v", hop, reached)
	}
	hop, reached = classify(false, 3)
	if !hop || !reached {
		t.Fatalf("classify dest unreach: hop=%v reached=%v", hop, reached)
	}

	v6 := make([]byte, 16+28)
	v6[4] = unix.SO_EE_ORIGIN_ICMP6
	v6[5] = 3 // time exceeded
	binary.LittleEndian.PutUint16(v6[16:18], unix.AF_INET6)
	copy(v6[24:40], a("2001:db8::1").AsSlice())
	from, typ, ok = parseExtErrData(v6)
	if !ok || typ != 3 || from.String() != "2001:db8::1" {
		t.Fatalf("v6 from=%s typ=%d ok=%v", from, typ, ok)
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
