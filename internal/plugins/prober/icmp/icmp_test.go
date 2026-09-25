package icmp

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func newProber(t *testing.T, y string) plugin.Prober {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	p, err := plugin.Probers.New(TypeName, c, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// skipIfNoSocket skips when neither raw nor datagram ICMP is permitted in
// this environment (e.g. an unprivileged CI runner).
func skipIfNoSocket(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), "icmp socket unavailable") {
		t.Skipf("no ICMP socket permission here: %v", err)
	}
}

func TestLoopbackEcho(t *testing.T) {
	lo := netip.MustParseAddr("127.0.0.1")
	p := newProber(t, "packet_interval: 1ms")
	res, err := p.Probe(context.Background(), plugin.ProbeRequest{Source: lo, Target: lo, Count: 3, Timeout: time.Second})
	skipIfNoSocket(t, err)
	if err != nil {
		t.Fatal(err)
	}
	if res.Sent != 3 || len(res.RTTs) != 3 {
		t.Fatalf("res = %+v", res)
	}
}

func TestSourceUnavailable(t *testing.T) {
	p := newProber(t, "")
	_, err := p.Probe(context.Background(), plugin.ProbeRequest{Source: netip.MustParseAddr("192.0.2.99"),
		Target: netip.MustParseAddr("192.0.2.1"), Count: 1, Timeout: 100 * time.Millisecond})
	skipIfNoSocket(t, err)
	if !errors.Is(err, plugin.ErrSourceUnavailable) {
		t.Fatalf("err = %v, want ErrSourceUnavailable", err)
	}
}

func TestFamilyMismatch(t *testing.T) {
	p := newProber(t, "")
	_, err := p.Probe(context.Background(), plugin.ProbeRequest{Source: netip.MustParseAddr("127.0.0.1"),
		Target: netip.MustParseAddr("::1"), Count: 1, Timeout: time.Second})
	if err == nil || !strings.Contains(err.Error(), "address family") {
		t.Fatalf("err = %v", err)
	}
}

func TestConfig(t *testing.T) {
	for y, want := range map[string]string{
		"socket: magic":        `socket "magic" is invalid`,
		"packet_interval: -1s": "must not be negative",
		"ttl: 3":               "field ttl not found",
	} {
		c, _ := plugin.ConfigFromYAML(y)
		if _, err := plugin.Probers.New(TypeName, c, plugin.Env{}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", y, err, want)
		}
	}
	for _, y := range []string{"", "socket: raw", "socket: udp", "socket: auto\npacket_interval: 50ms"} {
		c, _ := plugin.ConfigFromYAML(y)
		if _, err := plugin.Probers.New(TypeName, c, plugin.Env{}); err != nil {
			t.Errorf("%q: %v", y, err)
		}
	}
}
