package tcp

import (
	"context"
	"errors"
	"fmt"
	"net"
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

var lo = netip.MustParseAddr("127.0.0.1")

func TestProbeListening(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	p := newProber(t, fmt.Sprintf("port: %d\npacket_interval: 1ms", ln.Addr().(*net.TCPAddr).Port))
	res, err := p.Probe(context.Background(), plugin.ProbeRequest{Source: lo, Target: lo, Count: 3, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res.Sent != 3 || len(res.RTTs) != 3 {
		t.Fatalf("res = %+v", res)
	}
}

func TestProbeRefusedCountsAsReply(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // nothing listens now: RST
	p := newProber(t, fmt.Sprintf("port: %d\npacket_interval: 1ms", port))
	res, err := p.Probe(context.Background(), plugin.ProbeRequest{Source: lo, Target: lo, Count: 2, Timeout: time.Second})
	if err != nil || len(res.RTTs) != 2 {
		t.Fatalf("res = %+v err = %v", res, err)
	}
}

func TestSourceUnavailable(t *testing.T) {
	p := newProber(t, "")
	_, err := p.Probe(context.Background(), plugin.ProbeRequest{Source: netip.MustParseAddr("192.0.2.99"),
		Target: netip.MustParseAddr("192.0.2.1"), Count: 1, Timeout: 200 * time.Millisecond})
	if !errors.Is(err, plugin.ErrSourceUnavailable) {
		t.Fatalf("err = %v, want ErrSourceUnavailable", err)
	}
}

func TestFamilyMismatch(t *testing.T) {
	p := newProber(t, "")
	_, err := p.Probe(context.Background(), plugin.ProbeRequest{Source: lo, Target: netip.MustParseAddr("::1"), Count: 1, Timeout: time.Second})
	if err == nil || !strings.Contains(err.Error(), "address family") {
		t.Fatalf("err = %v", err)
	}
}

func TestConfig(t *testing.T) {
	for y, want := range map[string]string{
		"port: 70000":          "between 1 and 65535",
		"port: -1":             "between 1 and 65535",
		"packet_interval: -1s": "must not be negative",
		"mode: syn":            "field mode not found",
	} {
		c, _ := plugin.ConfigFromYAML(y)
		if _, err := plugin.Probers.New(TypeName, c, plugin.Env{}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", y, err, want)
		}
	}
}
