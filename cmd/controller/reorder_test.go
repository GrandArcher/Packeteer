package main

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/twamp"
)

const reorderYAML = `
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
  - name: transit-b
    source_ip: 192.0.2.12
    next_hop: 192.0.2.2
probe:
  interval: 10s
  timeout: 1s
  packets: 4
  rate_limit_pps: 10
  reorder:
    packets: 50
    spacing: 5ms
    flows: 2
    responders:
      - address: 203.0.113.9
      - address: 198.51.100.1
        type: icmp
`

// probe.reorder builds a monitor over the providers with one prober per
// responder type, and widens the packet budgets so one train fits a wait
// (#224). Without the block there is no monitor.
func TestNewReorderMonitor(t *testing.T) {
	cfg, err := config.Parse([]byte(reorderYAML))
	if err != nil {
		t.Fatal(err)
	}
	if reorderPackets(cfg) != 50 {
		t.Fatalf("reorderPackets = %d", reorderPackets(cfg))
	}
	lim := packetLimiter(cfg)
	if lim.Burst() != 50 {
		t.Fatalf("burst %d, want the train length", lim.Burst())
	}
	mon, err := newReorderMonitor(cfg, slog.New(slog.DiscardHandler), lim, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if mon == nil {
		t.Fatal("no monitor")
	}
	// Nothing has run: no results, and nothing to score.
	if rs := mon.Results(); len(rs) != 0 {
		t.Fatalf("results before a run: %+v", rs)
	}
	if got := mon.Scored(time.Now(), time.Minute); len(got) != 0 {
		t.Fatalf("scored before a run: %v", got)
	}

	plain, err := config.Parse([]byte(strings.SplitN(reorderYAML, "  reorder:", 2)[0]))
	if err != nil {
		t.Fatal(err)
	}
	if reorderPackets(plain) != 0 || packetLimiter(plain).Burst() != 10 {
		t.Fatalf("plain config: packets %d, burst %d", reorderPackets(plain), packetLimiter(plain).Burst())
	}
	off, err := newReorderMonitor(plain, slog.New(slog.DiscardHandler), packetLimiter(plain), nil, nil)
	if err != nil || off != nil {
		t.Fatalf("monitor without the block: %v, %v", off, err)
	}
}

// A reflector on the loopback answers the controller-built monitor: one
// result per provider and responder.
func TestReorderMonitorLoopback(t *testing.T) {
	y := strings.ReplaceAll(reorderYAML, "192.0.2.11", "127.0.0.1")
	y = strings.ReplaceAll(y, "192.0.2.12", "127.0.0.2")
	y = strings.Replace(y, "      - address: 203.0.113.9\n      - address: 198.51.100.1\n        type: icmp\n", "      - address: 127.0.0.1\n        port: PORT\n", 1)
	port := startReflector(t)
	cfg, err := config.Parse([]byte(strings.Replace(y, "PORT", port, 1)))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Probe.Reorder.Timeout = 300 * time.Millisecond
	// No packet budget: the trains run back to back.
	mon, err := newReorderMonitor(cfg, slog.New(slog.DiscardHandler), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	mon.RunOnce(t.Context())
	rs := mon.Results()
	if len(rs) != 2 || rs[0].Provider != "transit-a" || rs[1].Provider != "transit-b" {
		t.Fatalf("results %+v", rs)
	}
	for _, r := range rs {
		if !r.OK() || len(r.Flows) != 2 || r.Worst.Received != 50 || r.Worst.RatioPct != 0 || r.Estimate {
			t.Fatalf("result %+v", r)
		}
	}
	if got := mon.Scored(time.Now(), time.Minute); len(got) != 2 || got["transit-a"] != 0 {
		t.Fatalf("scored %v", got)
	}
}

// startReflector serves TWAMP-Light on a loopback port and returns the port.
func startReflector(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = twamp.Serve(ctx, conn, twamp.NewReflector(0), slog.New(slog.DiscardHandler))
	}()
	t.Cleanup(func() { cancel(); <-done })
	return strconv.Itoa(conn.LocalAddr().(*net.UDPAddr).Port)
}
