package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
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
  interval: 60s
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

// startSwapReflector serves TWAMP-Light on a loopback port, answering the
// packets from swapped in pairs, the second first: half of every train
// from that address arrives reordered. Others are answered at once.
func startSwapReflector(t *testing.T, swapped netip.Addr) string {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		r := twamp.NewReflector(0)
		held := map[netip.AddrPort][]byte{}
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			out, ok := r.Reply(from, 64, buf[:n], time.Now())
			switch first, waiting := held[from]; {
			case !ok:
			case from.Addr() != swapped:
				_, _ = conn.WriteToUDPAddrPort(out, from)
			case waiting:
				delete(held, from)
				_, _ = conn.WriteToUDPAddrPort(out, from)
				_, _ = conn.WriteToUDPAddrPort(first, from)
			default:
				held[from] = out
			}
		}
	}()
	t.Cleanup(func() { conn.Close(); <-done })
	return strconv.Itoa(conn.LocalAddr().(*net.UDPAddr).Port)
}

// #224 in inject against a simulated edge: transit-b is the fastest path
// for an allowlisted documentation prefix, but its controlled reading is
// 50% reordered, and with reorder_weight 5 the improvement goes to
// transit-c, the next fastest, tagged with the community and NO_EXPORT.
// Shutdown withdraws it. Probe sources are loopback addresses so the
// trains reach the reflector; confirm_rounds lets the readings arrive
// before a move.
func TestDaemonReorderWeight(t *testing.T) {
	port := startSwapReflector(t, netip.MustParseAddr("127.0.0.12"))
	edge := newMSEdge(t)
	edge.advertise("198.51.100.0/24")
	httpPort := freePort(t)
	d := runIX(t, edge, httpPort, fmt.Sprintf(`mode: inject
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 250
hold_time: 1s
thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15, confirm_rounds: 3}
http: {listen: "127.0.0.1:%d"}
providers:
  - {name: transit-a, source_ip: 127.0.0.11, next_hop: 192.0.2.1}
  - {name: transit-b, source_ip: 127.0.0.12, next_hop: 192.0.2.2}
  - {name: transit-c, source_ip: 127.0.0.13, next_hop: 192.0.2.3}
allowlist: {prefixes: ["198.51.100.0/24"]}
probe:
  interval: 1s
  timeout: 200ms
  packets: 1
  rate_limit_pps: 1000
  reorder: {packets: 20, spacing: 1ms, timeout: 100ms, interval: 1s, flows: 1, responders: [{address: 127.0.0.1, port: %s}]}
sources:
  - type: static
    config: {targets: [{prefix: 198.51.100.0/24}]}
probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 80}, {provider: transit-b, rtt_ms: 30}, {provider: transit-c, rtt_ms: 50}]}
scorer:
  type: weighted
  config: {reorder_weight: 5}
bgp:
  neighbors:
    - {address: 127.0.0.1, port: %d, local_address: 127.0.0.2}
announcer: {type: gobgp}
`, httpPort, port, edge.port))
	onC := routeVia("198.51.100.0/24", "192.0.2.3", ixCommunity, ixNoExport)
	d.waitWire("the improvement onto transit-c", onC)
	d.holdWire("the improvement stays on transit-c", 3*time.Second, onC)
	_, body := d.call("GET", "/api/reorder", "")
	rows, _ := body["reorder"].([]any)
	ratio := map[string]float64{}
	for _, r := range rows {
		row, _ := r.(map[string]any)
		worst, _ := row["worst"].(map[string]any)
		ratio[fmt.Sprint(row["provider"])], _ = worst["ratio_pct"].(float64)
	}
	if len(ratio) != 3 || ratio["transit-b"] != 50 || ratio["transit-a"] != 0 || ratio["transit-c"] != 0 {
		d.fatalf("readings %v, want transit-b 50%% and the others 0", ratio)
	}
	d.stop()
}
