package main

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const healthYAML = `
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.21
exchanges:
  - name: ix-lab
    lans: [203.0.113.0/24]
    health:
      min_peers: 2
    peers:
      - {name: ix-peer-a, asn: 64501, next_hop: 203.0.113.11, source_ip: 192.0.2.31}
      - {name: ix-peer-b, asn: 64502, next_hop: 203.0.113.12, source_ip: 192.0.2.32}
      - {name: ix-peer-c, asn: 64503, next_hop: 203.0.113.13, source_ip: 192.0.2.33}
  - name: ix-off
    lans: [198.51.100.0/24]
    health:
      enabled: false
    peers:
      - {name: off-peer, asn: 64504, next_hop: 198.51.100.11, source_ip: 192.0.2.34}
bgp:
  neighbors:
    - address: 192.0.2.254
      add_path: true
`

// fakeNet answers a probe unless its target is in down.
type fakeNet struct {
	plugin.Base
	mu   sync.Mutex
	down map[netip.Addr]bool
	got  []plugin.ProbeRequest
}

func (f *fakeNet) set(down ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = map[netip.Addr]bool{}
	for _, d := range down {
		f.down[netip.MustParseAddr(d)] = true
	}
}

func (f *fakeNet) Probe(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, req)
	if f.down[req.Target] {
		return plugin.ProbeResult{Sent: req.Count}, nil
	}
	rtts := make([]time.Duration, req.Count)
	for i := range rtts {
		rtts[i] = 3 * time.Millisecond
	}
	return plugin.ProbeResult{Sent: req.Count, RTTs: rtts}, nil
}

// #149: the next hops of the enabled exchanges' peers are probed from each
// peer's source_ip; the alert fires when the configured number of peers is
// down, resolves after the window, and nothing but events comes of it.
func TestExchangeHealthRaisesAndResolves(t *testing.T) {
	cfg, err := config.Parse([]byte(healthYAML))
	if err != nil {
		t.Fatal(err)
	}
	targets, h := exchangeHealth(cfg)
	if len(targets) != 3 || h == nil {
		t.Fatalf("targets = %+v", targets)
	}
	for _, tg := range targets {
		if tg.Provider == "off-peer" {
			t.Fatalf("a disabled exchange is probed: %+v", tg)
		}
	}
	net := &fakeNet{}
	engine, err := probe.New(
		[]probe.Provider{{Name: "transit-a", Source: netip.MustParseAddr("192.0.2.11")}},
		[]probe.NamedProber{{Name: "icmp", Prober: net}}, nil,
		probe.Options{Interval: time.Second, Timeout: 50 * time.Millisecond, Packets: 3, Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	s := &sink{}
	clock := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	round := func() []plugin.Event {
		healthRound(context.Background(), engine, h, targets, now, s.Emit)
		return s.take()
	}

	if evs := round(); len(evs) != 0 {
		t.Fatalf("healthy exchange emitted %s", kinds(evs))
	}
	snap := h.Snapshot()["ix-lab"]
	if r := snap.Peers["ix-peer-a"]; r.State != "reachable" || r.RTTMs != 3 || r.LossPct != 0 {
		t.Fatalf("peer a = %+v", r)
	}
	// Each peer is probed from its own source.
	want := map[string]string{"203.0.113.11": "192.0.2.31", "203.0.113.12": "192.0.2.32", "203.0.113.13": "192.0.2.33"}
	for _, req := range net.got {
		if want[req.Target.String()] != req.Source.String() {
			t.Errorf("probe of %s from %s", req.Target, req.Source)
		}
	}

	// One peer down: that member, not the exchange.
	net.set("203.0.113.11")
	clock = clock.Add(time.Minute)
	if evs := round(); len(evs) != 0 {
		t.Fatalf("one peer down emitted %s", kinds(evs))
	}
	if r := h.Snapshot()["ix-lab"].Peers["ix-peer-a"]; r.State != "unreachable" || r.LossPct != 100 {
		t.Fatalf("peer a down = %+v", r)
	}

	// A second peer: the exchange.
	net.set("203.0.113.11", "203.0.113.12")
	clock = clock.Add(time.Minute)
	evs := round()
	if kinds(evs) != plugin.EventExchangeDegraded {
		t.Fatalf("events = %s", kinds(evs))
	}
	ev := evs[0]
	if ev.Severity != plugin.SeverityWarning || ev.Fields["exchange"] != "ix-lab" || ev.Fields["degraded_peers"] != "ix-peer-a,ix-peer-b" ||
		ev.Fields["degraded"] != "2" || ev.Fields["peers"] != "3" || !strings.Contains(ev.Message, "ix-lab") {
		t.Fatalf("event = %+v", ev)
	}
	if evs := round(); len(evs) != 0 {
		t.Fatalf("repeat: %s", kinds(evs))
	}

	// Recovery: probes are healthy again, and the alert resolves once the
	// window (5m by default) has passed since the last bad probe.
	net.set()
	clock = clock.Add(2 * time.Minute)
	if evs := round(); len(evs) != 0 {
		t.Fatalf("inside the window: %s", kinds(evs))
	}
	clock = clock.Add(4 * time.Minute)
	evs = round()
	if kinds(evs) != plugin.EventExchangeRecovered || !evs[0].Resolves() || evs[0].DedupKey() != "packeteer/exchange/exchange=ix-lab" {
		t.Fatalf("events = %s", kinds(evs))
	}
}

// A cancelled round feeds nothing to the tracker.
func TestExchangeHealthRoundIgnoresCancelledProbes(t *testing.T) {
	cfg, err := config.Parse([]byte(healthYAML))
	if err != nil {
		t.Fatal(err)
	}
	targets, h := exchangeHealth(cfg)
	net := &fakeNet{}
	net.set("203.0.113.11", "203.0.113.12", "203.0.113.13")
	engine, err := probe.New(
		[]probe.Provider{{Name: "transit-a", Source: netip.MustParseAddr("192.0.2.11")}},
		[]probe.NamedProber{{Name: "icmp", Prober: net}}, nil,
		probe.Options{Interval: time.Second, Timeout: 50 * time.Millisecond, Packets: 3, Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &sink{}
	healthRound(ctx, engine, h, targets, time.Now, s.Emit)
	if evs := s.take(); len(evs) != 0 {
		t.Fatalf("cancelled round emitted %s", kinds(evs))
	}
	if r := h.Snapshot()["ix-lab"].Peers["ix-peer-a"]; r.State != "unknown" {
		t.Fatalf("peer a = %+v", r)
	}
}

func TestNoHealthWithoutExchanges(t *testing.T) {
	cfg, err := config.Parse([]byte(strings.Split(healthYAML, "exchanges:")[0]))
	if err != nil {
		t.Fatal(err)
	}
	if targets, h := exchangeHealth(cfg); targets != nil || h != nil {
		t.Fatalf("targets %v, health %v", targets, h)
	}
}

// probe.interval reloads online, but a reload that raises it above an
// exchange's health window is refused: a bad sample must not age out
// before the next probe.
func TestReloadKeepsHealthWindowAboveInterval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(healthYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(healthYAML+"probe: {interval: 10m}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rl := &reloader{path: path, getenv: noEnv, log: slog.New(slog.DiscardHandler), cur: cfg}
	applied, refused, fatal := rl.reload(context.Background())
	if fatal != nil || len(applied) != 0 || refused == nil ||
		!strings.Contains(refused.Error(), "health.window 5m0s must be between probe.interval (10m0s)") {
		t.Fatalf("applied %v refused %v fatal %v", applied, refused, fatal)
	}
	if rl.cur != cfg {
		t.Fatal("refused reload replaced the running config")
	}
}
