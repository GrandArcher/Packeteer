package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"

	"github.com/GrandArcher/Packeteer/internal/anomaly"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// flowSender sends synthetic NetFlow v5 toward 203.0.113.10 every 100ms:
// udp and tcp bytes per export, changeable while it runs.
type flowSender struct {
	udp, tcp atomic.Uint32
}

func (f *flowSender) run(ctx context.Context, t *testing.T, port int) {
	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Error(err)
		return
	}
	defer conn.Close()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		b := make([]byte, 24+2*48)
		binary.BigEndian.PutUint16(b[0:], 5)
		binary.BigEndian.PutUint16(b[2:], 2)
		for i, rec := range []struct {
			proto uint8
			n     uint32
		}{{17, f.udp.Load()}, {6, f.tcp.Load()}} {
			o := 24 + 48*i
			copy(b[o:o+4], netip.MustParseAddr("198.51.100.9").AsSlice())
			copy(b[o+4:o+8], netip.MustParseAddr("203.0.113.10").AsSlice())
			binary.BigEndian.PutUint32(b[o+20:], rec.n)
			b[o+38] = rec.proto
		}
		_, _ = conn.Write(b)
	}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// TestDaemonAnomalyDetectMitigateClearWithdraw runs the controller in
// inject against a simulated edge that advertises 203.0.113.0/24 and
// negotiates FlowSpec, fed synthetic NetFlow. Steady traffic raises
// nothing. A UDP flood is detected and, through the explicit udp rule,
// becomes a FlowSpec drop for the exact learned prefix and protocol,
// tagged and NO_EXPORT. A TCP flood at the same time is detected but has
// no rule, so nothing more is announced. When the flood stops the
// anomaly clears and the drop is withdrawn; a second flood is mitigated
// again, and shutdown withdraws it.
func TestDaemonAnomalyDetectMitigateClearWithdraw(t *testing.T) {
	srv, port := edgeRouter(t)
	if _, err := srv.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.2", PeerAsn: 64512},
		Transport: &api.Transport{PassiveMode: true},
		AfiSafis:  []*api.AfiSafi{{Config: &api.AfiSafiConfig{Family: v4, Enabled: true}}, {Config: &api.AfiSafiConfig{Family: fs4, Enabled: true}}},
	}}); err != nil {
		t.Fatal(err)
	}
	httpPort, flowPort := freePort(t), freeUDPPort(t)
	cfg := fmt.Sprintf(`mode: inject
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 250
hold_time: 1s
thresholds: {min_loss_delta_pct: 90, min_rtt_delta_ms: 5000}
http: {listen: "127.0.0.1:%d"}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2}
allowlist: {prefixes: ["198.51.100.0/24"]}
probe: {interval: 1s, timeout: 200ms, packets: 1}
probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 1}, {provider: transit-b, rtt_ms: 1}]}
sources:
  - type: flow
    config: {listen: "127.0.0.1:%d", window: 10s}
bgp:
  neighbors:
    - {address: 127.0.0.1, port: %d, local_address: 127.0.0.2}
announcer: {type: gobgp}
mitigation:
  mode: inject
  allowlist: [203.0.113.0/24]
  max_rules: 4
  announcer:
    type: gobgp
    config:
      marker: "64512:668"
      flowspec: {}
anomaly:
  interval: 1s
  detector:
    type: baseline
    config: {warmup: 3, trigger_rounds: 2, clear_rounds: 2, min_mbps: 1}
  rules:
    - name: udp-flood
      prefixes: [203.0.113.0/24]
      protocols: [udp]
      action: flowspec_drop
      ttl: 10m
`, httpPort, flowPort, port)
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	env := func(k string) string {
		switch k {
		case HTTPUserEnv:
			return "lab"
		case HTTPPassEnv:
			return "lab-only"
		}
		return ""
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, logs syncBuf
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"-config", path}, env, &out, &logs) }()

	get := func(url string) map[string]any {
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		req.SetBasicAuth("lab", "lab-only")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		return m
	}
	anomalies := fmt.Sprintf("http://127.0.0.1:%d/api/anomalies", httpPort)
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s\nedge: %v\nanomalies: %v\n%s", what, flowSpecOnEdge(t, srv), get(anomalies), logs.String())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	open := func() []any {
		st := get(anomalies)
		if st == nil {
			return nil
		}
		a, _ := st["anomalies"].([]any)
		return a
	}
	waitFor("the ops API", func() bool { return get(anomalies) != nil })
	waitFor("the session", func() bool { return strings.Contains(logs.String(), "state=ESTABLISHED") })

	// Steady: 1000 B udp and 5000 B tcp per 100ms (0.08 and 0.4 Mbit/s).
	var fs flowSender
	fs.udp.Store(1000)
	fs.tcp.Store(5000)
	sendCtx, stopSend := context.WithCancel(ctx)
	defer stopSend()
	go fs.run(sendCtx, t, flowPort)
	waitFor("baselines", func() bool {
		st := get(anomalies)
		return st != nil && st["baselines"] == float64(2)
	})
	time.Sleep(5 * time.Second) // past warmup
	if a := open(); len(a) != 0 {
		t.Fatalf("steady traffic raised %v", a)
	}
	if got := flowSpecOnEdge(t, srv); len(got) != 0 {
		t.Fatalf("flowspec with no anomaly: %v", got)
	}

	// UDP and TCP floods (32 Mbit/s each); only udp has a rule.
	fs.udp.Store(400000)
	fs.tcp.Store(400000)
	drop := "[destination: 203.0.113.0/24][protocol: ==udp] | discard"
	waitFor("the udp drop on the edge", func() bool {
		got := flowSpecOnEdge(t, srv)
		return len(got) == 1 && got[0] == drop
	})
	waitFor("both anomalies", func() bool { return len(open()) == 2 })
	for _, x := range open() {
		a := x.(map[string]any)
		switch a["protocol"] {
		case "udp":
			if a["state"] != anomaly.StateMitigating || a["rule"] != "udp-flood" {
				t.Fatalf("udp anomaly = %v", a)
			}
		case "tcp":
			if a["state"] != anomaly.StateNoRule || a["mitigation"] != nil {
				t.Fatalf("tcp anomaly = %v", a)
			}
		default:
			t.Fatalf("anomaly = %v", a)
		}
	}
	time.Sleep(2 * time.Second)
	if got := flowSpecOnEdge(t, srv); len(got) != 1 {
		t.Fatalf("the tcp anomaly without a rule was mitigated: %v", got)
	}

	// Flood ends: cleared, rule removed, drop withdrawn.
	fs.udp.Store(1000)
	fs.tcp.Store(5000)
	waitFor("anomalies cleared", func() bool { return open() != nil && len(open()) == 0 })
	waitFor("drop withdrawn after clearing", func() bool { return len(flowSpecOnEdge(t, srv)) == 0 })

	// Second flood; shutdown withdraws its drop.
	fs.udp.Store(400000)
	waitFor("the udp drop again", func() bool {
		got := flowSpecOnEdge(t, srv)
		return len(got) == 1 && got[0] == drop
	})
	stopSend()
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d\n%s", code, logs.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("daemon did not stop")
	}
	if !strings.Contains(logs.String(), "mitigation routes withdrawn") || !strings.Contains(logs.String(), "anomaly mitigation added") {
		t.Fatalf("logs:\n%s", logs.String())
	}
	waitFor("flowspec gone after shutdown", func() bool { return len(flowSpecOnEdge(t, srv)) == 0 })
}

func TestEventWatchAnomaly(t *testing.T) {
	s := &sink{}
	w := newEventWatch(s, "inject")
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	a := anomaly.Anomaly{ID: "a1", Prefix: netip.MustParsePrefix("203.0.113.0/24"), Protocol: 17, Mbps: 32, PeakMbps: 40, BaselineMbps: 0.08,
		Reason: "flood", Since: now, Rule: "udp-flood", Mitigation: "m1", Action: plugin.MitigationFlowSpecDrop}
	w.anomaly([]anomaly.Change{
		{Time: now, Kind: anomaly.ChangeDetected, Anomaly: a},
		{Time: now, Kind: anomaly.ChangeMitigated, Anomaly: a, Detail: "added"},
		{Time: now, Kind: anomaly.ChangeHeld, Anomaly: a, Detail: "waiting"},
		{Time: now, Kind: anomaly.ChangeEnded, Anomaly: a, Detail: "ended"},
		{Time: now, Kind: anomaly.ChangeCleared, Anomaly: a, Detail: "back"},
	})
	got := s.take()
	kinds := []string{plugin.EventAnomalyDetected, plugin.EventAnomalyMitigated, plugin.EventAnomalyHeld, plugin.EventAnomalyHeld, plugin.EventAnomalyCleared}
	if len(got) != len(kinds) {
		t.Fatalf("events = %+v", got)
	}
	for i, e := range got {
		if e.Kind != kinds[i] || e.Fields["anomaly"] != "a1" || e.Fields["protocol"] != "udp" || e.Fields["rule"] != "udp-flood" || e.Fields["peak_mbps"] != "40.00" {
			t.Errorf("event %d = %+v", i, e)
		}
	}
	var nilW *eventWatch
	nilW.anomaly([]anomaly.Change{{Kind: anomaly.ChangeDetected}}) // no panic
}

// The flow source is picked by name or, when there is one, by capability;
// rule actions are checked against the mitigation catalog.
func TestAnomalySourceAndActions(t *testing.T) {
	base := `mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
`
	build := func(y string) (*config.Config, *pluginhost.Set) {
		t.Helper()
		cfg, err := config.Parse([]byte(base + y))
		if err != nil {
			t.Fatal(err)
		}
		set, err := pluginhost.Build(cfg, pluginhost.Options{})
		if err != nil {
			t.Fatal(err)
		}
		return cfg, set
	}
	det := "anomaly:\n  detector: {type: baseline}\n"
	cfg, set := build("sources:\n  - {type: static, config: {targets: [{prefix: 203.0.113.0/24}]}}\n" + det)
	if _, _, err := anomalySource(cfg.Anomaly, set); err == nil || !strings.Contains(err.Error(), "needs a flow source") {
		t.Fatalf("no flow source: %v", err)
	}
	two := "sources:\n  - {type: flow, name: f1, config: {listen: '127.0.0.1:0'}}\n  - {type: flow, name: f2, config: {listen: '127.0.0.1:1'}}\n"
	cfg, set = build(two + det)
	if _, _, err := anomalySource(cfg.Anomaly, set); err == nil || !strings.Contains(err.Error(), "set anomaly.source") {
		t.Fatalf("two flow sources: %v", err)
	}
	cfg, set = build(two + det + "  source: f2\n")
	if _, name, err := anomalySource(cfg.Anomaly, set); err != nil || name != "f2" {
		t.Fatalf("named: %s %v", name, err)
	}
	cfg, set = build("sources:\n  - {type: static, config: {targets: [{prefix: 203.0.113.0/24}]}}\n" + det + "  source: static\n")
	if _, _, err := anomalySource(cfg.Anomaly, set); err == nil || !strings.Contains(err.Error(), "does not supply flow counters") {
		t.Fatalf("static named: %v", err)
	}

	mitBlock := `mitigation:
  allowlist: [203.0.113.0/24]
  announcer:
    type: gobgp
    config:
      marker: "64512:668"
      blackhole: {next_hop: 192.0.2.66}
`
	rule := func(action string) string {
		return "sources:\n  - {type: flow, config: {listen: '127.0.0.1:0'}}\n" + mitBlock + det +
			"  rules:\n    - {name: r, prefixes: [203.0.113.0/24], action: " + action + "}\n"
	}
	for action, ok := range map[string]bool{"blackhole": true, "flowspec_drop": false, "'redirect', target: nope": false} {
		cfg, set = build(rule(action))
		mit, err := newMitigation(cfg, set, quietLogger())
		if err != nil {
			t.Fatal(err)
		}
		_, err = newAnomaly(cfg, set, mit, func() {}, quietLogger())
		if (err == nil) != ok {
			t.Errorf("%s: err = %v", action, err)
		}
	}
}

func quietLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }
