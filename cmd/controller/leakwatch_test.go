package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// testLeakFeed is the leak source the daemon test drives by hand.
type testLeakFeed struct {
	plugin.Base
	mu      sync.Mutex
	sink    func(plugin.LeakSighting)
	healthy atomic.Bool
}

var theLeakFeed = &testLeakFeed{}

func (f *testLeakFeed) SetLeakSink(fn func(plugin.LeakSighting)) {
	f.mu.Lock()
	f.sink = fn
	f.mu.Unlock()
}
func (f *testLeakFeed) Healthy() bool { return f.healthy.Load() }
func (f *testLeakFeed) send(s plugin.LeakSighting) {
	f.mu.Lock()
	fn := f.sink
	f.mu.Unlock()
	fn(s)
}

func init() {
	plugin.LeakSources.Register("testfeed", func(plugin.Config, plugin.Env) (plugin.LeakSource, error) { return theLeakFeed, nil })
}

// TestDaemonLeakWatchWithdrawsOnlyTheLeakedRoute runs the controller in
// inject against a simulated edge with two injected routes. A clean
// sighting changes nothing; a sighting of one injected prefix with the
// local ASN in its path withdraws that route alone and keeps it out across
// decision rounds, with its source reporting unknown; an operator clear
// lets it return; shutdown withdraws the rest.
func TestDaemonLeakWatchWithdrawsOnlyTheLeakedRoute(t *testing.T) {
	edge := newMSEdge(t)
	edge.advertise("203.0.113.0/24", "198.51.100.0/24")
	httpPort := freePort(t)
	cfg := fmt.Sprintf(`mode: inject
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 250
hold_time: 1s
thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
http: {listen: "127.0.0.1:%d"}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2}
allowlist: {prefixes: ["198.51.100.0/24", "203.0.113.0/24"]}
probe: {interval: 1s, timeout: 200ms, packets: 1}
sources:
  - type: static
    config: {targets: [{prefix: 198.51.100.0/24}, {prefix: 203.0.113.0/24}]}
probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 80}, {provider: transit-b, rtt_ms: 10}]}
bgp:
  neighbors:
    - {address: 127.0.0.1, port: %d, local_address: 127.0.0.2}
announcer: {type: gobgp}
leak_watch:
  enabled: true
  as_path_rule: true
  sources:
    - {type: testfeed}
`, httpPort, edge.port)
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	theLeakFeed.healthy.Store(true)
	getenv := func(k string) string {
		switch k {
		case HTTPUserEnv:
			return "ops"
		case HTTPPassEnv:
			return "secret"
		}
		return ""
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, logs syncBuf
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"-config", path}, getenv, &out, &logs) }()

	waitWire := func(what string, want ...string) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for {
			got := edge.fromPacketeer()
			if slices.Equal(got, want) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s: edge has %v, want %v\n%s", what, got, want, logs.String())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	stayWire := func(what string, d time.Duration, want ...string) {
		t.Helper()
		for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
			if got := edge.fromPacketeer(); !slices.Equal(got, want) {
				t.Fatalf("%s: edge has %v, want %v\n%s", what, got, want, logs.String())
			}
		}
	}
	api := func(method, p, body string) (int, []byte) {
		t.Helper()
		req, _ := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", httpPort, p), bytes.NewReader([]byte(body)))
		req.SetBasicAuth("ops", "secret")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var b bytes.Buffer
		_, _ = b.ReadFrom(resp.Body)
		return resp.StatusCode, b.Bytes()
	}

	both := []string{"198.51.100.0/24", "203.0.113.0/24"}
	waitWire("both improvements", both...)

	// A clean run: sightings that are not leaks change nothing.
	theLeakFeed.send(plugin.LeakSighting{Prefix: netip.MustParsePrefix("203.0.113.0/24"), ASPath: []uint32{64511, 64496}})
	theLeakFeed.send(plugin.LeakSighting{Prefix: netip.MustParsePrefix("192.0.2.0/24"), ASPath: []uint32{64511, 64512}})
	stayWire("after clean sightings", 2*time.Second, both...)
	if code, b := api("GET", "/api/leaks", ""); code != 200 || !bytes.Contains(b, []byte(`"leaks":[]`)) || !bytes.Contains(b, []byte(`"state":"watching"`)) {
		t.Fatalf("leaks before any leak: %d %s", code, b)
	}

	// 203.0.113.0/24 shows up outside with our ASN. The source then goes
	// unhealthy; the withdraw and the hold do not depend on it.
	theLeakFeed.send(plugin.LeakSighting{Prefix: netip.MustParsePrefix("203.0.113.0/24"), ASPath: []uint32{64511, 64512, 64496}, Seen: "rrc00/192.0.2.9"})
	theLeakFeed.healthy.Store(false)
	waitWire("only the leaked route withdrawn", "198.51.100.0/24")
	stayWire("leaked route stays out across rounds", 4*time.Second, "198.51.100.0/24")
	code, b := api("GET", "/api/leaks", "")
	var st struct {
		State string `json:"state"`
		Leaks []struct {
			Prefix string `json:"prefix"`
			Reason string `json:"reason"`
			Action string `json:"action"`
		} `json:"leaks"`
	}
	if err := json.Unmarshal(b, &st); err != nil || code != 200 {
		t.Fatalf("%d %s %v", code, b, err)
	}
	if len(st.Leaks) != 1 || st.Leaks[0].Prefix != "203.0.113.0/24" || st.Leaks[0].Reason != "as_path" || st.Leaks[0].Action != "withdrawn" {
		t.Fatalf("leaks %s", b)
	}
	deadline := time.Now().Add(15 * time.Second)
	for st.State != "unknown" {
		if time.Now().After(deadline) {
			t.Fatalf("state %q with the source down, want unknown", st.State)
		}
		time.Sleep(200 * time.Millisecond)
		_, b = api("GET", "/api/leaks", "")
		_ = json.Unmarshal(b, &st)
	}

	// The operator fixed the export filter and clears the hold.
	if code, _ := api("POST", "/api/leaks/clear", `{"prefix":"203.0.113.0/24"}`); code != http.StatusNoContent {
		t.Fatalf("clear: %d", code)
	}
	waitWire("route back after clear", both...)

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d\n%s", code, logs.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("daemon did not stop")
	}
	waitWire("every route gone after shutdown")
}
