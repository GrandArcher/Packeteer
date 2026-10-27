package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// TestDaemonPartialTableSteersLearnedPrefixesOnly runs the controller in
// inject against a simulated edge that has no full table (#206): it sends
// one prefix and a default route. The learned prefix is steered; the
// default route (allowlisted here, so only its own rule holds it) and a
// prefix only the default route covers are measured and never announced;
// shutdown withdraws the steer.
func TestDaemonPartialTableSteersLearnedPrefixesOnly(t *testing.T) {
	edge := newMSEdge(t)
	edge.advertise("198.51.100.0/24", "0.0.0.0/0")
	httpPort := freePort(t)
	cfg := fmt.Sprintf(`mode: inject
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 250
hold_time: 1s
thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
http: {listen: "127.0.0.1:%d"}
auth: {enabled: false}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2}
allowlist: {prefixes: ["0.0.0.0/0"]}
probe: {interval: 1s, timeout: 200ms, packets: 1}
sources:
  - type: static
    config: {targets: [{prefix: 198.51.100.0/24}, {prefix: 203.0.113.0/24}, {prefix: 0.0.0.0/0, host: 192.0.2.200}]}
probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 80}, {provider: transit-b, rtt_ms: 10}]}
bgp:
  neighbors:
    - {address: 127.0.0.1, port: %d, local_address: 127.0.0.2}
announcer: {type: gobgp}
`, httpPort, edge.port)
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, logs syncBuf
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"-config", path}, func(string) string { return "" }, &out, &logs) }()

	reasons := func() map[string]string {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/decisions", httpPort))
		if err != nil {
			return nil
		}
		defer resp.Body.Close()
		var b bytes.Buffer
		_, _ = b.ReadFrom(resp.Body)
		var d struct {
			Decisions []struct {
				Prefix string `json:"prefix"`
				Action string `json:"action"`
				Reason string `json:"reason"`
			} `json:"decisions"`
		}
		_ = json.Unmarshal(b.Bytes(), &d)
		got := map[string]string{}
		for _, x := range d.Decisions {
			got[x.Prefix] = x.Action + ": " + x.Reason
		}
		return got
	}
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

	waitWire("the learned prefix steered", "198.51.100.0/24")
	want := map[string]string{
		"0.0.0.0/0":      "none: default route is never steered",
		"203.0.113.0/24": "none: prefix not in RIB",
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		got := reasons()
		if got["0.0.0.0/0"] == want["0.0.0.0/0"] && got["203.0.113.0/24"] == want["203.0.113.0/24"] {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("decisions = %v, want %v", got, want)
		}
		time.Sleep(200 * time.Millisecond)
	}
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		if got := edge.fromPacketeer(); !slices.Equal(got, []string{"198.51.100.0/24"}) {
			t.Fatalf("edge has %v, want only the learned prefix\n%s", got, logs.String())
		}
	}

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
