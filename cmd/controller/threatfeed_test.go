package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
)

// TestDaemonThreatFeedFlowSpecCapWithdraw runs the controller in inject
// against a simulated edge that advertises 203.0.113.0/24 and negotiates
// FlowSpec, with an httptest feed that needs a bearer token from the
// environment. Three listed sources become FlowSpec drops toward the
// learned prefix, but max_active 2 lets only the first two reach the edge,
// tagged and NO_EXPORT. A listed destination that is allowlisted but not
// learned is never announced (its rule is checked first, so the cap does
// not hide it). Shutdown withdraws the drops.
func TestDaemonThreatFeedFlowSpecCapWithdraw(t *testing.T) {
	var fetches, unauthorized atomic.Int32
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer lab-only-feed-token" {
			unauthorized.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fetches.Add(1)
		_, _ = io.WriteString(w, "192.0.2.1 ; lab bot 1\n192.0.2.2\n192.0.2.3\n203.0.113.128/25 ; not learned\n")
	}))
	defer feed.Close()

	srv, port := edgeRouter(t)
	if _, err := srv.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.2", PeerAsn: 64512},
		Transport: &api.Transport{PassiveMode: true},
		AfiSafis:  []*api.AfiSafi{{Config: &api.AfiSafiConfig{Family: v4, Enabled: true}}, {Config: &api.AfiSafiConfig{Family: fs4, Enabled: true}}},
	}}); err != nil {
		t.Fatal(err)
	}
	httpPort := freePort(t)
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
      blackhole: {next_hop: 192.0.2.66}
      flowspec: {}
threat_feeds:
  interval: 1m
  max_active: 2
  feeds:
    - name: lab-drop
      type: http
      config: {url: "%s/drop.txt", token_env: LAB_FEED_TOKEN}
  rules:
    - {name: bad-dests, feed: lab-drop, prefixes: [203.0.113.0/24], action: blackhole, ttl: 10m}
    - {name: bad-sources, feed: lab-drop, match: source, prefixes: [203.0.113.0/24], action: flowspec_drop, ttl: 10m}
`, httpPort, port, feed.URL)
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	env := func(k string) string {
		switch k {
		case HTTPUserEnv:
			return "lab"
		case HTTPPassEnv:
			return "lab-only"
		case "LAB_FEED_TOKEN":
			return "lab-only-feed-token"
		}
		return ""
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, logs syncBuf
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"-config", path}, env, &out, &logs) }()

	feeds := fmt.Sprintf("http://127.0.0.1:%d/api/threat-feeds", httpPort)
	get := func() map[string]any {
		req, _ := http.NewRequest(http.MethodGet, feeds, nil)
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
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(40 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s\nedge: %v\nfeeds: %v\n%s", what, flowSpecOnEdge(t, srv), get(), logs.String())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	want := []string{
		"[destination: 203.0.113.0/24][source: 192.0.2.1/32] | discard",
		"[destination: 203.0.113.0/24][source: 192.0.2.2/32] | discard",
	}
	waitFor("two drops on the edge", func() bool {
		return strings.Join(flowSpecOnEdge(t, srv), "\n") == strings.Join(want, "\n")
	})
	st := get()
	if st["enabled"] != true || st["held"] != float64(2) || !strings.Contains(fmt.Sprint(st["waiting"]), "max_active (2)") {
		t.Fatalf("status = %v", st)
	}
	time.Sleep(2 * time.Second)
	if got := flowSpecOnEdge(t, srv); len(got) != 2 {
		t.Fatalf("past max_active: %v", got)
	}
	if _, _, ok := packeteerPath(t, srv, "203.0.113.128/25"); ok {
		t.Fatal("a listed destination that is not learned was announced")
	}
	if !strings.Contains(logs.String(), "threat feed fetched") || strings.Contains(logs.String(), "rule=bad-dests") {
		t.Fatalf("the destination rule acted on an unlearned prefix:\n%s", logs.String())
	}
	if fetches.Load() != 1 || unauthorized.Load() != 0 {
		t.Fatalf("fetches = %d unauthorized = %d", fetches.Load(), unauthorized.Load())
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
	if !strings.Contains(logs.String(), "mitigation routes withdrawn") || !strings.Contains(logs.String(), "threat feed mitigation added") {
		t.Fatalf("logs:\n%s", logs.String())
	}
	waitFor("flowspec gone after shutdown", func() bool { return len(flowSpecOnEdge(t, srv)) == 0 })
}

// Rule actions are checked against the mitigation announcer's catalog at
// startup, and a missing token is refused when the feed is built.
func TestThreatFeedStartupChecks(t *testing.T) {
	base := `mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
mitigation:
  allowlist: [203.0.113.0/24]
  announcer:
    type: gobgp
    config: {marker: "64512:668", blackhole: {next_hop: 192.0.2.66}}
threat_feeds:
  feeds:
    - {name: f, type: http, config: {url: "https://feeds.example.net/drop.txt"%s}}
  rules:
    - {name: r, feed: f, prefixes: [203.0.113.0/24], %s}
`
	build := func(feedExtra, rule string, env map[string]string) (*config.Config, *pluginhost.Set, error) {
		t.Helper()
		cfg, err := config.Parse([]byte(fmt.Sprintf(base, feedExtra, rule)))
		if err != nil {
			t.Fatal(err)
		}
		set, err := pluginhost.Build(cfg, pluginhost.Options{Getenv: func(k string) string { return env[k] }})
		return cfg, set, err
	}
	if _, _, err := build(", token_env: LAB_FEED_TOKEN", "action: blackhole", nil); err == nil || !strings.Contains(err.Error(), "LAB_FEED_TOKEN is not set") {
		t.Fatalf("missing token: %v", err)
	}
	for _, c := range []struct{ rule, want string }{
		{"action: redirect, target: nope", `unknown redirect target "nope"`},
		{"match: source, action: flowspec_drop", "flowspec is not configured"},
		{"action: blackhole", ""},
	} {
		cfg, set, err := build("", c.rule, nil)
		if err != nil {
			t.Fatal(err)
		}
		mit, err := newMitigation(cfg, set, quietLogger())
		if err != nil {
			t.Fatal(err)
		}
		tf, err := newThreatFeeds(cfg, set, mit, nil, quietLogger())
		if c.want == "" {
			if err != nil || tf == nil || len(tf.Status().Rules) != 1 {
				t.Fatalf("%s: %v", c.rule, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.rule, err, c.want)
		}
	}
}
