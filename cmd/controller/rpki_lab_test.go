package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rpki"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// advertiseVia makes the edge advertise prefix through a provider's next
// hop with the given AS path, so the learned origin is the last AS.
func (e *msEdge) advertiseVia(prefix, nextHop string, asPath ...uint32) {
	e.t.Helper()
	p := netip.MustParsePrefix(prefix)
	nlri, _ := anypb.New(&api.IPAddressPrefix{Prefix: p.Addr().String(), PrefixLen: uint32(p.Bits())})
	origin, _ := anypb.New(&api.OriginAttribute{Origin: 0})
	nh, _ := anypb.New(&api.NextHopAttribute{NextHop: nextHop})
	aspath, _ := anypb.New(&api.AsPathAttribute{Segments: []*api.AsSegment{{Type: 2, Numbers: asPath}}})
	path := &api.Path{Family: v4, Nlri: nlri, Pattrs: []*anypb.Any{origin, nh, aspath}}
	if _, err := e.srv.AddPath(context.Background(), &api.AddPathRequest{Path: path}); err != nil {
		e.t.Fatal(err)
	}
	e.mu.Lock()
	e.adv[prefix] = path
	e.ever[prefix] = true
	e.mu.Unlock()
}

// rtrStub serves the RTR answer recorded from Routinator
// (internal/plugins/rpki/rtr/testdata) to every client until stopped: the
// reset response to a Reset Query, and an empty serial response (Cache
// Response, then the recorded End of Data) to each Serial Query.
type rtrStub struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func newRTRStub(t *testing.T) *rtrStub {
	t.Helper()
	reset, err := os.ReadFile(filepath.Join("..", "..", "internal", "plugins", "rpki", "rtr", "testdata", "routinator-reset.bin"))
	if err != nil {
		t.Fatal(err)
	}
	unchanged := append(slices.Clone(reset[:8]), reset[len(reset)-24:]...)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &rtrStub{ln: ln}
	t.Cleanup(s.stop)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, conn)
			s.mu.Unlock()
			go func() {
				defer conn.Close()
				for {
					head := make([]byte, 8)
					if _, err := io.ReadFull(conn, head); err != nil {
						return
					}
					if n := binary.BigEndian.Uint32(head[4:8]); n > 8 {
						if _, err := io.CopyN(io.Discard, conn, int64(n-8)); err != nil {
							return
						}
					}
					answer := unchanged
					if head[1] == 2 {
						answer = reset
					}
					if _, err := conn.Write(answer); err != nil {
						return
					}
				}
			}()
		}
	}()
	return s
}

func (s *rtrStub) addr() string { return s.ln.Addr().String() }

// stop closes the listener and every session, as a stopped cache would.
func (s *rtrStub) stop() {
	_ = s.ln.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.conns = nil
}

// TestDaemonRPKIPerProvider is the #200 lab check on a simulated edge. A
// stub RTR server replays Routinator's recorded answer and the recorded
// Routinator /json is the second source. The edge's paths are valid,
// invalid, and not found, and the API shows each with the source and its
// data time. Stopping the RTR server moves the answers to the second
// source and raises rpki.stale; stopping that one too ages the cache out
// to unknown while decisions continue and the injected route stays on the
// wire. Shutdown still withdraws it.
func TestDaemonRPKIPerProvider(t *testing.T) {
	edge := newMSEdge(t)
	// The ROAs: 203.0.113.0/24-25 AS64497, 192.0.2.0/24-24 AS64496,
	// 2001:db8::/32-48 AS64498.
	edge.advertiseVia("203.0.113.0/24", "192.0.2.1", 64501, 64497)
	edge.advertiseVia("203.0.113.0/25", "192.0.2.1", 64501, 64511)
	edge.advertiseVia("198.51.100.0/24", "192.0.2.1", 64501, 64499)
	rtr := newRTRStub(t)
	doc, err := os.ReadFile(filepath.Join("..", "..", "internal", "plugins", "rpki", "vrpjson", "testdata", "routinator.json"))
	if err != nil {
		t.Fatal(err)
	}
	generated := regexp.MustCompile(`"generated": \d+`)
	var jsonDown atomic.Bool
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if jsonDown.Load() {
			http.Error(w, "stopped", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(generated.ReplaceAll(doc, []byte(`"generated": `+strconv.FormatInt(time.Now().Unix(), 10))))
	}))
	defer backup.Close()

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
allowlist: {prefixes: ["198.51.100.0/24"]}
probe: {interval: 1s, timeout: 200ms, packets: 1}
sources:
  - type: static
    config: {targets: [{prefix: 198.51.100.0/24}, {prefix: 203.0.113.0/24}, {prefix: 203.0.113.0/25}]}
probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 80}, {provider: transit-b, rtt_ms: 10}]}
bgp:
  neighbors:
    - {address: 127.0.0.1, port: %d, local_address: 127.0.0.2}
announcer: {type: gobgp}
rpki:
  enabled: true
  avoid_invalid: true
  sources:
    - type: rtr
      name: routinator
      config: {address: "%s", refresh: 1s, staleness: 2s, timeout: 1s}
    - type: json
      name: routinator-json
      config: {url: "%s/json", refresh: 1s, staleness: 2s, timeout: 1s}
`, httpPort, edge.port, rtr.addr(), backup.URL)
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, logs syncBuf
	done := make(chan int, 1)
	getenv := func(k string) string {
		switch k {
		case HTTPUserEnv:
			return "ops"
		case HTTPPassEnv:
			return "secret"
		}
		return ""
	}
	go func() { done <- run(ctx, []string{"-config", path}, getenv, &out, &logs) }()

	get := func(p string) []byte {
		t.Helper()
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d%s", httpPort, p), nil)
		req.SetBasicAuth("ops", "secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()
		var b bytes.Buffer
		_, _ = b.ReadFrom(resp.Body)
		return b.Bytes()
	}
	type candidate struct {
		Provider    string     `json:"provider"`
		RPKI        string     `json:"rpki"`
		RPKISource  string     `json:"rpki_source"`
		RPKIUpdated *time.Time `json:"rpki_updated"`
	}
	type learned struct {
		Provider   string `json:"provider"`
		RPKI       string `json:"rpki"`
		RPKISource string `json:"rpki_source"`
	}
	// labels is prefix -> provider -> "state source" from /api/decisions,
	// and the same for the learned paths on /api/prefixes.
	labels := func() (map[string]map[string]string, map[string]map[string]string) {
		var d struct {
			Decisions []struct {
				Prefix     string      `json:"prefix"`
				Candidates []candidate `json:"candidates"`
			} `json:"decisions"`
		}
		var p struct {
			Prefixes []struct {
				Prefix string    `json:"prefix"`
				Paths  []learned `json:"paths"`
			} `json:"prefixes"`
		}
		_ = json.Unmarshal(get("/api/decisions"), &d)
		_ = json.Unmarshal(get("/api/prefixes"), &p)
		dec, card := map[string]map[string]string{}, map[string]map[string]string{}
		for _, x := range d.Decisions {
			dec[x.Prefix] = map[string]string{}
			for _, c := range x.Candidates {
				if c.RPKI != "" {
					dec[x.Prefix][c.Provider] = c.RPKI + " " + c.RPKISource
				}
				if c.RPKISource != "" && (c.RPKIUpdated == nil || time.Since(*c.RPKIUpdated) > time.Minute) {
					t.Fatalf("%s %s: rpki_updated %v, want the source's recent fetch", x.Prefix, c.Provider, c.RPKIUpdated)
				}
			}
		}
		for _, x := range p.Prefixes {
			card[x.Prefix] = map[string]string{}
			for _, l := range x.Paths {
				card[x.Prefix][l.Provider] = l.RPKI + " " + l.RPKISource
			}
		}
		return dec, card
	}
	waitLabels := func(what, source, valid, invalid, notfound string) {
		t.Helper()
		want := map[string]map[string]string{
			"203.0.113.0/24":  {"transit-a": valid + source},
			"203.0.113.0/25":  {"transit-a": invalid + source},
			"198.51.100.0/24": {"transit-a": notfound + source},
		}
		deadline := time.Now().Add(30 * time.Second)
		for {
			dec, card := labels()
			ok := true
			for p, w := range want {
				ok = ok && fmt.Sprint(dec[p]) == fmt.Sprint(w) && fmt.Sprint(card[p]) == fmt.Sprint(w)
			}
			if ok {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: decisions %v, prefix card %v, want %v\n%s", what, dec, card, want, logs.String())
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	waitEvent := func(kind, source string) {
		t.Helper()
		pat := regexp.MustCompile(`"kind":"` + regexp.QuoteMeta(kind) + `"[^}]*"fields":\{[^}]*"source":"` + regexp.QuoteMeta(source) + `"`)
		deadline := time.Now().Add(30 * time.Second)
		for !pat.Match(get("/api/events")) {
			if time.Now().After(deadline) {
				t.Fatalf("no %s event for %s: %s", kind, source, get("/api/events"))
			}
			time.Sleep(200 * time.Millisecond)
		}
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
				t.Fatalf("%s: edge has %v, want %v\n%s", what, got, want, logs.String())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	waitLabels("from the RTR server", " routinator", "valid", "invalid", "notfound")
	waitWire("improvement onto transit-b", "198.51.100.0/24")

	rtr.stop()
	waitLabels("primary down", " routinator-json", "valid", "invalid", "notfound")
	waitEvent("rpki.stale", "routinator")

	jsonDown.Store(true)
	waitLabels("both sources down", " ", "unknown", "unknown", "unknown")
	waitEvent("rpki.stale", "routinator-json")
	// Fail open: the decision rounds go on and the route RPKI no longer
	// knows about stays on the wire.
	waitWire("route kept with RPKI unknown", "198.51.100.0/24")

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d\n%s", code, logs.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("daemon did not stop")
	}
	waitWire("withdrawn on shutdown")
}

// #200: rpki.avoid_invalid with the answer recorded from Routinator, read
// by the rtr plugin: of three providers with paths for 203.0.113.0/25, the
// faster one whose origin is invalid gets no improvement and the valid one
// does. With avoid_invalid off (the default) the same labels change
// nothing.
func TestRPKIAvoidInvalidFromRecordedCache(t *testing.T) {
	stub := newRTRStub(t)
	c, err := plugin.ConfigFromYAML("address: " + stub.addr() + "\nrefresh: 1m\n")
	if err != nil {
		t.Fatal(err)
	}
	src, err := plugin.RPKIs.New("rtr", c, plugin.Env{Name: "routinator"})
	if err != nil {
		t.Fatal(err)
	}
	if err := src.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Stop(context.Background()) }()
	origins := rpki.NewSet([]plugin.RPKI{src})
	for deadline := time.Now().Add(5 * time.Second); src.Status().VRPs == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the rtr source never loaded the recording")
		}
	}
	pfx := netip.MustParsePrefix("203.0.113.0/25")
	paths := fakePaths{
		"transit-a": {{64501, 64497}},
		"transit-b": {{64502, 64511}},
		"transit-c": {{64503, 64497}},
	}
	now := time.Now()
	res := func(provider string, rtt time.Duration) probe.Result {
		return probe.Result{Provider: provider, Prefix: pfx, Time: now, Stats: probe.Stats{Sent: 4, Received: 4, RTTAvg: rtt}}
	}
	decide := func(avoid bool) (map[string]string, string) {
		t.Helper()
		cfg, err := config.Parse([]byte("mode: suggest\nasn: 64512\nrouter_id: 192.0.2.10\nhold_time: 1s\nthresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}\n" +
			"providers:\n  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}\n  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2}\n  - {name: transit-c, source_ip: 192.0.2.13, next_hop: 192.0.2.3}\n" +
			"rpki:\n  enabled: true\n  avoid_invalid: " + strconv.FormatBool(avoid) + "\n  sources: [{type: rtr, config: {address: \"192.0.2.20:3323\"}}]\n"))
		if err != nil {
			t.Fatal(err)
		}
		scorer, err := weighted.New(plugin.Config{}, plugin.Env{})
		if err != nil {
			t.Fatal(err)
		}
		decider, err := newDecider(cfg, &pluginhost.Set{Scorer: &pluginhost.Instance[plugin.Scorer]{Name: "weighted", Type: "weighted", Plugin: scorer}})
		if err != nil {
			t.Fatal(err)
		}
		in := policy.Input{
			Results:    []probe.Result{res("transit-a", 90*time.Millisecond), res("transit-b", 10*time.Millisecond), res("transit-c", 40*time.Millisecond)},
			ProviderUp: map[string]bool{"transit-a": true, "transit-b": true, "transit-c": true},
			RIBEnabled: true, RIBReady: true, Native: map[netip.Prefix]string{pfx: "transit-a"},
		}
		fillRPKI(&in, rpkiRoutes(paths, in.Results, origins))
		decider.Evaluate(in, now)
		ds, _ := decider.Decisions()
		labels := map[string]string{}
		for _, d := range ds {
			for _, cand := range d.Candidates {
				labels[cand.Provider] = string(cand.RPKI) + " " + cand.RPKISource
			}
		}
		var via string
		for _, imp := range decider.Improvements() {
			if imp.Prefix == pfx {
				via = imp.Provider
			}
		}
		return labels, via
	}
	wantLabels := "map[transit-a:valid routinator transit-b:invalid routinator transit-c:valid routinator]"
	labels, via := decide(true)
	if fmt.Sprint(labels) != wantLabels || via != "transit-c" {
		t.Fatalf("avoid_invalid on: labels %v, improvement via %q, want %s via transit-c", labels, via, wantLabels)
	}
	labels, via = decide(false)
	if fmt.Sprint(labels) != wantLabels || via != "transit-b" {
		t.Fatalf("avoid_invalid off: labels %v, improvement via %q, want %s via transit-b", labels, via, wantLabels)
	}
}
