package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/vip"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func noEnv(string) string { return "" }

func TestRunExampleConfig(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"-check", "-config", filepath.Join("..", "..", "config.example.yaml")}, noEnv, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, errOut.String())
	}
	for _, want := range []string{"mode: observe", "transit-a", "transit-b", "no BGP", "tcp", "http: 127.0.0.1:8080", "http auth: off", "log: info text"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout missing %q:\n%s", want, out.String())
		}
	}
}

func TestRunRefusesMissingMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	cfg := "asn: 64512\nrouter_id: 192.0.2.10\nproviders:\n  - name: a\n    source_ip: 192.0.2.11\n    next_hop: 192.0.2.1\n"
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-config", path}, noEnv, &out, &errOut); code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "mode is required") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestRunMissingFile(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-config", filepath.Join(t.TempDir(), "missing.yaml")}, noEnv, &out, &errOut); code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
}

func TestRunBadFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-nope"}, noEnv, &out, &errOut); code != 2 {
		t.Fatalf("exit code %d, want 2", code)
	}
}

func TestRunConfigFromEnv(t *testing.T) {
	example := filepath.Join("..", "..", "config.example.yaml")
	env := func(k string) string {
		if k == ConfigEnv {
			return example
		}
		return ""
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-check"}, env, &out, &errOut); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "config "+example+" loaded") {
		t.Errorf("stdout = %q", out.String())
	}
}

func TestRunFlagOverridesEnv(t *testing.T) {
	env := func(k string) string {
		if k == ConfigEnv {
			return "/nonexistent/from-env.yaml"
		}
		return ""
	}
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"-check", "-config", filepath.Join("..", "..", "config.example.yaml")}, env, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, errOut.String())
	}
}

func TestRunDefaultPath(t *testing.T) {
	if _, err := os.Stat(DefaultConfigPath); err == nil {
		t.Skip("default config exists on this machine")
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), nil, noEnv, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), DefaultConfigPath) {
		t.Errorf("code %d, stderr should mention %s: %q", code, DefaultConfigPath, errOut.String())
	}
}

func TestRunInjectCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	body := `
mode: inject
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 250
hold_time: 1m
thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
allowlist: {prefixes: ["198.51.100.0/24"]}
bgp:
  neighbors:
    - {address: 192.0.2.254}
announcer: {type: gobgp}
probers:
  - type: fixed
    config:
      paths:
        - {provider: transit-a, rtt_ms: 1}
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-check", "-config", path}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("exit %d stderr %s", code, errOut.String())
	}
	for _, want := range []string{"mode: inject", "announce: gobgp local_pref=250", "check: ok"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout missing %q:\n%s", want, out.String())
		}
	}
}

func TestRunVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-version"}, noEnv, &out, &errOut); code != 0 || !strings.Contains(out.String(), "packeteer dev") {
		t.Fatalf("code %d out %q", code, out.String())
	}
}

func TestRunUnknownPluginType(t *testing.T) {
	example, err := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "c.yaml")
	cfg := string(example) + "\nnotifiers:\n  - type: carrier-pigeon\n"
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-config", path}, noEnv, &out, &errOut); code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), `unknown notifier type "carrier-pigeon"`) {
		t.Errorf("stderr = %q", errOut.String())
	}
}

// TestDaemonProbesLoopback runs the real daemon path end to end on the
// loopback interface: static source -> tcp prober -> engine -> logs, then a
// clean shutdown when the context is cancelled.
func TestDaemonProbesLoopback(t *testing.T) {
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
	port := ln.Addr().(*net.TCPAddr).Port
	cfg := fmt.Sprintf(`mode: observe
asn: 64512
router_id: 192.0.2.10
http: {listen: ""}
providers:
  - name: loop
    source_ip: 127.0.0.1
    next_hop: 127.0.0.1
probe:
  interval: 1s
  timeout: 200ms
  packets: 2
probers:
  - type: tcp
    config: {port: %d, packet_interval: 10ms}
sources:
  - type: static
    config:
      targets:
        - {prefix: 127.0.0.1/32}
`, port)
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	var out, errOut bytes.Buffer
	if code := run(ctx, []string{"-config", path}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("exit code %d\n%s", code, errOut.String())
	}
	logs := errOut.String()
	for _, want := range []string{"packeteer running", "provider=loop", "prober=tcp", "loss_pct=0", "shutting down"} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs missing %q:\n%s", want, logs)
		}
	}
}

func TestCheckFlowSourceDoesNotBind(t *testing.T) {
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := fmt.Sprintf(`mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
sources:
  - type: flow
    config:
      listen: %q
`, ln.LocalAddr().String())
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-check", "-config", path}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("exit %d\n%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "source flow") {
		t.Fatalf("stdout = %s", out.String())
	}
}

type lookupSource struct {
	plugin.Base
	fn func(netip.Addr) (netip.Prefix, bool)
}

func (lookupSource) Targets(context.Context) ([]plugin.Target, error) { return nil, nil }

func (s *lookupSource) SetPrefixLookup(fn func(netip.Addr) (netip.Prefix, bool)) { s.fn = fn }

func TestWirePrefixLookupSkipsUnreadyRIB(t *testing.T) {
	view, err := rib.New(rib.Options{
		ASN: 64512, RouterID: netip.MustParseAddr("192.0.2.10"),
		Neighbors: []rib.Neighbor{{Address: netip.MustParseAddr("192.0.2.1")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	src := &lookupSource{}
	set := &pluginhost.Set{Sources: []pluginhost.Instance[plugin.TargetSource]{{Name: "flow", Plugin: src}}}
	wirePrefixLookup(set, nil)
	if src.fn != nil {
		t.Fatal("nil view should not install a lookup")
	}
	wirePrefixLookup(set, view)
	if src.fn == nil {
		t.Fatal("lookup was not installed")
	}
	if _, ok := src.fn(netip.MustParseAddr("198.51.100.1")); ok {
		t.Fatal("a RIB that is not ready must not map destinations")
	}
}

type fakeLearned struct {
	ready  bool
	gen    uint64
	routes []rib.Route
	calls  int
}

func (f *fakeLearned) Ready() bool        { return f.ready }
func (f *fakeLearned) Generation() uint64 { return f.gen }
func (f *fakeLearned) Routes() []rib.Route {
	f.calls++
	return f.routes
}

func TestLearnedSnapSkipsCopyWhenGenerationIsStable(t *testing.T) {
	f := &fakeLearned{ready: true, gen: 3, routes: []rib.Route{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASPath: []uint32{64496}},
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), ASPath: []uint32{64496}},
	}}
	var snap learnedSnap
	g, routes := snap.get(f)
	if g != 3 || len(routes) != 1 || routes[0].Prefix.String() != "198.51.100.0/24" || f.calls != 1 {
		t.Fatalf("g=%d routes=%v calls=%d", g, routes, f.calls)
	}
	if _, routes = snap.get(f); len(routes) != 1 || f.calls != 1 {
		t.Fatalf("copied the RIB again: calls=%d routes=%d", f.calls, len(routes))
	}
	f.gen = 4
	f.routes = nil
	if _, routes = snap.get(f); len(routes) != 0 || f.calls != 2 {
		t.Fatalf("new generation calls=%d routes=%d", f.calls, len(routes))
	}
	f.ready = false
	if g, routes = snap.get(f); g != 0 || routes != nil {
		t.Fatalf("unready view returned g=%d routes=%v", g, routes)
	}
}

func TestVIPIntervalMustFitStalenessWindow(t *testing.T) {
	dir := t.TempDir()
	write := func(interval string) string {
		t.Helper()
		path := filepath.Join(dir, interval+".yaml")
		body := fmt.Sprintf(`mode: observe
asn: 64512
router_id: 192.0.2.10
http: {listen: ""}
providers:
  - {name: a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
sources:
  - type: vip
    config:
      interval: %s
      prefixes:
        - {prefix: 198.51.100.0/24}
`, interval)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-check", "-config", write("5m")}, noEnv, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "staleness window") {
		t.Fatalf("code %d stderr %q", code, errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := run(context.Background(), []string{"-check", "-config", write("10s")}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("code %d stderr %q", code, errOut.String())
	}
}

func TestVIPASNNotUsedUntilRIBReady(t *testing.T) {
	c, err := plugin.ConfigFromYAML(`
interval: 10s
prefixes:
  - {prefix: 203.0.113.0/24, host: 203.0.113.8}
asns: [64496]
`)
	if err != nil {
		t.Fatal(err)
	}
	src, err := vip.New(c, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	view, err := rib.New(rib.Options{
		ASN: 64512, RouterID: netip.MustParseAddr("192.0.2.10"),
		Neighbors: []rib.Neighbor{{Address: netip.MustParseAddr("192.0.2.1")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	set := &pluginhost.Set{Sources: []pluginhost.Instance[plugin.TargetSource]{{Name: "vip", Plugin: src}}}
	wireLearnedRoutes(set, view)
	ts, err := src.Targets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 1 || ts[0].Prefix.String() != "203.0.113.0/24" {
		t.Fatalf("unready RIB must not expand ASNs: %+v", ts)
	}
}

func TestDaemonWithBGPNeighborStartsAndStops(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // no router listening: session stays down, daemon must still run and stop cleanly
	cfg := fmt.Sprintf(`mode: observe
asn: 64512
router_id: 192.0.2.10
http: {listen: ""}
providers:
  - {name: a, source_ip: 127.0.0.1, next_hop: 192.0.2.1}
probers: [{type: tcp}]
bgp:
  neighbors:
    - {address: 127.0.0.1, port: %d, description: edge1}
`, port)
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-check", "-config", path}, noEnv, &out, &errOut); code != 0 || !strings.Contains(out.String(), "bgp neighbors (1, learn-only)") {
		t.Fatalf("check: code %d out %q err %q", code, out.String(), errOut.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	out.Reset()
	errOut.Reset()
	if code := run(ctx, []string{"-config", path}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("exit code %d\n%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "bgp_neighbors=1") || !strings.Contains(errOut.String(), "shutting down") {
		t.Errorf("logs:\n%s", errOut.String())
	}
	if !strings.Contains(errOut.String(), "http disabled") {
		t.Errorf("logs missing http disabled:\n%s", errOut.String())
	}
}

func TestNewLoggerJSON(t *testing.T) {
	var buf bytes.Buffer
	log := newLogger(&buf, "info", "json")
	log.Info("hello", "k", "v")
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("json log: %v\n%s", err, buf.String())
	}
	if m["msg"] != "hello" || m["k"] != "v" {
		t.Fatalf("log = %v", m)
	}
	buf.Reset()
	newLogger(&buf, "info", "text").Info("hello")
	if !strings.Contains(buf.String(), "msg=hello") || strings.HasPrefix(strings.TrimSpace(buf.String()), "{") {
		t.Fatalf("text log = %q", buf.String())
	}
}

func TestHTTPEnvOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	body := `mode: observe
asn: 64512
router_id: 192.0.2.10
log: {level: info, format: text}
http: {listen: "127.0.0.1:8080"}
providers:
  - {name: a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	env := func(k string) string {
		switch k {
		case LogLevelEnv:
			return "debug"
		case LogFormatEnv:
			return "json"
		case HTTPListenEnv:
			return "off"
		default:
			return ""
		}
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-check", "-config", path}, env, &out, &errOut); code != 0 {
		t.Fatalf("exit %d\n%s", code, errOut.String())
	}
	for _, want := range []string{"log: debug json", "http: disabled"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout missing %q:\n%s", want, out.String())
		}
	}

	bad := func(k string) string {
		if k == HTTPListenEnv {
			return "not-a-port"
		}
		return ""
	}
	out.Reset()
	errOut.Reset()
	if code := run(context.Background(), []string{"-check", "-config", path}, bad, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "http.listen") {
		t.Fatalf("code %d stderr %q", code, errOut.String())
	}

	half := func(k string) string {
		if k == HTTPUserEnv {
			return "operator"
		}
		return ""
	}
	out.Reset()
	errOut.Reset()
	if code := run(context.Background(), []string{"-check", "-config", path}, half, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), HTTPPassEnv) {
		t.Fatalf("half auth code %d stderr %q", code, errOut.String())
	}
}

func TestCheckDoesNotBindHTTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	path := filepath.Join(t.TempDir(), "c.yaml")
	body := fmt.Sprintf(`mode: observe
asn: 64512
router_id: 192.0.2.10
http: {listen: %q}
providers:
  - {name: a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
`, ln.Addr().String())
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-check", "-config", path}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("check bound or failed: %d %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "http: "+ln.Addr().String()) {
		t.Fatalf("stdout = %s", out.String())
	}
}

func TestDaemonHTTPBindFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	path := filepath.Join(t.TempDir(), "c.yaml")
	body := fmt.Sprintf(`mode: observe
asn: 64512
router_id: 192.0.2.10
http: {listen: %q}
providers:
  - {name: a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
probers: [{type: fixed, config: {sent: 1, rtt_ms: 1}}]
`, ln.Addr().String())
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-config", path}, noEnv, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "listen") {
		t.Fatalf("code %d stderr %q", code, errOut.String())
	}
}

func TestDaemonServesHTTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	path := filepath.Join(t.TempDir(), "c.yaml")
	body := fmt.Sprintf(`mode: observe
asn: 64512
router_id: 192.0.2.10
http: {listen: "127.0.0.1:%d"}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2}
probe: {interval: 200ms, timeout: 50ms, packets: 4}
probers:
  - type: fixed
    config:
      paths:
        - {provider: transit-a, sent: 4, rtt_ms: 40, loss_pct: 0}
        - {provider: transit-b, sent: 4, rtt_ms: 10, loss_pct: 50}
sources:
  - type: static
    config:
      targets:
        - {prefix: 198.51.100.0/24, host: 198.51.100.1}
`, port)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	const user, pass = "tester", "test-pass"
	env := func(k string) string {
		switch k {
		case HTTPUserEnv:
			return user
		case HTTPPassEnv:
			return pass
		case LogFormatEnv:
			return "json"
		default:
			return ""
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, errOut bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"-config", path}, env, &out, &errOut)
	}()

	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	client := &http.Client{Timeout: time.Second}
	get := func(path string, auth bool) (*http.Response, []byte, error) {
		req, err := http.NewRequest(http.MethodGet, base+path, nil)
		if err != nil {
			return nil, nil, err
		}
		if auth {
			req.SetBasicAuth(user, pass)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		return resp, b, err
	}

	deadline := time.Now().Add(4 * time.Second)
	var metrics, prefixBody []byte
	for {
		_, body, mErr := get("/metrics", true)
		_, pbody, pErr := get("/api/prefixes", true)
		if mErr == nil && pErr == nil &&
			strings.Contains(string(body), "packeteer_probe_loss_ratio") &&
			strings.Contains(string(pbody), `"recommended":"transit-a"`) {
			metrics, prefixBody = body, pbody
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("api not ready\nmetrics:\n%s\nprefixes:\n%s\nlogs:\n%s", body, pbody, errOut.String())
		}
		time.Sleep(30 * time.Millisecond)
	}
	unauth, _, err := get("/healthz", false)
	if err != nil || unauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated healthz: %v %+v", err, unauth)
	}
	ready, readyBody, err := get("/readyz", true)
	if err != nil || ready.StatusCode != http.StatusOK || !strings.Contains(string(readyBody), `"ready":true`) {
		t.Fatalf("readyz: %v %s", err, readyBody)
	}
	dash, dashBody, err := get("/", true)
	if err != nil || dash.StatusCode != http.StatusOK || !strings.Contains(string(dashBody), "Packeteer") || !strings.Contains(string(dashBody), "/app.js") {
		t.Fatalf("dashboard: %v %s", err, dashBody)
	}
	var doc struct {
		Prefixes []struct {
			Prefix      string `json:"prefix"`
			Recommended string `json:"recommended"`
			Probes      []struct {
				Provider string  `json:"provider"`
				LossPct  float64 `json:"loss_pct"`
				RTTAvgMs float64 `json:"rtt_avg_ms"`
			} `json:"probes"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(prefixBody, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Prefixes) != 1 || doc.Prefixes[0].Prefix != "198.51.100.0/24" || doc.Prefixes[0].Recommended != "transit-a" {
		t.Fatalf("prefixes = %+v", doc.Prefixes)
	}
	var sawA, sawB bool
	for _, p := range doc.Prefixes[0].Probes {
		switch p.Provider {
		case "transit-a":
			sawA = p.RTTAvgMs == 40 && p.LossPct == 0
		case "transit-b":
			sawB = p.RTTAvgMs == 10 && p.LossPct == 50
		}
	}
	if !sawA || !sawB {
		t.Fatalf("probes = %+v", doc.Prefixes[0].Probes)
	}
	post, err := http.NewRequest(http.MethodPost, base+"/api/improvements", nil)
	if err != nil {
		t.Fatal(err)
	}
	post.SetBasicAuth(user, pass)
	resp, err := client.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d", resp.StatusCode)
	}
	for _, want := range []string{
		`provider="transit-a",prefix="198.51.100.0/24"`,
		"packeteer_probe_rtt_seconds",
		"packeteer_probe_jitter_seconds",
		"packeteer_decisions",
		"packeteer_improvements_active",
	} {
		if !strings.Contains(string(metrics), want) {
			t.Errorf("metrics missing %q\n%s", want, metrics)
		}
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d\n%s", code, errOut.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not exit")
	}
	logs := out.String() + errOut.String()
	if strings.Contains(logs, pass) {
		t.Fatal("password appeared in process output")
	}
	if !strings.Contains(errOut.String(), `"msg":"http listening"`) && !strings.Contains(errOut.String(), `"msg":"packeteer running"`) {
		t.Fatalf("expected json logs:\n%s", errOut.String())
	}
}
