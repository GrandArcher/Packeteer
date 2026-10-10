package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/GrandArcher/Packeteer/internal/upgrade"
)

// upgradeServer is a GitHub-like release server with one signed release
// whose binary is a shell script that passes the start checks.
func upgradeServer(t *testing.T) (url, pub string) {
	t.Helper()
	pub, priv, err := upgrade.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	bin := "#!/bin/sh\ncase \"$1\" in -version) echo 'packeteer 0.6.0';; esac\n"
	sum := sha256.Sum256([]byte(bin))
	sums := hex.EncodeToString(sum[:]) + "  packeteer-linux-amd64\n" + hex.EncodeToString(sum[:]) + "  packeteer-linux-arm64\n"
	sig, _ := upgrade.Sign(priv, []byte(sums))
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/example/packeteer/releases", func(w http.ResponseWriter, r *http.Request) {
		asset := func(n string) string {
			return fmt.Sprintf(`{"name":%q,"browser_download_url":"%s/dl/%s"}`, n, srv.URL, n)
		}
		fmt.Fprintf(w, `[{"tag_name":"v0.6.0","name":"Packeteer 0.6.0","body":"notes","draft":false,"prerelease":false,"published_at":"2026-10-01T00:00:00Z","assets":[%s]}]`,
			strings.Join([]string{asset("packeteer-linux-amd64"), asset("packeteer-linux-arm64"), asset("SHA256SUMS"), asset("SHA256SUMS.sig")}, ","))
	})
	mux.HandleFunc("GET /dl/{name}", func(w http.ResponseWriter, r *http.Request) {
		switch r.PathValue("name") {
		case "SHA256SUMS":
			io.WriteString(w, sums)
		case "SHA256SUMS.sig":
			io.WriteString(w, sig)
		default:
			io.WriteString(w, bin)
		}
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, pub
}

// execCall is what the stubbed exec was asked to start.
type execCall struct {
	path string
	argv []string
	env  []string
	// edge is what the edge held when the exec was called.
	edge map[string][]string
}

type upgradeInstance struct {
	http   int
	done   chan int
	exited chan struct{}
	logs   *syncBuf
	cancel context.CancelFunc
}

func (e *haEdge) nativePath() *api.Path {
	nlri, _ := anypb.New(&api.IPAddressPrefix{Prefix: "198.51.100.0", PrefixLen: 24})
	origin, _ := anypb.New(&api.OriginAttribute{Origin: 0})
	nh, _ := anypb.New(&api.NextHopAttribute{NextHop: "192.0.2.1"})
	return &api.Path{Family: v4, Nlri: nlri, Pattrs: []*anypb.Any{origin, nh}}
}

// withdrawNative stops the edge advertising the learned prefix.
func (e *haEdge) withdrawNative(t *testing.T) {
	t.Helper()
	if err := e.srv.DeletePath(context.Background(), &api.DeletePathRequest{Path: e.nativePath(), Family: v4}); err != nil {
		t.Fatal(err)
	}
}

func (e *haEdge) advertiseNative(t *testing.T) {
	t.Helper()
	if _, err := e.srv.AddPath(context.Background(), &api.AddPathRequest{Path: e.nativePath()}); err != nil {
		t.Fatal(err)
	}
}

const upgradeUser, upgradePass = "admin", "lab-password-1"

func startUpgradeInstance(t *testing.T, edge *haEdge, cfgPath string, env map[string]string, httpPort int) *upgradeInstance {
	t.Helper()
	in := &upgradeInstance{http: httpPort, done: make(chan int, 1), exited: make(chan struct{}), logs: &syncBuf{}}
	ctx, cancel := context.WithCancel(context.Background())
	in.cancel = cancel
	getenv := func(k string) string {
		switch k {
		case HTTPUserEnv:
			return upgradeUser
		case HTTPPassEnv:
			return upgradePass
		}
		return env[k]
	}
	var out syncBuf
	go func() {
		in.done <- run(ctx, []string{"-config", cfgPath}, getenv, &out, in.logs)
		close(in.exited)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-in.exited:
		case <-time.After(20 * time.Second):
		}
	})
	return in
}

func (in *upgradeInstance) post(t *testing.T, path, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d%s", in.http, path), strings.NewReader(body))
	req.SetBasicAuth(upgradeUser, upgradePass)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (in *upgradeInstance) waitHTTP(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/api/upgrade", in.http), nil)
		req.SetBasicAuth(upgradeUser, upgradePass)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("http never came up\n%s", in.logs.String())
}

// TestDaemonUpgradeWithdrawsRelearnsAndRollsBack is the lab test of #196:
// a controller in inject has a route on the simulated edge; an admin
// upgrades through the API; the edge sees the route withdrawn before the
// new binary is started; the new version, with the edge no longer
// advertising the prefix, announces nothing (it is not in the RIB view);
// when the edge advertises the prefix again the route returns. Rollback
// does the same in reverse. The config file is never touched.
func TestDaemonUpgradeWithdrawsRelearnsAndRollsBack(t *testing.T) {
	if testing.Short() {
		t.Skip("daemon upgrade test")
	}
	url, pub := upgradeServer(t)
	edge := newHAEdge(t)
	dir := t.TempDir()
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
    config: {targets: [{prefix: 198.51.100.0/24}]}
probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 80}, {provider: transit-b, rtt_ms: 10}]}
bgp:
  neighbors:
    - {address: 127.0.0.1, port: %d, local_address: 127.0.0.2}
announcer: {type: gobgp}
upgrade:
  enabled: true
  public_key: %s
  repo: example/packeteer
  api_url: %s
  dir: %s
`, httpPort, edge.port, pub, url, filepath.Join(dir, "upgrade"))
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var calls []execCall
	execFn = func(path string, argv, env []string) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, execCall{path: path, argv: argv, env: env, edge: edge.routes()})
		return nil
	}
	self := filepath.Join(dir, "packeteer-installed")
	executableFn = func() (string, error) { return self, nil }
	environFn = func() []string { return []string{"PATH=" + os.Getenv("PATH")} }
	trialFn = func(context.Context, string, string) error { return nil }
	confirmAfter = 200 * time.Millisecond
	t.Cleanup(func() {
		execFn, environFn, executableFn, trialFn, confirmAfter = syscall.Exec, os.Environ, os.Executable, nil, 30*time.Second
	})

	start := time.Now()
	step := func(what string) { t.Logf("%6.1fs %s", time.Since(start).Seconds(), what) }
	waitRoute := func(what string, in *upgradeInstance) {
		t.Helper()
		defer step(what)
		deadline := time.Now().Add(40 * time.Second)
		for !onlyFrom(edge.routes(), "127.0.0.2") {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s: edge has %v\n%s", what, edge.routes(), in.logs.String())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	waitDone := func(what string, in *upgradeInstance) {
		t.Helper()
		defer step(what)
		select {
		case code := <-in.done:
			if code != 0 {
				t.Fatalf("%s: exit %d\n%s", what, code, in.logs.String())
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("%s: did not stop\n%s", what, in.logs.String())
		}
	}

	// Version A (the installed binary) announces the improvement.
	a := startUpgradeInstance(t, edge, cfgPath, nil, httpPort)
	a.waitHTTP(t)
	waitRoute("the first version to announce", a)

	// An unconfirmed or unverifiable request changes nothing.
	if code, body := a.post(t, "/api/upgrade/apply", `{"tag":"v0.6.0"}`); code != 400 {
		t.Fatalf("unconfirmed apply: %d %s", code, body)
	}
	if !onlyFrom(edge.routes(), "127.0.0.2") || len(calls) != 0 {
		t.Fatal("an unconfirmed upgrade changed something")
	}
	if code, body := a.post(t, "/api/upgrade/check", `{}`); code != 200 || !strings.Contains(body, `"v0.6.0"`) || !strings.Contains(body, `"available":true`) {
		t.Fatalf("check: %d %s", code, body)
	}
	before, _ := os.ReadFile(cfgPath)

	// Upgrade. The route is withdrawn before the new binary is started.
	code, body := a.post(t, "/api/upgrade/apply", `{"tag":"v0.6.0","confirm":true}`)
	if code != http.StatusAccepted {
		t.Fatalf("apply: %d %s", code, body)
	}
	waitDone("upgrade shutdown", a)
	mu.Lock()
	if len(calls) != 1 {
		t.Fatalf("exec calls = %d", len(calls))
	}
	c := calls[0]
	mu.Unlock()
	staged := filepath.Join(dir, "upgrade", "versions", "0.6.0", "packeteer")
	if c.path != staged || c.argv[0] != staged || !strings.Contains(strings.Join(c.argv, " "), "-config "+cfgPath) {
		t.Fatalf("exec = %+v", c)
	}
	if !strings.Contains(strings.Join(c.env, "\n"), upgrade.LaunchedEnv+"=0.6.0") {
		t.Fatalf("env = %v", c.env)
	}
	if len(c.edge) != 0 {
		t.Fatalf("the edge still held %v when the new version was started", c.edge)
	}
	for _, want := range []string{"shutting down", "http listening"} {
		if !strings.Contains(a.logs.String(), want) {
			t.Fatalf("missing %q in logs:\n%s", want, a.logs.String())
		}
	}
	if got, _ := os.ReadFile(cfgPath); !bytes.Equal(got, before) {
		t.Fatal("the config file changed")
	}

	// The edge stops advertising the prefix while the new version comes up
	// (a process start has no RIB). It must announce nothing: the prefix is
	// not in its learned view.
	edge.withdrawNative(t)
	newEnv := map[string]string{upgrade.LaunchedEnv: "0.6.0"}
	b := startUpgradeInstance(t, edge, cfgPath, newEnv, httpPort)
	b.waitHTTP(t)
	deadline := time.Now().Add(6 * time.Second) // several probe rounds and hold times
	for time.Now().Before(deadline) {
		if r := edge.routes(); len(r) != 0 {
			t.Fatalf("the new version announced %v before it learned the prefix", r)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Learned again: the route returns, with the configured mode.
	edge.advertiseNative(t)
	waitRoute("the new version to announce after re-learning", b)

	// The staged version confirms itself once it has stayed up.
	deadline = time.Now().Add(5 * time.Second)
	var st map[string]any
	for time.Now().Before(deadline) {
		raw, _ := os.ReadFile(filepath.Join(dir, "upgrade", "state.json"))
		_ = json.Unmarshal(raw, &st)
		if st["confirmed"] == true {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if st["confirmed"] != true {
		t.Fatalf("state = %v", st)
	}

	// Rollback goes back to the installed version, the same way.
	code, body = b.post(t, "/api/upgrade/rollback", `{"confirm":true}`)
	if code != http.StatusAccepted {
		t.Fatalf("rollback: %d %s", code, body)
	}
	waitDone("rollback shutdown", b)
	mu.Lock()
	if len(calls) != 2 {
		t.Fatalf("exec calls = %d", len(calls))
	}
	c = calls[1]
	mu.Unlock()
	if c.path != self || strings.Contains(strings.Join(c.env, "\n"), upgrade.LaunchedEnv) || len(c.edge) != 0 {
		t.Fatalf("rollback exec = %+v", c)
	}
	if got, _ := os.ReadFile(cfgPath); !bytes.Equal(got, before) {
		t.Fatal("the config file changed by the rollback")
	}
}

// The launcher: an installed binary whose state names a staged version
// starts it before anything else; -check and a staged process do not.
func TestLaunchStagedAtStart(t *testing.T) {
	dir := t.TempDir()
	_, pub := upgradeServer(t)
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := fmt.Sprintf(`asn: 64512
router_id: 192.0.2.10
providers:
  - {name: a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
http: {listen: ""}
upgrade: {enabled: true, public_key: %s, dir: %s}
`, pub, filepath.Join(dir, "upgrade"))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(dir, "upgrade", "versions", "0.6.0", "packeteer")
	if err := os.MkdirAll(filepath.Dir(staged), 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte("#!/bin/sh\n")
	if err := os.WriteFile(staged, body, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	self := filepath.Join(dir, "installed")
	state := fmt.Sprintf(`{"base_version":%q,"base_path":%q,"active":{"version":"0.6.0","path":%q,"sha256":%q},"previous":{"version":%q,"path":%q},"attempts":1,"confirmed":false}`,
		version, self, staged, hex.EncodeToString(sum[:]), version, self)
	if err := os.WriteFile(filepath.Join(dir, "upgrade", "state.json"), []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	var got []execCall
	execFn = func(path string, argv, env []string) error {
		got = append(got, execCall{path: path, argv: argv, env: env})
		return nil
	}
	executableFn = func() (string, error) { return self, nil }
	environFn = func() []string { return []string{"A=b"} }
	t.Cleanup(func() { execFn, environFn, executableFn = syscall.Exec, os.Environ, os.Executable })

	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-config", cfgPath}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if len(got) != 1 || got[0].path != staged || strings.Join(got[0].argv, " ") != staged+" -config "+cfgPath {
		t.Fatalf("exec = %+v", got)
	}
	if out.Len() != 0 {
		t.Fatalf("the installed binary started anyway: %s", out.String())
	}
	// -check is the installed binary's own check.
	got = nil
	out.Reset()
	if code := run(context.Background(), []string{"-check", "-config", cfgPath}, noEnv, &out, &errOut); code != 0 || len(got) != 0 {
		t.Fatalf("-check: exit %d, exec %+v\n%s", code, got, errOut.String())
	}
	if !strings.Contains(out.String(), "upgrade: on") {
		t.Fatalf("-check does not say upgrade is on:\n%s", out.String())
	}
	// A staged process never hands over again.
	if code := run(context.Background(), []string{"-check", "-config", cfgPath}, func(k string) string {
		if k == upgrade.LaunchedEnv {
			return "0.6.0"
		}
		return ""
	}, &out, &errOut); code != 0 || len(got) != 0 {
		t.Fatalf("launched: exit %d, exec %+v", code, got)
	}
}
