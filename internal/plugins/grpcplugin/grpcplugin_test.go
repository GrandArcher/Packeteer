package grpcplugin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	goplugin "github.com/hashicorp/go-plugin"

	"github.com/GrandArcher/Packeteer/internal/plugins/oop"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
	"github.com/GrandArcher/Packeteer/pkg/plugin/rpc"
)

// The test binary doubles as the plugin process when HELPER_MODE is set.
func TestMain(m *testing.M) {
	if mode := os.Getenv("HELPER_MODE"); mode != "" {
		helper(mode)
		return
	}
	os.Exit(m.Run())
}

// helperPlugin implements every kind; the mode picks the misbehaviour.
type helperPlugin struct{ mode string }

func (h *helperPlugin) Init(_ context.Context, req rpc.InitRequest) error {
	var cfg struct {
		Channel string `json:"channel"`
	}
	if err := req.DecodeConfig(&cfg); err != nil {
		return err
	}
	if p := os.Getenv("PIDFILE"); p != "" {
		_ = os.WriteFile(p, []byte(strconv.Itoa(os.Getpid())), 0o600)
	}
	switch h.mode {
	case "init-fail":
		return errors.New("missing api key")
	case "no-host-env":
		if os.Getenv("PACKETEER_TEST_LEAK") != "" {
			return errors.New("host environment leaked into the plugin")
		}
	case "notifier":
		if cfg.Channel != "ops" || req.Name != "t" || req.Kind != plugin.KindNotifier || os.Getenv("TOKEN") != "s3cret" {
			return fmt.Errorf("bad init: %+v %+v token=%q", req, cfg, os.Getenv("TOKEN"))
		}
	case "die-after-init":
		// Dies once, on its own, without any call in flight.
		if marker := os.Getenv("MARKER"); marker != "" {
			if _, err := os.Stat(marker); err != nil {
				_ = os.WriteFile(marker, nil, 0o600)
				go func() {
					time.Sleep(100 * time.Millisecond)
					os.Exit(3)
				}()
			}
		}
	}
	return nil
}

func (h *helperPlugin) Probe(ctx context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	switch h.mode {
	case "hang":
		<-ctx.Done()
		return plugin.ProbeResult{}, ctx.Err()
	case "crash-once":
		if marker := os.Getenv("MARKER"); marker != "" {
			if _, err := os.Stat(marker); err != nil {
				_ = os.WriteFile(marker, nil, 0o600)
				os.Exit(3)
			}
		}
	case "always-crash":
		os.Exit(3)
	}
	if req.Source.String() != "192.0.2.11" || req.Target.String() != "198.51.100.1" || req.Count != 3 || req.DSCP != 46 {
		return plugin.ProbeResult{}, fmt.Errorf("unexpected request %+v", req)
	}
	// Sent carries the pid so a test can tell one process from the next.
	return plugin.ProbeResult{Sent: os.Getpid(), RTTs: []time.Duration{10500 * time.Microsecond, 12 * time.Millisecond}}, nil
}

func (h *helperPlugin) Targets(context.Context) ([]plugin.Target, error) {
	return []plugin.Target{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Host: netip.MustParseAddr("198.51.100.1")},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Weight: 2},
	}, nil
}

func (h *helperPlugin) Notify(_ context.Context, e plugin.Event) error {
	if e.Kind != plugin.EventBGPSessionDown || e.Fields["k"] != "v" {
		return fmt.Errorf("bad event %+v", e)
	}
	return nil
}

func helper(mode string) {
	if mode == "version-2" {
		// A plugin built against a newer protocol.
		hs := rpc.Handshake
		hs.ProtocolVersion = rpc.ProtocolVersion + 1
		goplugin.Serve(&goplugin.ServeConfig{HandshakeConfig: hs, Plugins: rpc.PluginSet(&helperPlugin{}), GRPCServer: goplugin.DefaultGRPCServer})
		return
	}
	rpc.Serve(&helperPlugin{mode: mode})
}

// helperConfig is a config for the test binary as the plugin. vars are
// extra environment entries for it, as "NAME=value".
func helperConfig(t *testing.T, mode, extra string, vars ...string) plugin.Config {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	y := fmt.Sprintf("command: %s\nenv:\n  HELPER_MODE: %s\n  TOKEN: ${SECRET}\n", exe, mode)
	for _, v := range vars {
		k, val, _ := strings.Cut(v, "=")
		y += "  " + k + ": " + val + "\n"
	}
	y += extra
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func env() plugin.Env {
	return plugin.Env{Name: "t", Logger: slog.New(slog.DiscardHandler), Getenv: func(k string) string {
		if k == "SECRET" {
			return "s3cret"
		}
		return ""
	}}
}

// fast supervision settings for tests that wait for a restart.
const fast = "timeout: 5s\nhealth_interval: 50ms\nrestart_backoff: 10ms\n"

func probeReq() plugin.ProbeRequest {
	return plugin.ProbeRequest{Provider: "transit-a", Source: netip.MustParseAddr("192.0.2.11"), Target: netip.MustParseAddr("198.51.100.1"),
		Count: 3, Timeout: time.Second, DSCP: 46}
}

func newProber(t *testing.T, mode, extra string, vars ...string) *Prober {
	t.Helper()
	p, err := plugin.Probers.New(TypeName, helperConfig(t, mode, extra, vars...), env())
	if err != nil {
		t.Fatal(err)
	}
	return p.(*Prober)
}

func start(t *testing.T, p plugin.Lifecycle) {
	t.Helper()
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := p.Stop(ctx); err != nil {
			t.Errorf("stop: %v", err)
		}
	})
}

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

func readPID(t *testing.T, file string) int {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(b))
	if err != nil {
		t.Fatal(err)
	}
	return pid
}

// until polls cond for up to five seconds.
func until(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestProber(t *testing.T) {
	p := newProber(t, "prober", "timeout: 5s\n")
	start(t, p)
	res, err := p.Probe(context.Background(), probeReq())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.RTTs) != 2 || res.RTTs[0] != 10500*time.Microsecond || res.RTTs[1] != 12*time.Millisecond {
		t.Fatalf("result = %+v", res)
	}
	// One process serves every call.
	again, err := p.Probe(context.Background(), probeReq())
	if err != nil || again.Sent != res.Sent {
		t.Fatalf("second call = %+v, %v; want the same process as %d", again, err, res.Sent)
	}
}

func TestSource(t *testing.T) {
	c := helperConfig(t, "source", "timeout: 5s\n")
	s, err := plugin.Sources.New(TypeName, c, env())
	if err != nil {
		t.Fatal(err)
	}
	start(t, s.(plugin.Lifecycle))
	tg, err := s.Targets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tg) != 2 || tg[0].Prefix.String() != "198.51.100.0/24" || tg[0].Host.String() != "198.51.100.1" ||
		tg[1].Prefix.String() != "2001:db8::/32" || tg[1].Weight != 2 || tg[1].Host.IsValid() {
		t.Fatalf("targets = %+v", tg)
	}
}

func TestNotifier(t *testing.T) {
	n, err := plugin.Notifiers.New(TypeName, helperConfig(t, "notifier", "timeout: 5s\nconfig:\n  channel: ops\nevents: [\"bgp.*\"]\n"), env())
	if err != nil {
		t.Fatal(err)
	}
	start(t, n)
	if n.(plugin.Gated).EventGate() == nil {
		t.Fatal("grpc notifier must expose its gate")
	}
	ev := plugin.Event{Time: time.Now(), Kind: plugin.EventBGPSessionDown, Severity: plugin.SeverityWarning, Message: "m", Fields: map[string]string{"k": "v"}}
	if err := n.Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	// The plugin rejects any event that is not bgp.session_down, so this
	// one would fail if the filter let it through.
	if err := n.Notify(context.Background(), plugin.NewEvent(plugin.EventControllerStopping, time.Now(), "", nil)); err != nil {
		t.Fatalf("filtered event reached the process: %v", err)
	}
	// A plugin error comes back with its message.
	bad := ev
	bad.Fields = nil
	if err := n.Notify(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "plugin error: bad event") {
		t.Fatalf("plugin error = %v", err)
	}
}

func TestPluginInitErrorRefusesBuild(t *testing.T) {
	_, err := plugin.Probers.New(TypeName, helperConfig(t, "init-fail", "timeout: 5s\n"), env())
	if err == nil || !strings.Contains(err.Error(), "missing api key") {
		t.Fatalf("err = %v", err)
	}
	// The plugin also rejects a config field it does not know.
	_, err = plugin.Notifiers.New(TypeName, helperConfig(t, "notifier", "timeout: 5s\nconfig:\n  channel: ops\n  bogus: 1\n"), env())
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("err = %v", err)
	}
}

func TestProtocolVersionMismatch(t *testing.T) {
	_, err := plugin.Probers.New(TypeName, helperConfig(t, "version-2", "timeout: 5s\n"), env())
	if err == nil || !strings.Contains(err.Error(), "incompatible API version") {
		t.Fatalf("err = %v, want a protocol version error", err)
	}
}

func TestCallTimeout(t *testing.T) {
	p := newProber(t, "hang", "timeout: 300ms\nhealth_interval: 1h\n")
	start(t, p)
	began := time.Now()
	_, err := p.Probe(context.Background(), probeReq())
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if d := time.Since(began); d > 3*time.Second {
		t.Fatalf("the call took %s", d)
	}
}

// A process that dies in the middle of a call fails that call, then comes
// back as a new process.
func TestCrashRestart(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "crashed")
	p := newProber(t, "crash-once", fast, "MARKER="+marker)
	start(t, p)
	if _, err := p.Probe(context.Background(), probeReq()); err == nil {
		t.Fatal("the call that killed the plugin succeeded")
	}
	var res plugin.ProbeResult
	until(t, "the restarted plugin to answer", func() bool {
		var err error
		res, err = p.Probe(context.Background(), probeReq())
		return err == nil
	})
	if res.Sent <= 0 || !alive(res.Sent) {
		t.Fatalf("restarted plugin pid = %d", res.Sent)
	}
}

// A process that dies with no call in flight is found by the health loop:
// nothing calls the plugin until a new process has taken over.
func TestHealthCheckRestart(t *testing.T) {
	dir := t.TempDir()
	marker, pidfile := filepath.Join(dir, "died"), filepath.Join(dir, "pid")
	p := newProber(t, "die-after-init", fast, "MARKER="+marker, "PIDFILE="+pidfile)
	// The factory run consumed the one death; reset so Start's process dies.
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	start(t, p)
	first := readPID(t, pidfile)
	until(t, "a new process after the first one died", func() bool {
		b, err := os.ReadFile(pidfile) // may be mid-write
		pid, aerr := strconv.Atoi(string(b))
		return err == nil && aerr == nil && pid != first
	})
	if alive(first) {
		t.Fatalf("the dead plugin process %d was not reaped", first)
	}
	until(t, "the new process to answer", func() bool {
		_, err := p.Probe(context.Background(), probeReq())
		return err == nil
	})
}

func TestRetryDelayDoublesToACap(t *testing.T) {
	s := newSupervisorFrom(plugin.KindProber, "t", oop.Spec{}, time.Second, 10*time.Millisecond, slog.New(slog.DiscardHandler))
	var got []time.Duration
	for range 9 {
		s.mu.Lock()
		got = append(got, s.scheduleRetry())
		s.mu.Unlock()
	}
	ms := time.Millisecond
	want := []time.Duration{10 * ms, 20 * ms, 40 * ms, 80 * ms, 160 * ms, 320 * ms, 600 * ms, 600 * ms, 600 * ms}
	if !slices.Equal(got, want) {
		t.Fatalf("delays = %v, want %v", got, want)
	}
}

// A plugin that dies right after every start is restarted ever more slowly;
// one that ran for a while is restarted at the base delay.
func TestCrashLoopBacksOff(t *testing.T) {
	p := newProber(t, "always-crash", "timeout: 5s\nhealth_interval: 20ms\nrestart_backoff: 20ms\n")
	start(t, p)
	for i := range 3 {
		until(t, fmt.Sprintf("plugin up before crash %d", i+1), func() bool {
			_, err := p.Probe(context.Background(), probeReq())
			return err != nil && !strings.Contains(err.Error(), "not running") // the call that killed it
		})
	}
	p.s.mu.Lock()
	grown := p.s.backoff
	p.s.mu.Unlock()
	if grown < 80*time.Millisecond {
		t.Fatalf("delay after three quick crashes = %s, want it to have doubled", grown)
	}
	until(t, "the plugin to be up again", func() bool {
		p.s.mu.Lock()
		defer p.s.mu.Unlock()
		if p.s.cur == nil {
			return false
		}
		p.s.upSince = time.Now().Add(-time.Hour)
		return true
	})
	if _, err := p.Probe(context.Background(), probeReq()); err == nil {
		t.Fatal("the call that killed the plugin succeeded")
	}
	p.s.mu.Lock()
	defer p.s.mu.Unlock()
	if p.s.backoff != 2*p.s.backoff0 { // reset to the base delay, which was used and doubled
		t.Fatalf("delay after a long run = %s, want a reset to %s", p.s.backoff, p.s.backoff0)
	}
}

func TestStopEndsTheProcess(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "pid")
	p := newProber(t, "prober", "timeout: 5s\n", "PIDFILE="+pidfile)
	// Building leaves nothing running.
	if pid := readPID(t, pidfile); alive(pid) {
		t.Fatalf("the validation process %d is still running after the build", pid)
	}
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	pid := readPID(t, pidfile)
	if !alive(pid) {
		t.Fatalf("plugin %d not running after Start", pid)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if alive(pid) {
		t.Fatalf("plugin %d still running after Stop", pid)
	}
	if _, err := p.Probe(context.Background(), probeReq()); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Fatalf("probe after Stop = %v", err)
	}
	if err := p.Stop(ctx); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

// The plugin gets the mapped variables and PATH, not Packeteer's environment.
func TestEnvironmentIsExplicit(t *testing.T) {
	t.Setenv("PACKETEER_TEST_LEAK", "secret")
	if _, err := plugin.Probers.New(TypeName, helperConfig(t, "no-host-env", "timeout: 5s\n"), env()); err != nil {
		t.Fatal(err)
	}
}

func TestConfigErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "plain.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	tests := []struct{ name, yaml, wantErr string }{
		{"missing command", "timeout: 1s", "command is required"},
		{"escape", "command: ../bin/sh", "escapes the plugin dir"},
		{"not found", "command: nope", "no such file"},
		{"not executable", "command: plain.txt", "not an executable"},
		{"negative timeout", "command: /bin/sh\ntimeout: -1s", "must not be negative"},
		{"negative health interval", "command: /bin/sh\nhealth_interval: -1s", "must not be negative"},
		{"negative backoff", "command: /bin/sh\nrestart_backoff: -1s", "must not be negative"},
		{"unknown field", "command: /bin/sh\nbogus: 1", "field bogus not found"},
		{"bad env name", "command: /bin/sh\nenv:\n  \"A=B\": x", "invalid variable name"},
		{"filter on a source", "command: /bin/sh\nmin_severity: warning", "only for notifiers"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := plugin.ConfigFromYAML(tt.yaml)
			if err != nil {
				t.Fatal(err)
			}
			e := env()
			e.PluginDir = dir
			_, err = plugin.Sources.New(TypeName, c, e)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// A config check (the config editor, #34) validates the config without
// starting the program.
func TestCheckOnlyNeverRuns(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "pid")
	e := env()
	e.CheckOnly = true
	// init-fail would refuse the build if the plugin ran.
	p, err := plugin.Probers.New(TypeName, helperConfig(t, "init-fail", "", "PIDFILE="+pidfile), e)
	if err != nil {
		t.Fatalf("check-only build ran the plugin: %v", err)
	}
	if _, err := p.Probe(context.Background(), probeReq()); err == nil || !strings.Contains(err.Error(), "config check") {
		t.Fatalf("check-only probe = %v, want refusal", err)
	}
	if err := p.Start(context.Background()); err == nil {
		t.Fatal("check-only plugin started")
	}
	if _, err := os.Stat(pidfile); err == nil {
		t.Fatal("a check-only build started the program")
	}
	c, _ := plugin.ConfigFromYAML("command: ../bin/sh")
	if _, err := plugin.Probers.New(TypeName, c, e); err == nil {
		t.Fatal("check-only build accepted a command outside the plugin dir")
	}
}

// TestExamplePlugin builds the documented example and runs it as all three
// kinds through the real protocol, as a derived image would.
func TestExamplePlugin(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain")
	}
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "grpc-example")
	build := exec.Command(goBin, "build", "-o", bin, "./examples/plugins/grpc-example")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	cfg := func(extra string) plugin.Config {
		c, err := plugin.ConfigFromYAML("command: " + bin + "\ntimeout: 10s\nconfig:\n" + extra)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	src, err := plugin.Sources.New(TypeName, cfg("  targets:\n    - {prefix: 198.51.100.0/24, host: 198.51.100.1}\n    - {prefix: 203.0.113.0/24, weight: 2}\n"), env())
	if err != nil {
		t.Fatal(err)
	}
	start(t, src)
	tg, err := src.Targets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tg) != 2 || tg[0].Host.String() != "198.51.100.1" || tg[1].Prefix.String() != "203.0.113.0/24" || tg[1].Weight != 2 {
		t.Fatalf("targets = %+v", tg)
	}

	pr, err := plugin.Probers.New(TypeName, cfg("  rtt_ms: 7.5\n"), env())
	if err != nil {
		t.Fatal(err)
	}
	start(t, pr)
	res, err := pr.Probe(context.Background(), probeReq())
	if err != nil || res.Sent != 3 || len(res.RTTs) != 3 || res.RTTs[0] != 7500*time.Microsecond {
		t.Fatalf("probe = %+v, %v", res, err)
	}

	nt, err := plugin.Notifiers.New(TypeName, cfg("  rtt_ms: 1\n"), env())
	if err != nil {
		t.Fatal(err)
	}
	start(t, nt)
	if err := nt.Notify(context.Background(), plugin.NewEvent(plugin.EventBGPSessionDown, time.Now(), "neighbor 192.0.2.1 down", nil)); err != nil {
		t.Fatal(err)
	}

	// A config the plugin does not accept refuses the build.
	if _, err := plugin.Sources.New(TypeName, cfg("  bogus: 1\n"), env()); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("bad config: %v", err)
	}
	if _, err := plugin.Sources.New(TypeName, cfg("  rtt_ms: -1\n"), env()); err == nil || !strings.Contains(err.Error(), "rtt_ms must not be negative") {
		t.Fatalf("negative rtt: %v", err)
	}
}

// A reload that is refused stops sources and starts them again.
func TestStartAfterStop(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "pid")
	p := newProber(t, "prober", "timeout: 5s\n", "PIDFILE="+pidfile)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := p.Start(ctx); err != nil {
		t.Fatal(err)
	}
	first := readPID(t, pidfile)
	if err := p.Start(ctx); err == nil {
		t.Fatal("second Start while running succeeded")
	}
	if err := p.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(ctx); err != nil {
		t.Fatalf("restart after Stop: %v", err)
	}
	defer p.Stop(ctx)
	second := readPID(t, pidfile)
	if second == first || !alive(second) {
		t.Fatalf("pids first %d second %d (alive %v)", first, second, alive(second))
	}
	if _, err := p.Probe(ctx, probeReq()); err != nil {
		t.Fatalf("probe after restart: %v", err)
	}
}
