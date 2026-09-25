package exec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// The test binary doubles as the plugin process when HELPER_MODE is set.
func TestMain(m *testing.M) {
	if mode := os.Getenv("HELPER_MODE"); mode != "" {
		os.Exit(helper(mode))
	}
	os.Exit(m.Run())
}

func helper(mode string) int {
	data, _ := io.ReadAll(os.Stdin)
	var req request
	if err := json.Unmarshal(data, &req); err != nil {
		fmt.Println(`{"error":"bad request"}`)
		return 0
	}
	if req.Protocol != Protocol {
		fmt.Println(`{"error":"bad protocol"}`)
		return 0
	}
	if req.Method == "init" && mode != "init-fail" {
		fmt.Println(`{"result":{}}`)
		return 0
	}
	switch mode {
	case "init-fail":
		fmt.Println(`{"error":"missing api key"}`)
	case "prober":
		var p probeParams
		b, _ := json.Marshal(req.Params)
		_ = json.Unmarshal(b, &p)
		if p.Source != "192.0.2.11" || p.Target != "198.51.100.1" || p.Count != 3 {
			fmt.Printf(`{"error":"unexpected params %s"}`+"\n", b)
			return 0
		}
		fmt.Println(`{"result":{"sent":3,"rtts_ms":[10.5,12,11]}}`)
	case "prober-inconsistent":
		fmt.Println(`{"result":{"sent":1,"rtts_ms":[1,2]}}`)
	case "source":
		fmt.Println(`{"result":{"targets":[{"prefix":"198.51.100.0/24","host":"198.51.100.1"},{"prefix":"2001:db8::/32","weight":2}]}}`)
	case "source-badhost":
		fmt.Println(`{"result":{"targets":[{"prefix":"198.51.100.0/24","host":"203.0.113.1"}]}}`)
	case "notifier":
		ev, _ := json.Marshal(req.Params)
		cfg, _ := json.Marshal(req.Config)
		fmt.Fprintf(os.Stderr, "event %s\n", ev)
		if !strings.Contains(string(ev), `"kind":"test.event"`) || !strings.Contains(string(cfg), `"channel":"ops"`) {
			fmt.Printf(`{"error":"bad event %s cfg %s"}`+"\n", ev, cfg)
			return 0
		}
		if os.Getenv("TOKEN") != "s3cret" {
			fmt.Println(`{"error":"env not expanded"}`)
			return 0
		}
		fmt.Println(`{"result":{}}`)
	case "exit1":
		fmt.Fprintln(os.Stderr, "boom")
		return 1
	case "garbage":
		fmt.Println("not json")
	case "silent":
	case "sleep":
		time.Sleep(5 * time.Second)
	}
	return 0
}

func helperConfig(t *testing.T, mode, extra string) plugin.Config {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	y := fmt.Sprintf("command: %s\nenv:\n  HELPER_MODE: %s\n  TOKEN: ${SECRET}\n%s", exe, mode, extra)
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func env() plugin.Env {
	return plugin.Env{Name: "t", Getenv: func(k string) string {
		if k == "SECRET" {
			return "s3cret"
		}
		return ""
	}}
}

func TestProber(t *testing.T) {
	p, err := plugin.Probers.New(TypeName, helperConfig(t, "prober", ""), env())
	if err != nil {
		t.Fatal(err)
	}
	res, err := p.Probe(context.Background(), plugin.ProbeRequest{Provider: "a",
		Source: netip.MustParseAddr("192.0.2.11"), Target: netip.MustParseAddr("198.51.100.1"),
		Count: 3, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res.Sent != 3 || len(res.RTTs) != 3 || res.RTTs[0] != 10500*time.Microsecond {
		t.Fatalf("res = %+v", res)
	}
}

func TestSource(t *testing.T) {
	s, err := plugin.Sources.New(TypeName, helperConfig(t, "source", ""), env())
	if err != nil {
		t.Fatal(err)
	}
	tg, err := s.Targets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tg) != 2 || tg[0].Host != netip.MustParseAddr("198.51.100.1") || tg[1].Weight != 2 {
		t.Fatalf("targets = %+v", tg)
	}
}

func TestNotifier(t *testing.T) {
	n, err := plugin.Notifiers.New(TypeName, helperConfig(t, "notifier", "config:\n  channel: ops\n"), env())
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(context.Background(), plugin.Event{Kind: "test.event", Severity: plugin.SeverityInfo}); err != nil {
		t.Fatal(err)
	}
}

func TestCallErrors(t *testing.T) {
	tests := []struct {
		mode    string
		extra   string
		call    func(ctxt context.Context, c plugin.Config) error
		wantErr string
	}{
		{"init-fail", "", newSource, "init: init: plugin error: missing api key"},
		{"exit1", "", sourceTargets, "exit status 1: boom"},
		{"garbage", "", sourceTargets, "invalid JSON response"},
		{"silent", "", sourceTargets, "wrote no response"},
		{"sleep", "timeout: 200ms\n", sourceTargets, "timed out after 200ms"},
		{"source-badhost", "", sourceTargets, "is not an address inside"},
		{"prober-inconsistent", "", func(ctx context.Context, c plugin.Config) error {
			p, err := plugin.Probers.New(TypeName, c, env())
			if err != nil {
				return err
			}
			_, err = p.Probe(ctx, plugin.ProbeRequest{})
			return err
		}, "inconsistent result"},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			err := tt.call(context.Background(), helperConfig(t, tt.mode, tt.extra))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func newSource(_ context.Context, c plugin.Config) error {
	_, err := plugin.Sources.New(TypeName, c, env())
	return err
}

// sourceTargets builds a source (init answered by every mode except
// init-fail/sleep/exit1/garbage/silent, which fail at init) and calls Targets.
func sourceTargets(ctx context.Context, c plugin.Config) error {
	s, err := plugin.Sources.New(TypeName, c, env())
	if err != nil {
		return err
	}
	_, err = s.Targets(ctx)
	return err
}

func TestConfigErrors(t *testing.T) {
	dir := t.TempDir()
	notExec := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(notExec, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	tests := []struct{ name, yaml, wantErr string }{
		{"missing command", "timeout: 1s", "command is required"},
		{"escape", "command: ../bin/sh", "escapes the plugin dir"},
		{"not found", "command: nope.sh", "no such file"},
		{"not executable", "command: plain.txt", "not an executable"},
		{"negative timeout", "command: /bin/sh\ntimeout: -1s", "must not be negative"},
		{"unknown field", "command: /bin/sh\nbogus: 1", "field bogus not found"},
		{"bad env name", "command: /bin/sh\nenv:\n  \"A=B\": x", "invalid variable name"},
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

func TestResolveCommand(t *testing.T) {
	tests := []struct{ dir, cmd, want, wantErr string }{
		{"/etc/packeteer/plugins", "a.sh", "/etc/packeteer/plugins/a.sh", ""},
		{"/etc/packeteer/plugins", "sub/../a.sh", "/etc/packeteer/plugins/a.sh", ""},
		{"/etc/packeteer/plugins", "/opt/x", "/opt/x", ""},
		{"/etc/packeteer/plugins", "../x", "", "escapes"},
		{"", "a.sh", "", "no plugin dir"},
		{"/p", "", "", "required"},
	}
	for _, tt := range tests {
		got, err := ResolveCommand(tt.dir, tt.cmd)
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("%q: err = %v", tt.cmd, err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("%q: got %q, %v", tt.cmd, got, err)
		}
	}
}

// TestExampleScript runs the documented example plugin through the real
// protocol, the same way the stock container image would.
func TestExampleScript(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "examples", "plugins"))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := plugin.ConfigFromYAML("command: static-targets.sh")
	e := env()
	e.PluginDir = dir
	s, err := plugin.Sources.New(TypeName, c, e)
	if err != nil {
		t.Fatal(err)
	}
	tg, err := s.Targets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tg) != 2 || tg[0].Prefix.String() != "198.51.100.0/24" {
		t.Fatalf("targets = %+v", tg)
	}
}
