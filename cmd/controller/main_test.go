package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func noEnv(string) string { return "" }

func TestRunExampleConfig(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"-check", "-config", filepath.Join("..", "..", "config.example.yaml")}, noEnv, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, errOut.String())
	}
	for _, want := range []string{"mode: observe", "transit-a", "transit-b", "no BGP", "tcp"} {
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
	env := func(string) string { return "/nonexistent/from-env.yaml" }
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

func TestDaemonWithBGPNeighborStartsAndStops(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // no router listening: session stays down, daemon must still run and stop cleanly
	cfg := fmt.Sprintf(`mode: observe
asn: 64512
router_id: 192.0.2.10
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
}
