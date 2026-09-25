package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func noEnv(string) string { return "" }

func TestRunExampleConfig(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"-config", filepath.Join("..", "..", "config.example.yaml")}, noEnv, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, errOut.String())
	}
	for _, want := range []string{"mode: observe", "transit-a", "transit-b", "no BGP"} {
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
	if code := run([]string{"-config", path}, noEnv, &out, &errOut); code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "mode is required") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestRunMissingFile(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"-config", filepath.Join(t.TempDir(), "missing.yaml")}, noEnv, &out, &errOut); code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
}

func TestRunBadFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"-nope"}, noEnv, &out, &errOut); code != 2 {
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
	if code := run(nil, env, &out, &errOut); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "config "+example+" loaded") {
		t.Errorf("stdout = %q", out.String())
	}
}

func TestRunFlagOverridesEnv(t *testing.T) {
	env := func(string) string { return "/nonexistent/from-env.yaml" }
	var out, errOut bytes.Buffer
	code := run([]string{"-config", filepath.Join("..", "..", "config.example.yaml")}, env, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, errOut.String())
	}
}

func TestRunDefaultPath(t *testing.T) {
	if _, err := os.Stat(DefaultConfigPath); err == nil {
		t.Skip("default config exists on this machine")
	}
	var out, errOut bytes.Buffer
	if code := run(nil, noEnv, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), DefaultConfigPath) {
		t.Errorf("code %d, stderr should mention %s: %q", code, DefaultConfigPath, errOut.String())
	}
}

func TestRunVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"-version"}, noEnv, &out, &errOut); code != 0 || !strings.Contains(out.String(), "packeteer dev") {
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
	if code := run([]string{"-config", path}, noEnv, &out, &errOut); code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), `unknown notifier type "carrier-pigeon"`) {
		t.Errorf("stderr = %q", errOut.String())
	}
}
