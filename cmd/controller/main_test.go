package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunExampleConfig(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"-config", filepath.Join("..", "..", "config.example.yaml")}, &out, &errOut)
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
	if code := run([]string{"-config", path}, &out, &errOut); code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "mode is required") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestRunMissingFile(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"-config", filepath.Join(t.TempDir(), "missing.yaml")}, &out, &errOut); code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
}

func TestRunBadFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"-nope"}, &out, &errOut); code != 2 {
		t.Fatalf("exit code %d, want 2", code)
	}
}
