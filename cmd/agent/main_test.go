package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/agentwire/pkitest"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	ca := pkitest.New(t)
	leaf := ca.Issue(t, "agent-a")
	path := filepath.Join(t.TempDir(), "agent.yaml")
	cfg := fmt.Sprintf("controller_url: https://192.0.2.10:9444\ncert_file: %s\nkey_file: %s\nca_file: %s\nsite: dc-a\n%s",
		leaf.CertFile, leaf.KeyFile, ca.CAFile, body)
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckValidatesTheConfig(t *testing.T) {
	good := writeConfig(t, "providers:\n  - {name: carrier-a, source_ip: 192.0.2.11}\n")
	var out bytes.Buffer
	if code := run([]string{"-config", good, "-check"}, &out); code != 0 || !strings.Contains(out.String(), "site dc-a, 1 providers") {
		t.Fatalf("good config: code %d, output %q", code, out.String())
	}
	bad := writeConfig(t, "providers:\n  - {name: carrier-a, source_ip: nope}\n")
	out.Reset()
	if code := run([]string{"-config", bad, "-check"}, &out); code != 1 || !strings.Contains(out.String(), "source_ip") {
		t.Fatalf("bad config: code %d, output %q", code, out.String())
	}
	out.Reset()
	if code := run([]string{"-config", filepath.Join(t.TempDir(), "missing.yaml")}, &out); code != 1 {
		t.Fatalf("missing file: code %d", code)
	}
}

func TestVersion(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"-version"}, &out); code != 0 || !strings.Contains(out.String(), "packeteer-agent") {
		t.Fatalf("code %d, output %q", code, out.String())
	}
}
