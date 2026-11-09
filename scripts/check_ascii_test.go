package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckASCIIScansTrackedSourceAndSkipsTheWebUI(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	script, err := filepath.Abs("check-ascii.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path, body string
		wantFail         bool
	}{
		{"clean go", "a.go", "package a // plain\n", false},
		{"dash in go comment", "a.go", "package a // one \u2014 two\n", true},
		{"arrow in yml", ".github/workflows/x.yml", "run: echo a \u2192 b\n", true},
		{"smart quote in sh", "scripts/x.sh", "echo \u201chi\u201d\n", true},
		{"ellipsis in md", "docs/x.md", "wait\u2026\n", true},
		{"tab is allowed", "a.go", "package a\n\tvar x = 1\n", false},
		{"web ui is exempt", "internal/httpapi/web/app.js", "const dash = '\u2013'\n", false},
		{"untracked type is skipped", "data.json", "{\"a\": \"\u00e9\"}\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			git := func(args ...string) {
				t.Helper()
				c := exec.Command("git", args...)
				c.Dir = dir
				if out, err := c.CombinedOutput(); err != nil {
					t.Fatalf("git %v: %v\n%s", args, err, out)
				}
			}
			git("init", "-q")
			p := filepath.Join(dir, tc.path)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}
			git("add", "-A")
			c := exec.Command("sh", script)
			c.Dir = dir
			out, err := c.CombinedOutput()
			if tc.wantFail {
				if err == nil || !strings.Contains(string(out), tc.path) {
					t.Fatalf("want a failure naming %s, got err=%v\n%s", tc.path, err, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("want a pass: %v\n%s", err, out)
			}
		})
	}
}
