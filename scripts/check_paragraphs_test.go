package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckParagraphsWarnsOnLongLinesAndAllowsFeatureRows(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	script, err := filepath.Abs("check-paragraphs.sh")
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("a", 1501)
	atLimit := strings.Repeat("a", 1500)
	for _, tc := range []struct {
		name, path, body string
		wantWarn         bool
	}{
		{"long README line", "README.md", long + "\n", true},
		{"long docs line", "docs/x.md", "short\n" + long + "\n", true},
		{"line at the limit", "docs/x.md", atLimit + "\n", false},
		{"short bullets", "docs/x.md", "- one\n- two\n", false},
		{"long FEATURES table row", "docs/FEATURES.md", "| " + long + " |\n", false},
		{"long FEATURES paragraph", "docs/FEATURES.md", long + "\n", true},
		{"long CHANGELOG summary", "CHANGELOG.md", long + "\n", false},
		{"long lab README line", "lab/README.md", long + "\n", true},
		{"long nested lab README line", "lab/chaos/README.md", long + "\n", true},
		{"lab line at the limit", "lab/README.md", atLimit + "\n", false},
		{"long line in a lab script", "lab/e2e.sh", long + "\n", false},
		{"long line outside docs and lab", "internal/x.md", long + "\n", false},
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
			if err != nil {
				t.Fatalf("a warning-level lint must exit 0: %v\n%s", err, out)
			}
			want := "::warning file=" + tc.path + ",line="
			if got := strings.Contains(string(out), want); got != tc.wantWarn {
				t.Fatalf("warning for %s = %v, want %v\n%s", tc.path, got, tc.wantWarn, out)
			}
		})
	}
}
