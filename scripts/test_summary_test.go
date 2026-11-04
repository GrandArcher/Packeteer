package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// moduleWith writes a throwaway module with one package per entry.
func moduleWith(t *testing.T, pkgs map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{"go.mod": "module example.test/ts\n\ngo 1.22\n"}
	for name, body := range pkgs {
		files[filepath.Join(name, name+"_test.go")] = "package " + name + "\n\nimport \"testing\"\n\n" + body
	}
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func runSummary(t *testing.T, dir string) (string, error) {
	t.Helper()
	script, err := filepath.Abs("test-summary.sh")
	if err != nil {
		t.Fatal(err)
	}
	c := exec.Command("sh", script)
	c.Dir = dir
	out, err := c.CombinedOutput()
	return string(out), err
}

func needTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"go", "awk"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not installed")
		}
	}
}

func TestTestSummaryListsSkippedTests(t *testing.T) {
	needTools(t)
	dir := moduleWith(t, map[string]string{
		"a": "func TestPlain(t *testing.T) {}\n\nfunc TestRoot(t *testing.T) { t.Skip(\"needs root\") }\n",
		"b": "func TestPage(t *testing.T) { t.Skip(\"node is not on PATH\") }\n",
	})
	out, err := runSummary(t, dir)
	if err != nil {
		t.Fatalf("a passing run failed: %v\n%s", err, out)
	}
	for _, want := range []string{
		"ok  \texample.test/ts/a",
		"skipped tests: 2",
		"example.test/ts/a: TestRoot: needs root",
		"example.test/ts/b: TestPage: node is not on PATH",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "=== RUN") {
		t.Errorf("a passing package printed its test log:\n%s", out)
	}
}

func TestTestSummaryKeepsFailuresAndTheExitStatus(t *testing.T) {
	needTools(t)
	dir := moduleWith(t, map[string]string{
		"a": "func TestBroken(t *testing.T) { t.Fatal(\"wrong answer 42\") }\n",
		"b": "func TestPlain(t *testing.T) {}\n",
	})
	out, err := runSummary(t, dir)
	if err == nil {
		t.Fatalf("a failing run exited 0:\n%s", out)
	}
	for _, want := range []string{"wrong answer 42", "FAIL\texample.test/ts/a", "ok  \texample.test/ts/b", "skipped tests: none"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}
