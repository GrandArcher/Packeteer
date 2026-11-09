package httpapi

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestSynthesizeBanner runs the synthesize banner (#122) in Node. Like the
// other page tests, it is skipped without Node locally and required in CI.
func TestSynthesizeBanner(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the synthesize banner test")
		}
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "synth_banner_test.js").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("synthesize banner: %v\n%s", err, out)
	}
}
