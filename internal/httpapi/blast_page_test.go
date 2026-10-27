package httpapi

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestBlastPage runs blast_page_test.js, which exercises the blast-radius
// section of settings.js against a DOM stand-in. It is skipped without Node
// locally and required in CI.
func TestBlastPage(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the blast page test")
		}
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "blast_page_test.js").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("blast page: %v\n%s", err, out)
	}
}
