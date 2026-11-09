package httpapi

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestAtlasPage runs the prefix page RIPE Atlas panel in Node (#213). Like
// the Why? panel test, it is skipped without Node locally and required in CI.
func TestAtlasPage(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the atlas page test")
		}
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "atlas_page_test.js").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("atlas page: %v\n%s", err, out)
	}
}
