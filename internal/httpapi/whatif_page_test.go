package httpapi

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestWhatIfPage runs whatif_page_test.js, which exercises the replay
// section of settings.js against a DOM stand-in. It is skipped without Node
// locally and required in CI.
func TestWhatIfPage(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the what-if page test")
		}
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "whatif_page_test.js").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("what-if page: %v\n%s", err, out)
	}
}
