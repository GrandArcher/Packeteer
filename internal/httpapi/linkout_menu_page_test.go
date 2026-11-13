package httpapi

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestLinkoutMenuPage runs linkout_menu_page_test.js, which exercises the
// Open in menu and the table stacking rule against a DOM stand-in. It is
// skipped without Node
// locally and required in CI.
func TestLinkoutMenuPage(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the linkout menu page test")
		}
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "linkout_menu_page_test.js").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("linkout menu page: %v\n%s", err, out)
	}
}
