package httpapi

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestFederationPushPage runs the dashboard's settings push control in
// Node (#137). Like the settings form test, it is skipped without Node
// locally and required in CI.
func TestFederationPushPage(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the federation push page test")
		}
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "federation_push_page_test.js").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("federation push page: %v\n%s", err, out)
	}
}
