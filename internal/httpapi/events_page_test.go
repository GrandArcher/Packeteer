package httpapi

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestEventsPageRendering runs the Events row, the Improvements empty
// state, and the checklist doc link in Node (#347). Like the settings form
// test, it is skipped without Node locally and required in CI.
func TestEventsPageRendering(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the events page test")
		}
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "events_page_test.js").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("events page: %v\n%s", err, out)
	}
}
