package httpapi

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestWhyPage runs the prefix page "Why?" panel in Node (#201). Like the
// events page test, it is skipped without Node locally and required in CI.
func TestWhyPage(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the why page test")
		}
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "why_page_test.js").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("why page: %v\n%s", err, out)
	}
}
