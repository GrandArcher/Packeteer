package httpapi

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestPrefixCardMED runs the prefix card's MED override badge and line
// (#303) in Node. Like the other page tests, it is skipped without Node
// locally and required in CI.
func TestPrefixCardMED(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the prefix card test")
		}
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "prefix_card_test.js").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("prefix card: %v\n%s", err, out)
	}
}
