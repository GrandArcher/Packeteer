package httpapi

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestProviderStatsPage runs the Providers table cells, the sparkline, and
// the Overview charts in Node (#349). Like the events page test, it is
// skipped without Node locally and required in CI.
func TestProviderStatsPage(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the provider stats page test")
		}
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "provider_stats_page_test.js").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("provider stats page: %v\n%s", err, out)
	}
}
