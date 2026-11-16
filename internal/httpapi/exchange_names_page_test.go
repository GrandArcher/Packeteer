package httpapi

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestExchangeNamesPage runs the potential-peers tables and the settings
// discovered-member list in Node (#629). It is skipped without Node locally
// and required in CI.
func TestExchangeNamesPage(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the exchange names page test")
		}
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "exchange_names_page_test.js").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("exchange names page: %v\n%s", err, out)
	}
}
