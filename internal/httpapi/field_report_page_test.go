package httpapi

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestFieldReportPage runs field_report_page_test.js, which exercises the field
// report section of settings.js against a DOM stand-in. It is skipped without Node
// locally and required in CI.
func TestFieldReportPage(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the field report page test")
		}
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "field_report_page_test.js").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("field report page: %v\n%s", err, out)
	}
}
