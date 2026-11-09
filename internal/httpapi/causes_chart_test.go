package httpapi

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestCausesChart runs causes_chart_test.js, which draws the causes report
// with renderCauses from charts.js against a DOM stand-in. It is skipped
// without Node locally and required in CI.
func TestCausesChart(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the causes chart test")
		}
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "causes_chart_test.js").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("causes chart: %v\n%s", err, out)
	}
}
