package httpapi

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TestTelemetryCapacityAndUtilization checks the interface capacity fields
// of /api/telemetry (#307): utilization needs a capacity and a sample, the
// threshold comes from the provider, and overloaded means past it.
func TestTelemetryCapacityAndUtilization(t *testing.T) {
	at := time.Date(2030, 1, 20, 12, 0, 0, 0, time.UTC)
	providers := []config.Provider{
		{Name: "transit-a", InterfaceCapacityThresholdPct: 85},
		{Name: "transit-b", InterfaceCapacityThresholdPct: 85},
		{Name: "transit-c"},
	}
	rows := assembleTelemetry([]plugin.Usage{
		{Provider: "transit-a", CapacityMbps: 1000, OutMbps: 900, Updated: at},
		{Provider: "transit-b", CapacityMbps: 1000, OutMbps: 850, Updated: at},
		{Provider: "transit-c", CapacityMbps: 2000, OutMbps: 1500, Updated: at},
		{Provider: "transit-d", OutMbps: 10, Updated: at},
		{Provider: "transit-e", CapacityMbps: 1000, OutMbps: 10},
	}, providers)
	byName := map[string]Telemetry{}
	for _, r := range rows {
		byName[r.Provider] = r
	}
	a := byName["transit-a"]
	if a.CapacityMbps == nil || *a.CapacityMbps != 1000 || a.UtilizationPct == nil || *a.UtilizationPct != 90 || a.ThresholdPct != 85 || !a.Overloaded {
		t.Fatalf("transit-a = %+v", a)
	}
	// Exactly at the limit is not past it.
	if b := byName["transit-b"]; b.UtilizationPct == nil || *b.UtilizationPct != 85 || b.Overloaded {
		t.Fatalf("transit-b = %+v", b)
	}
	// No limit: the utilization shows, and nothing is overloaded.
	if c := byName["transit-c"]; c.UtilizationPct == nil || *c.UtilizationPct != 75 || c.ThresholdPct != 0 || c.Overloaded {
		t.Fatalf("transit-c = %+v", c)
	}
	// No capacity, or no sample yet: no utilization.
	if d := byName["transit-d"]; d.CapacityMbps != nil || d.UtilizationPct != nil {
		t.Fatalf("transit-d = %+v", d)
	}
	if e := byName["transit-e"]; e.CapacityMbps == nil || e.UtilizationPct != nil || e.Overloaded {
		t.Fatalf("transit-e = %+v", e)
	}
}

// TestCommitLoadPage runs the Commit & Cost capacity columns in Node (#307).
// Like the verification page test, it is skipped without Node locally and
// required in CI.
func TestCommitLoadPage(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the commit load page test")
		}
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "commit_load_page_test.js").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("commit load page: %v\n%s", err, out)
	}
}
