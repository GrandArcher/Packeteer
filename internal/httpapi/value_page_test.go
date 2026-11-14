package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// valueReports serves the value report for a hand-checkable history on
// documentation prefixes. lab-b has two announced moves (inject) and one
// recommended (observe); lab-c has two recommended moves, one measured.
type valueReports struct{ fakeReports }

func (valueReports) Report(_ context.Context, q history.Query) (history.Report, error) {
	meas := func(r plugin.ImprovementRecord, bl, br, al, ar float64) plugin.ImprovementRecord {
		r.HasBefore, r.BeforeLoss, r.BeforeRTT = true, bl, br
		r.HasAfter, r.AfterLoss, r.AfterRTT = true, al, ar
		return r
	}
	at := func(ago time.Duration) time.Time { return q.To.Add(-ago) }
	h := plugin.History{Improvements: []plugin.ImprovementRecord{
		meas(plugin.ImprovementRecord{ID: "1", Prefix: netip.MustParsePrefix("198.51.100.0/24"), Provider: "lab-b", Native: "lab-a", Mode: "inject",
			VolumeMbps: 100, Start: at(30 * time.Hour), End: at(20 * time.Hour)}, 10, 50, 0, 30),
		meas(plugin.ImprovementRecord{ID: "2", Prefix: netip.MustParsePrefix("203.0.113.0/24"), Provider: "lab-b", Native: "lab-a", Mode: "inject",
			VolumeMbps: 300, Start: at(28 * time.Hour), End: at(10 * time.Hour)}, 2, 80, 1, 60),
		meas(plugin.ImprovementRecord{ID: "3", Prefix: netip.MustParsePrefix("192.0.2.0/24"), Provider: "lab-b", Native: "lab-a", Mode: "observe",
			VolumeMbps: 200, Start: at(5 * time.Hour)}, 20, 70, 2, 40),
		meas(plugin.ImprovementRecord{ID: "4", Prefix: netip.MustParsePrefix("2001:db8::/32"), Provider: "lab-c", Native: "lab-a", Mode: "observe",
			Start: at(3 * time.Hour)}, 4, 100, 1, 90),
		{ID: "5", Prefix: netip.MustParsePrefix("198.51.100.0/24"), Provider: "lab-c", Native: "lab-a", Mode: "observe", Start: at(2 * time.Hour)},
	}}
	return history.Build(h, q)
}

// #588: the value page shows the per-provider figures of the value report
// (#583), worded as announced for inject and as an estimate for observe.
// Like the other page tests it is skipped without Node locally and required
// in CI.
func TestValuePage(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the value page test")
		}
		t.Skip("node not installed")
	}
	ts := reportServer(t, &valueReports{}, "", "")
	code, _, body := do(t, http.MethodGet, ts.URL+"/api/reports/value?days=7", "", "")
	if code != http.StatusOK {
		t.Fatalf("value report %d %s", code, body)
	}
	var got struct {
		Rows []history.ValueRow `json:"rows"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	// The hand calculation the page test relies on: lab-b announced is
	// weighted 100 and 300 Mbps, lab-b estimated is one move.
	var announced, estimate int
	for _, r := range got.Rows {
		if r.Scope != history.ValueProvider || r.Provider != "lab-b" {
			continue
		}
		switch r.Basis {
		case history.BasisAnnounced:
			announced++
			if r.LossAvoided == nil || r.RTTAvoidedMs == nil || r.BeforeRTTMs == nil || r.AfterRTTMs == nil {
				t.Fatalf("announced lab-b is missing a figure: %+v", r)
			}
			if *r.LossAvoided != 3.25 || *r.RTTAvoidedMs != 20 || *r.BeforeRTTMs != 72.5 || *r.AfterRTTMs != 52.5 {
				t.Fatalf("announced lab-b = %+v", r)
			}
		case history.BasisEstimate:
			estimate++
			if r.LossAvoided == nil || r.RTTAvoidedMs == nil {
				t.Fatalf("estimate lab-b is missing a figure: %+v", r)
			}
			if *r.LossAvoided != 18 || *r.RTTAvoidedMs != 30 {
				t.Fatalf("estimate lab-b = %+v", r)
			}
		}
	}
	if announced != 1 || estimate != 1 {
		t.Fatalf("lab-b rows: %d announced, %d estimate in %+v", announced, estimate, got.Rows)
	}
	file := filepath.Join(t.TempDir(), "value.json")
	if err := os.WriteFile(file, body, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, "value_page_test.js", file).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("value page: %v\n%s", err, out)
	}
}
