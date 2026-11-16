package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/eventlog"
	"github.com/GrandArcher/Packeteer/internal/fieldreport"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func shareServer(t *testing.T, opt Options) *httptest.Server {
	t.Helper()
	opt.Snapshot = sampleSnap
	s, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func getShare(t *testing.T, ts *httptest.Server) (filename, report string) {
	t.Helper()
	code, _, body := do(t, http.MethodGet, ts.URL+"/api/report/share", "", "")
	if code != http.StatusOK {
		t.Fatalf("share %d %s", code, body)
	}
	var out struct{ Filename, Report string }
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out.Filename, out.Report
}

// #625: the summary counts events and reads the value totals, names no
// provider, and carries nothing from the events but their kinds.
func TestShareReport(t *testing.T) {
	log := eventlog.New(nil, nil, nil)
	now := time.Now()
	for _, e := range []plugin.Event{
		{Time: now, Kind: "bgp.session_down", Severity: plugin.SeverityCritical, Message: "session to 8.8.8.8 down", Fields: map[string]string{"peer": "8.8.8.8", "password": "hunter2-secret"}},
		{Time: now, Kind: "provider.down", Severity: plugin.SeverityWarning, Message: "AS3356 transit.example.net down"},
		{Time: now, Kind: "provider.down", Severity: plugin.SeverityWarning, Message: "again"},
		{Time: now, Kind: "improvement.added", Severity: plugin.SeverityInfo, Message: "moved 192.0.2.0/24"},
	} {
		log.Record(e)
	}
	facts := fieldreport.Facts{Providers: 2, BGPNeighbors: 1, ProbeTypes: []string{"icmp"}, SourceTypes: []string{"static"}}
	ts := shareServer(t, Options{Events: log, Reports: &valueReports{}, Setup: Setup{Report: facts}})
	name, report := getShare(t, ts)
	if name != fieldreport.FileName {
		t.Errorf("filename %q", name)
	}
	for _, want := range []string{
		"mode: " + sampleSnap().Mode, "version: " + sampleSnap().Version, "providers: 2", "probers: icmp", "target sources: static",
		"events (newest 1000 at most): 4 total, 2 warning, 1 critical", "- bgp.session_down: 1", "- provider.down: 2",
		"value report, last 30 days:", "- announced: 2 improvements, 2 measured", "- estimate: 3 improvements",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("missing %q in:\n%s", want, report)
		}
	}
	for _, leak := range []string{"8.8.8.8", "hunter2", "3356", "transit.example.net", "lab-b", "lab-c", "192.0.2.0/24", "improvement.added"} {
		if strings.Contains(report, leak) {
			t.Errorf("%q is in the report:\n%s", leak, report)
		}
	}
}

func TestShareReportWithoutEventsOrHistory(t *testing.T) {
	_, report := getShare(t, shareServer(t, Options{}))
	for _, want := range []string{"events: not kept", "value report: not available"} {
		if !strings.Contains(report, want) {
			t.Errorf("missing %q in:\n%s", want, report)
		}
	}
}

func TestShareReportNeedsSignIn(t *testing.T) {
	s, err := New(Options{User: "u", Password: "p", Snapshot: sampleSnap})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	if code, _, _ := do(t, http.MethodGet, ts.URL+"/api/report/share", "", ""); code != http.StatusUnauthorized {
		t.Errorf("without credentials: %d", code)
	}
	if code, _, _ := do(t, http.MethodGet, ts.URL+"/api/report/share", "u", "p"); code != http.StatusOK {
		t.Errorf("with credentials: %d", code)
	}
}

func TestCountEvents(t *testing.T) {
	got := countEvents([]plugin.Event{
		{Kind: "a", Severity: plugin.SeverityWarning}, {Kind: "a", Severity: plugin.SeverityCritical},
		{Kind: "b", Severity: plugin.SeverityInfo},
	})
	if got.Total != 3 || got.Warning != 1 || got.Critical != 1 || len(got.Kinds) != 1 || got.Kinds["a"] != 2 {
		t.Errorf("counts %+v", got)
	}
}
