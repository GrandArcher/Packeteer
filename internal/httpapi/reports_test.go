package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// fakeReports builds reports from a fixed history and records the query.
type fakeReports struct {
	last history.Query
}

func (f *fakeReports) Report(_ context.Context, q history.Query) (history.Report, error) {
	f.last = q
	start := q.To.Add(-time.Hour)
	h := plugin.History{Improvements: []plugin.ImprovementRecord{{
		ID: "1", Prefix: netip.MustParsePrefix("192.0.2.0/24"), Provider: "transit-b", Native: "transit-a",
		Cause: plugin.CausePerformance, Start: start, HasBefore: true, BeforeLoss: 5, HasAfter: true, AfterLoss: 0, OriginASN: 64500,
	}}}
	return history.Build(h, q)
}

func reportServer(t *testing.T, src ReportSource, user, pass string) *httptest.Server {
	t.Helper()
	s, err := New(Options{User: user, Password: pass, Snapshot: sampleSnap, Reports: src})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestReportList(t *testing.T) {
	ts := reportServer(t, nil, "", "")
	code, _, body := do(t, http.MethodGet, ts.URL+"/api/reports", "", "")
	if code != http.StatusOK {
		t.Fatalf("list %d %s", code, body)
	}
	var got struct {
		Enabled bool `json:"enabled"`
		Reports []struct {
			Name string `json:"name"`
		} `json:"reports"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Enabled || len(got.Reports) != len(history.Reports) {
		t.Fatalf("list = %+v", got)
	}
	code, _, body = do(t, http.MethodGet, ts.URL+"/api/reports/summary", "", "")
	if code != http.StatusNotFound || !strings.Contains(string(body), "storage is not configured") {
		t.Fatalf("no storage: %d %s", code, body)
	}
}

func TestReportJSONAndCSV(t *testing.T) {
	src := &fakeReports{}
	ts := reportServer(t, src, "", "")

	code, _, body := do(t, http.MethodGet, ts.URL+"/api/reports/improvements?from=2026-09-01&to=2026-09-03T00:00:00Z&limit=5", "", "")
	if code != http.StatusOK {
		t.Fatalf("json %d %s", code, body)
	}
	if !src.last.From.Equal(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)) || !src.last.To.Equal(time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)) || src.last.Limit != 5 {
		t.Fatalf("query = %+v", src.last)
	}
	var got struct {
		Mode   string                   `json:"mode"`
		Report string                   `json:"report"`
		Rows   []history.ImprovementRow `json:"rows"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Report != "improvements" || got.Mode != "observe" || len(got.Rows) != 1 || got.Rows[0].Prefix != "192.0.2.0/24" || *got.Rows[0].BeforeLossPct != 5 {
		t.Fatalf("json body = %s", body)
	}

	code, hdr, body := do(t, http.MethodGet, ts.URL+"/api/reports/improvements?days=2&format=csv", "", "")
	if code != http.StatusOK || !strings.HasPrefix(hdr.Get("Content-Type"), "text/csv") || !strings.Contains(hdr.Get("Content-Disposition"), "packeteer-improvements-") {
		t.Fatalf("csv %d %v", code, hdr)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "prefix,provider,native,cause") || !strings.HasPrefix(lines[1], "192.0.2.0/24,transit-b,transit-a,performance") {
		t.Fatalf("csv body = %s", body)
	}
	if d := src.last.To.Sub(src.last.From); d != 48*time.Hour {
		t.Fatalf("days=2 range = %s", d)
	}
}

func TestReportBadRequests(t *testing.T) {
	ts := reportServer(t, &fakeReports{}, "", "")
	for _, tc := range []struct {
		path string
		code int
	}{
		{"/api/reports/nope", http.StatusNotFound},
		{"/api/reports/summary?format=xml", http.StatusBadRequest},
		{"/api/reports/summary?from=yesterday", http.StatusBadRequest},
		{"/api/reports/summary?from=2026-09-02&to=2026-09-01", http.StatusBadRequest},
		{"/api/reports/summary?days=0", http.StatusBadRequest},
		{"/api/reports/summary?days=2&from=2026-09-01", http.StatusBadRequest},
		{"/api/reports/summary?limit=-1", http.StatusBadRequest},
		{"/api/reports/prefixes?sort=size", http.StatusBadRequest},
	} {
		code, _, body := do(t, http.MethodGet, ts.URL+tc.path, "", "")
		if code != tc.code {
			t.Errorf("%s: %d %s", tc.path, code, body)
		}
	}
	code, _, _ := do(t, http.MethodPost, ts.URL+"/api/reports/summary", "", "")
	if code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", code)
	}
}

func TestReportAuth(t *testing.T) {
	ts := reportServer(t, &fakeReports{}, "ops", "secret")
	if code, _, _ := do(t, http.MethodGet, ts.URL+"/api/reports/summary", "", ""); code != http.StatusUnauthorized {
		t.Fatalf("no auth: %d", code)
	}
	if code, _, _ := do(t, http.MethodGet, ts.URL+"/api/reports/summary?format=csv", "ops", "secret"); code != http.StatusOK {
		t.Fatalf("auth: %d", code)
	}
}
