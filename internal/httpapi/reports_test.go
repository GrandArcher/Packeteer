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

func (f *fakeReports) Prefix(_ context.Context, p netip.Prefix, q history.Query) (history.PrefixHistory, error) {
	f.last = q
	start := q.To.Add(-time.Hour)
	h := plugin.History{
		Buckets: []plugin.ProbeBucket{
			{Day: q.To.Truncate(24 * time.Hour), Prefix: netip.MustParsePrefix("192.0.2.0/24"), Provider: "transit-a", Probes: 4, Measured: 4, LossSum: 8, RTTSumMs: 80},
			{Day: q.To.Truncate(24 * time.Hour), Prefix: netip.MustParsePrefix("198.51.100.0/24"), Provider: "transit-a", Probes: 9, Measured: 9},
		},
		Improvements: []plugin.ImprovementRecord{
			{ID: "1", Prefix: netip.MustParsePrefix("192.0.2.0/24"), Provider: "transit-b", Native: "transit-a", Mode: "observe", Start: start},
			{ID: "2", Prefix: netip.MustParsePrefix("198.51.100.0/24"), Provider: "transit-b", Native: "transit-a", Start: start},
		},
	}
	return history.BuildPrefix(h, p, q), nil
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

// tsReports serves the timeseries report from a fixed history (#129).
type tsReports struct{ *fakeReports }

func (tsReports) Report(_ context.Context, q history.Query) (history.Report, error) {
	day := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	pfx := netip.MustParsePrefix("192.0.2.0/24")
	h := plugin.History{
		Buckets: []plugin.ProbeBucket{
			{Day: day, Prefix: pfx, Provider: "transit-a", Probes: 10, Measured: 10, LossSum: 100, RTTSumMs: 1000},
			{Day: day, Prefix: pfx, Provider: "transit-b", Probes: 10, Measured: 10, LossSum: 0, RTTSumMs: 400},
		},
		Improvements: []plugin.ImprovementRecord{{ID: "1", Prefix: pfx, Provider: "transit-b", Native: "transit-a",
			Cause: plugin.CausePerformance, Start: day.Add(time.Hour), End: day.Add(5 * time.Hour)}},
	}
	return history.Build(h, q)
}

func TestReportTimeSeriesAPI(t *testing.T) {
	ts := reportServer(t, tsReports{&fakeReports{}}, "", "")
	code, _, body := do(t, http.MethodGet, ts.URL+"/api/reports/timeseries?from=2026-09-01&to=2026-09-03", "", "")
	if code != http.StatusOK {
		t.Fatalf("json %d %s", code, body)
	}
	var got struct {
		Report string                  `json:"report"`
		Rows   []history.TimeSeriesRow `json:"rows"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Report != "timeseries" || len(got.Rows) != 4 {
		t.Fatalf("body = %s", body)
	}
	for _, r := range got.Rows {
		if r.Day != "2026-09-01" || r.Prefixes != 1 || r.BeforeLossPct != 10 || r.AfterLossPct != 0 || r.BeforeRTTMs != 100 || r.AfterRTTMs != 40 {
			t.Errorf("row = %+v", r)
		}
	}
	code, hdr, body := do(t, http.MethodGet, ts.URL+"/api/reports/timeseries?from=2026-09-01&to=2026-09-03&format=csv", "", "")
	if code != http.StatusOK || !strings.HasPrefix(hdr.Get("Content-Type"), "text/csv") ||
		!strings.HasPrefix(string(body), "day,bucket,prefixes,before_loss_pct,after_loss_pct,before_rtt_ms,after_rtt_ms\n2026-09-01,all,1,10,0,100,40\n") {
		t.Fatalf("csv %d %s", code, body)
	}
	// A range with no history is an empty list, not an error.
	code, _, body = do(t, http.MethodGet, ts.URL+"/api/reports/timeseries?from=2026-01-01&to=2026-01-03", "", "")
	if code != http.StatusOK || !strings.Contains(string(body), `"rows":[]`) {
		t.Fatalf("empty range %d %s", code, body)
	}
}

func TestPrefixHistory(t *testing.T) {
	src := &fakeReports{}
	ts := reportServer(t, src, "", "")
	code, _, body := do(t, http.MethodGet, ts.URL+"/api/prefixes/history?prefix=192.0.2.0/24&days=30", "", "")
	if code != http.StatusOK {
		t.Fatalf("history %d %s", code, body)
	}
	var got struct {
		Enabled bool   `json:"enabled"`
		Mode    string `json:"mode"`
		Prefix  string `json:"prefix"`
		Days    []struct {
			Provider string   `json:"provider"`
			Probes   int      `json:"probes"`
			LossPct  *float64 `json:"loss_pct"`
		} `json:"days"`
		Improvements []struct {
			Prefix   string `json:"prefix"`
			Provider string `json:"provider"`
			Mode     string `json:"mode"`
		} `json:"improvements"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || got.Prefix != "192.0.2.0/24" || got.Mode == "" {
		t.Fatalf("history = %s", body)
	}
	// Only the asked prefix, and the stored mode travels with the row so the
	// page can say "recommended" outside inject.
	if len(got.Days) != 1 || got.Days[0].Probes != 4 || *got.Days[0].LossPct != 2 {
		t.Errorf("days = %+v", got.Days)
	}
	if len(got.Improvements) != 1 || got.Improvements[0].Prefix != "192.0.2.0/24" || got.Improvements[0].Mode != "observe" {
		t.Errorf("improvements = %+v", got.Improvements)
	}
	if d := src.last.To.Sub(src.last.From); d != 30*24*time.Hour {
		t.Errorf("range = %v, want 30 days", d)
	}

	for _, bad := range []string{"", "prefix=nope", "prefix=192.0.2.5/24", "prefix=192.0.2.0/24&days=0", "prefix=192.0.2.0/24&days=x"} {
		if code, _, body := do(t, http.MethodGet, ts.URL+"/api/prefixes/history?"+bad, "", ""); code != http.StatusBadRequest {
			t.Errorf("%q: %d %s, want 400", bad, code, body)
		}
	}
}

func TestPrefixHistoryStorageOff(t *testing.T) {
	ts := reportServer(t, nil, "", "")
	code, _, body := do(t, http.MethodGet, ts.URL+"/api/prefixes/history?prefix=2001:db8::/32", "", "")
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["enabled"] != false || got["prefix"] != "2001:db8::/32" || got["improvements"] != nil {
		t.Errorf("storage off = %s", body)
	}
}

// The prefix page is a real URL for any prefix, IPv6 included, and needs
// the same sign-in as every other page.
func TestPrefixPageRoute(t *testing.T) {
	ts := reportServer(t, nil, "ops", "secret")
	for _, path := range []string{"/prefix/192.0.2.0/24", "/prefix/192.0.2.0%2F24", "/prefix/2001:db8::/32"} {
		code, _, body := do(t, http.MethodGet, ts.URL+path, "ops", "secret")
		if code != http.StatusOK || !strings.Contains(string(body), `data-page="prefixes"`) || !strings.Contains(string(body), `id="prefix-timeline"`) {
			t.Errorf("%s: %d", path, code)
		}
		if code, _, _ := do(t, http.MethodGet, ts.URL+path, "", ""); code != http.StatusUnauthorized {
			t.Errorf("%s without credentials: %d", path, code)
		}
	}
	if code, _, _ := do(t, http.MethodGet, ts.URL+"/api/prefixes/history?prefix=192.0.2.0/24", "", ""); code != http.StatusUnauthorized {
		t.Errorf("history without credentials: %d", code)
	}
}
