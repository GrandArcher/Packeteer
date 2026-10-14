package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
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
	last      history.Query
	search    history.SearchQuery
	searchErr error
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

func (f *fakeReports) Search(_ context.Context, q history.SearchQuery) (history.SearchResult, error) {
	f.search = q
	if f.searchErr != nil {
		return history.SearchResult{}, f.searchErr
	}
	h := plugin.History{
		Buckets: []plugin.ProbeBucket{
			{Day: q.To.Truncate(24 * time.Hour), Prefix: netip.MustParsePrefix("198.51.100.0/24"), Provider: "transit-a", Probes: 4, Measured: 4, LossSum: 8, RTTSumMs: 80},
		},
		Improvements: []plugin.ImprovementRecord{
			{ID: "1", Prefix: netip.MustParsePrefix("198.51.100.0/24"), Provider: "transit-b", Native: "transit-a", Start: q.To.Add(-48 * time.Hour), OriginASN: 64510},
			{ID: "2", Prefix: netip.MustParsePrefix("203.0.113.0/24"), Provider: "transit-b", Native: "transit-a", Start: q.To.Add(-24 * time.Hour), OriginASN: 64511},
		},
		Prefixes: []plugin.PrefixInfo{{Prefix: netip.MustParsePrefix("198.51.100.0/24"), OriginASN: 64510}},
	}
	return history.Search(h, q), nil
}

func TestReportQueryFilters(t *testing.T) {
	now := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	parse := func(name, qs string) (history.Query, error) {
		r := httptest.NewRequest(http.MethodGet, "/x?"+qs, nil)
		return reportQuery(r, name, now)
	}
	q, err := parse(history.ReportImprovements, "prefix=198.51.100.0/24&asn=%20as64510")
	if err != nil || q.Prefix != netip.MustParsePrefix("198.51.100.0/24") || q.ASN != 64510 {
		t.Errorf("good input: %+v, %v", q, err)
	}
	q, err = parse(history.ReportImprovements, "days=2")
	if err != nil || q.Prefix.IsValid() || q.ASN != 0 {
		t.Errorf("no filter: %+v, %v", q, err)
	}
	for _, bad := range []string{"prefix=198.51.100.5/24", "prefix=198.51.100.0", "prefix=x", "asn=0", "asn=AS", "asn=4294967296", "asn=64510x"} {
		if _, err := parse(history.ReportImprovements, bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	// A filter the report does not list, and a parameter nobody lists.
	for _, bad := range [][2]string{
		{history.ReportSummary, "cause=cost"}, {history.ReportTimeSeries, "provider=transit-a"}, {history.ReportMitigations, "asn=64510"},
		{history.ReportImprovements, "provder=transit-a"}, {history.ReportImprovements, "cause=nope"}, {history.ReportImprovements, "ip_version=5"},
		{history.ReportImprovements, "order=desc"}, {history.ReportImprovements, "sort=nope"}, {history.ReportImprovements, "sort=volume"},
	} {
		if _, err := parse(bad[0], bad[1]); err == nil {
			t.Errorf("%s?%s accepted", bad[0], bad[1])
		}
	}
	q, err = parse(history.ReportPrefixes, "provider=transit-a&asn=64510&prefix=198.51.100.0/24&ip_version=4&sort=avg_rtt_ms&order=desc&from=2026-09-01&to=2026-09-02")
	if err != nil || q.Provider != "transit-a" || q.ASN != 64510 || q.IPVersion != 4 || q.Sort != "avg_rtt_ms" || q.Order != history.OrderDesc ||
		!q.From.Equal(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)) || !q.To.Equal(time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("prefixes filters: %+v, %v", q, err)
	}
	// The prefix history call passes no report name and keeps its own prefix.
	if _, err := parse("", "prefix=198.51.100.0/24&asn=64510"); err != nil {
		t.Errorf("prefix history call: %v", err)
	}
}

func TestReportFilterOverHTTP(t *testing.T) {
	src := &fakeReports{}
	ts := reportServer(t, src, "", "")
	code, _, body := do(t, http.MethodGet, ts.URL+"/api/reports/improvements?prefix=198.51.100.0/24&asn=AS64510", "", "")
	if code != http.StatusOK || src.last.Prefix != netip.MustParsePrefix("198.51.100.0/24") || src.last.ASN != 64510 {
		t.Fatalf("filtered: %d %s %+v", code, body, src.last)
	}
	for _, path := range []string{"/api/reports/improvements?asn=x", "/api/reports/summary?cause=cost", "/api/reports/summary?color=red", "/api/reports/summary?format=pdf"} {
		if code, _, body := do(t, http.MethodGet, ts.URL+path, "", ""); code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", path, code, body)
		}
	}
}

func TestReportXLSXAndCSVHoldTheSameFilteredRows(t *testing.T) {
	src := &fakeReports{}
	ts := reportServer(t, src, "", "")
	const qs = "?days=2&provider=transit-b&asn=64500&cause=performance&ip_version=4&sort=hours&order=desc"
	code, hdr, body := do(t, http.MethodGet, ts.URL+"/api/reports/improvements"+qs+"&format=xlsx", "", "")
	if code != http.StatusOK || hdr.Get("Content-Type") != history.XLSXContentType ||
		!strings.HasPrefix(hdr.Get("Content-Disposition"), `attachment; filename="packeteer-improvements-`) || !strings.HasSuffix(hdr.Get("Content-Disposition"), `.xlsx"`) {
		t.Fatalf("xlsx %d %v", code, hdr)
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("not a workbook: %v", err)
	}
	var sheet string
	for _, f := range zr.File {
		if f.Name == "xl/worksheets/sheet1.xml" {
			rc, _ := f.Open()
			b, _ := io.ReadAll(rc)
			rc.Close()
			sheet = string(b)
		}
	}
	if !strings.Contains(sheet, "<t>Prefix</t>") || !strings.Contains(sheet, "192.0.2.0/24") || !strings.Contains(sheet, "transit-b") {
		t.Errorf("sheet = %s", sheet)
	}
	q := src.last
	if q.Provider != "transit-b" || q.ASN != 64500 || q.Cause != "performance" || q.IPVersion != 4 || q.Sort != "hours" || q.Order != "desc" {
		t.Errorf("xlsx query = %+v", q)
	}
	// CSV and JSON take the same parameters, so the three exports agree.
	code, _, csvBody := do(t, http.MethodGet, ts.URL+"/api/reports/improvements"+qs+"&format=csv", "", "")
	if code != http.StatusOK || strings.Count(strings.TrimSpace(string(csvBody)), "\n") != 1 ||
		src.last.Provider != q.Provider || src.last.ASN != q.ASN || src.last.Cause != q.Cause || src.last.IPVersion != q.IPVersion || src.last.Sort != q.Sort || src.last.Order != q.Order {
		t.Errorf("csv %d %s, query %+v", code, csvBody, src.last)
	}
	// A filter that matches nothing is an empty report, not an error.
	code, _, body = do(t, http.MethodGet, ts.URL+"/api/reports/improvements?provider=nobody", "", "")
	var got struct {
		Total   int              `json:"total"`
		Rows    []map[string]any `json:"rows"`
		Columns []history.Column `json:"columns"`
	}
	if err := json.Unmarshal(body, &got); err != nil || code != http.StatusOK || got.Total != 0 || len(got.Rows) != 0 || len(got.Columns) == 0 {
		t.Errorf("no match: %d %s", code, body)
	}
}

func TestReportDaysURLsKeepWorking(t *testing.T) {
	src := &fakeReports{}
	ts := reportServer(t, src, "", "")
	for _, qs := range []string{"", "?days=30", "?days=30&format=csv", "?days=1&limit=5&sort=loss", "?from=2026-09-01&to=2026-09-03", "?to=2026-09-03&days=2"} {
		if code, _, body := do(t, http.MethodGet, ts.URL+"/api/reports/prefixes"+qs, "", ""); code != http.StatusOK {
			t.Errorf("prefixes%s: %d %s", qs, code, body)
		}
	}
	if code, _, _ := do(t, http.MethodGet, ts.URL+"/api/reports/summary?days=2&from=2026-09-01", "", ""); code != http.StatusBadRequest {
		t.Errorf("days with from: %d", code)
	}
}

func TestReportListHasCategoriesFiltersAndColumns(t *testing.T) {
	ts := reportServer(t, &fakeReports{}, "", "")
	_, _, body := do(t, http.MethodGet, ts.URL+"/api/reports", "", "")
	var got struct {
		Reports []history.Def `json:"reports"`
	}
	if err := json.Unmarshal(body, &got); err != nil || len(got.Reports) != len(history.Reports) {
		t.Fatalf("%v %s", err, body)
	}
	want, _ := json.Marshal(history.Reports)
	have, _ := json.Marshal(got.Reports)
	if !bytes.Equal(have, want) {
		t.Errorf("report list differs from the catalog:\n got %s\nwant %s", have, want)
	}
}

func TestWidgetQueryIsCheckedLikeTheEndpoint(t *testing.T) {
	ok := []Widget{
		{Type: "report", Report: "improvements", Days: 30, Query: "provider=transit-a&sort=hours&order=desc"},
		{Type: "report", Report: "prefixes", Query: "from=2026-09-01&to=2026-09-03&ip_version=6"},
		{Type: "report", Report: "summary", Days: 7},
	}
	if err := (DashboardSpec{Widgets: ok}).Validate(); err != nil {
		t.Fatal(err)
	}
	for name, w := range map[string]Widget{
		"unsupported filter": {Type: "report", Report: "summary", Query: "cause=cost"},
		"unknown parameter":  {Type: "report", Report: "summary", Query: "color=red"},
		"days in the query":  {Type: "report", Report: "summary", Query: "days=3"},
		"format":             {Type: "report", Report: "summary", Query: "format=csv"},
		"days and from":      {Type: "report", Report: "summary", Days: 3, Query: "from=2026-09-01"},
		"bad value":          {Type: "report", Report: "improvements", Query: "prefix=nope"},
		"newline":            {Type: "report", Report: "summary", Query: "provider=a\nb"},
		"too long":           {Type: "report", Report: "summary", Query: "provider=" + strings.Repeat("a", 600)},
		"on timeseries":      {Type: "timeseries", Query: "provider=a"},
		"on providers":       {Type: "providers", Query: "provider=a"},
	} {
		if err := (DashboardSpec{Widgets: []Widget{w}}).Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
