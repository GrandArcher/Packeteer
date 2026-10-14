package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/commitview"
	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var commitNow = time.Date(2030, 1, 20, 12, 0, 0, 0, time.UTC)

// fakeUsage keeps samples in memory and answers like the sqlite store:
// one binding, [From, To), oldest first.
type fakeUsage struct {
	rows  []plugin.UsageSample
	err   error
	calls []plugin.UsageSampleQuery
}

func (f *fakeUsage) UsageSamples(_ context.Context, q plugin.UsageSampleQuery) ([]plugin.UsageSample, error) {
	f.calls = append(f.calls, q)
	if f.err != nil {
		return nil, f.err
	}
	var out []plugin.UsageSample
	for _, r := range f.rows {
		if r.Provider == q.Provider && r.Host == q.Host && r.Interface == q.Interface && !r.At.Before(q.From) && r.At.Before(q.To) {
			out = append(out, r)
		}
	}
	return out, nil
}

// commitSamples is a sample every 5 minutes for ten days (the billing
// period began on the 1st), 1 Mbps rising by one per hour.
func commitSamples(provider string) []plugin.UsageSample {
	start := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	var out []plugin.UsageSample
	for at := commitNow.Add(-10 * 24 * time.Hour); at.Before(commitNow); at = at.Add(5 * time.Minute) {
		mbps := float64(at.Sub(start)/time.Hour + 1)
		out = append(out, plugin.UsageSample{Provider: provider, Host: "edge", Interface: "ether1", PeriodStart: start, PeriodEnd: start.AddDate(0, 1, 0),
			At: at, InBps: mbps * 1e5, OutBps: mbps * 1e6})
	}
	return out
}

func commitServer(t *testing.T, tel []Telemetry, usage UsageReader, reports ReportSource) *Server {
	t.Helper()
	snap := Snapshot{At: commitNow, Mode: "observe", Telemetry: tel}
	s, err := New(Options{Snapshot: func() Snapshot { return snap }, Usage: usage, Reports: reports})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type commitBody struct {
	Mode        string    `json:"mode"`
	Days        int       `json:"days"`
	From        time.Time `json:"from"`
	To          time.Time `json:"to"`
	StepSeconds int       `json:"step_seconds"`
	Samples     bool      `json:"samples_stored"`
	Moves       bool      `json:"moves_recorded"`
	Truncated   bool      `json:"moves_truncated"`
	Providers   []struct {
		Telemetry
		BillableMbps *float64           `json:"billable_mbps"`
		Points       []commitview.Point `json:"points"`
		Moves        []commitview.Move  `json:"moves"`
	} `json:"providers"`
}

func getCommit(t *testing.T, s *Server, query string) (int, commitBody) {
	t.Helper()
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	code, _, body := do(t, http.MethodGet, ts.URL+"/api/commit"+query, "", "")
	var out commitBody
	if code == http.StatusOK {
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("%v: %s", err, body)
		}
	}
	return code, out
}

func binding(provider string, billable *float64) Telemetry {
	return Telemetry{Provider: provider, Host: "edge", Interface: "ether1", CommitMbps: 200, BillingDay: 1, Percentile: "separate",
		PeriodStart: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), PeriodEnd: time.Date(2030, 2, 1, 0, 0, 0, 0, time.UTC),
		Samples: 2880, OutMbps95: 230, UsageMbps: billable}
}

func TestCommitRangesFromPersistedSamples(t *testing.T) {
	usage := &fakeUsage{rows: commitSamples("transit-a")}
	s := commitServer(t, []Telemetry{binding("transit-a", nil)}, usage, nil)
	for _, c := range []struct {
		query        string
		days, step   int
		wantPointsAt int
	}{{"?days=1", 1, 300, 288}, {"?days=7", 7, 1800, 336}, {"?days=30", 30, 7200, 0}, {"", 7, 1800, 336}} {
		code, got := getCommit(t, s, c.query)
		if code != http.StatusOK || got.Days != c.days || got.StepSeconds != c.step || got.Mode != "observe" || !got.Samples {
			t.Fatalf("%s: %d %+v", c.query, code, got)
		}
		if !got.To.Equal(commitNow) || !got.From.Equal(commitNow.Add(-time.Duration(c.days)*24*time.Hour)) {
			t.Fatalf("%s: range %s - %s", c.query, got.From, got.To)
		}
		pts := got.Providers[0].Points
		if c.wantPointsAt > 0 && len(pts) != c.wantPointsAt {
			t.Fatalf("%s: %d points, want %d", c.query, len(pts), c.wantPointsAt)
		}
		if c.days == 30 && (len(pts) < 100 || len(pts) > 130) {
			t.Fatalf("30 days: %d points", len(pts)) // ten days of samples in two hour points
		}
		last := pts[len(pts)-1]
		// The newest sample is 11:55 on the 20th: 19*24+12 = 468 hours into the period, 1 Mbps per hour, 1 more at 12:00.
		if last.Mbps < 468 || last.Mbps > 469 || last.P95Mbps <= 0 || last.P95Mbps > last.Mbps {
			t.Fatalf("%s: last point %+v", c.query, last)
		}
		if pts[0].At.Before(got.From) {
			t.Fatalf("%s: first point %s before the range", c.query, pts[0].At)
		}
	}
	// The running 95th counts the whole billing period, not only the
	// range: the one-day view reads the earlier samples too.
	_, got := getCommit(t, s, "?days=1")
	p := got.Providers[0].Points
	all := commitview.Series(plugin.PercentileSeparate, commitSamples("transit-a"), commitNow.Add(-24*time.Hour), 5*time.Minute)
	if len(p) != len(all) || p[len(p)-1].P95Mbps != all[len(all)-1].P95Mbps {
		t.Fatalf("1 day series differs from the whole-period series: %v vs %v", p[len(p)-1], all[len(all)-1])
	}
	if got.Providers[0].BillableMbps == nil || *got.Providers[0].BillableMbps != 230 {
		t.Fatalf("billable = %v", got.Providers[0].BillableMbps)
	}
}

func TestCommitWithoutDataStillAnswers(t *testing.T) {
	code, got := getCommit(t, commitServer(t, nil, nil, nil), "")
	if code != http.StatusOK || got.Samples || got.Moves || len(got.Providers) != 0 {
		t.Fatalf("no telemetry: %d %+v", code, got)
	}
	// A binding with no stored samples, and no store at all: the live
	// figures are shown, points and moves are empty arrays.
	usage := &fakeUsage{}
	fresh := binding("transit-a", nil)
	fresh.Samples, fresh.OutMbps95 = 0, 0
	for _, u := range []UsageReader{usage, nil} {
		s := commitServer(t, []Telemetry{fresh}, u, nil)
		ts := httptest.NewServer(s.Handler())
		t.Cleanup(ts.Close)
		code, _, body := do(t, http.MethodGet, ts.URL+"/api/commit?days=30", "", "")
		var raw struct {
			Providers []map[string]json.RawMessage `json:"providers"`
		}
		if err := json.Unmarshal(body, &raw); err != nil || code != http.StatusOK || len(raw.Providers) != 1 {
			t.Fatalf("%d %s", code, body)
		}
		if string(raw.Providers[0]["points"]) != "[]" || string(raw.Providers[0]["moves"]) != "[]" {
			t.Fatalf("points %s moves %s", raw.Providers[0]["points"], raw.Providers[0]["moves"])
		}
		if _, set := raw.Providers[0]["billable_mbps"]; set {
			t.Fatalf("a figure without a sample: %s", body)
		}
	}
	// The fixed telemetry plugin has no host or interface: nothing to read.
	fixed := Telemetry{Provider: "transit-a", CommitMbps: 100, Percentile: "separate", Samples: 1, OutMbps95: 50}
	usage = &fakeUsage{rows: commitSamples("transit-a")}
	_, got = getCommit(t, commitServer(t, []Telemetry{fixed}, usage, nil), "")
	if len(usage.calls) != 0 || len(got.Providers[0].Points) != 0 || got.Providers[0].BillableMbps == nil || *got.Providers[0].BillableMbps != 50 {
		t.Fatalf("fixed binding: calls %d %+v", len(usage.calls), got.Providers[0])
	}
}

func TestCommitRefusesOtherRanges(t *testing.T) {
	s := commitServer(t, nil, nil, nil)
	for _, q := range []string{"?days=0", "?days=2", "?days=365", "?days=x", "?days=-7"} {
		if code, _ := getCommit(t, s, q); code != http.StatusBadRequest {
			t.Errorf("%s: %d", q, code)
		}
	}
}

// commitReports answers the improvements report from a fixed history.
type commitReports struct {
	ReportSource
	err  error
	last history.Query
	// cap, when set, cuts the report to that many rows as the real limit does.
	cap int
}

func (c *commitReports) Report(_ context.Context, q history.Query) (history.Report, error) {
	c.last = q
	if c.err != nil {
		return history.Report{}, c.err
	}
	rec := func(id, prefix, prov, native, cause, mode string, ago time.Duration) plugin.ImprovementRecord {
		return plugin.ImprovementRecord{ID: id, Prefix: netip.MustParsePrefix(prefix), Provider: prov, Native: native, Cause: cause, Mode: mode, Start: commitNow.Add(-ago)}
	}
	h := plugin.History{Improvements: []plugin.ImprovementRecord{
		rec("1", "192.0.2.0/24", "transit-b", "transit-a", plugin.CauseCommit, "observe", 2*time.Hour),
		rec("2", "198.51.100.0/24", "transit-b", "transit-a", plugin.CauseCommit, "observe", 2*time.Hour-time.Minute),
		rec("3", "203.0.113.0/24", "transit-b", "transit-a", plugin.CausePerformance, "observe", 2*time.Hour),
		rec("4", "192.0.2.0/24", "transit-b", "transit-a", plugin.CauseCommit, "observe", 40*24*time.Hour),
	}}
	if c.cap > 0 {
		q.Limit = c.cap
	}
	return history.Build(h, q)
}

func TestCommitMarksWhereCommitControlMovedTraffic(t *testing.T) {
	reports := &commitReports{}
	s := commitServer(t, []Telemetry{binding("transit-a", nil), binding("transit-b", nil)}, &fakeUsage{rows: commitSamples("transit-a")}, reports)
	_, got := getCommit(t, s, "?days=7")
	if !got.Moves || reports.last.Cause != plugin.CauseCommit || reports.last.Name != history.ReportImprovements {
		t.Fatalf("query = %+v moves=%v", reports.last, got.Moves)
	}
	a, b := got.Providers[0], got.Providers[1]
	if a.Provider != "transit-a" || len(a.Moves) != 1 || a.Moves[0].Direction != "off" || a.Moves[0].Peer != "transit-b" || a.Moves[0].Prefixes != 2 || a.Moves[0].Announced {
		t.Fatalf("transit-a moves = %+v", a.Moves)
	}
	if len(b.Moves) != 1 || b.Moves[0].Direction != "onto" || b.Moves[0].Peer != "transit-a" || b.Moves[0].Prefixes != 2 {
		t.Fatalf("transit-b moves = %+v", b.Moves)
	}
	if len(b.Points) != 0 {
		t.Fatalf("transit-b has no stored samples but %d points", len(b.Points))
	}
	if got.Truncated {
		t.Fatal("moves_truncated set though every row was read")
	}
}

func TestCommitSaysWhenTheHistoryWasCut(t *testing.T) {
	s := commitServer(t, []Telemetry{binding("transit-a", nil)}, nil, &commitReports{cap: 1})
	_, got := getCommit(t, s, "?days=7")
	if !got.Truncated {
		t.Fatal("two matching rows, one read, and no sign of it")
	}
}

func TestCommitBillableNeedsAPositiveCommit(t *testing.T) {
	none := binding("transit-a", nil)
	none.CommitMbps = 0
	single := 410.0
	one := binding("transit-b", &single)
	_, got := getCommit(t, commitServer(t, []Telemetry{none, one}, nil, nil), "")
	if got.Providers[0].BillableMbps != nil {
		t.Fatalf("billable %v with no commit", *got.Providers[0].BillableMbps)
	}
	if b := got.Providers[1].BillableMbps; b == nil || *b != 410 {
		t.Fatalf("single-figure billable = %v", b)
	}
}

func TestCommitReadFailuresAreErrors(t *testing.T) {
	tel := []Telemetry{binding("transit-a", nil)}
	if code, _ := getCommit(t, commitServer(t, tel, &fakeUsage{err: errors.New("disk")}, nil), ""); code != http.StatusInternalServerError {
		t.Fatalf("samples: %d", code)
	}
	if code, _ := getCommit(t, commitServer(t, tel, nil, &commitReports{err: errors.New("disk")}), ""); code != http.StatusInternalServerError {
		t.Fatalf("history: %d", code)
	}
}
