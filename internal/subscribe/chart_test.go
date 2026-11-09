package subscribe

import (
	"bytes"
	"context"
	"flag"
	"image"
	"image/color"
	"image/png"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var update = flag.Bool("update", false, "rewrite the golden chart images in testdata")

var (
	chartFrom = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	chartTo   = time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
)

// gapRows has points on days 1, 2, 4, and 5 of the range, so the line
// breaks on the 3rd, and nothing on the last two days.
func gapRows() []history.TimeSeriesRow {
	row := func(day string, bl, al, br, ar float64) history.TimeSeriesRow {
		return history.TimeSeriesRow{Day: day, Bucket: history.BucketAll, Prefixes: 2, BeforeLossPct: bl, AfterLossPct: al, BeforeRTTMs: br, AfterRTTMs: ar}
	}
	return []history.TimeSeriesRow{
		row("2026-09-01", 8, 1, 120, 60),
		row("2026-09-02", 6, 0.5, 110, 55),
		row("2026-09-04", 9, 2, 150, 70),
		row("2026-09-05", 3, 0, 90, 45),
	}
}

func decode(t *testing.T, data []byte) image.Image {
	t.Helper()
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode png: %v", err)
	}
	return img
}

func samePixels(a, b image.Image) bool {
	if a.Bounds() != b.Bounds() {
		return false
	}
	for y := a.Bounds().Min.Y; y < a.Bounds().Max.Y; y++ {
		for x := a.Bounds().Min.X; x < a.Bounds().Max.X; x++ {
			if a.At(x, y) != b.At(x, y) {
				return false
			}
		}
	}
	return true
}

// TestChartSnapshot compares the rendered charts with the images in
// testdata pixel by pixel (the PNG bytes may change with the Go version,
// the pixels must not). Run with -update after an intended change and look
// at the images.
func TestChartSnapshot(t *testing.T) {
	lone := []history.TimeSeriesRow{{Day: "2026-09-03", Bucket: history.BucketAll, Prefixes: 1, BeforeRTTMs: 40, AfterRTTMs: 25}}
	for _, tc := range []struct {
		file   string
		rows   []history.TimeSeriesRow
		metric chartMetric
	}{
		{"loss_gap.png", gapRows(), chartMetrics[0]},
		{"rtt_gap.png", gapRows(), chartMetrics[1]},
		{"rtt_lone_day.png", lone, chartMetrics[1]},
	} {
		got, err := chartPNG(tc.rows, chartFrom, chartTo, tc.metric)
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		path := filepath.Join("testdata", tc.file)
		if *update {
			if err := os.MkdirAll("testdata", 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, got, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (run go test ./internal/subscribe -update)", tc.file, err)
		}
		if !samePixels(decode(t, got), decode(t, want)) {
			t.Errorf("%s: rendered chart differs from testdata; run go test ./internal/subscribe -update and compare", tc.file)
		}
	}
}

func colorCount(img image.Image, c color.RGBA, x0, x1 int) int {
	n := 0
	for y := 0; y < img.Bounds().Dy(); y++ {
		for x := x0; x < x1; x++ {
			if img.At(x, y) == c {
				n++
			}
		}
	}
	return n
}

func TestChartDrawsBothLinesAndBreaksAtAGap(t *testing.T) {
	data, err := chartPNG(gapRows(), chartFrom, chartTo, chartMetrics[0])
	if err != nil {
		t.Fatal(err)
	}
	img := decode(t, data)
	if b := img.Bounds(); b.Dx() != chartW || b.Dy() != chartH {
		t.Fatalf("size = %v", b)
	}
	// The range has 7 days (the 1st to the 7th), so day d is at this x.
	plotW := chartW - marginL - marginR
	x := func(day int) int { return marginL + plotW*(day-1)/6 }
	for name, c := range map[string]color.RGBA{"before": colBefore, "after": colAfter} {
		if colorCount(img, c, 0, chartW) == 0 {
			t.Errorf("no %s pixels", name)
		}
		// Day 3 has no row: nothing of either line there, and the points on
		// days 2 and 4 are drawn apart from it.
		if n := colorCount(img, c, x(3)-4, x(3)+4); n != 0 {
			t.Errorf("%s: %d pixels across the missing day", name, n)
		}
		if n := colorCount(img, c, x(2)-2, x(2)+3); n == 0 {
			t.Errorf("%s: no point on day 2", name)
		}
		// Days 6 and 7 have no rows either.
		if n := colorCount(img, c, x(6)-3, chartW); n != 0 {
			t.Errorf("%s: %d pixels after the last row", name, n)
		}
	}
}

func TestBeforeIsDashedAndAfterSolid(t *testing.T) {
	flat := []history.TimeSeriesRow{
		{Day: "2026-09-01", Bucket: history.BucketAll, BeforeLossPct: 5, AfterLossPct: 3},
		{Day: "2026-09-02", Bucket: history.BucketAll, BeforeLossPct: 5, AfterLossPct: 3},
	}
	data, err := chartPNG(flat, chartFrom, chartFrom.Add(2*24*time.Hour), chartMetrics[0])
	if err != nil {
		t.Fatal(err)
	}
	img := decode(t, data)
	before, after := colorCount(img, colBefore, 0, chartW), colorCount(img, colAfter, 0, chartW)
	if before == 0 || before >= after*8/10 {
		t.Fatalf("before=%d after=%d pixels: want a dashed before line well under the solid after line", before, after)
	}
}

func TestChartTicks(t *testing.T) {
	for _, tc := range []struct {
		max  float64
		want []float64
	}{
		{0, []float64{0, 1}},
		{9, []float64{0, 2.5, 5, 7.5, 10}},
		{150, []float64{0, 100, 200}},
		{0.4, []float64{0, 0.1, 0.2, 0.3, 0.4}},
	} {
		if got := chartTicks(tc.max); !slices.Equal(got, tc.want) {
			t.Errorf("chartTicks(%v) = %v, want %v", tc.max, got, tc.want)
		}
	}
}

func TestChartNeedsRows(t *testing.T) {
	if _, err := chartPNG(nil, chartFrom, chartTo, chartMetrics[0]); err == nil {
		t.Fatal("no rows gave an image")
	}
}

// tsHistory is documentation-prefix history with an improvement on two
// days, the first better by more than 50% and the second not better.
func tsHistory() plugin.History {
	p := netip.MustParsePrefix("192.0.2.0/24")
	d1 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	d2 := d1.Add(24 * time.Hour)
	b := func(day time.Time, provider string, loss, rtt float64) plugin.ProbeBucket {
		return plugin.ProbeBucket{Day: day, Prefix: p, Provider: provider, Probes: 10, Measured: 10, LossSum: loss * 10, RTTSumMs: rtt * 10}
	}
	return plugin.History{
		Buckets: []plugin.ProbeBucket{
			b(d1, "transit-a", 10, 100), b(d1, "transit-b", 0, 40),
			b(d2, "transit-a", 2, 80), b(d2, "transit-b", 2, 79),
		},
		Improvements: []plugin.ImprovementRecord{{ID: "i1", Prefix: p, Provider: "transit-b", Native: "transit-a",
			Cause: plugin.CausePerformance, Start: d1.Add(time.Hour), End: d2.Add(time.Hour)}},
	}
}

func tsSub() config.ReportSubscription {
	return config.ReportSubscription{Name: "graphs", Report: history.ReportTimeSeries, Schedule: config.ScheduleWeekly, Weekday: "monday", At: "06:00", Notifier: "mail", Days: 7}
}

func TestBuildTimeSeriesMailHasChartsAndCSV(t *testing.T) {
	src := &fakeSource{h: tsHistory()}
	to := time.Date(2026, 9, 7, 6, 0, 0, 0, time.UTC)
	m, err := Build(context.Background(), src, tsSub(), to)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Attachments) != 1 || m.Attachments[0].ContentType != "text/csv" || !strings.Contains(string(m.Attachments[0].Data), "2026-09-01,all,1,") {
		t.Fatalf("csv attachment = %+v", m.Attachments)
	}
	// All four buckets have rows (day 1 is better by more than 50%), two
	// charts each.
	if len(m.Inline) != 8 {
		t.Fatalf("inline images = %d, want 8 (loss and latency for 4 buckets)", len(m.Inline))
	}
	for _, a := range m.Inline {
		if a.ContentType != "image/png" || a.ContentID == "" {
			t.Fatalf("inline %+v", a)
		}
		if !strings.Contains(m.HTML, `src="cid:`+a.ContentID+`"`) {
			t.Errorf("html does not show %s", a.ContentID)
		}
		if b := decode(t, a.Data).Bounds(); b.Dx() != chartW || b.Dy() != chartH {
			t.Errorf("%s size %v", a.Name, b)
		}
	}
	for _, want := range []string{"All destinations", "Problem prefixes", "20% or more better", "50% or more better", "Dashed orange", "Solid blue", "<b>Loss (%)</b>", "<b>Latency (ms)</b>", `alt="Loss (%), All destinations`, "attached as CSV"} {
		if !strings.Contains(m.HTML, want) {
			t.Errorf("html lacks %q", want)
		}
	}
	if strings.Contains(m.HTML, "ZgotmplZ") {
		t.Error("html template filtered a cid URL")
	}
	if !strings.Contains(m.Text, "CSV attached") {
		t.Errorf("text = %q", m.Text)
	}
}

func TestBuildTimeSeriesMailWithoutData(t *testing.T) {
	m, err := Build(context.Background(), &fakeSource{}, tsSub(), time.Date(2026, 9, 7, 6, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Inline) != 0 || !strings.Contains(m.HTML, "No before/after data in this range") || strings.Contains(m.HTML, "<img") {
		t.Fatalf("no-data mail: inline=%d html=%q", len(m.Inline), m.HTML)
	}
	if len(m.Attachments) != 1 {
		t.Fatalf("csv attachment missing: %+v", m.Attachments)
	}
}

func TestOtherReportsHaveNoCharts(t *testing.T) {
	m, err := Build(context.Background(), &fakeSource{h: tsHistory()}, sub("daily", config.ScheduleDaily), time.Date(2026, 9, 7, 6, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if m.HTML != "" || len(m.Inline) != 0 {
		t.Fatalf("summary report got charts: html=%q inline=%d", m.HTML, len(m.Inline))
	}
}
