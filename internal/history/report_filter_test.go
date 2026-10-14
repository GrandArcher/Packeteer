package history

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// everyReportHistory adds what the seed lacks: an IPv6 prefix, a mitigation,
// and an anomaly.
func everyReportHistory() plugin.History {
	h := seed()
	v6 := netip.MustParsePrefix("2001:db8::/32")
	h.Buckets = append(h.Buckets, plugin.ProbeBucket{Day: from, Prefix: v6, Provider: "transit-a", Probes: 3, Measured: 3, LossSum: 3, RTTSumMs: 30})
	h.Improvements = append(h.Improvements, plugin.ImprovementRecord{ID: "6", Prefix: v6, Provider: "transit-b", Native: "transit-a",
		Cause: plugin.CausePerformance, Start: from.Add(5 * time.Hour), End: from.Add(6 * time.Hour), OriginASN: 64502})
	h.Mitigations = []plugin.MitigationRecord{
		{ID: "m1", Prefix: pfxA, Action: "rtbh", Mode: "observe", Created: from.Add(time.Hour), Expires: from.Add(2 * time.Hour)},
		{ID: "m2", Prefix: v6, Action: "rtbh", Mode: "observe", Created: from.Add(3 * time.Hour), Expires: from.Add(4 * time.Hour)},
	}
	h.Anomalies = []plugin.AnomalyRecord{
		{ID: "a1", Prefix: pfxA, Protocol: "udp", PeakMbps: 90, BaselineMbps: 10, Start: from.Add(time.Hour), End: from.Add(2 * time.Hour)},
		{ID: "a2", Prefix: v6, Protocol: "tcp", PeakMbps: 50, BaselineMbps: 10, Start: from.Add(3 * time.Hour)},
	}
	return h
}

func buildAll(t *testing.T, name string, mod ...func(*Query)) Report {
	t.Helper()
	q := Query{Name: name, From: from, To: to, Now: now, Exchanges: map[string]string{"transit-b": "ix-lab"}}
	for _, m := range mod {
		m(&q)
	}
	r, err := Build(everyReportHistory(), q)
	if err != nil {
		t.Fatalf("Build(%s): %v", name, err)
	}
	return r
}

func TestColumnsDescribeEveryRow(t *testing.T) {
	for _, d := range Reports {
		rep := buildAll(t, d.Name)
		if rep.Total == 0 {
			t.Errorf("%s: the test history gives no rows", d.Name)
		}
		var rows []map[string]any
		raw, _ := json.Marshal(rep.Rows)
		if err := json.Unmarshal(raw, &rows); err != nil || len(rows) != len(rep.lines) {
			t.Fatalf("%s: %d json rows, %d csv lines: %v", d.Name, len(rows), len(rep.lines), err)
		}
		keys := map[string]bool{}
		for _, c := range d.Columns {
			keys[c.Key] = true
			if c.Label == "" || c.Type == "" {
				t.Errorf("%s.%s: label and type are required", d.Name, c.Key)
			}
		}
		for i, line := range rep.lines {
			if len(line) != len(d.Columns) {
				t.Fatalf("%s: line %d has %d cells for %d columns", d.Name, i, len(line), len(d.Columns))
			}
			for k := range rows[i] {
				if !keys[k] {
					t.Errorf("%s: row field %q is not a column", d.Name, k)
				}
			}
			for j, c := range d.Columns {
				if c.Type == TypeNumber && line[j] != "" {
					if _, err := strconv.ParseFloat(line[j], 64); err != nil {
						t.Errorf("%s.%s: %q is not a number", d.Name, c.Key, line[j])
					}
				}
			}
		}
		var buf bytes.Buffer
		if err := rep.CSV(&buf); err != nil {
			t.Fatal(err)
		}
		head, _ := csv.NewReader(&buf).Read()
		if len(head) != len(d.Columns) {
			t.Errorf("%s: csv header %v", d.Name, head)
		}
	}
}

func TestCSVHeadersKeepTheirNames(t *testing.T) {
	// Subscriptions and scripts read these headers (#23, #34).
	for name, want := range map[string]string{
		ReportASNs:         "origin_asn,prefixes,volume_mbps,probes,avg_loss_pct,avg_rtt_ms,improvements,steered_hours",
		ReportCountries:    "country,prefixes,volume_mbps,probes,avg_loss_pct,avg_rtt_ms,improvements,steered_hours",
		ReportCauses:       "day,performance,commit,cost,total",
		ReportTimeSeries:   "day,bucket,prefixes,before_loss_pct,after_loss_pct,before_rtt_ms,after_rtt_ms",
		ReportMitigations:  "id,prefix,action,target,match,source_countries,rate_mbps,routes,reason,mode,created,expires,announced,end,end_reason,announced_hours",
		ReportImprovements: "prefix,provider,native,cause,reason,mode,start,end,end_reason,hours,before_loss_pct,after_loss_pct,before_rtt_ms,after_rtt_ms,origin_asn,country,volume_mbps,cost_delta,est_savings",
	} {
		var buf bytes.Buffer
		if err := buildAll(t, name).CSV(&buf); err != nil {
			t.Fatal(err)
		}
		if got, _, _ := strings.Cut(buf.String(), "\n"); got != want {
			t.Errorf("%s header = %s", name, got)
		}
	}
}

// prefixesOf lists the prefix column, wherever the report has it.
func prefixesOf(rep Report) string {
	col := slices.IndexFunc(rep.Columns, func(c Column) bool { return c.Key == "prefix" })
	var out []string
	for _, l := range rep.lines {
		out = append(out, l[col])
	}
	return strings.Join(out, ",")
}

func TestFiltersNarrowEveryReportTheSameWay(t *testing.T) {
	v6 := netip.MustParsePrefix("2001:db8::/32")
	imps := func(mod func(*Query)) string {
		return prefixesOf(buildAll(t, ReportImprovements, mod))
	}
	for _, c := range []struct {
		name string
		mod  func(*Query)
		want string
	}{
		{"ipv6", func(q *Query) { q.IPVersion = 6 }, "2001:db8::/32"},
		{"ipv4", func(q *Query) { q.IPVersion = 4 }, "203.0.113.0/24,198.51.100.0/24,192.0.2.0/24,192.0.2.0/24,198.51.100.0/24"},
		{"native provider", func(q *Query) { q.Provider = "transit-b"; q.Cause = plugin.CauseCommit }, "203.0.113.0/24"},
		{"chosen provider", func(q *Query) { q.Provider = "transit-a"; q.Cause = plugin.CauseCommit }, "203.0.113.0/24"},
		{"asn from the improvement", func(q *Query) { q.ASN = 64502 }, "2001:db8::/32"},
		{"cause cost", func(q *Query) { q.Cause = plugin.CauseCost }, "198.51.100.0/24,198.51.100.0/24"},
		{"empty cause is performance", func(q *Query) { q.Cause = plugin.CausePerformance; q.Prefix = pfxA }, "192.0.2.0/24,192.0.2.0/24"},
		{"all of them", func(q *Query) {
			q.Prefix, q.ASN, q.Provider, q.Cause, q.IPVersion = v6, 64502, "transit-b", plugin.CausePerformance, 6
		}, "2001:db8::/32"},
		{"all but ip version", func(q *Query) { q.Prefix, q.IPVersion = v6, 4 }, ""},
	} {
		if got := imps(c.mod); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}

	// A probe-based report filters the probes and the improvements alike.
	probes := buildAll(t, ReportSummary, func(q *Query) { q.Provider = "transit-b" }).Rows.([]SummaryRow)[0]
	if probes.Probes != 16 || probes.Prefixes != 2 {
		t.Errorf("summary for transit-b: %+v", probes)
	}
	six := buildAll(t, ReportSummary, func(q *Query) { q.IPVersion = 6 }).Rows.([]SummaryRow)[0]
	if six.Probes != 3 || six.Improvements != 1 || six.Prefixes != 1 {
		t.Errorf("summary for IPv6: %+v", six)
	}
	prov := buildAll(t, ReportProviders, func(q *Query) { q.Provider = "transit-b" }).Rows.([]ProviderRow)
	if len(prov) != 1 || prov[0].Provider != "transit-b" || prov[0].Probes != 16 {
		t.Errorf("providers for transit-b: %+v", prov)
	}
	causes := buildAll(t, ReportCauses, func(q *Query) { q.Cause = plugin.CauseCost }).Rows.([]CauseRow)
	if len(causes) != 1 || causes[0].Cost != 1 || causes[0].Total != 1 {
		t.Errorf("causes for cost: %+v", causes)
	}
	if got := prefixesOf(buildAll(t, ReportPrefixes, func(q *Query) { q.ASN = 64500 })); !strings.Contains(got, "192.0.2.0/24") || strings.Contains(got, "198.51.100.0/24") || strings.Contains(got, "2001:db8::/32") {
		t.Errorf("prefixes for AS64500: %s", got)
	}
	if got := prefixesOf(buildAll(t, ReportMitigations, func(q *Query) { q.IPVersion = 6 })); got != "2001:db8::/32" {
		t.Errorf("mitigations for IPv6: %s", got)
	}
	if got := prefixesOf(buildAll(t, ReportAnomalies, func(q *Query) { q.Prefix = pfxA })); got != "192.0.2.0/24" {
		t.Errorf("anomalies for %s: %s", pfxA, got)
	}
}

func TestValidateRefusesWhatItWouldIgnore(t *testing.T) {
	for _, c := range []struct {
		name string
		q    Query
	}{
		{"cause on summary", Query{Name: ReportSummary, Cause: plugin.CauseCost}},
		{"provider on timeseries", Query{Name: ReportTimeSeries, Provider: "transit-a"}},
		{"asn on anomalies", Query{Name: ReportAnomalies, ASN: 64500}},
		{"cause value", Query{Name: ReportImprovements, Cause: "nope"}},
		{"ip version", Query{Name: ReportImprovements, IPVersion: 5}},
		{"sort key", Query{Name: ReportImprovements, Sort: "nope"}},
		{"top-N key outside the top-N reports", Query{Name: ReportImprovements, Sort: SortVolume}},
		{"order without a column", Query{Name: ReportPrefixes, Sort: SortLoss, Order: OrderDesc}},
		{"order value", Query{Name: ReportImprovements, Sort: "hours", Order: "up"}},
		{"unknown report", Query{Name: "nope"}},
	} {
		c.q.From, c.q.To = from, to
		if _, err := Build(seed(), c.q); err == nil {
			t.Errorf("%s accepted", c.name)
		}
	}
	// The top-N keys still work, and a column sort needs no order.
	for _, sort := range []string{SortProblems, SortVolume, SortLoss, "avg_rtt_ms"} {
		if _, err := Build(seed(), Query{Name: ReportPrefixes, From: from, To: to, Sort: sort}); err != nil {
			t.Errorf("sort=%s: %v", sort, err)
		}
	}
}

func TestSortByColumn(t *testing.T) {
	first := func(rep Report, col int) []string {
		var out []string
		for _, l := range rep.lines {
			out = append(out, l[col])
		}
		return out
	}
	hours := buildAll(t, ReportImprovements, func(q *Query) { q.Sort, q.Order = "hours", OrderDesc })
	if got := first(hours, 9); !slices.Equal(got, []string{"5", "4", "2", "2", "1", "1"}) {
		t.Errorf("hours desc: %v", got)
	}
	asc := buildAll(t, ReportImprovements, func(q *Query) { q.Sort = "hours" })
	if got := first(asc, 9); !slices.Equal(got, []string{"1", "1", "2", "2", "4", "5"}) {
		t.Errorf("hours asc: %v", got)
	}
	// Addresses sort as addresses, so 2001:db8:: follows 203.0.113.0.
	pfx := buildAll(t, ReportImprovements, func(q *Query) { q.Sort = "prefix" })
	if got := first(pfx, 0); got[0] != "192.0.2.0/24" || got[len(got)-1] != "2001:db8::/32" {
		t.Errorf("prefix asc: %v", got)
	}
	// An empty end (still active) sorts last both ways.
	for _, order := range []string{OrderAsc, OrderDesc} {
		end := first(buildAll(t, ReportImprovements, func(q *Query) { q.Sort, q.Order = "end", order }), 7)
		if end[len(end)-1] != "" || end[len(end)-2] != "" || end[0] == "" {
			t.Errorf("end %s: %v", order, end)
		}
	}
	// JSON rows and CSV lines are reordered together.
	rows := hours.Rows.([]ImprovementRow)
	for i, l := range hours.lines {
		if rows[i].Prefix != l[0] || f(rows[i].Hours) != l[9] {
			t.Fatalf("row %d: json %+v, csv %v", i, rows[i], l)
		}
	}
}

func TestSortBeforeTheRowLimit(t *testing.T) {
	// The default order is newest first, so the longest improvement is not first.
	def := buildAll(t, ReportImprovements, func(q *Query) { q.Limit = 1 })
	top := buildAll(t, ReportImprovements, func(q *Query) { q.Limit, q.Sort, q.Order = 1, "hours", OrderDesc })
	if def.lines[0][9] == "5" || top.lines[0][9] != "5" || top.Total != 6 || len(top.lines) != 1 || len(top.Rows.([]ImprovementRow)) != 1 {
		t.Errorf("default %v, sorted %v, total %d", def.lines, top.lines, top.Total)
	}
	// A top-N report is cut by its own key; a column sort replaces that key
	// before the cut.
	byLoss := buildAll(t, ReportPrefixes, func(q *Query) { q.Sort, q.Limit = SortLoss, 2 })
	byPrefix := buildAll(t, ReportPrefixes, func(q *Query) { q.Sort, q.Order, q.Limit = "prefix", OrderAsc, 100 })
	if byLoss.Total != 4 || len(byLoss.lines) != 2 || len(byPrefix.lines) != 4 || byPrefix.lines[0][0] != "192.0.2.0/24" {
		t.Errorf("loss %v, prefix %v", byLoss.lines, byPrefix.lines)
	}
	cut := buildAll(t, ReportPrefixes, func(q *Query) { q.Sort, q.Order, q.Limit = "prefix", OrderDesc, 2 })
	if cut.Total != 4 || len(cut.lines) != 2 || cut.lines[0][0] != byPrefix.lines[3][0] || cut.lines[1][0] != byPrefix.lines[2][0] {
		t.Errorf("column sort replaces the top key before the cut: %v, all %v", cut.lines, byPrefix.lines)
	}
}

// A report that is never cut refuses a limit instead of ignoring it.
func TestLimitRefusedOnReportsThatAreNeverCut(t *testing.T) {
	for _, d := range Reports {
		err := Query{Name: d.Name, From: from, To: to, Now: now, Limit: 5}.Validate()
		if d.Limited && err != nil {
			t.Errorf("%s: %v", d.Name, err)
		}
		if !d.Limited && (err == nil || !strings.Contains(err.Error(), "no limit")) {
			t.Errorf("%s: err = %v, want a limit refusal", d.Name, err)
		}
	}
}

type xlsxCell struct {
	Ref    string `xml:"r,attr"`
	Type   string `xml:"t,attr"`
	Value  string `xml:"v"`
	Inline string `xml:"is>t"`
}

func readXLSX(t *testing.T, b []byte) (files map[string]string, rows [][]xlsxCell) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	files = map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		body, _ := io.ReadAll(rc)
		rc.Close()
		files[f.Name] = string(body)
		var doc struct {
			Rows []struct {
				Cells []xlsxCell `xml:"c"`
			} `xml:"sheetData>row"`
		}
		if strings.HasSuffix(f.Name, ".xml") || strings.HasSuffix(f.Name, ".rels") {
			if err := xml.Unmarshal(body, &doc); err != nil {
				t.Fatalf("%s is not well-formed XML: %v", f.Name, err)
			}
		}
		for _, r := range doc.Rows {
			rows = append(rows, r.Cells)
		}
	}
	return files, rows
}

func TestXLSXHoldsTheFilteredSortedRows(t *testing.T) {
	h := everyReportHistory()
	h.Improvements[0].Reason = `=HYPERLINK("http://192.0.2.1","x") & <b>`
	rep, err := Build(h, Query{Name: ReportImprovements, From: from, To: to, Now: now, Sort: "hours", Order: OrderDesc, Cause: plugin.CausePerformance})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := rep.XLSX(&buf); err != nil {
		t.Fatal(err)
	}
	files, rows := readXLSX(t, buf.Bytes())
	for _, name := range []string{"[Content_Types].xml", "_rels/.rels", "xl/workbook.xml", "xl/_rels/workbook.xml.rels", "xl/styles.xml", "xl/worksheets/sheet1.xml"} {
		if files[name] == "" {
			t.Errorf("%s is missing", name)
		}
	}
	if !strings.Contains(files["xl/workbook.xml"], `name="improvements"`) {
		t.Errorf("sheet name: %s", files["xl/workbook.xml"])
	}
	// The filter drops the cost and commit rows; the header is the labels.
	if len(rows) != rep.Len()+1 || rep.Len() != 3 {
		t.Fatalf("%d xlsx rows for %d report rows", len(rows), rep.Len())
	}
	if rows[0][0].Inline != "Prefix" || rows[0][9].Inline != "Active (h)" || rows[0][0].Type != "inlineStr" {
		t.Errorf("header: %+v", rows[0])
	}
	for i, line := range rep.lines {
		row := map[string]xlsxCell{}
		for _, c := range rows[i+1] {
			row[strings.TrimRight(c.Ref, "0123456789")] = c
		}
		if row["A"].Inline != line[0] || row["J"].Value != line[9] || row["J"].Type != "" {
			t.Errorf("row %d: %+v vs %v", i, row, line)
		}
	}
	// Hours are sorted, descending, and text that looks like a formula is text.
	if got := []string{rep.lines[0][9], rep.lines[1][9], rep.lines[2][9]}; !slices.Equal(got, []string{"5", "2", "1"}) {
		t.Errorf("hours: %v", got)
	}
	found := false
	for _, r := range rows[1:] {
		for _, c := range r {
			if strings.HasPrefix(c.Inline, "=HYPERLINK") {
				found = c.Type == "inlineStr" && strings.HasSuffix(c.Inline, "& <b>")
			}
		}
	}
	if !found {
		t.Error("the formula-looking reason is not kept as text")
	}
	if strings.Contains(files["xl/worksheets/sheet1.xml"], "<f>") {
		t.Error("the sheet has a formula")
	}
}

func TestColName(t *testing.T) {
	for i, want := range map[int]string{0: "A", 25: "Z", 26: "AA", 27: "AB", 51: "AZ", 52: "BA", 701: "ZZ", 702: "AAA"} {
		if got := colName(i); got != want {
			t.Errorf("colName(%d) = %s, want %s", i, got, want)
		}
	}
}

func TestASNFilterMatchesTheOriginRecordedWithTheImprovement(t *testing.T) {
	h := seed()
	// The prefix is stored under 64501 but this improvement was recorded under 64500, as Search and the filter see it.
	h.Prefixes = []plugin.PrefixInfo{{Prefix: pfxA, OriginASN: 64501}}
	h.Improvements = []plugin.ImprovementRecord{
		{ID: "1", Prefix: pfxA, Provider: "transit-a", Start: from.Add(time.Hour), End: from.Add(2 * time.Hour), OriginASN: 64500},
		{ID: "2", Prefix: pfxA, Provider: "transit-a", Start: from.Add(3 * time.Hour), End: from.Add(4 * time.Hour)},
	}
	ids := func(asn uint32) string {
		rep, err := Build(h, Query{Name: ReportImprovements, From: from, To: to, Now: now, ASN: asn})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range rep.Rows.([]ImprovementRow) {
			out = append(out, strconv.Itoa(int(r.Start.Sub(from).Hours())))
		}
		slices.Sort(out)
		return strings.Join(out, ",")
	}
	if got := ids(64500); got != "1" {
		t.Errorf("recorded origin: %q", got)
	}
	if got := ids(64501); got != "3" {
		t.Errorf("stored origin applies only to an improvement with none: %q", got)
	}
}

// Probe rows carry no origin of their own: the asn filter uses the prefix's
// stored origin, like Search, and not an improvement's recorded one (this one is outside the range).
func TestASNFilterOnProbeRowsUsesTheStoredPrefixOrigin(t *testing.T) {
	h := plugin.History{
		Prefixes:     []plugin.PrefixInfo{{Prefix: pfxA, OriginASN: 64501}},
		Improvements: []plugin.ImprovementRecord{{ID: "1", Prefix: pfxA, Provider: "transit-a", Start: from.Add(-48 * time.Hour), End: from.Add(-47 * time.Hour), OriginASN: 64500}},
		Buckets:      []plugin.ProbeBucket{{Day: from, Prefix: pfxA, Provider: "transit-a", Probes: 3, Measured: 3, LossSum: 3, RTTSumMs: 30}},
	}
	count := func(asn uint32) int {
		rep, err := Build(h, Query{Name: ReportPrefixes, From: from, To: to, Now: now, ASN: asn})
		if err != nil {
			t.Fatal(err)
		}
		return len(rep.Rows.([]PrefixRow))
	}
	if got := count(64501); got != 1 {
		t.Errorf("stored origin: %d rows, want 1", got)
	}
	if got := count(64500); got != 0 {
		t.Errorf("improvement origin: %d rows, want 0", got)
	}
}

// A prefix with no stored origin shows its improvement's origin, so the asn
// filter keeps its probe counts on that row too.
func TestASNFilterKeepsProbesOfAPrefixWithNoStoredOrigin(t *testing.T) {
	h := plugin.History{
		Improvements: []plugin.ImprovementRecord{{ID: "1", Prefix: pfxA, Provider: "transit-a", Start: from.Add(time.Hour), End: from.Add(2 * time.Hour), OriginASN: 64500}},
		Buckets:      []plugin.ProbeBucket{{Day: from, Prefix: pfxA, Provider: "transit-a", Probes: 3, Measured: 3, LossSum: 3, RTTSumMs: 30}},
	}
	rows := func(asn uint32) []PrefixRow {
		rep, err := Build(h, Query{Name: ReportPrefixes, From: from, To: to, Now: now, ASN: asn})
		if err != nil {
			t.Fatal(err)
		}
		return rep.Rows.([]PrefixRow)
	}
	if got := rows(64500); len(got) != 1 || got[0].OriginASN != 64500 || got[0].Probes != 3 || got[0].Improvements != 1 || got[0].SteeredHours != 1 {
		t.Errorf("improvement origin: %+v", got)
	}
	if got := rows(64501); len(got) != 0 {
		t.Errorf("other origin: %+v", got)
	}
}

func TestCompareCellsFallsBackToTextOnUnparsableCells(t *testing.T) {
	for _, c := range []struct {
		typ, a, b string
		want      int
	}{
		{TypeNumber, "9", "10", -1},
		{TypeNumber, "n/a", "10", 1},
		{TypePrefix, "192.0.2.0/24", "198.51.100.0/24", -1},
		{TypePrefix, "bad", "192.0.2.0/24", 1},
	} {
		if got := compareCells(c.typ, c.a, c.b); got != c.want {
			t.Errorf("%s %q vs %q: got %d, want %d", c.typ, c.a, c.b, got, c.want)
		}
	}
}
