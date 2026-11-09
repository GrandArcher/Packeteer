package httpapi

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
)

// pagedRows builds n measured prefixes inside 2001:db8::/32, already in
// prefix order. Row i has origin AS 64500+i%7. Every third row has a
// recommended exit that differs from the current one, with a gain of
// i/3 and an exit loss of i%10 percent. RTT falls as i grows.
func pagedRows(n int) []Prefix {
	rows := make([]Prefix, 0, n)
	for i := range n {
		b := netip.MustParseAddr("2001:db8::").As16()
		binary.BigEndian.PutUint32(b[4:8], uint32(i))
		p := netip.PrefixFrom(netip.AddrFrom16(b), 64)
		loss, rtt := float64(i%10), float64(n-i)
		row := Prefix{
			Prefix: p.String(), Current: "lab-a", Recommended: "lab-a", InRIB: true,
			Probes: []Probe{
				{Provider: "lab-a", OK: true, LossPct: loss, RTTAvgMs: rtt},
				{Provider: "lab-b", OK: true, LossPct: 0, RTTAvgMs: 1},
			},
			Paths:       []LearnedPath{{Provider: "lab-a", NextHop: "192.0.2.1", ASPath: []uint32{64496, uint32(64500 + i%7)}}},
			ExitLossPct: &loss, ExitRTTMs: &rtt,
		}
		if i%3 == 0 {
			row.Recommended = "lab-b"
			row.Gain = float64(i / 3)
		}
		rows = append(rows, row)
	}
	return rows
}

func pagedServer(t *testing.T, n int) (*Snapshot, string) {
	t.Helper()
	snap := Snapshot{Version: "test", Mode: "observe", Started: true, Prefixes: pagedRows(n)}
	snap.ASNMap = assembleASNMap(snap.Prefixes)
	return &snap, newTestServer(t, snap, "", "").URL
}

func getPage(t *testing.T, base, query string) (PrefixPage, int, []byte) {
	t.Helper()
	code, _, body := do(t, http.MethodGet, base+"/api/prefixes"+query, "", "")
	var out PrefixPage
	if code == http.StatusOK {
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	return out, code, body
}

func prefixNames(rows []Prefix) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Prefix
	}
	return out
}

func TestPrefixesPaging(t *testing.T) {
	snap, base := pagedServer(t, 250)
	all := prefixNames(snap.Prefixes)

	// An unpaged client gets the documented first page of the whole table.
	got, code, _ := getPage(t, base, "")
	if code != 200 || got.Total != 250 || got.Measured != 250 || got.Limit != defaultPrefixLimit || got.Offset != 0 {
		t.Fatalf("default page = %d %+v", code, got)
	}
	if !reflect.DeepEqual(prefixNames(got.Prefixes), all[:defaultPrefixLimit]) {
		t.Fatalf("default page rows = %v", prefixNames(got.Prefixes))
	}

	got, _, _ = getPage(t, base, "?limit=40&offset=240")
	if !reflect.DeepEqual(prefixNames(got.Prefixes), all[240:]) || got.Total != 250 {
		t.Fatalf("last page = %v total %d", prefixNames(got.Prefixes), got.Total)
	}
	got, _, body := getPage(t, base, "?offset=1000")
	if len(got.Prefixes) != 0 || got.Total != 250 {
		t.Fatalf("past the end = %+v", got)
	}
	if !json.Valid(body) || !reflect.DeepEqual(got.Prefixes, []Prefix{}) {
		t.Fatalf("past the end must encode []: %s", body)
	}

	cases := []struct {
		name, query string
		want        func(r Prefix) bool
		count       int
	}{
		{"differs", "?differs=true&limit=500", func(r Prefix) bool { return r.Recommended != r.Current }, 84},
		{"provider is case-insensitive", "?provider=LAB-B&limit=500", func(r Prefix) bool { return true }, 250},
		{"provider matches a recommended exit only by name", "?provider=lab-b&differs=1&limit=500", func(r Prefix) bool { return r.Recommended == "lab-b" }, 84},
		{"unknown provider", "?provider=lab", func(r Prefix) bool { return false }, 0},
		{"origin AS", "?asn=64503&limit=500", func(r Prefix) bool { return r.Paths[0].ASPath[1] == 64503 }, 36},
		{"origin AS with prefix", "?asn=AS64503&limit=500", func(r Prefix) bool { return r.Paths[0].ASPath[1] == 64503 }, 36},
		{"transit AS is not the origin", "?asn=64496", func(r Prefix) bool { return false }, 0},
		{"combined", "?differs=1&asn=64500&limit=500", func(r Prefix) bool { return r.Recommended != r.Current && r.Paths[0].ASPath[1] == 64500 }, 12},
	}
	for _, c := range cases {
		got, code, body := getPage(t, base, c.query)
		if code != 200 || got.Total != c.count {
			t.Errorf("%s: %d total %d want %d (%s)", c.name, code, got.Total, c.count, body)
			continue
		}
		for _, r := range got.Prefixes {
			if !c.want(r) {
				t.Errorf("%s: unexpected row %s", c.name, r.Prefix)
			}
		}
	}

	// A CIDR is an exact match, other text a substring.
	got, _, _ = getPage(t, base, "?prefix="+all[7])
	if got.Total != 1 || got.Prefixes[0].Prefix != all[7] {
		t.Fatalf("exact prefix = %+v", got)
	}
	got, _, _ = getPage(t, base, "?prefix=db8:0:1:")
	if got.Total != 1 || got.Prefixes[0].Prefix != "2001:db8:0:1::/64" {
		t.Fatalf("substring = %v", prefixNames(got.Prefixes))
	}
	// Filters apply before the window, and the window moves inside them.
	got, _, _ = getPage(t, base, "?differs=1&limit=10&offset=80")
	if got.Total != 84 || len(got.Prefixes) != 4 {
		t.Fatalf("filtered window = total %d rows %d", got.Total, len(got.Prefixes))
	}
}

func TestPrefixesSort(t *testing.T) {
	_, base := pagedServer(t, 250)
	got, _, _ := getPage(t, base, "?sort=gain&limit=3")
	// The largest gain is row 249 (249/3 = 83), then 246, 243.
	want := []float64{83, 82, 81}
	for i, r := range got.Prefixes {
		if r.Gain != want[i] {
			t.Fatalf("gain order = %v", prefixNames(got.Prefixes))
		}
	}
	got, _, _ = getPage(t, base, "?sort=loss&limit=500")
	for i := 1; i < len(got.Prefixes); i++ {
		if *got.Prefixes[i-1].ExitLossPct < *got.Prefixes[i].ExitLossPct {
			t.Fatalf("loss not worst first at %d", i)
		}
	}
	if *got.Prefixes[0].ExitLossPct != 9 {
		t.Fatalf("worst loss = %v", *got.Prefixes[0].ExitLossPct)
	}
	got, _, _ = getPage(t, base, "?sort=rtt&limit=2")
	if *got.Prefixes[0].ExitRTTMs != 250 || *got.Prefixes[1].ExitRTTMs != 249 {
		t.Fatalf("rtt order = %v %v", *got.Prefixes[0].ExitRTTMs, *got.Prefixes[1].ExitRTTMs)
	}
	// Equal keys keep prefix order, so pages do not overlap or skip.
	p1, _, _ := getPage(t, base, "?sort=loss&limit=100&offset=0")
	p2, _, _ := getPage(t, base, "?sort=loss&limit=100&offset=100")
	p3, _, _ := getPage(t, base, "?sort=loss&limit=100&offset=200")
	seen := map[string]bool{}
	for _, page := range [][]Prefix{p1.Prefixes, p2.Prefixes, p3.Prefixes} {
		for _, r := range page {
			if seen[r.Prefix] {
				t.Fatalf("%s on two pages", r.Prefix)
			}
			seen[r.Prefix] = true
		}
	}
	if len(seen) != 250 {
		t.Fatalf("pages cover %d of 250 rows", len(seen))
	}
}

// Rows with no successful probe sort after measured rows for loss and RTT.
func TestPrefixesSortUnmeasuredLast(t *testing.T) {
	rows := pagedRows(3)
	rows[0].ExitLossPct, rows[0].ExitRTTMs = nil, nil
	q := prefixQuery{sort: "loss", limit: 10}
	got, _ := q.page(rows)
	if got[2].Prefix != rows[0].Prefix {
		t.Fatalf("loss order = %v", prefixNames(got))
	}
	q.sort = "rtt"
	got, _ = q.page(rows)
	if got[2].Prefix != rows[0].Prefix {
		t.Fatalf("rtt order = %v", prefixNames(got))
	}
}

func TestPrefixesBadQuery(t *testing.T) {
	_, base := pagedServer(t, 3)
	for _, q := range []string{
		"?limit=0", "?limit=501", "?limit=x", "?offset=-1", "?offset=x", "?sort=score", "?asn=0", "?asn=x", "?asn=4294967296", "?differs=maybe",
	} {
		if _, code, body := getPage(t, base, q); code != http.StatusBadRequest {
			t.Errorf("%s = %d %s", q, code, body)
		}
	}
}

// With 100k measured prefixes a page and the ASN map stay small.
func TestPrefixesLargeTableIsBounded(t *testing.T) {
	_, base := pagedServer(t, 100_000)
	got, code, body := getPage(t, base, "")
	if code != 200 || got.Total != 100_000 || len(got.Prefixes) != defaultPrefixLimit {
		t.Fatalf("100k default page = %d total %d rows %d", code, got.Total, len(got.Prefixes))
	}
	if len(body) > 256<<10 {
		t.Fatalf("default page is %d bytes", len(body))
	}
	_, _, big := getPage(t, base, "?limit=500&sort=gain")
	if len(big) > 1<<20 {
		t.Fatalf("largest page is %d bytes", len(big))
	}
	if got.ASNTotal != 7 || len(got.ASNMap) != 7 {
		t.Fatalf("asn map = %d of %d", len(got.ASNMap), got.ASNTotal)
	}
	for _, n := range got.ASNMap {
		for _, s := range n.Sites {
			if len(s.Prefixes) != asnSitePrefixes || s.Count < 14000 {
				t.Fatalf("AS%d site lists %d of %d", n.ASN, len(s.Prefixes), s.Count)
			}
		}
	}
	one, _, _ := getPage(t, base, "?asn=64502&limit=5")
	if one.Total < 14000 || len(one.ASNMap) != 1 || one.ASNMap[0].ASN != 64502 || one.ASNTotal != 1 {
		t.Fatalf("asn filter = total %d map %+v", one.Total, one.ASNMap)
	}
}

// The ASN map cuts a large number of origin ASNs to asnMapNodes and says
// how many there are, without changing the snapshot behind it.
func TestBoundASNMap(t *testing.T) {
	var nodes []ASNNode
	for i := range 300 {
		prefs := make([]string, 20)
		for j := range prefs {
			prefs[j] = fmt.Sprintf("2001:db8:%x:%x::/64", i, j)
		}
		nodes = append(nodes, ASNNode{ASN: uint32(64512 + i), Sites: []ASNSite{{Provider: "lab-a", Prefixes: prefs, Count: len(prefs)}}})
	}
	out, total := boundASNMap(nodes, 0)
	if total != 300 || len(out) != asnMapNodes {
		t.Fatalf("bounded %d of %d", len(out), total)
	}
	if s := out[0].Sites[0]; len(s.Prefixes) != asnSitePrefixes || s.Count != 20 {
		t.Fatalf("site = %d listed, count %d", len(s.Prefixes), s.Count)
	}
	if len(nodes[0].Sites[0].Prefixes) != 20 {
		t.Fatal("the snapshot was truncated")
	}
	out, total = boundASNMap(nodes, 64600)
	if total != 1 || len(out) != 1 || out[0].ASN != 64600 {
		t.Fatalf("one AS = %+v", out)
	}
	if out, total = boundASNMap(nodes, 65000); total != 0 || out == nil || len(out) != 0 {
		t.Fatalf("missing AS = %v %d", out, total)
	}
}

// The gain and exit measurement come from the decision and the probes.
func TestPrefixGainAndExit(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	p := netip.MustParsePrefix("198.51.100.0/24")
	q := netip.MustParsePrefix("203.0.113.0/24")
	result := func(provider string, pfx netip.Prefix, loss float64, rtt time.Duration) probe.Result {
		return probe.Result{Provider: provider, Prefix: pfx, Time: at,
			Stats: probe.Stats{Sent: 4, Received: 4, LossPct: loss, RTTAvg: rtt}}
	}
	snap := Assemble(Input{
		Mode: "observe",
		Results: []probe.Result{
			result("lab-a", p, 2, 30*time.Millisecond), result("lab-b", p, 0, 10*time.Millisecond),
			result("lab-a", q, 1, 20*time.Millisecond), result("lab-b", q, 0, 5*time.Millisecond),
		},
		Decisions: []policy.Decision{
			{Prefix: p, Native: "lab-a", Current: "lab-a", Recommended: "lab-b", Action: policy.ActionImprove, Candidates: []policy.Candidate{
				{Provider: "lab-a", Score: 9, Usable: true}, {Provider: "lab-b", Score: 4, Usable: true}}},
			// The recommended exit was not usable, so there is no gain to rank by.
			{Prefix: q, Native: "lab-a", Current: "lab-a", Recommended: "lab-b", Action: policy.ActionKeep, Candidates: []policy.Candidate{
				{Provider: "lab-a", Score: 9, Usable: true}, {Provider: "lab-b", Usable: false}}},
		},
	})
	byPrefix := map[string]Prefix{}
	for _, r := range snap.Prefixes {
		byPrefix[r.Prefix] = r
	}
	a, b := byPrefix[p.String()], byPrefix[q.String()]
	if a.Gain != 5 || *a.ExitLossPct != 2 || *a.ExitRTTMs != 30 {
		t.Fatalf("gain %v exit %v/%v", a.Gain, *a.ExitLossPct, *a.ExitRTTMs)
	}
	if b.Gain != 0 || *b.ExitLossPct != 1 || *b.ExitRTTMs != 20 {
		t.Fatalf("unusable recommended: gain %v exit %v/%v", b.Gain, *b.ExitLossPct, *b.ExitRTTMs)
	}
}

// With no probe through the current exit the recommended exit's probe is used.
func TestPrefixExitFallsBackToRecommended(t *testing.T) {
	row := Prefix{Current: "lab-a", Recommended: "lab-b", Probes: []Probe{
		{Provider: "lab-a", OK: false, Error: "no reply"},
		{Provider: "lab-b", OK: true, LossPct: 3, RTTAvgMs: 12},
	}}
	row.setExit()
	if row.ExitLossPct == nil || *row.ExitLossPct != 3 || *row.ExitRTTMs != 12 {
		t.Fatalf("exit = %+v", row)
	}
	none := Prefix{Current: "lab-a", Probes: []Probe{{Provider: "lab-a", OK: false}}}
	none.setExit()
	if none.ExitLossPct != nil || none.ExitRTTMs != nil {
		t.Fatalf("unmeasured row has an exit: %+v", none)
	}
}
