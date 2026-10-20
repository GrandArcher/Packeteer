package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/internal/troubleshoot"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var (
	searchP198 = netip.MustParsePrefix("198.51.100.0/24")
	searchP203 = netip.MustParsePrefix("203.0.113.0/24")
)

// searchInput is sampleInput with an AS path on each learned prefix:
// 198.51.100.0/24 originates in AS64510 and 203.0.113.0/24 in AS64511.
func searchInput() Input {
	in := sampleInput()
	r := in.Routes[searchP198]
	r.ASPath = []uint32{64496, 64510}
	in.Routes[searchP198] = r
	in.Routes[searchP203] = rib.Route{Prefix: searchP203, NextHop: netip.MustParseAddr("192.0.2.2"), Provider: "transit-b", ASPath: []uint32{64496, 64511}}
	in.Paths = map[netip.Prefix][]rib.Route{searchP198: {in.Routes[searchP198]}, searchP203: {in.Routes[searchP203]}}
	return in
}

// fakeSearchRIB holds routes and finds them the way rib.View does.
type fakeSearchRIB []rib.Route

func (f fakeSearchRIB) Find(keep func(rib.Route) bool, before func(a, b rib.Route) bool, limit int) ([]rib.Route, int) {
	var out []rib.Route
	for _, r := range f {
		if keep(r) {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b rib.Route) int {
		switch {
		case before(a, b):
			return -1
		case before(b, a):
			return 1
		}
		return 0
	})
	total := len(out)
	return out[:min(total, limit)], total
}

type nameWhois struct{ plugin.Base }

func (nameWhois) Lookup(_ context.Context, q string) (plugin.WhoisResult, error) {
	return plugin.WhoisResult{Query: q, Kind: "asn", Name: "Documentation Carrier"}, nil
}

type searchEnv struct {
	calls int
	h     http.Handler
	hist  *fakeReports
	tools *troubleshoot.Tools
}

func newSearchEnv(t *testing.T, withHistory bool, routes fakeSearchRIB) *searchEnv {
	t.Helper()
	e := &searchEnv{hist: &fakeReports{}, tools: troubleshoot.New(troubleshoot.Options{Enabled: true, Whois: nameWhois{}})}
	snap := Assemble(searchInput())
	snap.Providers = append(snap.Providers, Provider{Name: "ix-peer-a", Exchange: "ix-1", PeerASN: 64512}, Provider{Name: "transit-lab", ASN: 64496, Type: "transit"})
	opt := Options{Snapshot: func() Snapshot { return snap }, Tools: e.tools}
	if withHistory {
		opt.Reports = e.hist
	}
	srv, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	if routes != nil {
		srv.SetSearchRIB(routes)
	}
	e.h = srv.Handler()
	return e
}

func (e *searchEnv) get(t *testing.T, q string) (int, SearchResponse, http.Header) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/search?q="+url.QueryEscape(q), nil)
	// A caller of its own, so that the rate limit does not end a long test.
	e.calls++
	req.RemoteAddr = fmt.Sprintf("10.%d.%d.1:1234", e.calls/250, e.calls%250)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	var got SearchResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("%q: %v: %s", q, err, rec.Body)
		}
	}
	return rec.Code, got, rec.Header()
}

func prefixesOf[T any](g searchGroup[T], f func(T) string) []string {
	var out []string
	for _, r := range g.Rows {
		out = append(out, f(r))
	}
	return out
}

func testRoutes() fakeSearchRIB {
	return fakeSearchRIB{
		{Prefix: searchP198, NextHop: netip.MustParseAddr("192.0.2.1"), Provider: "transit-a", ASPath: []uint32{64496, 64510}, Age: time.Unix(1000, 0)},
		{Prefix: netip.MustParsePrefix("198.51.100.128/25"), NextHop: netip.MustParseAddr("192.0.2.1"), ASPath: []uint32{64496, 64510}, Age: time.Unix(2000, 0)},
		{Prefix: netip.MustParsePrefix("198.51.0.0/16"), NextHop: netip.MustParseAddr("192.0.2.2"), ASPath: []uint32{64496, 64513}, Age: time.Unix(500, 0)},
		{Prefix: searchP203, NextHop: netip.MustParseAddr("192.0.2.2"), ASPath: []uint32{64496, 64511}, Age: time.Unix(3000, 0)},
	}
}

func TestSearchPrefixGroupsLiveAndHistory(t *testing.T) {
	e := newSearchEnv(t, true, testRoutes())
	code, got, _ := e.get(t, "198.51.100.0/24")
	if code != http.StatusOK || got.Kind != kindPrefix || got.Limit != searchLimit || got.Query != "198.51.100.0/24" {
		t.Fatalf("code %d, answer %+v", code, got.meta)
	}
	if rows := got.Measured.Rows; len(rows) != 1 || rows[0].Prefix != "198.51.100.0/24" || rows[0].Relation != netpfx.RelExact ||
		rows[0].OriginASN != 64510 || rows[0].Recommended != "transit-b" {
		t.Errorf("measured = %+v", got.Measured)
	}
	// The RIB list is newest first: the more specific, the exact route,
	// then the covering /16. The unrelated /24 is not in it.
	want := []string{"198.51.100.128/25|more-specific", "198.51.100.0/24|exact", "198.51.0.0/16|covering"}
	if have := prefixesOf(got.RIB, func(r SearchRoute) string { return r.Prefix + "|" + r.Relation }); !slices.Equal(have, want) || got.RIB.Total != 3 {
		t.Errorf("rib = %v of %d", have, got.RIB.Total)
	}
	if rows := got.Recommendations.Rows; len(rows) != 1 || rows[0].Provider != "transit-b" || rows[0].Native != "transit-a" || rows[0].Relation != netpfx.RelExact {
		t.Errorf("recommendations = %+v", got.Recommendations)
	}
	if !got.History.Enabled || got.History.Days != searchDays || got.History.Note != "" {
		t.Errorf("history = %+v", got.History)
	}
	if rows := got.Improvements.Rows; len(rows) != 1 || rows[0].Prefix != "198.51.100.0/24" || rows[0].Relation != netpfx.RelExact {
		t.Errorf("history improvements = %+v", got.Improvements)
	}
	if rows := got.Rollups.Rows; len(rows) != 1 || rows[0].Prefix != "198.51.100.0/24" || rows[0].Probes != 4 {
		t.Errorf("history rollups = %+v", got.Rollups)
	}
	if q := e.hist.search; q.Prefix != searchP198 || len(q.ASNs) != 0 || q.Limit != searchLimit ||
		q.To.Sub(q.From) < searchDays*24*time.Hour-time.Hour {
		t.Errorf("history query = %+v", q)
	}
}

func TestSearchAddressFindsCoveringPrefixes(t *testing.T) {
	e := newSearchEnv(t, false, testRoutes())
	_, got, _ := e.get(t, "198.51.100.200")
	if got.Kind != kindPrefix {
		t.Fatalf("kind = %s", got.Kind)
	}
	want := []string{"198.51.100.128/25|covering", "198.51.100.0/24|covering", "198.51.0.0/16|covering"}
	have := prefixesOf(got.RIB, func(r SearchRoute) string { return r.Prefix + "|" + r.Relation })
	// 198.51.100.128/25 holds .200; /24 and /16 cover it too.
	if !slices.Equal(have, want) {
		t.Errorf("rib = %v, want %v", have, want)
	}
}

func TestSearchASNForms(t *testing.T) {
	e := newSearchEnv(t, true, testRoutes())
	var first SearchResponse
	for i, q := range []string{"AS64510", "as64510", "64510", " AS64510 "} {
		code, got, _ := e.get(t, q)
		if code != http.StatusOK || got.Kind != kindASN {
			t.Fatalf("%q: %d kind %s", q, code, got.Kind)
		}
		if rows := got.ASNs.Rows; len(rows) != 1 || rows[0].ASN != 64510 || rows[0].Name != "" {
			t.Errorf("%q asns = %+v", q, got.ASNs)
		}
		if i == 0 {
			first = got
			continue
		}
		if got.Measured.Total != first.Measured.Total || got.RIB.Total != first.RIB.Total || got.Improvements.Total != first.Improvements.Total {
			t.Errorf("%q differs from AS64510", q)
		}
	}
	if rows := first.Measured.Rows; len(rows) != 1 || rows[0].Prefix != "198.51.100.0/24" || rows[0].Relation != "" {
		t.Errorf("measured = %+v", first.Measured)
	}
	if have := prefixesOf(first.RIB, func(r SearchRoute) string { return r.Prefix }); !slices.Equal(have, []string{"198.51.100.128/25", "198.51.100.0/24"}) {
		t.Errorf("rib = %v", have)
	}
	if rows := first.Improvements.Rows; len(rows) != 1 || rows[0].OriginASN != 64510 {
		t.Errorf("history improvements = %+v", first.Improvements)
	}
	if q := e.hist.search; !slices.Equal(q.ASNs, []uint32{64510}) || q.Prefix.IsValid() {
		t.Errorf("history query = %+v", q)
	}
}

func TestSearchASNameUsesConfiguredAndLookedUpNames(t *testing.T) {
	e := newSearchEnv(t, true, testRoutes())
	// Before any whois lookup only the exchange peer in the config has a name.
	_, got, _ := e.get(t, "carrier")
	if got.Kind != kindName || got.ASNs.Total != 0 {
		t.Fatalf("before a lookup: %+v", got.ASNs)
	}
	if _, err := e.tools.Whois(context.Background(), "AS64511"); err != nil {
		t.Fatal(err)
	}
	_, got, _ = e.get(t, "CARRIER")
	if rows := got.ASNs.Rows; len(rows) != 1 || rows[0].ASN != 64511 || rows[0].Name != "Documentation Carrier" || rows[0].Source != "whois" {
		t.Fatalf("asns = %+v", got.ASNs)
	}
	if rows := got.Measured.Rows; len(rows) != 1 || rows[0].Prefix != "203.0.113.0/24" || rows[0].OriginASN != 64511 {
		t.Errorf("measured = %+v", rows)
	}
	if have := prefixesOf(got.RIB, func(r SearchRoute) string { return r.Prefix }); !slices.Equal(have, []string{"203.0.113.0/24"}) {
		t.Errorf("rib = %v", have)
	}
	if rows := got.Improvements.Rows; len(rows) != 1 || rows[0].Prefix != "203.0.113.0/24" {
		t.Errorf("history improvements = %+v", got.Improvements)
	}

	_, got, _ = e.get(t, "ix-peer")
	if rows := got.ASNs.Rows; len(rows) != 1 || rows[0].ASN != 64512 || rows[0].Source != "provider" {
		t.Errorf("provider name asns = %+v", got.ASNs)
	}
}

func TestSearchFindsProviderASN(t *testing.T) {
	e := newSearchEnv(t, true, testRoutes())
	_, got, _ := e.get(t, "transit-lab")
	if rows := got.ASNs.Rows; len(rows) != 1 || rows[0].ASN != 64496 || rows[0].Source != "provider" {
		t.Fatalf("asns = %+v", got.ASNs)
	}
}

func TestSearchRefusesInvalidInput(t *testing.T) {
	e := newSearchEnv(t, true, testRoutes())
	for _, q := range []string{
		"", " ", "x", "AS0", "0", "AS4294967296", "99999999999", "192.0.2", "192.0.2.0/33", "fe80::1%eth0",
		"<script>alert(1)</script>", "a;b", "name\nline", "AS64510\x00", "../etc/passwd", strings.Repeat("a", maxSearchLen+1), "::ffff:192.0.2.0/120",
	} {
		if code, _, _ := e.get(t, q); code != http.StatusBadRequest {
			t.Errorf("q=%q: %d, want 400", q, code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/api/search", nil)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "AS number") {
		t.Errorf("no q: %d %s", rec.Code, rec.Body)
	}
	if e.hist.search.Limit != 0 {
		t.Error("an invalid search reached the history store")
	}
}

func TestSearchWithoutStorageIsLiveOnly(t *testing.T) {
	e := newSearchEnv(t, false, testRoutes())
	code, got, _ := e.get(t, "AS64510")
	if code != http.StatusOK || got.History.Enabled || !strings.Contains(got.History.Note, "History is off") {
		t.Fatalf("code %d history %+v", code, got.History)
	}
	if got.Measured.Total != 1 || got.RIB.Total != 2 {
		t.Errorf("live results = %d measured, %d rib", got.Measured.Total, got.RIB.Total)
	}
	if got.Improvements.Rows == nil || got.Rollups.Rows == nil || len(got.Improvements.Rows)+len(got.Rollups.Rows) != 0 {
		t.Errorf("history lists = %+v %+v", got.Improvements, got.Rollups)
	}
}

func TestSearchHistoryErrorKeepsLiveResults(t *testing.T) {
	e := newSearchEnv(t, true, testRoutes())
	e.hist.searchErr = errors.New("database is locked")
	code, got, _ := e.get(t, "AS64510")
	if code != http.StatusOK || !got.History.Enabled || !strings.Contains(got.History.Note, "did not answer") {
		t.Fatalf("code %d history %+v", code, got.History)
	}
	if strings.Contains(got.History.Note, "locked") || got.Measured.Total != 1 {
		t.Errorf("history note leaks the error or live rows are lost: %+v", got)
	}
}

func TestSearchCapsEveryLiveList(t *testing.T) {
	var many fakeSearchRIB
	var rows []Prefix
	var imps []Improvement
	for i := range 40 {
		many = append(many, rib.Route{Prefix: netip.MustParsePrefix(fmt.Sprintf("198.51.100.%d/32", i)), ASPath: []uint32{64510}, Age: time.Unix(int64(i), 0)})
		name := fmt.Sprintf("198.51.100.%d/32", i)
		rows = append(rows, Prefix{Prefix: name, Paths: []LearnedPath{{ASPath: []uint32{64496, 64510}}},
			Probes: []Probe{{Time: time.Unix(int64(i), 0)}}})
		imps = append(imps, Improvement{Prefix: name, Provider: "transit-b", Since: time.Unix(int64(i), 0)})
	}
	m := matcher{prefix: netip.MustParsePrefix("198.51.100.0/24")}

	measured := searchMeasured(rows, m)
	if measured.Total != 40 || len(measured.Rows) != searchLimit {
		t.Fatalf("measured %d rows of %d", len(measured.Rows), measured.Total)
	}
	// Most recently probed first: the kept rows are .39 down to .15.
	if measured.Rows[0].Prefix != "198.51.100.39/32" || measured.Rows[searchLimit-1].Prefix != "198.51.100.15/32" {
		t.Errorf("measured rows run from %s to %s", measured.Rows[0].Prefix, measured.Rows[searchLimit-1].Prefix)
	}

	recs := searchImprovements(Snapshot{Prefixes: rows, Improvements: imps}, m)
	if recs.Total != 40 || len(recs.Rows) != searchLimit {
		t.Fatalf("recommendations %d rows of %d", len(recs.Rows), recs.Total)
	}
	if recs.Rows[0].Prefix != "198.51.100.39/32" || recs.Rows[searchLimit-1].Prefix != "198.51.100.15/32" {
		t.Errorf("recommendation rows run from %s to %s", recs.Rows[0].Prefix, recs.Rows[searchLimit-1].Prefix)
	}

	e := newSearchEnv(t, false, many)
	_, got, _ := e.get(t, "198.51.100.0/24")
	if got.RIB.Total != 40 || len(got.RIB.Rows) != searchLimit {
		t.Fatalf("rib %d rows of %d", len(got.RIB.Rows), got.RIB.Total)
	}
	// Newest first: the kept rows are the 25 youngest, .39 down to .15.
	if got.RIB.Rows[0].Prefix != "198.51.100.39/32" || got.RIB.Rows[searchLimit-1].Prefix != "198.51.100.15/32" {
		t.Errorf("rib rows run from %s to %s", got.RIB.Rows[0].Prefix, got.RIB.Rows[searchLimit-1].Prefix)
	}
}

// An AS search lists a prefix's recommendation whenever it lists the prefix
// as measured, whichever learned path ends at the searched AS.
func TestSearchASMatchesRecommendationsOnAnyPath(t *testing.T) {
	rows := []Prefix{{Prefix: "198.51.100.0/24", Paths: []LearnedPath{
		{ASPath: []uint32{64496, 64510}},
		{ASPath: []uint32{64497, 64511}},
	}}}
	imps := []Improvement{{Prefix: "198.51.100.0/24", Provider: "transit-b"}}
	m := matcher{asns: []uint32{64511}}

	if got := searchMeasured(rows, m); got.Total != 1 {
		t.Fatalf("measured = %+v", got)
	}
	got := searchImprovements(Snapshot{Prefixes: rows, Improvements: imps}, m)
	if got.Total != 1 || got.Rows[0].OriginASN != 64510 {
		t.Errorf("recommendations = %+v", got)
	}
}

func TestSearchIsRateLimitedPerCaller(t *testing.T) {
	e := newSearchEnv(t, false, nil)
	call := func(remote string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/search?q=AS64510", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests && rec.Header().Get("Retry-After") == "" {
			t.Error("429 without Retry-After")
		}
		return rec.Code
	}
	for i := range searchBurst {
		if code := call("203.0.113.7:1"); code != http.StatusOK {
			t.Fatalf("search %d: %d", i+1, code)
		}
	}
	if code := call("203.0.113.7:2"); code != http.StatusTooManyRequests {
		t.Fatalf("search past the burst: %d", code)
	}
	if code := call("203.0.113.8:1"); code != http.StatusOK {
		t.Fatalf("another caller: %d", code)
	}
	// Invalid input counts too.
	req := httptest.NewRequest(http.MethodGet, "/api/search?q=%3Cx%3E", nil)
	req.RemoteAddr = "203.0.113.7:3"
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("invalid search from a limited caller: %d", rec.Code)
	}
}

func TestSearchLimiterForgetsIdleCallersAndStaysBounded(t *testing.T) {
	var l searchLimiters
	for i := range searchCallers {
		if !l.allow(strconv.Itoa(i)) {
			t.Fatalf("caller %d refused", i)
		}
	}
	// Every caller spent one token, so none is idle yet: a new one is refused.
	if l.allow("new") {
		t.Fatal("table over its bound accepted a caller")
	}
	if len(l.by) != searchCallers {
		t.Fatalf("callers = %d", len(l.by))
	}
	// Idle callers (full burst) are dropped to make room.
	for _, lim := range l.by {
		lim.SetBurst(searchBurst + 5)
		lim.SetLimit(1e9)
	}
	time.Sleep(10 * time.Millisecond)
	if !l.allow("new") || len(l.by) > 1 {
		t.Fatalf("idle callers were not dropped: %d kept", len(l.by))
	}
}

func TestSearchReadOnlyAndViewerOnly(t *testing.T) {
	e := newRBAC(t, nil)
	for _, role := range []plugin.Role{plugin.RoleViewer, plugin.RoleOperator, plugin.RoleAdmin} {
		if rec := e.do(http.MethodGet, "/api/search?q=AS64510", e.tokens[role], ""); rec.Code != http.StatusOK {
			t.Errorf("%s: %d %s", role, rec.Code, rec.Body)
		}
	}
	if rec := e.do(http.MethodGet, "/api/search?q=AS64510", "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", rec.Code)
	}
	before := len(e.store.Records())
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		if rec := e.do(m, "/api/search?q=AS64510", e.tokens[plugin.RoleAdmin], ""); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: %d", m, rec.Code)
		}
	}
	if len(e.store.Records()) != before {
		t.Error("a search or refused method wrote an audit record")
	}
}

func TestImprovementsReportFilters(t *testing.T) {
	src := &fakeReports{}
	ts := reportServer(t, src, "", "")
	code, _, body := do(t, http.MethodGet, ts.URL+"/api/reports/improvements?prefix=192.0.2.0/24&asn=AS64500", "", "")
	if code != http.StatusOK || src.last.Prefix != netip.MustParsePrefix("192.0.2.0/24") || src.last.ASN != 64500 {
		t.Fatalf("%d %s, query %+v", code, body, src.last)
	}
	for _, path := range []string{
		"/api/reports/improvements?prefix=192.0.2.5/24", "/api/reports/improvements?prefix=nope",
		"/api/reports/improvements?asn=0", "/api/reports/improvements?asn=x", "/api/reports/improvements?asn=SA64500", "/api/reports/improvements?asn=S64500", "/api/reports/improvements?asn=ASAS64500", "/api/reports/mitigations?asn=64500",
	} {
		if code, _, body := do(t, http.MethodGet, ts.URL+path, "", ""); code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", path, code, body)
		}
	}
}
