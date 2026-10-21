package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/federation"
	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/troubleshoot"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestProxyAddsBasicAuth(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "lab" || p != "lab-only" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/providers" {
			t.Errorf("path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"mode":"observe"}`)
	}))
	defer origin.Close()

	h, err := handler(origin.URL, "lab", "lab-only")
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(h)
	defer front.Close()

	resp, err := http.Get(front.URL + "/api/providers")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != `{"mode":"observe"}` {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
}

func TestProxyRefusesOpenListenAndMissingAuth(t *testing.T) {
	if err := loopback("0.0.0.0:18089"); err == nil {
		t.Fatal("accepted a non-loopback listen address")
	}
	if err := loopback("127.0.0.1:18089"); err != nil {
		t.Fatal(err)
	}
	if _, err := handler("http://127.0.0.1:8080", "", "secret"); err == nil {
		t.Fatal("missing user accepted")
	}
	if _, err := handler("http://lab:lab-only@127.0.0.1:8080", "lab", "lab-only"); err == nil {
		t.Fatal("userinfo in the upstream URL accepted")
	}
}

const troubleshootFixtures = "../ui-fixtures/troubleshoot"

func TestFixturesStubAndInject(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/troubleshooting.html" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "<html><body><main></main></body></html>")
			return
		}
		_, _ = io.WriteString(w, "origin "+r.URL.Path)
	}))
	defer origin.Close()
	h, err := handler(origin.URL, "lab", "lab-only")
	if err != nil {
		t.Fatal(err)
	}
	f, err := loadFixtures(troubleshootFixtures)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(f.wrap(h))
	defer front.Close()

	do := func(method, path, body string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, front.URL+path, strings.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := do("GET", "/api/troubleshoot/lookingglass?prefix=198.51.100.0%2F24", ""); code != 200 || !strings.Contains(body, `"rib_ready": true`) {
		t.Errorf("stubbed glass: %d %s", code, body)
	}
	if code, body := do("POST", "/api/troubleshoot/traceroute", `{"target":"203.0.113.99","provider":""}`); code != 429 || !strings.Contains(body, "rate limited") {
		t.Errorf("stubbed rate limit: %d %s", code, body)
	}
	if code, body := do("POST", "/api/troubleshoot/probe", `{"target":"host.example.net"}`); code != 200 || !strings.Contains(body, `"best": "transit-b"`) {
		t.Errorf("stubbed hostname probe: %d %s", code, body)
	}
	if code, body := do("POST", "/api/troubleshoot/optimize", `{"target":"198.51.100.9"}`); code != 200 || !strings.Contains(body, `"prefix": "198.51.100.0/24"`) {
		t.Errorf("stubbed optimize: %d %s", code, body)
	}
	if code, body := do("GET", "/api/troubleshoot", ""); code != 200 || !strings.Contains(body, `"optimize": true`) {
		t.Errorf("stubbed status: %d %s", code, body)
	}
	// A call with no stub, and the same path with another target, reach the origin.
	if code, body := do("GET", "/api/troubleshoot/lookingglass?prefix=192.0.2.0%2F24", ""); code != 200 || body != "origin /api/troubleshoot/lookingglass" {
		t.Errorf("unstubbed glass: %d %s", code, body)
	}
	if code, body := do("POST", "/api/troubleshoot/traceroute", `{"target":"192.0.2.77"}`); code != 200 || !strings.HasPrefix(body, "origin ") {
		t.Errorf("unstubbed trace: %d %s", code, body)
	}
	code, page := do("GET", "/troubleshooting.html", "")
	if code != 200 || !strings.Contains(page, `<script src="/__fixture-driver.js"></script></body>`) {
		t.Errorf("injected page: %d %s", code, page)
	}
	if code, js := do("GET", driverPath, ""); code != 200 || !strings.Contains(js, "press(") {
		t.Errorf("driver: %d", code)
	}
}

// TestTroubleshootFixturesMatchAPI decodes each canned answer with the types
// the API returns, so a renamed or removed field breaks this test instead of
// leaving the UI smoke test drawing a shape the server no longer sends.
func TestTroubleshootFixturesMatchAPI(t *testing.T) {
	decode := func(file string, v any) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(troubleshootFixtures, file))
		if err != nil {
			t.Fatal(err)
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(v); err != nil {
			t.Errorf("%s: %v", file, err)
		}
	}
	var g troubleshoot.Glass
	decode("glass-learned.json", &g)
	if g.Exact == nil || len(g.Paths) != 2 || g.Paths[1].MED == nil || len(g.MoreSpecifics) != 1 {
		t.Errorf("learned glass: %+v", g)
	}
	decode("glass-covering.json", &g)
	var multi, single troubleshoot.TraceAnswer
	decode("trace-multi.json", &multi)
	decode("trace-single.json", &single)
	if len(multi.Traces) != 3 || multi.Traces[0].Hops[0].OriginAS != 64496 || multi.Traces[2].Error == "" || len(single.Traces) != 1 {
		t.Errorf("traces: %+v %+v", multi, single)
	}
	var probed troubleshoot.ProbeAnswer
	decode("probe-host.json", &probed)
	if probed.Host == "" || len(probed.Results) != 2 || !probed.Results[1].Indirect || probed.Results[1].Stats.Received != 5 ||
		probed.Current != "transit-a" || probed.Best != "transit-b" || probed.Route == nil || probed.Route.Provider != probed.Current {
		t.Errorf("hostname probe: %+v", probed)
	}
	var queued troubleshoot.OptimizeAnswer
	decode("optimize.json", &queued)
	if queued.Prefix != probed.Route.Prefix || queued.Target != probed.Target || queued.Expires.IsZero() {
		t.Errorf("optimize: %+v", queued)
	}
	var e struct {
		Error string `json:"error"`
	}
	decode("rate-limited.json", &e)
	if e.Error != troubleshoot.ErrBusy.Error() {
		t.Errorf("rate-limited fixture says %q, the API says %q", e.Error, troubleshoot.ErrBusy)
	}
}

// TestPrefixFixturesMatchAPI decodes the canned /api/prefixes pages with the
// type the API returns (#183), so a renamed field fails here and not as a
// silently empty table in the UI smoke test.
func TestPrefixFixturesMatchAPI(t *testing.T) {
	f, err := loadFixtures("../ui-fixtures/prefixes")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Stubs) != 3 {
		t.Fatalf("stubs = %d", len(f.Stubs))
	}
	for _, s := range f.Stubs {
		var page httpapi.PrefixPage
		dec := json.NewDecoder(bytes.NewReader(s.body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&page); err != nil {
			t.Errorf("%s: %v", s.File, err)
			continue
		}
		if page.Limit != 25 || len(page.Prefixes) == 0 || len(page.Prefixes) > page.Limit || page.Total < len(page.Prefixes) || page.Measured < page.Total {
			t.Errorf("%s: limit %d rows %d total %d measured %d", s.File, page.Limit, len(page.Prefixes), page.Total, page.Measured)
		}
		for _, r := range page.Prefixes {
			if r.Probes == nil || len(r.Paths) == 0 || r.Paths[0].MED == nil || r.ExitRTTMs == nil {
				t.Errorf("%s: row %s is missing probes, a path with MED, or the exit measurement", s.File, r.Prefix)
			}
		}
	}
}

// TestExchangeFixturesMatchAPI decodes the canned /api/exchanges answer with
// the type the API returns (#155), so a renamed field fails here and not as
// an empty list in the UI smoke test.
func TestExchangeFixturesMatchAPI(t *testing.T) {
	f, err := loadFixtures("../ui-fixtures/exchanges")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Stubs) != 1 || f.Inject.Page != "/settings.html" {
		t.Fatalf("stubs = %d, page = %q", len(f.Stubs), f.Inject.Page)
	}
	var out struct {
		Exchanges []exchange.Stats `json:"exchanges"`
	}
	dec := json.NewDecoder(bytes.NewReader(f.Stubs[0].body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Exchanges) != 2 || out.Exchanges[0].Name != "ix-lab" || len(out.Exchanges[0].Discovered) != 2 ||
		out.Exchanges[0].Discovered[0].NextHop != "203.0.113.13" || out.Exchanges[0].Discovered[0].ASN != 64503 || out.Exchanges[0].Discovered[1].ASN != 0 {
		t.Fatalf("exchanges = %+v", out.Exchanges)
	}
}

// TestExchangePageFixturesMatchAPI decodes the canned exchange page answers
// with the API's own types (#148), so a renamed field fails here and not as
// an empty table in the UI smoke test.
func TestExchangePageFixturesMatchAPI(t *testing.T) {
	f, err := loadFixtures("../ui-fixtures/exchange-page")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Stubs) != 5 || f.Inject.Page != "" {
		t.Fatalf("stubs = %d, inject = %q", len(f.Stubs), f.Inject.Page)
	}
	strict := func(body []byte, v any) {
		t.Helper()
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(v); err != nil {
			t.Fatal(err)
		}
	}
	var ex struct {
		Exchanges []exchange.Stats `json:"exchanges"`
	}
	strict(f.Stubs[0].body, &ex)
	if len(ex.Exchanges) != 1 {
		t.Fatalf("exchanges = %+v", ex.Exchanges)
	}
	a, b := ex.Exchanges[0].Peers[0], ex.Exchanges[0].Peers[1]
	if a.Via != "bilateral" || a.MovedMbps != 42.5 || len(a.Moves) != 2 || a.Moves[0].VolumeMbps+a.Moves[1].VolumeMbps != a.MovedMbps ||
		a.Improvements != len(a.Moves) || b.ObservedASN != 64599 || b.Up || b.Via != "route_server" {
		t.Fatalf("peers = %+v", ex.Exchanges[0].Peers)
	}
	if st := ex.Exchanges[0]; !st.Degraded || len(st.DegradedPeers) != 2 || a.Reach.State != exchange.ReachReachable || a.Reach.LossPct != 60 ||
		b.Reach.State != exchange.ReachUnreachable || !a.Reach.Degraded || !b.Reach.Degraded {
		t.Fatalf("health = %+v", st)
	}
	// #156: the comparison columns and flags the smoke test looks for.
	c := ex.Exchanges[0].Peers[2]
	if a.Availability.Flag != exchange.FlagRSPartial || a.Availability.RouteServerOnly+a.Availability.BilateralOnly+a.Availability.Both != 8 ||
		b.Availability.Flag != "" || b.Availability.RouteServerOnly != 3 || c.Availability.Flag != exchange.FlagRSMissing || c.Availability.BilateralOnly != 4 {
		t.Fatalf("availability = %+v %+v %+v", a.Availability, b.Availability, c.Availability)
	}
	// #152: the offload table the smoke test looks for.
	var off exchange.Offload
	strict(f.Stubs[1].body, &off)
	if off.Prefixes != len(off.Rows) || off.Rows[0].Bytes < off.Rows[1].Bytes || off.Rows[0].EstSavings != nil ||
		off.Rows[1].EstSavings == nil || *off.Rows[1].EstSavings != *off.EstSavings || len(off.Rows[0].Peers) != 2 {
		t.Fatalf("offload = %+v", off)
	}
	// #154: the two potential-peers tables the smoke test looks for.
	var rs, bi exchange.PotentialPeers
	strict(f.Stubs[2].body, &rs)
	strict(f.Stubs[3].body, &bi)
	if rs.ASNs != len(rs.Rows) || rs.Rows[0].Class != exchange.ClassRouteServer || rs.Rows[0].LANPrefixes >= rs.Rows[0].Prefixes ||
		bi.Rows[0].Class != exchange.ClassBilateral || bi.Rows[0].Members[0].Peer != "ix-peer-c" || rs.Classes[exchange.ClassAbsent].ASNs != 3 {
		t.Fatalf("potential peers = %+v %+v", rs, bi)
	}
	var rep struct {
		Report string                `json:"report"`
		From   string                `json:"from"`
		To     string                `json:"to"`
		Rows   []history.ExchangeRow `json:"rows"`
	}
	strict(f.Stubs[4].body, &rep)
	if rep.Report != "exchanges" || len(rep.Rows) != 2 || rep.Rows[0].Peer != "ix-peer-a" || rep.Rows[0].VolumeMbps != 61.5 {
		t.Fatalf("report = %+v", rep)
	}
}

// TestIXPMemberFixturesMatchAPI decodes the canned member page answers with
// the API's own types (#166), so a renamed field fails here and not as an
// empty table in the UI smoke test.
func TestIXPMemberFixturesMatchAPI(t *testing.T) {
	f, err := loadFixtures("../ui-fixtures/ixp-member")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Stubs) != 3 || f.Inject.Page != "" {
		t.Fatalf("stubs = %d, inject = %q", len(f.Stubs), f.Inject.Page)
	}
	strict := func(body []byte, v any) {
		t.Helper()
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(v); err != nil {
			t.Fatal(err)
		}
	}
	var page httpapi.IXPMemberPage
	strict(f.Stubs[0].body, &page)
	if page.ASN != 64496 || len(page.Connections) != 1 || len(page.Fabric.Samples) != 2 || len(page.Sessions) != 1 ||
		!strings.HasPrefix(page.ManagerLink, "https://ixp.example.invalid/admin/search?search=AS") {
		t.Fatalf("page = %+v", page)
	}
	if a, b := page.Fabric.Samples[0], page.Fabric.Samples[1]; a.PastTolerance || !b.PastTolerance || b.LossPct != 40 || b.RTTMs != 310.5 {
		t.Fatalf("samples = %+v %+v", a, b)
	}
	var hist struct {
		Version     string                     `json:"version"`
		Mode        string                     `json:"mode"`
		Ready       bool                       `json:"ready"`
		GeneratedAt string                     `json:"generated_at"`
		Server      string                     `json:"server"`
		Session     string                     `json:"session"`
		Samples     []plugin.RouteServerSample `json:"samples"`
	}
	strict(f.Stubs[1].body, &hist)
	if hist.Session != page.Sessions[0].Session || len(hist.Samples) != 2 || hist.Samples[1].Filtered != 3 {
		t.Fatalf("history = %+v", hist)
	}
}

// TestIXPSitesFixturesMatchAPI decodes the canned /api/ixp/sites answer with
// the API's own types (#167), so a renamed field fails here and not as an
// empty table in the UI smoke test.
func TestIXPSitesFixturesMatchAPI(t *testing.T) {
	f, err := loadFixtures("../ui-fixtures/ixp-sites")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Stubs) != 1 || f.Inject.Page != "" {
		t.Fatalf("stubs = %d, inject = %q", len(f.Stubs), f.Inject.Page)
	}
	var v struct {
		Version     string `json:"version"`
		Mode        string `json:"mode"`
		Ready       bool   `json:"ready"`
		GeneratedAt string `json:"generated_at"`
		federation.IXPSitesView
	}
	dec := json.NewDecoder(bytes.NewReader(f.Stubs[0].body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	if !v.Enabled || len(v.Sites) != 3 || len(v.Links) != 2 || len(v.Incidents) != 4 {
		t.Fatalf("view = %+v", v)
	}
	a, b, c := v.Sites[0], v.Sites[1], v.Sites[2]
	if !a.Self || a.Status != federation.StatusOK || b.Status != federation.StatusDegraded || c.Status != federation.StatusUnreachable || c.Fresh {
		t.Fatalf("sites = %+v", v.Sites)
	}
	if p := b.PastTolerance; len(p) != 1 || p[0].ASN != 64497 || p[0].LossPct != 40 || p[0].RTTMs != 310.5 {
		t.Fatalf("site-b past tolerance = %+v", p)
	}
	if l := v.Links[1]; l.Site != "site-a" || l.Peer != "site-c" || l.Up || !l.Degraded {
		t.Fatalf("link = %+v", l)
	}
}

// TestMaintenanceFixturesMatchAPI decodes the canned /api/maintenance answer
// with the type the API returns (#177), so a renamed field fails here and
// not as an empty table in the UI smoke test.
func TestMaintenanceFixturesMatchAPI(t *testing.T) {
	f, err := loadFixtures("../ui-fixtures/maintenance-viewer")
	if err != nil {
		t.Fatal(err)
	}
	var list httpapi.MaintenanceList
	for _, s := range f.Stubs {
		if s.Path != "/api/maintenance" {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(s.body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&list); err != nil {
			t.Fatal(err)
		}
	}
	if !list.Configured || !list.OnDemand || len(list.Windows) != 1 || len(list.Upcoming) != 1 || len(list.Finished) != 1 {
		t.Fatalf("list = %+v", list)
	}
	if w := list.Windows[0]; w.ID != "api-3" || w.Source != "api" || !w.End.After(w.Start) {
		t.Fatalf("open window = %+v", w)
	}
}

// TestCommitDriverMatchesPage keeps the Commit setup driver (#174) in step
// with the page it drives: it stubs nothing, injects into the settings page,
// and every element id and field label it uses is in settings.html or
// commitsetup.js, so a rename fails here and not as a timeout in CI.
func TestCommitDriverMatchesPage(t *testing.T) {
	f, err := loadFixtures("../ui-fixtures/commit")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Stubs) != 0 || f.Inject.Page != "/settings.html" || len(f.driver) == 0 {
		t.Fatalf("fixtures = %+v", f)
	}
	web := "../../internal/httpapi/web/"
	page, err := os.ReadFile(web + "settings.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(web + "commitsetup.js")
	if err != nil {
		t.Fatal(err)
	}
	settings, err := os.ReadFile(web + "settings.js")
	if err != nil {
		t.Fatal(err)
	}
	driver := string(f.driver)
	ids := regexp.MustCompile(`byId\("([^"]+)"\)`).FindAllStringSubmatch(driver, -1)
	if len(ids) == 0 {
		t.Fatal("the driver uses no element")
	}
	if !strings.Contains(string(settings), `"Remove provider"`) {
		t.Error("the driver removes a provider row by its title, which settings.js lacks")
	}
	for _, m := range ids {
		if !strings.Contains(string(page), `id="`+m[1]+`"`) {
			t.Errorf("driver uses #%s, which settings.html lacks", m[1])
		}
	}
	for _, m := range regexp.MustCompile(`field\([^,]+, "([^"]+)"\)`).FindAllStringSubmatch(driver, -1) {
		if !strings.Contains(string(script), `"`+m[1]+`"`) && !strings.Contains(string(settings), `labeled("`+m[1]+`"`) {
			t.Errorf("driver looks for the label %q, which commitsetup.js and settings.js lack", m[1])
		}
	}
}

// TestGuidedDriverMatchesPage keeps the guided-input driver (#329) on the
// settings page it drives. It stubs nothing, so Apply talks to the real
// form API. A renamed id fails here instead of as a timeout in CI.
func TestGuidedDriverMatchesPage(t *testing.T) {
	f, err := loadFixtures("../ui-fixtures/guided")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Stubs) != 0 || f.Inject.Page != "/settings.html" || len(f.driver) == 0 {
		t.Fatalf("fixtures = %+v", f)
	}
	page, err := os.ReadFile("../../internal/httpapi/web/settings.html")
	if err != nil {
		t.Fatal(err)
	}
	driver := string(f.driver)
	if !strings.Contains(driver, "yaml-same:") || !strings.Contains(driver, "999.1.1.1/24") || !strings.Contains(driver, `method === "PUT"`) {
		t.Fatal("driver does not check an unchanged Apply, a bad prefix, and PUT")
	}
	if strings.Contains(driver, "confirm_inject") || strings.Contains(driver, "/api/config\"") {
		t.Fatal("driver writes config")
	}
	ids := regexp.MustCompile(`byId\("([^"]+)"\)`).FindAllStringSubmatch(driver, -1)
	if len(ids) == 0 {
		t.Fatal("the driver uses no element")
	}
	for _, m := range ids {
		if !strings.Contains(string(page), `id="`+m[1]+`"`) {
			t.Errorf("driver uses #%s, which settings.html lacks", m[1])
		}
	}
	for _, id := range []string{"form-providers", "form-flows", "form-policies", "form-vips", "form-outages", "form-exchanges", "form-allow", "form-anomaly-rules", "in-prefix-box", "in-perf-loss-on", "fm-hold"} {
		if !strings.Contains(driver, id) || !strings.Contains(string(page), `id="`+id+`"`) {
			t.Errorf("guided card %s is missing from the driver or the page", id)
		}
	}
}

// TestObserveWordingFixturesMatchAPI decodes the canned observe-mode
// answers with the API's own types (#346): a pending recommendation whose
// current exit is the learned path, and the event worded as a recommendation.
func TestObserveWordingFixturesMatchAPI(t *testing.T) {
	f, err := loadFixtures("../ui-fixtures/observe-wording")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Stubs) != 2 {
		t.Fatalf("stubs = %d", len(f.Stubs))
	}
	var page httpapi.PrefixPage
	dec := json.NewDecoder(bytes.NewReader(f.Stubs[0].body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&page); err != nil {
		t.Fatal(err)
	}
	if len(page.Prefixes) != 1 || page.Prefixes[0].Prefix != "198.51.100.0/24" || page.Prefixes[0].Current != "lab-a" || page.Prefixes[0].Recommended != "lab-b" {
		t.Fatalf("prefixes = %+v", page.Prefixes)
	}
	var events struct {
		Events []struct {
			plugin.Event
			Source string `json:"source"`
		} `json:"events"`
		Stored bool      `json:"stored"`
		Since  time.Time `json:"since"`
		Now    time.Time `json:"now"`
	}
	dec = json.NewDecoder(bytes.NewReader(f.Stubs[1].body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&events); err != nil {
		t.Fatal(err)
	}
	const want = "Recommends moving 198.51.100.0/24 from lab-a to lab-b (not announced, observe mode)"
	if len(events.Events) != 1 || events.Events[0].Message != want || events.Events[0].Kind != plugin.EventImprovementAdded {
		t.Fatalf("events = %+v", events.Events)
	}
}

// TestPlainLanguageFixturesMatchAPI decodes the canned answers behind the
// plain-language smoke test (#351) with the API's own types: a session in
// Active, and a checklist whose remedy links to the config editor.
func TestPlainLanguageFixturesMatchAPI(t *testing.T) {
	f, err := loadFixtures("../ui-fixtures/plain-language")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Stubs) != 4 {
		t.Fatalf("stubs = %d", len(f.Stubs))
	}
	var o httpapi.Overview
	dec := json.NewDecoder(bytes.NewReader(f.Stubs[0].body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&o); err != nil {
		t.Fatal(err)
	}
	editor := false
	for _, ft := range o.Features {
		editor = editor || ft.Name == "config_editor" && ft.On
	}
	var fix string
	for _, h := range o.Setup {
		if h.ID == "bgp-down" {
			fix = h.Fix
		}
	}
	if !editor || fix != httpapi.FixBGP || o.BGP.Established != 0 {
		t.Fatalf("overview: editor %v, bgp-down fix %q, bgp %+v", editor, fix, o.BGP)
	}
	var prov struct {
		BGP struct {
			Peers []httpapi.Peer `json:"peers"`
		} `json:"bgp"`
	}
	if err := json.Unmarshal(f.Stubs[1].body, &prov); err != nil {
		t.Fatal(err)
	}
	if len(prov.BGP.Peers) != 1 || prov.BGP.Peers[0].State != "ACTIVE" || prov.BGP.Peers[0].Established {
		t.Fatalf("peers = %+v", prov.BGP.Peers)
	}
	var page httpapi.PrefixPage
	dec = json.NewDecoder(bytes.NewReader(f.Stubs[2].body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&page); err != nil || len(page.Prefixes) != 1 {
		t.Fatalf("prefixes: %v %+v", err, page.Prefixes)
	}
	var imp struct {
		Improvements []httpapi.Improvement `json:"improvements"`
	}
	if err := json.Unmarshal(f.Stubs[3].body, &imp); err != nil || len(imp.Improvements) != 1 || imp.Improvements[0].Native != "lab-a" {
		t.Fatalf("improvements: %v %+v", err, imp.Improvements)
	}
}

// TestMobileFixturesMatchAPI decodes the canned answers behind the phone
// width smoke test (#352) with the API's own types, and checks the cases the
// test is about: a provider that does not answer, and a long name and an
// IPv6 prefix that must wrap.
func TestMobileFixturesMatchAPI(t *testing.T) {
	f, err := loadFixtures("../ui-fixtures/mobile")
	if err != nil {
		t.Fatal(err)
	}
	if !f.Frames || f.Inject.Page != "/providers.html" || len(f.Stubs) != 5 {
		t.Fatalf("fixtures = %+v", f)
	}
	decode := func(path string, v any) {
		t.Helper()
		for _, s := range f.Stubs {
			if s.Path == path {
				dec := json.NewDecoder(bytes.NewReader(s.body))
				dec.DisallowUnknownFields()
				if err := dec.Decode(v); err != nil {
					t.Errorf("%s: %v", path, err)
				}
				return
			}
		}
		t.Errorf("no stub for %s", path)
	}
	var ov httpapi.Overview
	decode("/api/overview", &ov)
	if ov.Auth == "off" || len(ov.Providers) != 3 || ov.Providers[2].Detail != "no answer" || len(ov.Problems) != 2 {
		t.Errorf("overview = %+v", ov)
	}
	var provs struct {
		Version     string             `json:"version"`
		Mode        string             `json:"mode"`
		Ready       bool               `json:"ready"`
		GeneratedAt time.Time          `json:"generated_at"`
		Providers   []httpapi.Provider `json:"providers"`
		BGP         struct {
			Configured, Ready bool
			Peers             []struct{}
		} `json:"bgp"`
	}
	decode("/api/providers", &provs)
	if len(provs.Providers) != 3 || provs.Providers[2].Name != ov.Providers[2].Name || provs.Providers[2].PeerASN != 64496 {
		t.Errorf("providers = %+v", provs.Providers)
	}
	var imps struct {
		Version      string                `json:"version"`
		Mode         string                `json:"mode"`
		Ready        bool                  `json:"ready"`
		GeneratedAt  time.Time             `json:"generated_at"`
		Improvements []httpapi.Improvement `json:"improvements"`
	}
	decode("/api/improvements", &imps)
	if len(imps.Improvements) != 2 || !strings.HasPrefix(imps.Improvements[0].Prefix, "2001:db8:") {
		t.Errorf("improvements = %+v", imps.Improvements)
	}
	var events struct {
		Events []struct {
			plugin.Event
			Source  string `json:"source"`
			HelpURL string `json:"help_url"`
		} `json:"events"`
		Stored bool      `json:"stored"`
		Since  time.Time `json:"since"`
		Now    time.Time `json:"now"`
	}
	decode("/api/events", &events)
	if len(events.Events) != 2 || events.Events[0].Severity != plugin.SeverityWarning {
		t.Errorf("events = %+v", events.Events)
	}
	var page httpapi.PrefixPage
	decode("/api/prefixes", &page)
	if len(page.Prefixes) != 1 {
		t.Errorf("prefixes = %+v", page.Prefixes)
	}
}

// TestMobileDriverMatchesPage keeps the phone width driver on the markup and
// column names it reads. A renamed id or header fails here instead of as a
// timeout in CI.
func TestMobileDriverMatchesPage(t *testing.T) {
	f, err := loadFixtures("../ui-fixtures/mobile")
	if err != nil {
		t.Fatal(err)
	}
	web := "../../internal/httpapi/web/"
	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(web + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	providers, settings, app := read("providers.html"), read("settings.html"), read("app.js")
	driver := string(f.driver)
	ids := regexp.MustCompile(`getElementById\("([^"]+)"\)`).FindAllStringSubmatch(driver, -1)
	if len(ids) == 0 {
		t.Fatal("the driver uses no element")
	}
	for _, m := range ids {
		if !strings.Contains(providers, `id="`+m[1]+`"`) && !strings.Contains(settings, `id="`+m[1]+`"`) {
			t.Errorf("driver uses #%s, which neither providers.html nor settings.html has", m[1])
		}
	}
	for _, h := range regexp.MustCompile(`data-label="([^"]+)"`).FindAllStringSubmatch(driver, -1) {
		if !strings.Contains(app, `"`+h[1]+`"`) {
			t.Errorf("driver reads the %q column, which app.js does not draw", h[1])
		}
	}
	if !strings.Contains(driver, "window.top !== window") {
		t.Error("the driver must skip the frames it opens, or each frame would open more")
	}
}

// TestFixturesFramesOptIn checks the dashboard's no-framing headers are
// relaxed to same-origin framing only for fixtures that ask for it.
func TestFixturesFramesOptIn(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; object-src 'none'")
		_, _ = io.WriteString(w, "page")
	}))
	defer origin.Close()
	h, err := handler(origin.URL, "lab", "lab-only")
	if err != nil {
		t.Fatal(err)
	}
	for _, frames := range []bool{false, true} {
		front := httptest.NewServer((&fixtures{Frames: frames}).wrap(h))
		resp, err := http.Get(front.URL + "/x.html")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		front.Close()
		xfo, csp := resp.Header.Get("X-Frame-Options"), resp.Header.Get("Content-Security-Policy")
		if frames {
			if xfo != "" || csp != "default-src 'self'; frame-ancestors 'self'; object-src 'none'" {
				t.Errorf("frames on: X-Frame-Options %q, CSP %q", xfo, csp)
			}
		} else if xfo != "DENY" || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("frames off: X-Frame-Options %q, CSP %q", xfo, csp)
		}
	}
}

// TestExplainFixturesMatchAPI decodes the canned answers behind the
// improvement explanation smoke test (#348) with the API's own types, and
// checks the driver reads the columns and cells the page draws.
func TestExplainFixturesMatchAPI(t *testing.T) {
	f, err := loadFixtures("../ui-fixtures/explain")
	if err != nil {
		t.Fatal(err)
	}
	if !f.Frames || f.Inject.Page != "/improvements.html" || len(f.Stubs) != 2 {
		t.Fatalf("fixtures = %+v", f)
	}
	var imps struct {
		Mode         string                `json:"mode"`
		Version      string                `json:"version"`
		Ready        bool                  `json:"ready"`
		GeneratedAt  time.Time             `json:"generated_at"`
		Improvements []httpapi.Improvement `json:"improvements"`
	}
	for _, s := range f.Stubs {
		if s.Path != "/api/improvements" {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(s.body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&imps); err != nil {
			t.Fatal(err)
		}
	}
	if len(imps.Improvements) != 2 || imps.Mode != "observe" {
		t.Fatalf("improvements = %+v", imps)
	}
	first, second := imps.Improvements[0], imps.Improvements[1]
	if first.ASN != 64496 || first.VolumeMbps != 12.5 || first.HoldLeftS != 130 || !strings.Contains(first.Explain, "Threshold 15 ms.") {
		t.Errorf("first = %+v", first)
	}
	if second.VolumeMbps != 0 || !strings.HasPrefix(second.Prefix, "2001:db8:") || second.ASName != "" {
		t.Errorf("second must have no flow data and no AS name: %+v", second)
	}
	app, err := os.ReadFile("../../internal/httpapi/web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	driver := string(f.driver)
	for _, h := range regexp.MustCompile(`"([A-Za-z ]+)"`).FindAllStringSubmatch(regexp.MustCompile(`var HEADS = \[[^\]]*\]`).FindString(driver), -1) {
		if !strings.Contains(string(app), `["`+h[1]+`"`) && !strings.Contains(string(app), `[inject ? "Steered to" : "`+h[1]+`"]`) {
			t.Errorf("driver expects the %q column, which app.js does not draw", h[1])
		}
	}
	if !strings.Contains(driver, "window.top !== window") {
		t.Error("the driver must skip the frames it opens")
	}
}
