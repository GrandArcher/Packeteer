package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/troubleshoot"
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
