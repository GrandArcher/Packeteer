package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func sampleInput() Input {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	p198 := netip.MustParsePrefix("198.51.100.0/24")
	p203 := netip.MustParsePrefix("203.0.113.0/24")
	return Input{
		Version: "test",
		Mode:    "observe",
		Started: true,
		At:      at,
		Providers: []config.Provider{
			{Name: "transit-a", SourceIP: "192.0.2.11", NextHop: "192.0.2.1"},
			{Name: "transit-b", SourceIP: "192.0.2.12", NextHop: "192.0.2.2", Exclude: true},
		},
		Status: []probe.ProviderStatus{
			{Name: "transit-a", Source: netip.MustParseAddr("192.0.2.11"), Up: true, Since: at},
			{Name: "transit-b", Source: netip.MustParseAddr("192.0.2.12"), Up: false, Reason: "source down", Since: at},
		},
		Results: []probe.Result{
			{
				Provider: "transit-a", Prefix: p198, Target: netip.MustParseAddr("198.51.100.1"), Prober: "icmp",
				Stats: probe.Stats{Sent: 4, Received: 4, LossPct: 0, RTTMin: 10 * time.Millisecond, RTTAvg: 40 * time.Millisecond, RTTMax: 50 * time.Millisecond, Jitter: 2 * time.Millisecond},
				Time:  at,
			},
			{
				Provider: "transit-b", Prefix: p198, Target: netip.MustParseAddr("198.51.100.1"), Prober: "icmp",
				Stats: probe.Stats{Sent: 4, Received: 2, LossPct: 50, RTTAvg: 10 * time.Millisecond, Jitter: time.Millisecond},
				Time:  at,
			},
			{
				Provider: "quote\"\\\nname", Prefix: p203, Err: "no reply", Time: at,
			},
		},
		Decisions: []policy.Decision{{
			Prefix: p198, Native: "transit-a", Current: "transit-a", Recommended: "transit-b",
			Action: policy.ActionImprove, Reason: "loss",
			Candidates: []policy.Candidate{{
				Provider: "transit-a", Score: math.NaN(), LossPct: 0, RTTAvg: 40 * time.Millisecond, Usable: true,
			}},
		}},
		DecidedAt: at,
		Improvements: []policy.Improvement{{
			Prefix: p198, Provider: "transit-b", Native: "transit-a", Since: at, Reason: "loss",
		}},
		BGPConfigured: true,
		RIBReady:      true,
		Peers: []rib.PeerState{{
			Address: netip.MustParseAddr("192.0.2.254"), Description: "edge", State: "idle", Since: at,
		}},
		Routes: map[netip.Prefix]rib.Route{
			p198: {
				Prefix: p198, NextHop: netip.MustParseAddr("192.0.2.1"), Provider: "transit-a",
				Neighbor: netip.MustParseAddr("192.0.2.254"),
			},
			// Learned, but not probed: the API must not dump the RIB.
			netip.MustParsePrefix("192.0.2.0/24"): {
				Prefix: netip.MustParsePrefix("192.0.2.0/24"), NextHop: netip.MustParseAddr("192.0.2.9"), Provider: "transit-a",
			},
		},
	}
}

func sampleSnap() Snapshot { return Assemble(sampleInput()) }

func newTestServer(t *testing.T, snap Snapshot, user, pass string) *httptest.Server {
	t.Helper()
	s, err := New(Options{User: user, Password: pass, Snapshot: func() Snapshot { return snap }})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func do(t *testing.T, method, url, user, pass string) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, body
}

func TestEndpoints(t *testing.T) {
	snap := sampleSnap()
	ts := newTestServer(t, snap, "", "")
	paths := []string{
		"/healthz", "/readyz", "/metrics",
		"/api/providers", "/api/probes", "/api/prefixes", "/api/decisions", "/api/improvements", "/api/telemetry",
		"/", "/app.js", "/app.css",
	}
	for _, p := range paths {
		code, hdr, body := do(t, http.MethodGet, ts.URL+p, "", "")
		if code != http.StatusOK {
			t.Errorf("GET %s = %d (%s)", p, code, body)
		}
		if hdr.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("GET %s missing nosniff", p)
		}
		if strings.Contains(hdr.Get("Content-Security-Policy"), "http://") || strings.Contains(hdr.Get("Content-Security-Policy"), "https://") {
			t.Errorf("GET %s CSP loads a remote origin: %s", p, hdr.Get("Content-Security-Policy"))
		}
		code, hdr, _ = do(t, http.MethodPost, ts.URL+p, "", "")
		if code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d, want 405", p, code)
		}
		if !strings.Contains(hdr.Get("Allow"), "GET") {
			t.Errorf("POST %s Allow = %q", p, hdr.Get("Allow"))
		}
		for _, m := range []string{http.MethodPut, http.MethodDelete} {
			code, _, _ = do(t, m, ts.URL+p, "", "")
			if code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s = %d, want 405", m, p, code)
			}
		}
	}
}

func TestHealthAndReady(t *testing.T) {
	ts := newTestServer(t, sampleSnap(), "", "")
	_, _, body := do(t, http.MethodGet, ts.URL+"/healthz", "", "")
	if !strings.Contains(string(body), `"status":"ok"`) || !strings.Contains(string(body), `"version":"test"`) {
		t.Fatalf("healthz = %s", body)
	}
	code, _, body := do(t, http.MethodGet, ts.URL+"/readyz", "", "")
	if code != http.StatusOK || !strings.Contains(string(body), `"ready":true`) {
		t.Fatalf("readyz %d %s", code, body)
	}

	notReady := sampleSnap()
	notReady.Started = true
	notReady.BGPConfigured = true
	notReady.RIBReady = false
	ts2 := newTestServer(t, notReady, "", "")
	code, _, body = do(t, http.MethodGet, ts2.URL+"/healthz", "", "")
	if code != http.StatusOK {
		t.Fatalf("healthz while not ready = %d", code)
	}
	code, _, body = do(t, http.MethodGet, ts2.URL+"/readyz", "", "")
	if code != http.StatusServiceUnavailable || !strings.Contains(string(body), `"ready":false`) || !strings.Contains(string(body), `"rib_ready":false`) {
		t.Fatalf("readyz not ready = %d %s", code, body)
	}
}

func TestJSONAPI(t *testing.T) {
	ts := newTestServer(t, sampleSnap(), "", "")
	assertJSON(t, ts.URL+"/api/providers", func(t *testing.T, m map[string]any) {
		if m["mode"] != "observe" || m["ready"] != true || m["version"] != "test" {
			t.Fatalf("meta = %v", m)
		}
		provs, _ := m["providers"].([]any)
		if len(provs) != 2 {
			t.Fatalf("providers = %v", m["providers"])
		}
		b, _ := provs[1].(map[string]any)
		if b["name"] != "transit-b" || b["up"] != false || b["exclude"] != true || b["reason"] != "source down" {
			t.Fatalf("transit-b = %v", b)
		}
		bgp, _ := m["bgp"].(map[string]any)
		if bgp["configured"] != true || bgp["ready"] != true {
			t.Fatalf("bgp = %v", bgp)
		}
		peers, _ := bgp["peers"].([]any)
		if len(peers) != 1 {
			t.Fatalf("peers = %v", peers)
		}
	})
	assertJSON(t, ts.URL+"/api/probes", func(t *testing.T, m map[string]any) {
		probes, _ := m["probes"].([]any)
		if len(probes) != 3 {
			t.Fatalf("probes = %d", len(probes))
		}
		found := false
		for _, raw := range probes {
			p := raw.(map[string]any)
			if p["provider"] == "transit-b" {
				found = true
				if p["loss_pct"] != 50.0 || p["rtt_avg_ms"] != 10.0 || p["ok"] != true {
					t.Fatalf("transit-b probe = %v", p)
				}
			}
		}
		if !found {
			t.Fatal("missing transit-b probe")
		}
	})
	assertJSON(t, ts.URL+"/api/prefixes", func(t *testing.T, m map[string]any) {
		rows, _ := m["prefixes"].([]any)
		if len(rows) != 2 {
			t.Fatalf("prefixes = %v", m["prefixes"])
		}
		for _, raw := range rows {
			p := raw.(map[string]any)
			if p["prefix"] == "192.0.2.0/24" {
				t.Fatal("RIB-only prefix was exported")
			}
		}
		p := rows[0].(map[string]any)
		if p["prefix"] != "198.51.100.0/24" || p["current"] != "transit-a" || p["recommended"] != "transit-b" || p["action"] != "improve" || p["in_rib"] != true || p["next_hop"] != "192.0.2.1" {
			t.Fatalf("prefix = %v", p)
		}
		probes, _ := p["probes"].([]any)
		if len(probes) != 2 {
			t.Fatalf("prefix probes = %v", probes)
		}
	})
	assertJSON(t, ts.URL+"/api/decisions", func(t *testing.T, m map[string]any) {
		if m["decided_at"] == nil {
			t.Fatal("missing decided_at")
		}
		rows, _ := m["decisions"].([]any)
		if len(rows) != 1 {
			t.Fatalf("decisions = %v", rows)
		}
		d := rows[0].(map[string]any)
		cands, _ := d["candidates"].([]any)
		if len(cands) != 1 || cands[0].(map[string]any)["score"] != 0.0 {
			t.Fatalf("NaN score leaked: %v", d)
		}
	})
	code, hdr, body := do(t, http.MethodGet, ts.URL+"/api/improvements", "", "")
	if code != http.StatusOK || !strings.Contains(hdr.Get("Content-Type"), "application/json") {
		t.Fatalf("improvements %d %s", code, hdr.Get("Content-Type"))
	}
	if strings.Contains(string(body), "null") {
		t.Fatalf("null in improvements JSON: %s", body)
	}
	var doc struct {
		Improvements []Improvement `json:"improvements"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Improvements) != 1 || doc.Improvements[0].Provider != "transit-b" || doc.Improvements[0].Native != "transit-a" || doc.Improvements[0].Prefix != "198.51.100.0/24" {
		t.Fatalf("improvements = %+v", doc.Improvements)
	}
}

func TestMetrics(t *testing.T) {
	ts := newTestServer(t, sampleSnap(), "", "")
	code, hdr, body := do(t, http.MethodGet, ts.URL+"/metrics", "", "")
	if code != http.StatusOK || !strings.Contains(hdr.Get("Content-Type"), "text/plain") {
		t.Fatalf("metrics %d %s", code, hdr.Get("Content-Type"))
	}
	text := string(body)
	for _, want := range []string{
		"packeteer_probe_rtt_seconds{",
		`provider="transit-a",prefix="198.51.100.0/24"`,
		" 0.04\n",
		"packeteer_probe_loss_ratio{",
		`provider="transit-b",prefix="198.51.100.0/24"`,
		" 0.5\n",
		"packeteer_probe_jitter_seconds{",
		" 0.002\n",
		`packeteer_decisions{action="improve"} 1`,
		`packeteer_decisions{action="none"} 0`,
		`packeteer_decision{prefix="198.51.100.0/24",action="improve",native="transit-a",current="transit-a",recommended="transit-b"} 1`,
		"packeteer_improvements_active 1",
		`packeteer_improvement{prefix="198.51.100.0/24",provider="transit-b",native="transit-a"} 1`,
		`packeteer_bgp_session_up{peer="192.0.2.254"} 0`,
		`packeteer_bgp_session{peer="192.0.2.254",state="IDLE"} 1`,
		`packeteer_bgp_session{peer="192.0.2.254",state="ESTABLISHED"} 0`,
		"packeteer_bgp_ready 1",
		"packeteer_ready 1",
		`provider="quote\"\\\nname"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q\n%s", want, text)
		}
	}
	// A failed probe must not look like a 0 ms path.
	if strings.Contains(text, `prefix="203.0.113.0/24"`) && strings.Contains(text, "packeteer_probe_rtt_seconds{") {
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(line, "packeteer_probe_rtt_seconds{") && strings.Contains(line, "203.0.113.0/24") {
				t.Errorf("failed probe exported an RTT: %s", line)
			}
		}
	}
	if !strings.Contains(text, `prefix="203.0.113.0/24"`) || !strings.Contains(text, "packeteer_probe_success{") {
		t.Fatalf("failed probe success series missing:\n%s", text)
	}
}

func TestTelemetryAPI(t *testing.T) {
	in := sampleInput()
	usage := 40.0
	in.Telemetry = []plugin.Usage{
		{
			Provider: "transit-b", Host: "edge", Interface: "ether2", IfIndex: 6,
			CommitMbps: 500, BillingDay: 1, Mode: plugin.PercentileGreater,
			PeriodStart: in.At, PeriodEnd: in.At.Add(24 * time.Hour),
			Samples: 4, InMbps: 10, OutMbps: 20, InMbps95: 15, OutMbps95: 25,
			UsageMbps: usage, Single: true, Polled: in.At,
		},
		{
			Provider: "transit-a", Host: "edge", Interface: "ether1", IfIndex: 5,
			CommitMbps: 1000, BillingDay: 1, Mode: plugin.PercentileSeparate,
			PeriodStart: in.At, PeriodEnd: in.At.Add(24 * time.Hour),
			Samples: 4, InMbps: 100, OutMbps: 40, InMbps95: 90, OutMbps95: 30,
			Polled: in.At,
		},
	}
	snap := Assemble(in)
	if len(snap.Telemetry) != 2 || snap.Telemetry[0].Provider != "transit-a" || snap.Telemetry[0].UsageMbps != nil {
		t.Fatalf("separate row = %+v", snap.Telemetry)
	}
	if snap.Telemetry[1].UsageMbps == nil || *snap.Telemetry[1].UsageMbps != 40 {
		t.Fatalf("greater row = %+v", snap.Telemetry[1])
	}
	ts := newTestServer(t, snap, "", "")
	code, _, body := do(t, http.MethodGet, ts.URL+"/api/telemetry", "", "")
	if code != http.StatusOK {
		t.Fatalf("status %d %s", code, body)
	}
	if !strings.Contains(string(body), `"percentile":"separate"`) || strings.Contains(string(body), `"usage_mbps":0`) {
		t.Fatalf("body = %s", body)
	}
	text := string(Metrics(snap))
	for _, want := range []string{
		`packeteer_telemetry_up{provider="transit-a",interface="ether1",percentile="separate"} 1`,
		`packeteer_telemetry_in_95th_bps{provider="transit-a",interface="ether1",percentile="separate"} 9e+07`,
		`packeteer_telemetry_usage_bps{provider="transit-b",interface="ether2",percentile="greater"} 4e+07`,
		`packeteer_telemetry_commit_bps{provider="transit-a",interface="ether1",percentile="separate"} 1e+09`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q\n%s", want, text)
		}
	}
	if strings.Contains(text, `percentile="separate"}`) && strings.Contains(text, "packeteer_telemetry_usage_bps{") {
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(line, "packeteer_telemetry_usage_bps{") && strings.Contains(line, `percentile="separate"`) {
				t.Errorf("separate mode exported a single usage: %s", line)
			}
		}
	}
}

func TestMetricsNotReady(t *testing.T) {
	s := Snapshot{Mode: "observe", BGPConfigured: true}
	text := string(Metrics(s))
	if !strings.Contains(text, "packeteer_ready 0") || !strings.Contains(text, "packeteer_bgp_ready 0") || !strings.Contains(text, "packeteer_improvements_active 0") {
		t.Fatalf("metrics:\n%s", text)
	}
	if strings.Contains(text, "packeteer_bgp_session") {
		t.Fatalf("session series without peers:\n%s", text)
	}
}

func TestBasicAuth(t *testing.T) {
	ts := newTestServer(t, sampleSnap(), "operator", "s3cret")
	code, hdr, _ := do(t, http.MethodGet, ts.URL+"/healthz", "", "")
	if code != http.StatusUnauthorized || !strings.Contains(hdr.Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("no auth = %d %q", code, hdr.Get("WWW-Authenticate"))
	}
	code, _, _ = do(t, http.MethodGet, ts.URL+"/metrics", "operator", "wrong")
	if code != http.StatusUnauthorized {
		t.Fatalf("bad password = %d", code)
	}
	code, _, _ = do(t, http.MethodGet, ts.URL+"/", "operator", "s3cret")
	if code != http.StatusOK {
		t.Fatalf("dashboard with auth = %d", code)
	}
	code, _, body := do(t, http.MethodGet, ts.URL+"/api/probes", "operator", "s3cret")
	if code != http.StatusOK || !strings.Contains(string(body), "198.51.100.0/24") {
		t.Fatalf("api with auth = %d %s", code, body)
	}
	if _, err := New(Options{User: "only-user"}); err == nil {
		t.Fatal("one-sided auth was accepted")
	}
}

func TestDashboardIsLocal(t *testing.T) {
	entries, err := fs.ReadDir(webFS, "web")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no dashboard files")
	}
	for _, e := range entries {
		b, err := fs.ReadFile(webFS, "web/"+e.Name())
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		for _, bad := range []string{"http://", "https://", "//cdn", "unpkg", "jsdelivr", "googleapis", "innerHTML", "document.write"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s contains %q", e.Name(), bad)
			}
		}
	}
	html, err := fs.ReadFile(webFS, "web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(html)
	for _, want := range []string{`href="/app.css"`, `src="/app.js"`, "Providers", "Prefixes", "Active improvements"} {
		if !strings.Contains(page, want) {
			t.Errorf("index missing %q", want)
		}
	}
	if strings.Contains(page, "<form") || strings.Contains(page, "onclick=") {
		t.Fatalf("dashboard is not read-only:\n%s", page)
	}
	js, err := fs.ReadFile(webFS, "web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(js)
	for _, want := range []string{"textContent", "REFRESH_MS", "/api/prefixes", "/api/improvements", "/api/providers", "setInterval"} {
		if !strings.Contains(script, want) {
			t.Errorf("app.js missing %q", want)
		}
	}
}

func TestAssembleSortsAndSkipsUnprobedRIB(t *testing.T) {
	snap := sampleSnap()
	if len(snap.Prefixes) != 2 || snap.Prefixes[0].Prefix != "198.51.100.0/24" || snap.Prefixes[1].Prefix != "203.0.113.0/24" {
		t.Fatalf("prefixes = %+v", snap.Prefixes)
	}
	if !snap.Prefixes[0].InRIB || snap.Prefixes[0].Current != "transit-a" || snap.Prefixes[0].Recommended != "transit-b" {
		t.Fatalf("joined prefix = %+v", snap.Prefixes[0])
	}
	if snap.Prefixes[1].InRIB {
		t.Fatal("failed probe picked up a route it does not have")
	}
	if len(snap.Decisions[0].Candidates) != 1 || snap.Decisions[0].Candidates[0].Score != 0 {
		t.Fatalf("score = %+v", snap.Decisions[0].Candidates)
	}
}

func TestCollectorBeforeStart(t *testing.T) {
	ps := []config.Provider{{Name: "transit-a", SourceIP: "192.0.2.11", NextHop: "192.0.2.1"}}
	c := NewCollector("dev", "observe", ps)
	ps[0].Name = "changed"
	snap := c.Snapshot()
	if snap.Ready() || snap.Providers[0].Name != "transit-a" || snap.Providers[0].Reason != "starting" || snap.Providers[0].Up {
		t.Fatalf("before start: %+v", snap.Providers)
	}
	c.SetStarted(true)
	snap = c.Snapshot()
	if !snap.Ready() || snap.BGPConfigured {
		t.Fatalf("observe without BGP should be ready: %+v", snap)
	}
	if snap.Providers[0].Reason != "unknown" {
		t.Fatalf("reason = %q", snap.Providers[0].Reason)
	}
}

func TestStartAndShutdown(t *testing.T) {
	s, err := New(Options{Addr: "127.0.0.1:0", Snapshot: func() Snapshot {
		return Snapshot{Version: "dev", Mode: "observe", Started: true}
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get("http://" + s.Addr() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestListenInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	s, err := New(Options{Addr: ln.Addr().String(), Snapshot: func() Snapshot { return Snapshot{} }})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err == nil {
		_ = s.Shutdown(context.Background())
		t.Fatal("Start succeeded on a busy address")
	}
}

func assertJSON(t *testing.T, url string, check func(*testing.T, map[string]any)) {
	t.Helper()
	code, _, body := do(t, http.MethodGet, url, "", "")
	if code != http.StatusOK {
		t.Fatalf("%s = %d %s", url, code, body)
	}
	if strings.Contains(string(body), ":null") {
		t.Fatalf("%s contains null: %s", url, body)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("%s: %v (%s)", url, err, body)
	}
	check(t, m)
}
