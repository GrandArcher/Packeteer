package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/nonbgp"
	"github.com/GrandArcher/Packeteer/internal/policy"
)

func getSynthetic(t *testing.T, opt Options) map[string]any {
	t.Helper()
	opt.Snapshot = func() Snapshot { return Snapshot{Mode: "inject"} }
	s, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/synthetic", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestSyntheticEndpoint(t *testing.T) {
	off := getSynthetic(t, Options{})
	if off["enabled"] != false || len(off["routes"].([]any)) != 0 {
		t.Fatalf("disabled body = %v", off)
	}
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	st := nonbgp.Status{
		Meta:   nonbgp.Meta{Mode: "inject", DefaultProvider: "isp-a", Steerer: "mikrotik", Covering: "ripestat", WidenBits: 4, MaxBlocks: 10000},
		Blocks: 3, Dropped: 2, LookupErrors: 1, LastError: "ripestat: 429 Too Many Requests",
		Routes: []nonbgp.RouteStatus{
			{Source: nonbgp.SourceSynthetic, Prefix: netip.MustParsePrefix("198.51.100.0/24"), Upper: netip.MustParsePrefix("198.51.100.0/23"), Blocks: 1, LastSeen: at,
				SteeredTo: "isp-b", NextHop: netip.MustParseAddr("198.51.100.1"), SteeredSince: at},
			{Source: nonbgp.SourceSynthetic, Prefix: netip.MustParsePrefix("2001:db8::/46"), Blocks: 2, LastSeen: at},
		},
	}
	on := getSynthetic(t, Options{Synthetic: func() nonbgp.Status { return st }})
	if on["enabled"] != true || on["mode"] != "inject" || on["default_provider"] != "isp-a" || on["steerer"] != "mikrotik" ||
		on["tracked_blocks"] != float64(3) || on["dropped_blocks"] != float64(2) || on["last_error"] != "ripestat: 429 Too Many Requests" {
		t.Fatalf("body = %v", on)
	}
	rows := on["routes"].([]any)
	steered, plain := rows[0].(map[string]any), rows[1].(map[string]any)
	if steered["source"] != "synthetic" || steered["prefix"] != "198.51.100.0/24" || steered["upper"] != "198.51.100.0/23" ||
		steered["steered_to"] != "isp-b" || steered["next_hop"] != "198.51.100.1" {
		t.Fatalf("steered row = %v", steered)
	}
	for _, k := range []string{"upper", "steered_to", "next_hop", "steered_since"} {
		if _, ok := plain[k]; ok {
			t.Errorf("an unsteered row carries %s: %v", k, plain)
		}
	}
	if plain["source"] != "synthetic" {
		t.Fatalf("a synthetic row is not labeled: %v", plain)
	}
}

func TestImprovementsAreLabeledSynthetic(t *testing.T) {
	syn := netip.MustParsePrefix("198.51.100.0/24")
	in := Input{
		Improvements: []policy.Improvement{
			{Prefix: syn, Provider: "isp-b", Native: "isp-a"},
			{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Provider: "isp-b", Native: "isp-a"},
		},
		Synthetic: func(p netip.Prefix) bool { return p == syn },
	}
	rows := assembleImprovements(in)
	if len(rows) != 2 || rows[0].Prefix != "198.51.100.0/24" || rows[0].Source != "synthetic" || rows[1].Source != "" {
		t.Fatalf("rows = %+v", rows)
	}
	in.Synthetic = nil
	for _, r := range assembleImprovements(in) {
		if r.Source != "" {
			t.Fatalf("a BGP deployment labeled %s", r.Prefix)
		}
	}
}

func TestImprovementsPageHasSyntheticSection(t *testing.T) {
	html := mustWeb(t, "web/improvements.html")
	if !strings.Contains(html, `id="synthetic-section" hidden`) || !strings.Contains(html, `id="synthetic"`) {
		t.Fatal("improvements.html has no hidden synthetic section")
	}
	app := mustWeb(t, "web/app.js")
	if !strings.Contains(app, `"/api/synthetic"`) || !strings.Contains(app, "renderSynthetic") {
		t.Fatal("app.js does not read /api/synthetic")
	}
}

// TestSyntheticPage runs the Improvements page's synthetic section in Node
// (#300). Like the verification page test, it is skipped without Node
// locally and required in CI.
func TestSyntheticPage(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the synthetic page test")
		}
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "synthetic_page_test.js").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("synthetic page: %v\n%s", err, out)
	}
}
