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

	"github.com/GrandArcher/Packeteer/internal/verify"
)

func getVerification(t *testing.T, opt Options) map[string]any {
	t.Helper()
	opt.Snapshot = func() Snapshot { return Snapshot{Mode: "inject"} }
	s, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/verification", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestVerificationEndpoint(t *testing.T) {
	off := getVerification(t, Options{})
	if off["enabled"] != false || len(off["results"].([]any)) != 0 {
		t.Fatalf("disabled body = %v", off)
	}
	at := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	rows := []verify.Result{
		{Kind: verify.Outbound, Prefix: netip.MustParsePrefix("198.51.100.0/24"), Provider: "transit-b", From: "transit-a", Status: verify.Verified,
			Started: at, Due: at.Add(5 * time.Minute), Checked: at.Add(5 * time.Minute), ExpectedMbps: 40, MovedMbps: 38, MovedPct: 95, Detail: "38.0 of 40.0 Mbps moved (95%)"},
		{Kind: verify.Inbound, Provider: "transit-a", Status: verify.NotMoved, BackedOut: true, Backoff: time.Hour,
			Started: at, Due: at.Add(10 * time.Minute), Checked: at.Add(10 * time.Minute), ExpectedMbps: 150, Detail: "0.0 of 150.0 Mbps moved (0%)"},
	}
	on := getVerification(t, Options{Verification: func() []verify.Result { return rows }})
	if on["enabled"] != true || on["mode"] != "inject" {
		t.Fatalf("body = %v", on)
	}
	res := on["results"].([]any)
	out, in := res[0].(map[string]any), res[1].(map[string]any)
	if out["kind"] != "outbound" || out["prefix"] != "198.51.100.0/24" || out["status"] != "verified" || out["moved_pct"] != float64(95) || out["from"] != "transit-a" {
		t.Fatalf("outbound = %v", out)
	}
	if in["kind"] != "inbound" || in["status"] != "not_moved" || in["backed_out"] != true || in["provider"] != "transit-a" {
		t.Fatalf("inbound = %v", in)
	}
	if _, ok := in["prefix"]; ok {
		t.Fatalf("an inbound result carries a prefix: %v", in)
	}
	if _, ok := in["Backoff"]; ok {
		t.Fatalf("backoff leaked into the JSON: %v", in)
	}
}

func TestImprovementsPageHasVerificationSection(t *testing.T) {
	html := mustWeb(t, "web/improvements.html")
	if !strings.Contains(html, `id="verification-section" hidden`) || !strings.Contains(html, `id="verification"`) {
		t.Fatal("improvements.html has no hidden verification section")
	}
	app := mustWeb(t, "web/app.js")
	for _, want := range []string{`"/api/verification"`, "renderVerification", `"Not moved"`, "backed out"} {
		if !strings.Contains(app, want) {
			t.Errorf("app.js missing %s", want)
		}
	}
}

// TestVerificationPage runs the Improvements page section in Node (#305).
// Like the Atlas page test, it is skipped without Node locally and required
// in CI.
func TestVerificationPage(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the verification page test")
		}
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "verification_page_test.js").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("verification page: %v\n%s", err, out)
	}
}
