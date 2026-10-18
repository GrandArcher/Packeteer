package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func lookupFixture() plugin.LookupView {
	zero, n := 0, 120
	return plugin.LookupView{
		Configured: true, Anonymous: true, BaseURL: "https://pdb.example.invalid",
		Fetched: time.Now().Add(-time.Minute), NetworkCount: 2, MembershipCount: 3,
		Exchanges: []plugin.LookupExchange{{Name: "example-ix", IXID: 1, IXName: "Example IX"}},
		Networks: []plugin.LookupNetwork{
			{ASN: 64496, Name: "Net A", Org: "Org A", Policy: "Open", InfoPrefixes4: &n, InfoPrefixes6: &zero},
			{ASN: 64497, Name: "Net B", Org: "Org B"},
		},
		Memberships: []plugin.LookupMembership{
			{Exchange: "example-ix", IXID: 1, ASN: 64496, IPv4: "192.0.2.10", IPv6: "2001:db8::10", RouteServer: true},
			{Exchange: "example-ix", IXID: 1, ASN: 64496, IPv4: "192.0.2.12"},
			{Exchange: "example-ix", IXID: 1, ASN: 64497, IPv4: "192.0.2.11"},
		},
	}
}

func getLookup(t *testing.T, s *Server, target string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	return rec.Code, body
}

func TestLookupUnconfigured(t *testing.T) {
	s := newIXPServer(t)
	code, body := getLookup(t, s, "/api/lookup")
	if code != http.StatusOK || body["configured"] != false || body["mode"] != "observe" {
		t.Fatalf("%d %v", code, body)
	}
	for _, k := range []string{"exchanges", "networks", "memberships"} {
		if l, ok := body[k].([]any); !ok || len(l) != 0 {
			t.Errorf("%s = %#v, want empty list", k, body[k])
		}
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(rec.Body.String(), "packeteer_lookup_") {
		t.Fatalf("metrics without a lookup:\n%s", rec.Body)
	}
}

func TestLookupAPI(t *testing.T) {
	s := newIXPServer(t)
	s.SetLookup(lookupFixture)
	code, body := getLookup(t, s, "/api/lookup")
	if code != http.StatusOK || body["configured"] != true || body["anonymous"] != true || body["network_count"] != float64(2) {
		t.Fatalf("%d %v", code, body)
	}
	nets := body["networks"].([]any)
	a := nets[0].(map[string]any)
	if a["org"] != "Org A" || a["policy"] != "Open" || a["info_prefixes4"] != float64(120) || a["info_prefixes6"] != float64(0) {
		t.Fatalf("network A %v", a)
	}
	if _, ok := nets[1].(map[string]any)["info_prefixes4"]; ok {
		t.Fatalf("absent info_prefixes4 serialized as a value: %v", nets[1])
	}
	if len(body["memberships"].([]any)) != 3 {
		t.Fatalf("memberships %v", body["memberships"])
	}

	for _, q := range []string{"?asn=64496", "?asn=AS64496", "?asn=as64496"} {
		code, body = getLookup(t, s, "/api/lookup"+q)
		nets, mems := body["networks"].([]any), body["memberships"].([]any)
		if code != http.StatusOK || len(nets) != 1 || len(mems) != 2 || nets[0].(map[string]any)["asn"] != float64(64496) || body["membership_count"] != float64(3) {
			t.Fatalf("%s: %d %v", q, code, body)
		}
	}
	code, body = getLookup(t, s, "/api/lookup?asn=64999")
	if code != http.StatusOK || len(body["networks"].([]any)) != 0 || len(body["memberships"].([]any)) != 0 {
		t.Fatalf("unknown asn: %d %v", code, body)
	}
	for _, q := range []string{"?asn=x", "?asn=0", "?asn=4294967296", "?asn=-1"} {
		if code, _ = getLookup(t, s, "/api/lookup"+q); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", q, code)
		}
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/lookup", nil))
	if rec.Code == http.StatusOK {
		t.Fatalf("POST answered %d", rec.Code)
	}
}

func TestLookupMetrics(t *testing.T) {
	s := newIXPServer(t)
	s.SetLookup(lookupFixture)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	m := rec.Body.String()
	for _, want := range []string{"packeteer_lookup_networks 2\n", "packeteer_lookup_memberships 3\n", "packeteer_lookup_up 1\n", "packeteer_lookup_age_seconds "} {
		if !strings.Contains(m, want) {
			t.Errorf("missing %q in\n%s", want, m)
		}
	}

	stale := lookupFixture()
	stale.Stale, stale.Error = true, "lookup is stale"
	out := string(LookupMetrics(stale, time.Now()))
	for _, want := range []string{"packeteer_lookup_networks 0\n", "packeteer_lookup_memberships 0\n", "packeteer_lookup_up 0\n", "packeteer_lookup_age_seconds "} {
		if !strings.Contains(out, want) {
			t.Errorf("stale: missing %q in\n%s", want, out)
		}
	}
	failing := lookupFixture()
	failing.Error = "lookup: HTTP 500"
	if out = string(LookupMetrics(failing, time.Now())); !strings.Contains(out, "packeteer_lookup_up 0\n") || !strings.Contains(out, "packeteer_lookup_networks 2\n") {
		t.Fatalf("failing refresh:\n%s", out)
	}
	never := plugin.LookupView{Configured: true}
	if out = string(LookupMetrics(never, time.Now())); !strings.Contains(out, "packeteer_lookup_up 0\n") || strings.Contains(out, "age_seconds") {
		t.Fatalf("never fetched:\n%s", out)
	}
}
