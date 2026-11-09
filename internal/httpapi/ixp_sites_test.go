package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/federation"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func sitesView() federation.IXPSitesView {
	return federation.IXPSitesView{
		Enabled: true,
		Sites: []federation.SiteHealth{
			{Name: "site-a", Self: true, Fresh: true, Status: federation.StatusOK},
			{Name: "site-b", Fresh: true, Status: federation.StatusDegraded, MembersPast: 1,
				PastTolerance: []plugin.FabricPath{{ASN: 64497, VLANID: 10, Vantage: "lan1", Family: "ipv4", LossPct: 40, RTTMs: 310.5, PastTolerance: true}}},
			{Name: "site-c", Status: federation.StatusUnreachable, PastTolerance: []plugin.FabricPath{}},
		},
		Links: []federation.SiteLink{
			{Site: "site-a", CoreLinkStatus: plugin.CoreLinkStatus{Name: "a-to-b", Peer: "site-b", Up: true, LossPct: 2.5, RTTMs: 3.25}},
			{Site: "site-a", CoreLinkStatus: plugin.CoreLinkStatus{Name: "a-to-c", Peer: "site-c", Error: "source address unavailable", Degraded: true}},
		},
		Incidents: []federation.SiteIncident{
			{Site: "site-b", Scope: federation.ScopeFabric, Detail: "switch sw2: 3 of 4 members degraded"},
			{Site: "site-c", Scope: federation.ScopeSite, Detail: "no fresh federation snapshot"},
		},
	}
}

func TestIXPSitesEndpoint(t *testing.T) {
	s := newIXPServer(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ixp/sites", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"sites", "links", "incidents"} {
		if l, ok := body[k].([]any); !ok || len(l) != 0 {
			t.Errorf("unwired %s = %#v, want an empty list", k, body[k])
		}
	}
	if body["enabled"] != false || body["mode"] != "observe" {
		t.Fatalf("unwired: %s", rec.Body)
	}
	mrec := httptest.NewRecorder()
	s.Handler().ServeHTTP(mrec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(mrec.Body.String(), "packeteer_ixp_site") || strings.Contains(mrec.Body.String(), "packeteer_ixp_core") {
		t.Fatalf("site metrics without the view:\n%s", mrec.Body)
	}

	s.SetIXPSites(sitesView)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ixp/sites", nil))
	var got struct {
		Enabled   bool                      `json:"enabled"`
		Sites     []federation.SiteHealth   `json:"sites"`
		Links     []federation.SiteLink     `json:"links"`
		Incidents []federation.SiteIncident `json:"incidents"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || len(got.Sites) != 3 || got.Sites[1].PastTolerance[0].RTTMs != 310.5 || got.Links[0].Peer != "site-b" || got.Links[0].Site != "site-a" || got.Incidents[0].Scope != "fabric" {
		t.Fatalf("view = %s", rec.Body)
	}
	for _, want := range []string{`"status":"degraded"`, `"members_past_tolerance":1`, `"past_tolerance":[]`, `"loss_pct":2.5`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("missing %s in %s", want, rec.Body)
		}
	}

	wrong := httptest.NewRecorder()
	s.Handler().ServeHTTP(wrong, httptest.NewRequest(http.MethodPost, "/api/ixp/sites", nil))
	if wrong.Code == http.StatusOK {
		t.Fatalf("POST answered %d", wrong.Code)
	}
}

func TestIXPSitesMetrics(t *testing.T) {
	s := newIXPServer(t)
	s.SetIXPSites(sitesView)
	mrec := httptest.NewRecorder()
	s.Handler().ServeHTTP(mrec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	m := mrec.Body.String()
	for _, want := range []string{
		`packeteer_ixp_site_up{site="site-a"} 1`, `packeteer_ixp_site_up{site="site-c"} 0`,
		`packeteer_ixp_site_incidents{site="site-a"} 0`, `packeteer_ixp_site_incidents{site="site-b"} 1`,
		`packeteer_ixp_core_rtt_ms{site="site-a",peer="site-b",link="a-to-b"} 3.25`,
		`packeteer_ixp_core_loss_pct{site="site-a",peer="site-b",link="a-to-b"} 2.5`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("missing %s in\n%s", want, m)
		}
	}
	if strings.Contains(m, `link="a-to-c"`) {
		t.Errorf("a link that could not be probed has a series:\n%s", m)
	}
	if b := IXPSitesMetrics(federation.IXPSitesView{}); len(b) != 0 {
		t.Errorf("disabled view has series:\n%s", b)
	}
}

// #167: the page and the endpoint are GET only, open to every signed-in
// role, and closed without a login.
func TestIXPSitesPageRoles(t *testing.T) {
	e := newUI(t)
	for _, path := range []string{"/ixp/sites", "/ixp-sites.js", "/api/ixp/sites"} {
		rec, _ := e.do(t, "GET", path, plugin.RoleViewer, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("viewer GET %s = %d", path, rec.Code)
		}
		anon := httptest.NewRecorder()
		e.h.ServeHTTP(anon, httptest.NewRequest(http.MethodGet, path, nil))
		if anon.Code != http.StatusUnauthorized && anon.Code != http.StatusFound {
			t.Errorf("anonymous GET %s = %d", path, anon.Code)
		}
	}
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if rec, _ := e.do(t, method, "/api/ixp/sites", plugin.RoleAdmin, nil); rec.Code == http.StatusOK {
			t.Errorf("%s /api/ixp/sites = %d, want a refusal", method, rec.Code)
		}
	}
	rec, _ := e.do(t, "GET", "/ixp-sites.js", plugin.RoleViewer, nil)
	js := rec.Body.String()
	if !strings.Contains(js, `"/api/ixp/sites"`) {
		t.Error("ixp-sites.js does not read /api/ixp/sites")
	}
	for _, banned := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", `"POST"`, `"PUT"`, `"DELETE"`, "eval("} {
		if strings.Contains(js, banned) {
			t.Errorf("ixp-sites.js contains %q", banned)
		}
	}
}
