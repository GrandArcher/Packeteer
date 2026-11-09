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

func memberFixture(t *testing.T) *Server {
	t.Helper()
	s := newIXPServer(t)
	s.SetIXPMembers(func() plugin.MemberView {
		return plugin.MemberView{
			Configured: true, Manager: true, ManagerURL: "https://ixp.example.invalid/ixp",
			Members: []plugin.IXPMember{
				{ASN: 64496, Name: "Doc Member", Connections: []plugin.IXPConnection{{
					IXPID: 1, State: "active",
					Interfaces: []plugin.IXPInterface{{SwitchID: 7, Switch: "sw1", Colo: "cab-a", SpeedMbps: 10000}},
					Addresses:  []plugin.IXPAddress{{Family: "ipv4", Address: "192.0.2.20", VLANID: 10}},
				}}},
				{ASN: 64497, Name: "Other Member"},
			},
		}
	})
	at := time.Unix(1_800_000_000, 0).UTC()
	s.SetIXPFabric(func() plugin.FabricView {
		return plugin.FabricView{Configured: true, Round: at, Samples: []plugin.FabricSample{
			{Vantage: "v2", ASN: 64496, Address: "192.0.2.20", Family: "ipv4", VLANID: 10, LossPct: 0, RTTMs: 0.8, JitterMs: 0.1, At: at},
			{Vantage: "v1", ASN: 64496, Address: "192.0.2.20", Family: "ipv4", VLANID: 10, LossPct: 5, RTTMs: 1.5, JitterMs: 0.2, PastTolerance: true, At: at},
			{Vantage: "v1", ASN: 64497, Address: "192.0.2.21", Family: "ipv4", VLANID: 10, RTTMs: 9, At: at},
		}}
	})
	s.SetIXPRouteServers(func() plugin.RouteServerView {
		return plugin.RouteServerView{Configured: true, Sessions: []plugin.RouteServerSession{
			{Server: "rs1", Session: "pb_a", ASN: 64496, Established: true, Counted: true, Received: 10, Accepted: 7, Filtered: 3},
			{Server: "rs1", Session: "pb_b", ASN: 64497},
		}}
	}, func(server, session string) ([]plugin.RouteServerSample, bool) { return nil, false })
	return s
}

func getJSONBody(t *testing.T, s *Server, path string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func TestIXPMemberAPI(t *testing.T) {
	s := memberFixture(t)
	code, body := getJSONBody(t, s, "/api/ixp/members/64496")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if body["asn"] != float64(64496) || body["name"] != "Doc Member" {
		t.Fatalf("identity %v", body)
	}
	if body["ixp_manager_url"] != "https://ixp.example.invalid/ixp/admin/search?search=AS64496" {
		t.Fatalf("link %v", body["ixp_manager_url"])
	}
	if c, _ := body["connections"].([]any); len(c) != 1 {
		t.Fatalf("connections %v", body["connections"])
	}
	fab, _ := body["fabric"].(map[string]any)
	samples, _ := fab["samples"].([]any)
	if len(samples) != 2 {
		t.Fatalf("this member's samples only: %v", fab)
	}
	first, _ := samples[0].(map[string]any)
	second, _ := samples[1].(map[string]any)
	if first["vantage"] != "v1" || second["vantage"] != "v2" || first["loss_pct"] != float64(5) || first["rtt_ms"] != 1.5 {
		t.Fatalf("samples not sorted by vantage or wrong values: %v", samples)
	}
	sess, _ := body["route_server_sessions"].([]any)
	if len(sess) != 1 || sess[0].(map[string]any)["session"] != "pb_a" {
		t.Fatalf("sessions %v", sess)
	}

	// A member the list does not know, and a bad ASN.
	if code, _ := getJSONBody(t, s, "/api/ixp/members/64499"); code != http.StatusNotFound {
		t.Errorf("unknown asn = %d", code)
	}
	for _, bad := range []string{"0", "abc", "4294967296", "-1", "AS64496"} {
		if code, _ := getJSONBody(t, s, "/api/ixp/members/"+bad); code != http.StatusBadRequest {
			t.Errorf("asn %q = %d, want 400", bad, code)
		}
	}
}

func TestIXPMemberAPIWithoutManagerOrFabric(t *testing.T) {
	s := newIXPServer(t)
	s.SetIXPMembers(func() plugin.MemberView {
		return plugin.MemberView{Configured: true, Members: []plugin.IXPMember{{ASN: 64496}}}
	})
	code, body := getJSONBody(t, s, "/api/ixp/members/64496")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if _, ok := body["ixp_manager_url"]; ok {
		t.Errorf("a named IX-F document has no IXP Manager link: %v", body["ixp_manager_url"])
	}
	fab, _ := body["fabric"].(map[string]any)
	if fab["configured"] != false {
		t.Errorf("fabric %v", fab)
	}
	if l, ok := fab["samples"].([]any); !ok || len(l) != 0 {
		t.Errorf("samples %#v", fab["samples"])
	}
	if l, ok := body["route_server_sessions"].([]any); !ok || len(l) != 0 {
		t.Errorf("sessions %#v", body["route_server_sessions"])
	}
}

func TestIXPMemberAPINeedsAnIXPSource(t *testing.T) {
	if code, _ := getJSONBody(t, newIXPServer(t), "/api/ixp/members/64496"); code != http.StatusNotFound {
		t.Fatalf("no ixp sources = %d, want 404", code)
	}
}

// A route-server-only deployment (no ixp.members) still has pages.
func TestIXPMemberFromRouteServerOnly(t *testing.T) {
	s := newIXPServer(t)
	s.SetIXPRouteServers(func() plugin.RouteServerView {
		return plugin.RouteServerView{Configured: true, Sessions: []plugin.RouteServerSession{{Server: "rs1", Session: "pb_a", ASN: 64496, Name: "Doc Member"}}}
	}, func(string, string) ([]plugin.RouteServerSample, bool) { return nil, false })
	code, body := getJSONBody(t, s, "/api/ixp/members/64496")
	if code != http.StatusOK || body["name"] != "Doc Member" {
		t.Fatalf("%d %v", code, body)
	}
}

func TestIXPMemberMetrics(t *testing.T) {
	s := memberFixture(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	text := rec.Body.String()
	for _, want := range []string{
		`packeteer_ixp_member_rtt_ms{asn="64496",vlan="10",vantage="v1",family="ipv4"} 1.5` + "\n",
		`packeteer_ixp_member_rtt_ms{asn="64496",vlan="10",vantage="v2",family="ipv4"} 0.8` + "\n",
		`packeteer_ixp_member_loss_pct{asn="64496",vlan="10",vantage="v1",family="ipv4"} 5` + "\n",
		`packeteer_ixp_member_jitter_ms{asn="64497",vlan="10",vantage="v1",family="ipv4"} 0` + "\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
}

func TestIXPMemberMetricsWorstAddressErrorsAndStale(t *testing.T) {
	samples := []plugin.FabricSample{
		{Vantage: "v1", ASN: 64496, Address: "192.0.2.20", Family: "ipv4", VLANID: 10, LossPct: 1, RTTMs: 2, JitterMs: 0.5},
		{Vantage: "v1", ASN: 64496, Address: "192.0.2.30", Family: "ipv4", VLANID: 10, LossPct: 4, RTTMs: 1, JitterMs: 0.1},
		{Vantage: "v1", ASN: 64496, Address: "2001:db8::20", Family: "ipv6", VLANID: 10, RTTMs: 3},
		{Vantage: "v1", ASN: 64496, Address: "192.0.2.40", Family: "ipv4", VLANID: 11, Error: "timeout"},
	}
	out := string(IXPMemberFabricMetrics(plugin.FabricView{Configured: true, Samples: samples}))
	for _, want := range []string{
		`packeteer_ixp_member_rtt_ms{asn="64496",vlan="10",vantage="v1",family="ipv4"} 2` + "\n",
		`packeteer_ixp_member_loss_pct{asn="64496",vlan="10",vantage="v1",family="ipv4"} 4` + "\n",
		`packeteer_ixp_member_jitter_ms{asn="64496",vlan="10",vantage="v1",family="ipv4"} 0.5` + "\n",
		`packeteer_ixp_member_rtt_ms{asn="64496",vlan="10",vantage="v1",family="ipv6"} 3` + "\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Count(out, "packeteer_ixp_member_rtt_ms{") != 2 {
		t.Errorf("one series per asn, vlan, vantage, family; an error is not a measurement:\n%s", out)
	}
	if strings.Contains(out, `vlan="11"`) {
		t.Errorf("a probe error made a series:\n%s", out)
	}
	if b := IXPMemberFabricMetrics(plugin.FabricView{Configured: true, Stale: true, Samples: samples}); len(b) != 0 {
		t.Errorf("stale list still has series:\n%s", b)
	}
	if b := IXPMemberFabricMetrics(plugin.FabricView{Samples: samples}); len(b) != 0 {
		t.Errorf("unconfigured fabric has series:\n%s", b)
	}
}

// #166: the pages and the member endpoint are GET only, open to every
// signed-in role (all are exchange staff), and closed without a login.
func TestIXPMemberPageRoles(t *testing.T) {
	e := newUI(t)
	for _, path := range []string{"/ixp/member/64496", "/ixp/member/", "/ixp-member.js", "/api/ixp/members/64496"} {
		rec, _ := e.do(t, "GET", path, plugin.RoleViewer, nil)
		want := http.StatusOK
		if path == "/api/ixp/members/64496" {
			want = http.StatusNotFound
		}
		if rec.Code != want {
			t.Errorf("viewer GET %s = %d, want %d", path, rec.Code, want)
		}
		anon := httptest.NewRecorder()
		e.h.ServeHTTP(anon, httptest.NewRequest(http.MethodGet, path, nil))
		if anon.Code != http.StatusUnauthorized && anon.Code != http.StatusFound {
			t.Errorf("anonymous GET %s = %d", path, anon.Code)
		}
	}
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if rec, _ := e.do(t, method, "/api/ixp/members/64496", plugin.RoleAdmin, nil); rec.Code == http.StatusOK {
			t.Errorf("%s /api/ixp/members/64496 = %d, want a refusal", method, rec.Code)
		}
	}
	rec, _ := e.do(t, "GET", "/ixp-member.js", plugin.RoleViewer, nil)
	js := rec.Body.String()
	for _, want := range []string{`"/api/ixp/members/"`, `"/api/ixp/routeservers/history`, `ixp_manager_url`, `rel = "noopener noreferrer"`} {
		if !strings.Contains(js, want) {
			t.Errorf("ixp-member.js missing %q", want)
		}
	}
	for _, banned := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", `"POST"`, `"PUT"`, `"DELETE"`, "eval("} {
		if strings.Contains(js, banned) {
			t.Errorf("ixp-member.js contains %q", banned)
		}
	}
}
