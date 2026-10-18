package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/ixpmember/ixf"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestIXPMembersUnconfigured(t *testing.T) {
	s := newIXPServer(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ixp/members", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["configured"] != false || body["mode"] != "observe" {
		t.Fatalf("%s", rec.Body)
	}
	members, ok := body["members"].([]any)
	ixps, ok2 := body["ixps"].([]any)
	if !ok || len(members) != 0 || !ok2 || len(ixps) != 0 {
		t.Fatalf("lists %#v %#v", body["members"], body["ixps"])
	}
	mrec := httptest.NewRecorder()
	s.Handler().ServeHTTP(mrec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(mrec.Body.String(), "packeteer_ixp_") {
		t.Fatalf("metrics without a source:\n%s", mrec.Body)
	}
}

func TestIXPMembersAPIAndMetrics(t *testing.T) {
	doc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("X-IXP-Manager-API-Key") != "" {
			t.Errorf("method %s header %q", r.Method, r.Header.Get("X-IXP-Manager-API-Key"))
		}
		_, _ = io.WriteString(w, `{"version":"1.0","ixp_list":[{"ixp_id":1,"shortname":"example-ix","name":"Example IX","vlan":[{"id":10,"ipv4":{"prefix":"192.0.2.0","mask_length":24}}],"switch":[{"id":7,"name":"sw1","colo":"cab-a"}]}],"member_list":[{"asnum":64496,"name":"Member A","contact_email":["hidden@example.invalid"],"connection_list":[{"ixp_id":1,"state":"active","if_list":[{"switch_id":7,"if_speed":10000,"if_phys_speed":100000}],"vlan_list":[{"vlan_id":10,"ipv4":{"address":"192.0.2.20","routeserver":true,"as_macro":"AS64496:AS-EXAMPLE","max_prefix":10,"mac_addresses":["02:00:00:00:00:01"]}}]}]}]}`)
	}))
	defer doc.Close()
	cfg, err := plugin.ConfigFromYAML("url: " + doc.URL + "/members.json\n")
	if err != nil {
		t.Fatal(err)
	}
	p, err := ixf.New(cfg, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Stop(context.Background()) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && p.View().MemberCount != 1 {
		time.Sleep(10 * time.Millisecond)
	}
	if p.View().Error != "" || p.View().MemberCount != 1 {
		t.Fatalf("%+v", p.View())
	}
	s := newIXPServer(t)
	s.SetIXPMembers(p.View)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ixp/members", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	text := rec.Body.String()
	for _, want := range []string{`"asn":64496`, `"address":"192.0.2.20"`, `"speed_mbps":10000`, `"if_phys_speed":100000`, `"colo":"cab-a"`, `"route_server":true`, `"as_macro":"AS64496:AS-EXAMPLE"`, `"mode":"observe"`} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %s in %s", want, text)
		}
	}
	for _, hidden := range []string{"hidden@example.invalid", "02:00:00:00:00:01"} {
		if strings.Contains(text, hidden) {
			t.Errorf("response contains %s", hidden)
		}
	}
	mrec := httptest.NewRecorder()
	s.Handler().ServeHTTP(mrec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	metrics := mrec.Body.String()
	if !strings.Contains(metrics, "packeteer_ixp_members 1\n") || !strings.Contains(metrics, "packeteer_ixp_member_addresses 1\n") || !strings.Contains(metrics, "packeteer_ixp_member_import_up 1\n") {
		t.Fatalf("metrics\n%s", metrics)
	}

	stale := p.View()
	stale.Stale = true
	stale.Error = "member list is stale"
	s.SetIXPMembers(func() plugin.MemberView { return stale })
	mrec = httptest.NewRecorder()
	s.Handler().ServeHTTP(mrec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	metrics = mrec.Body.String()
	if !strings.Contains(metrics, "packeteer_ixp_members 0\n") || !strings.Contains(metrics, "packeteer_ixp_member_import_up 0\n") || !strings.Contains(metrics, "packeteer_ixp_member_import_age_seconds") {
		t.Fatalf("stale metrics\n%s", metrics)
	}
}

func TestIXPProbesAPIAndMetrics(t *testing.T) {
	s := newIXPServer(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ixp/probes", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["configured"] != false || body["mode"] != "observe" {
		t.Fatalf("%s", rec.Body)
	}
	vantages, ok := body["vantages"].([]any)
	samples, ok2 := body["samples"].([]any)
	if !ok || len(vantages) != 0 || !ok2 || len(samples) != 0 {
		t.Fatalf("lists %#v %#v", body["vantages"], body["samples"])
	}
	mrec := httptest.NewRecorder()
	s.Handler().ServeHTTP(mrec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(mrec.Body.String(), "packeteer_ixp_") {
		t.Fatalf("metrics without fabric:\n%s", mrec.Body)
	}

	round := time.Unix(1000, 0).UTC()
	s.SetIXPFabric(func() plugin.FabricView {
		return plugin.FabricView{
			Configured: true,
			Round:      round,
			Targets:    3,
			OptOut:     1,
			Vantages:   []plugin.FabricVantageStatus{{Name: "lan1-v4", Address: "192.0.2.8", VLANID: 10, Up: true, Targets: 3}},
			Samples: []plugin.FabricSample{
				{Vantage: "lan1-v4", ASN: 64496, Address: "192.0.2.20", LossPct: 20, RTTMs: 12, JitterMs: 2, PastTolerance: true},
				{Vantage: "lan1-v4", ASN: 64497, Address: "192.0.2.21", PastTolerance: false},
			},
		}
	})
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ixp/probes", nil))
	text := rec.Body.String()
	for _, want := range []string{`"targets":3`, `"opt_out":1`, `"asn":64496`, `"loss_pct":20`, `"rtt_ms":12`, `"jitter_ms":2`, `"past_tolerance":true`, `"name":"lan1-v4"`} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %s in %s", want, text)
		}
	}
	if strings.Contains(text, "api_key") || strings.Contains(text, "SuperSecret") {
		t.Fatalf("secret field in %s", text)
	}
	mrec = httptest.NewRecorder()
	s.Handler().ServeHTTP(mrec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	metrics := mrec.Body.String()
	for _, want := range []string{
		"packeteer_ixp_fabric_up 1\n",
		"packeteer_ixp_fabric_targets 3\n",
		"packeteer_ixp_fabric_opt_out 1\n",
		"packeteer_ixp_fabric_past_tolerance 1\n",
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("missing %s in\n%s", want, metrics)
		}
	}
	if strings.Contains(metrics, "packeteer_ixp_member_rtt") {
		t.Fatalf("per-member series:\n%s", metrics)
	}

	s.SetIXPFabric(func() plugin.FabricView {
		return plugin.FabricView{Configured: true, Stale: true, Round: round, Targets: 3, OptOut: 1, Error: "member list is stale",
			Samples: []plugin.FabricSample{{PastTolerance: true}}}
	})
	mrec = httptest.NewRecorder()
	s.Handler().ServeHTTP(mrec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	metrics = mrec.Body.String()
	for _, want := range []string{
		"packeteer_ixp_fabric_up 0\n",
		"packeteer_ixp_fabric_targets 0\n",
		"packeteer_ixp_fabric_past_tolerance 0\n",
		"packeteer_ixp_fabric_age_seconds",
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("stale missing %s in\n%s", want, metrics)
		}
	}
}

func TestIXPRouteServersAPIAndMetrics(t *testing.T) {
	s := newIXPServer(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ixp/routeservers", nil))
	var body map[string]any
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil || body["configured"] != false {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if l, ok := body["servers"].([]any); !ok || len(l) != 0 {
		t.Fatalf("servers %#v", body["servers"])
	}
	if l, ok := body["sessions"].([]any); !ok || len(l) != 0 {
		t.Fatalf("sessions %#v", body["sessions"])
	}
	for _, path := range []string{"/api/ixp/routeservers/history?server=rs1&session=pb_a", "/api/ixp/routeservers/history"} {
		rec = httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		want := http.StatusNotFound
		if !strings.Contains(path, "server=") {
			want = http.StatusBadRequest
		}
		if rec.Code != want {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
	}
	mrec := httptest.NewRecorder()
	s.Handler().ServeHTTP(mrec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(mrec.Body.String(), "packeteer_ixp_rs_") {
		t.Fatalf("metrics without a watch:\n%s", mrec.Body)
	}

	polled := time.Now().Add(-30 * time.Second)
	s.SetIXPRouteServers(func() plugin.RouteServerView {
		return plugin.RouteServerView{
			Configured: true,
			Servers:    []plugin.RouteServerStatus{{Name: "rs1", ASN: 64496, Up: true, Polled: polled, Sessions: 2}},
			Sessions: []plugin.RouteServerSession{
				{Server: "rs1", Session: "pb_a", ASN: 64497, Name: "Doc Member", Established: true, Counted: true,
					Received: 10, Accepted: 7, Filtered: 3, Reasons: []plugin.RouteServerReason{{Reason: 4, Count: 3}}, MaxPrefix: 100, UsedPct: 7},
				{Server: "rs1", Session: "pb_b", ASN: 64498, State: "Active"},
			},
		}
	}, func(server, session string) ([]plugin.RouteServerSample, bool) {
		if server != "rs1" || session != "pb_a" {
			return nil, false
		}
		return []plugin.RouteServerSample{{At: polled, Established: true, Counted: true, Received: 10, Accepted: 7, Filtered: 3}}, true
	})
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ixp/routeservers", nil))
	text := rec.Body.String()
	for _, want := range []string{`"configured":true`, `"asn":64496`, `"session":"pb_a"`, `"name":"Doc Member"`, `"filtered":3`, `"reason":4`, `"used_pct":7`, `"mode":"observe"`} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %s in %s", want, text)
		}
	}
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ixp/routeservers/history?server=rs1&session=pb_a", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"samples":[{`) || !strings.Contains(rec.Body.String(), `"accepted":7`) {
		t.Fatalf("history %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ixp/routeservers/history?server=rs1&session=zzz", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown session %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/ixp/routeservers", nil))
	if rec.Code == http.StatusOK {
		t.Fatalf("POST accepted: %d", rec.Code)
	}

	mrec = httptest.NewRecorder()
	s.Handler().ServeHTTP(mrec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	metrics := mrec.Body.String()
	for _, want := range []string{
		"packeteer_ixp_rs_up 1\n",
		"packeteer_ixp_rs_sessions_established 1\n",
		"packeteer_ixp_rs_sessions_down 1\n",
		"packeteer_ixp_rs_filtered_routes 3\n",
		"packeteer_ixp_rs_age_seconds ",
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("missing %s in\n%s", want, metrics)
		}
	}
	if strings.Contains(metrics, "pb_a") || strings.Contains(metrics, "64497") {
		t.Fatalf("per-member series:\n%s", metrics)
	}
}

func newIXPServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(Options{Snapshot: func() Snapshot { return Snapshot{Version: "test", Mode: "observe", Started: true} }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
