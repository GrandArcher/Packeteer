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

func newIXPServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(Options{Snapshot: func() Snapshot { return Snapshot{Version: "test", Mode: "observe", Started: true} }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
