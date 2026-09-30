package httpapi

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/mitigation"
)

func mitServer(t *testing.T, m MitigationControl, user string) http.Handler {
	t.Helper()
	pass := ""
	if user != "" {
		pass = "secret"
	}
	s, err := New(Options{User: user, Password: pass, Mitigation: m, Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if err != nil {
		t.Fatal(err)
	}
	return s.Handler()
}

// mitControl is the real controller in observe (no announcer), which is
// what the API talks to in a dry run.
type mitControl struct{ c *mitigation.Controller }

func (m mitControl) Status() mitigation.Status { return m.c.Status() }
func (m mitControl) Add(r mitigation.Request) (mitigation.Rule, error) {
	return m.c.Add(r, time.Now())
}
func (m mitControl) Remove(id string) bool { return m.c.Remove(id) }

func newMitControl(t *testing.T) mitControl {
	t.Helper()
	c, err := mitigation.New(mitigation.Config{
		Mode: config.ModeObserve, Allowlist: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		MaxRules: 1, DefaultTTL: time.Hour, MaxTTL: 2 * time.Hour,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return mitControl{c}
}

func TestMitigationEndpoints(t *testing.T) {
	// Not configured.
	off := mitServer(t, nil, "ops")
	rec := mdo(off, http.MethodGet, "/api/mitigations", "", "", true)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusOK || body["enabled"] != false || len(body["rules"].([]any)) != 0 {
		t.Fatalf("disabled: %d %v", rec.Code, body)
	}
	if rec := mdo(off, http.MethodPost, "/api/mitigations", "application/json", `{"prefix":"203.0.113.0/24","action":"blackhole"}`, true); rec.Code != http.StatusNotFound {
		t.Fatalf("post without mitigation: %d", rec.Code)
	}

	// Writes need basic auth.
	ctl := newMitControl(t)
	noAuth := mitServer(t, ctl, "")
	if rec := mdo(noAuth, http.MethodPost, "/api/mitigations", "application/json", `{"prefix":"203.0.113.0/24","action":"blackhole"}`, false); rec.Code != http.StatusForbidden {
		t.Fatalf("post without auth configured: %d", rec.Code)
	}
	if rec := mdo(noAuth, http.MethodDelete, "/api/mitigations/x", "", "", false); rec.Code != http.StatusForbidden {
		t.Fatalf("delete without auth configured: %d", rec.Code)
	}

	h := mitServer(t, ctl, "ops")
	if rec := mdo(h, http.MethodPost, "/api/mitigations", "application/json", `{"prefix":"203.0.113.0/24","action":"blackhole"}`, false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("post without credentials: %d", rec.Code)
	}
	bad := map[string]struct {
		ctype, body string
		code        int
	}{
		"form":              {"application/x-www-form-urlencoded", "prefix=203.0.113.0/24", http.StatusUnsupportedMediaType},
		"unknown field":     {"application/json", `{"prefix":"203.0.113.0/24","action":"blackhole","next_hop":"192.0.2.1"}`, http.StatusBadRequest},
		"bad prefix":        {"application/json", `{"prefix":"203.0.113.0","action":"blackhole"}`, http.StatusBadRequest},
		"bad ttl":           {"application/json", `{"prefix":"203.0.113.0/24","action":"blackhole","ttl":"soon"}`, http.StatusBadRequest},
		"ttl over max":      {"application/json", `{"prefix":"203.0.113.0/24","action":"blackhole","ttl":"3h"}`, http.StatusBadRequest},
		"outside allowlist": {"application/json", `{"prefix":"198.51.100.0/24","action":"blackhole"}`, http.StatusBadRequest},
		"bad action":        {"application/json", `{"prefix":"203.0.113.0/24","action":"drop"}`, http.StatusBadRequest},
		"redirect, no ann":  {"application/json", `{"prefix":"203.0.113.0/24","action":"redirect","target":"scrubber"}`, http.StatusBadRequest},
	}
	for name, c := range bad {
		if rec := mdo(h, http.MethodPost, "/api/mitigations", c.ctype, c.body, true); rec.Code != c.code {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}

	rec = mdo(h, http.MethodPost, "/api/mitigations", "application/json", `{"prefix":"203.0.113.0/24","action":"blackhole","ttl":"10m","reason":"ddos"}`, true)
	var rule map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rule); err != nil || rec.Code != http.StatusCreated || rule["prefix"] != "203.0.113.0/24" || rule["announced"] != false {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if rec := mdo(h, http.MethodPost, "/api/mitigations", "application/json", `{"prefix":"203.0.113.0/25","action":"blackhole"}`, true); rec.Code != http.StatusConflict {
		t.Fatalf("past max_rules: %d", rec.Code)
	}

	rec = mdo(h, http.MethodGet, "/api/mitigations", "", "", true)
	body = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["enabled"] != true || body["writable"] != true ||
		body["mitigation_mode"] != "observe" || body["max_rules"] != float64(1) || len(body["rules"].([]any)) != 1 {
		t.Fatalf("status: %v", body)
	}
	r0 := body["rules"].([]any)[0].(map[string]any)
	if r0["reason"] != "ddos" || r0["pending"] == "" {
		t.Fatalf("rule: %v", r0)
	}

	if rec := mdo(h, http.MethodDelete, "/api/mitigations/nope", "", "", true); rec.Code != http.StatusNotFound {
		t.Fatalf("delete unknown: %d", rec.Code)
	}
	if rec := mdo(h, http.MethodDelete, "/api/mitigations/"+rule["id"].(string), "", "", true); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	if len(ctl.Status().Rules) != 0 {
		t.Fatal("rule not removed")
	}
}

func TestMitigationFlowSpecRequest(t *testing.T) {
	c, err := mitigation.New(mitigation.Config{
		Mode: config.ModeObserve, Allowlist: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		MaxRules: 4, DefaultTTL: time.Hour, MaxTTL: 2 * time.Hour,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := mitServer(t, mitControl{c}, "ops")
	bad := map[string]string{
		"bad protocol":     `{"prefix":"203.0.113.0/24","action":"flowspec_drop","match":{"protocols":["quic"]}}`,
		"bad port":         `{"prefix":"203.0.113.0/24","action":"flowspec_drop","match":{"destination_ports":["80-10"]}}`,
		"unknown match":    `{"prefix":"203.0.113.0/24","action":"flowspec_drop","match":{"tcp_flags":"syn"}}`,
		"countries no geo": `{"prefix":"203.0.113.0/24","action":"flowspec_drop","source_countries":["XA"]}`,
		"rate on drop":     `{"prefix":"203.0.113.0/24","action":"flowspec_drop","rate_mbps":5}`,
	}
	for name, body := range bad {
		if rec := mdo(h, http.MethodPost, "/api/mitigations", "application/json", body, true); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	rec := mdo(h, http.MethodPost, "/api/mitigations", "application/json",
		`{"prefix":"203.0.113.0/24","action":"flowspec_rate_limit","rate_mbps":20,"match":{"source":"198.51.100.0/24","protocols":["udp",6],"destination_ports":[53,"1000-2000"]},"ttl":"10m"}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var rule map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rule); err != nil {
		t.Fatal(err)
	}
	m := rule["match"].(map[string]any)
	if rule["rate_mbps"] != float64(20) || m["source"] != "198.51.100.0/24" || len(m["protocols"].([]any)) != 2 ||
		m["protocols"].([]any)[0] != "tcp" || m["destination_ports"].([]any)[1] != "1000-2000" || rule["routes"] != float64(1) {
		t.Fatalf("rule = %v", rule)
	}
	rec = mdo(h, http.MethodGet, "/api/mitigations", "", "", true)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	feed := body["feed"].([]any)
	if len(feed) != 1 || feed[0].(map[string]any)["kind"] != "added" || body["routes_held"] != float64(1) || body["geoip"] != false {
		t.Fatalf("status = %v", body)
	}
}

func TestMitigationMetrics(t *testing.T) {
	ctl := newMitControl(t)
	if _, err := ctl.Add(mitigation.Request{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Action: "flowspec_drop"}); err != nil {
		t.Fatal(err)
	}
	h := mitServer(t, ctl, "ops")
	text := mdo(h, http.MethodGet, "/metrics", "", "", true).Body.String()
	for _, want := range []string{
		`packeteer_mitigation_rules{action="flowspec_drop",state="pending"} 1`,
		`packeteer_mitigation_rules{action="blackhole",state="announced"} 0`,
		"packeteer_mitigation_routes_held 1",
		"packeteer_mitigation_routes_announced 0",
		`packeteer_mitigation_max_rules{mode="observe"} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	if off := mdo(mitServer(t, nil, "ops"), http.MethodGet, "/metrics", "", "", true).Body.String(); strings.Contains(off, "packeteer_mitigation_") {
		t.Fatal("mitigation metrics without mitigation")
	}
}
