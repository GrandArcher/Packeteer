package httpapi

import (
	"encoding/json"
	"net/http"
	"net/netip"
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
