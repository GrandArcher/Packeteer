package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/eventlog"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func eventsEnv(t *testing.T) (*uiEnv, *eventlog.Log) {
	t.Helper()
	log := eventlog.New(nil, nil, nil)
	t0 := time.Now().Add(-time.Hour).UTC()
	log.Record(plugin.Event{Time: t0, Kind: plugin.EventControllerStarted, Severity: plugin.SeverityInfo, Message: "packeteer started"})
	log.Record(plugin.Event{Time: t0.Add(time.Minute), Kind: plugin.EventCommitExceeded, Severity: plugin.SeverityWarning, Message: "over commit",
		Fields: map[string]string{"provider": "transit-b"}})
	log.Record(plugin.Event{Time: t0.Add(2 * time.Minute), Kind: plugin.EventProviderDown, Severity: plugin.SeverityCritical, Message: "probe source is down",
		Fields: map[string]string{"provider": "transit-a"}})
	return newUIWith(t, func(o *Options) { o.Events = log }), log
}

func eventKinds(body map[string]any) []string {
	var out []string
	for _, v := range body["events"].([]any) {
		out = append(out, v.(map[string]any)["kind"].(string))
	}
	return out
}

// GET /api/events lists the log newest first with the catalog source,
// and filters by severity floor, text, and range. A viewer may read it.
func TestEventsAPI(t *testing.T) {
	e, _ := eventsEnv(t)
	rec, body := e.do(t, "GET", "/api/events", plugin.RoleViewer, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("viewer GET = %d %s", rec.Code, rec.Body)
	}
	if got := fmt.Sprint(eventKinds(body)); got != "[provider.down commit.exceeded controller.started]" {
		t.Errorf("kinds = %s", got)
	}
	first := body["events"].([]any)[0].(map[string]any)
	if first["source"] != "provider" || first["severity"] != "critical" || first["message"] != "probe source is down" ||
		first["fields"].(map[string]any)["provider"] != "transit-a" {
		t.Errorf("first event = %v", first)
	}
	if body["stored"] != false || body["since"] == nil || body["now"] == nil {
		t.Errorf("without a store the answer says stored=false with a since time: %v", body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("events are cacheable")
	}

	for query, want := range map[string]string{
		"severity=warning":                   "[provider.down commit.exceeded]",
		"severity=critical":                  "[provider.down]",
		"q=TRANSIT-B":                        "[commit.exceeded]",
		"q=started":                          "[controller.started]",
		"limit=1":                            "[provider.down]",
		"severity=warning&q=transit&limit=1": "[provider.down]",
		"from=" + time.Now().Add(time.Hour).UTC().Format(time.RFC3339):  "[]",
		"to=" + time.Now().Add(-2*time.Hour).UTC().Format(time.RFC3339): "[]",
	} {
		rec, body := e.do(t, "GET", "/api/events?"+query, plugin.RoleViewer, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: %d %s", query, rec.Code, rec.Body)
			continue
		}
		if got := fmt.Sprint(eventKinds(body)); got != want {
			t.Errorf("%s: kinds = %s, want %s", query, got, want)
		}
	}
	if rec, _ := e.do(t, "GET", "/api/events?q=nothing-like-this", plugin.RoleViewer, nil); !strings.Contains(rec.Body.String(), `"events":[]`) {
		t.Errorf("no match must be an empty list, not null: %s", rec.Body)
	}
	for _, query := range []string{"severity=fatal", "limit=0", "limit=1001", "limit=x", "from=yesterday", "to=1", "q=" + strings.Repeat("a", maxEventText+1)} {
		if rec, _ := e.do(t, "GET", "/api/events?"+query, plugin.RoleViewer, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", query, rec.Code)
		}
	}
	if rec, _ := e.do(t, "POST", "/api/events", plugin.RoleAdmin, "{}"); rec.Code == http.StatusOK || rec.Code == http.StatusCreated {
		t.Errorf("POST /api/events = %d: the log is read-only", rec.Code)
	}
}

func TestEventsAPIWithoutAnEventLog(t *testing.T) {
	e := newUI(t)
	if rec, _ := e.do(t, "GET", "/api/events", plugin.RoleViewer, nil); rec.Code != http.StatusNotFound {
		t.Errorf("GET without an event log = %d, want 404", rec.Code)
	}
}

// The audit tab reads the existing admin-only /api/audit: a viewer is
// refused, an admin sees who did what, and no secret is in the answer.
func TestAuditTabEndpointIsAdminOnlyAndHasNoSecrets(t *testing.T) {
	e := newUI(t)
	rec, raw := e.asUser(t, "operator-user", "POST", "/api/tokens", map[string]any{"name": "ci"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create token = %d %s", rec.Code, raw)
	}
	var made struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(raw), &made); err != nil || made.Token == "" {
		t.Fatalf("no token secret in %s", raw)
	}
	secret := made.Token
	rec, raw = e.asUser(t, "admin-user", "POST", "/api/users", map[string]any{"name": "newbie", "role": "viewer", "password": "a-long-enough-password"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create user = %d %s", rec.Code, raw)
	}
	if rec, _ := e.do(t, "GET", "/api/audit", plugin.RoleViewer, nil); rec.Code != http.StatusForbidden {
		t.Errorf("viewer audit = %d, want 403", rec.Code)
	}
	if rec, _ := e.do(t, "GET", "/api/audit", plugin.RoleOperator, nil); rec.Code != http.StatusForbidden {
		t.Errorf("operator audit = %d, want 403", rec.Code)
	}
	rec, body := e.do(t, "GET", "/api/audit", plugin.RoleAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin audit = %d %s", rec.Code, rec.Body)
	}
	recs, _ := body["records"].([]any)
	var sawToken, sawUser bool
	for _, r := range recs {
		m := r.(map[string]any)
		for _, k := range []string{"actor", "role", "method", "action", "result", "status"} {
			if m[k] == nil {
				t.Errorf("record without %s: %v", k, m)
			}
		}
		switch m["action"] {
		case "POST /api/tokens":
			sawToken = m["actor"] == "operator-user" && m["role"] == "operator" && m["method"] == "password" && m["result"] == "ok"
		case "POST /api/users":
			sawUser = m["actor"] == "admin-user" && m["target"] == "newbie"
		}
	}
	if !sawToken || !sawUser {
		t.Errorf("audit records missing the token (%v) or user (%v) change: %s", sawToken, sawUser, rec.Body)
	}
	for _, secretText := range []string{secret, "a-long-enough-password"} {
		if strings.Contains(rec.Body.String(), secretText) {
			t.Errorf("audit answer contains a secret: %q", secretText)
		}
	}
}
