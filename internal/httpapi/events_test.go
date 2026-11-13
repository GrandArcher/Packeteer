package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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

// Every catalog group has a "What to do" link, and a doc link names a file
// and heading that exist in the repository (#347).
func TestEventHelpLinks(t *testing.T) {
	groups := map[string]bool{}
	for _, s := range plugin.EventCatalog() {
		groups[s.Group] = true
		u := helpURL(s.Kind)
		if u == "" {
			t.Errorf("%s has no help link", s.Kind)
			continue
		}
		if strings.HasPrefix(u, "/") {
			if u != "/system.html" {
				t.Errorf("%s links the unknown page %s", s.Kind, u)
			}
			continue
		}
		path, ok := strings.CutPrefix(u, DocBase)
		if !ok {
			t.Errorf("%s: %s is neither an in-app path nor a doc URL", s.Kind, u)
			continue
		}
		file, anchor, _ := strings.Cut(path, "#")
		doc, err := os.ReadFile("../../" + file)
		if err != nil {
			t.Errorf("%s: %v", s.Kind, err)
			continue
		}
		if anchor != "" && !hasHeading(string(doc), anchor) {
			t.Errorf("%s: %s has no heading for #%s", s.Kind, file, anchor)
		}
	}
	for g := range eventHelp {
		if !groups[g] {
			t.Errorf("eventHelp has an entry for %q, which is not a catalog group", g)
		}
	}
	if helpURL("nope.nothing") != "" {
		t.Error("an unknown kind has a help link")
	}
}

// hasHeading reports whether a Markdown heading slugs to anchor the way
// GitHub does: lower case, spaces to hyphens, other punctuation dropped.
func hasHeading(doc, anchor string) bool {
	for _, line := range strings.Split(doc, "\n") {
		text := strings.TrimLeft(line, "#")
		if text == line || !strings.HasPrefix(text, " ") {
			continue
		}
		var b strings.Builder
		for _, r := range strings.ToLower(strings.TrimSpace(text)) {
			switch {
			case r == ' ':
				b.WriteByte('-')
			case r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
				b.WriteRune(r)
			}
		}
		if b.String() == anchor {
			return true
		}
	}
	return false
}

// The events API carries the link, and the Events page shows it.
func TestEventsAPIHelpURL(t *testing.T) {
	e, _ := eventsEnv(t)
	_, body := e.do(t, "GET", "/api/events", plugin.RoleViewer, nil)
	got := map[string]string{}
	for _, v := range body["events"].([]any) {
		row := v.(map[string]any)
		u, _ := row["help_url"].(string)
		got[row["kind"].(string)] = u
	}
	want := map[string]string{
		"provider.down":      DocBase + "docs/troubleshooting.md#probes-fail",
		"commit.exceeded":    DocBase + "docs/CONFIG.md#scorer-commit",
		"controller.started": "/system.html",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("help urls = %v, want %v", got, want)
	}
}

// open=1 is the top bar badge's view (#579): a session that failed and is
// Established again no longer counts, while the plain list keeps every line.
func TestEventsAPIOpenDropsRecoveredAlerts(t *testing.T) {
	log := eventlog.New(nil, nil, nil)
	t0 := time.Now().Add(-time.Hour).UTC()
	nb := func(n string) map[string]string { return map[string]string{"neighbor": n} }
	log.Record(plugin.Event{Time: t0, Kind: plugin.EventBGPSessionStuck, Severity: plugin.SeverityCritical, Message: "not established", Fields: nb("192.0.2.1")})
	log.Record(plugin.Event{Time: t0.Add(time.Minute), Kind: plugin.EventBGPSessionStuck, Severity: plugin.SeverityCritical, Message: "still not established", Fields: nb("192.0.2.1")})
	log.Record(plugin.Event{Time: t0.Add(2 * time.Minute), Kind: plugin.EventBGPSessionUp, Severity: plugin.SeverityInfo, Message: "session is established", Fields: nb("192.0.2.1")})
	log.Record(plugin.Event{Time: t0.Add(3 * time.Minute), Kind: plugin.EventBGPSessionDown, Severity: plugin.SeverityCritical, Message: "session down", Fields: nb("192.0.2.2")})
	log.Record(plugin.Event{Time: t0.Add(4 * time.Minute), Kind: plugin.EventBGPSessionUp, Severity: plugin.SeverityInfo, Message: "session is established", Fields: nb("192.0.2.2")})
	log.Record(plugin.Event{Time: t0.Add(5 * time.Minute), Kind: plugin.EventBGPSessionDown, Severity: plugin.SeverityCritical, Message: "session down again", Fields: nb("192.0.2.2")})
	log.Record(plugin.Event{Time: t0.Add(6 * time.Minute), Kind: plugin.EventProviderDown, Severity: plugin.SeverityCritical, Message: "probe source is down",
		Fields: map[string]string{"provider": "transit-a"}})
	e := newUIWith(t, func(o *Options) { o.Events = log })

	get := func(query string) []any {
		t.Helper()
		rec, body := e.do(t, "GET", "/api/events?"+query, plugin.RoleViewer, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", query, rec.Code, rec.Body)
		}
		return body["events"].([]any)
	}
	messages := func(evs []any) string {
		var out []string
		for _, v := range evs {
			out = append(out, v.(map[string]any)["message"].(string))
		}
		return strings.Join(out, "|")
	}

	if n := len(get("severity=warning")); n != 5 {
		t.Errorf("the page lists %d critical lines, want all 5", n)
	}
	if n := len(get("")); n != 7 {
		t.Errorf("the page lists %d events, want 7 including the established lines", n)
	}
	// Only the newest event of each still-open alert counts: neighbor
	// 192.0.2.1 recovered; 192.0.2.2 failed again after recovering.
	if got := messages(get("severity=warning&open=1")); got != "probe source is down|session down again" {
		t.Errorf("open alerts = %q", got)
	}
	if got := messages(get("severity=warning&open=1&limit=1")); got != "probe source is down" {
		t.Errorf("open alerts with limit=1 = %q", got)
	}
	if got := messages(get("severity=warning&open=1&q=transit")); got != "probe source is down" {
		t.Errorf("open alerts with q = %q", got)
	}
	// An alert resolved after the window opened is not counted either.
	from := t0.Add(30 * time.Second).UTC().Format(time.RFC3339Nano)
	if got := messages(get("severity=warning&open=1&from=" + from)); got != "probe source is down|session down again" {
		t.Errorf("open alerts from %s = %q", from, got)
	}
	if got := get("severity=warning&open=0"); len(got) != 5 {
		t.Errorf("open=0 lists %d, want the plain list", len(got))
	}
	if rec, _ := e.do(t, "GET", "/api/events?open=yes", plugin.RoleViewer, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("open=yes = %d, want 400", rec.Code)
	}
}
