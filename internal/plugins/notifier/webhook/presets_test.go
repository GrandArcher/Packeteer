package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type capture struct {
	body  []byte
	ctype string
}

func captureServer(t *testing.T) (*httptest.Server, *capture) {
	t.Helper()
	c := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.body, _ = io.ReadAll(r.Body)
		c.ctype = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)
	return srv, c
}

func newWithEnv(t *testing.T, y string, env map[string]string) (plugin.Notifier, error) {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	return plugin.Notifiers.New(TypeName, c, plugin.Env{Getenv: func(k string) string { return env[k] }})
}

var downEvent = plugin.NewEvent(plugin.EventProviderDown, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	"probe source for transit-a is down", map[string]string{"provider": "transit-a", "source": "192.0.2.10"})

func TestSlackPreset(t *testing.T) {
	srv, c := captureServer(t)
	n, err := newWithEnv(t, "preset: slack\nurl: ${SLACK_URL}", map[string]string{"SLACK_URL": srv.URL + "/services/x"})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(context.Background(), downEvent); err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(c.body, &got); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got["text"], "[CRITICAL] provider.down: probe source") || !strings.Contains(got["text"], "provider: transit-a") {
		t.Fatalf("text = %q", got["text"])
	}
}

func TestTeamsPreset(t *testing.T) {
	srv, c := captureServer(t)
	n, err := newWithEnv(t, "preset: teams\nurl: "+srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(context.Background(), downEvent); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(c.body, &got)
	if got["@type"] != "MessageCard" || got["title"] != "[CRITICAL] provider.down" || got["themeColor"] != "D93F0B" {
		t.Fatalf("card = %v", got)
	}
}

func TestPagerDutyPreset(t *testing.T) {
	srv, c := captureServer(t)
	env := map[string]string{"PD_KEY": "0123456789abcdef"}
	n, err := newWithEnv(t, "preset: pagerduty\nrouting_key_env: PD_KEY\nurl: "+srv.URL, env)
	if err != nil {
		t.Fatal(err)
	}
	type pd struct {
		RoutingKey  string `json:"routing_key"`
		EventAction string `json:"event_action"`
		DedupKey    string `json:"dedup_key"`
		Payload     struct {
			Summary   string            `json:"summary"`
			Source    string            `json:"source"`
			Severity  string            `json:"severity"`
			Timestamp string            `json:"timestamp"`
			Details   map[string]string `json:"custom_details"`
		} `json:"payload"`
	}
	if err := n.Notify(context.Background(), downEvent); err != nil {
		t.Fatal(err)
	}
	var trig pd
	_ = json.Unmarshal(c.body, &trig)
	if trig.RoutingKey != "0123456789abcdef" || trig.EventAction != "trigger" || trig.Payload.Severity != "critical" ||
		trig.Payload.Timestamp != "2026-01-02T03:04:05Z" || trig.Payload.Details["provider"] != "transit-a" || trig.Payload.Source != "packeteer" {
		t.Fatalf("trigger = %+v", trig)
	}
	up := plugin.NewEvent(plugin.EventProviderUp, downEvent.Time, "recovered", map[string]string{"provider": "transit-a"})
	if err := n.Notify(context.Background(), up); err != nil {
		t.Fatal(err)
	}
	var res pd
	_ = json.Unmarshal(c.body, &res)
	if res.EventAction != "resolve" || res.DedupKey != trig.DedupKey || res.DedupKey == "" {
		t.Fatalf("resolve = %+v, trigger dedup %q", res, trig.DedupKey)
	}

	// Default URL, missing key.
	if _, err := newWithEnv(t, "preset: pagerduty\nrouting_key_env: PD_KEY", nil); err == nil || !strings.Contains(err.Error(), "PD_KEY is not set") {
		t.Fatalf("err = %v", err)
	}
	nn, err := newWithEnv(t, "preset: pagerduty\nrouting_key_env: PD_KEY", env)
	if err != nil || nn.(*Notifier).url != PagerDutyURL {
		t.Fatalf("default url: %v", err)
	}
}

func TestTemplateForSMSGateway(t *testing.T) {
	srv, c := captureServer(t)
	y := "url: " + srv.URL + "\ncontent_type: application/x-www-form-urlencoded\n" +
		"template: 'to=%2B15550100&body={{urlquery .Kind}}%20{{urlquery .Message}}&p={{.Fields.provider}}'"
	n, err := newWithEnv(t, y, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(context.Background(), downEvent); err != nil {
		t.Fatal(err)
	}
	want := "to=%2B15550100&body=provider.down%20probe+source+for+transit-a+is+down&p=transit-a"
	if string(c.body) != want || c.ctype != "application/x-www-form-urlencoded" {
		t.Fatalf("body %q ctype %q", c.body, c.ctype)
	}
	j, err := newWithEnv(t, "url: "+srv.URL+"\ntemplate: '{\"msg\": {{json .Message}}}'", nil)
	if err != nil {
		t.Fatal(err)
	}
	ev := downEvent
	ev.Message = `quote " and newline` + "\n"
	if err := j.Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(c.body, &got); err != nil || got["msg"] != ev.Message {
		t.Fatalf("json template body %q: %v", c.body, err)
	}
}

func TestPresetValidation(t *testing.T) {
	tests := []struct{ name, yaml, want string }{
		{"bad preset", "url: http://example.invalid\npreset: irc", `preset "irc"`},
		{"routing key on slack", "url: http://example.invalid\npreset: slack\nrouting_key_env: X", "only for preset pagerduty"},
		{"bad routing env", "preset: pagerduty\nrouting_key_env: 'a b'", "environment variable name"},
		{"template with preset", "url: http://example.invalid\npreset: slack\ntemplate: x", "cannot be combined"},
		{"bad template", "url: http://example.invalid\ntemplate: '{{'", "template"},
		{"content type alone", "url: http://example.invalid\ncontent_type: text/plain", "only used with template"},
		{"bad events", "url: http://example.invalid\nevents: [nope]", "matches no event kind"},
		{"bad rate", "url: http://example.invalid\nrate_limit: -1", "rate_limit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newWithEnv(t, tt.yaml, nil)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestEventsFilterAndGate(t *testing.T) {
	srv, c := captureServer(t)
	n, err := newWithEnv(t, "url: "+srv.URL+"\nevents: [\"bgp.*\"]\nrate_limit: 5", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(context.Background(), downEvent); err != nil || c.body != nil {
		t.Fatalf("provider.down should be filtered: %v %q", err, c.body)
	}
	if n.(plugin.Gated).EventGate() == nil {
		t.Fatal("webhook must expose its gate")
	}
}

func TestErrorDoesNotLeakURL(t *testing.T) {
	n, err := newWithEnv(t, "url: http://127.0.0.1:1/hook?token=${T}", map[string]string{"T": "sekret"})
	if err != nil {
		t.Fatal(err)
	}
	err = n.Notify(context.Background(), downEvent)
	if err == nil || strings.Contains(err.Error(), "sekret") {
		t.Fatalf("err = %v", err)
	}
}
