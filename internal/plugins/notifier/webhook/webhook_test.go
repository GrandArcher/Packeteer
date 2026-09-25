package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func newNotifier(t *testing.T, y string) (plugin.Notifier, error) {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	return plugin.Notifiers.New(TypeName, c, plugin.Env{Getenv: func(k string) string {
		if k == "HOOK_TOKEN" {
			return "abc"
		}
		return ""
	}})
}

func TestNotify(t *testing.T) {
	var got plugin.Event
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	n, err := newNotifier(t, "url: "+srv.URL+"\nheaders:\n  Authorization: Bearer ${HOOK_TOKEN}\n")
	if err != nil {
		t.Fatal(err)
	}
	ev := plugin.Event{Time: time.Unix(0, 0).UTC(), Kind: "improvement.added", Severity: plugin.SeverityWarning,
		Message: "198.51.100.0/24 via transit-b", Fields: map[string]string{"prefix": "198.51.100.0/24"}}
	if err := n.Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if got.Kind != ev.Kind || got.Fields["prefix"] != "198.51.100.0/24" {
		t.Errorf("got %+v", got)
	}
	if auth != "Bearer abc" {
		t.Errorf("Authorization = %q", auth)
	}
}

func TestMinSeverityAndErrors(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	n, err := newNotifier(t, "url: "+srv.URL+"\nmin_severity: warning\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(context.Background(), plugin.Event{Severity: plugin.SeverityInfo}); err != nil || calls != 0 {
		t.Fatalf("info should be dropped: err=%v calls=%d", err, calls)
	}
	err = n.Notify(context.Background(), plugin.Event{Severity: plugin.SeverityCritical})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct{ name, yaml, wantErr string }{
		{"missing url", "timeout: 1s", "url is required"},
		{"bad scheme", "url: ftp://example.invalid/x", "http(s)"},
		{"relative url", "url: /hook", "http(s)"},
		{"negative timeout", "url: http://example.invalid\ntimeout: -1s", "must not be negative"},
		{"bad severity", "url: http://example.invalid\nmin_severity: loud", `min_severity "loud"`},
		{"unknown field", "url: http://example.invalid\nretries: 3", "field retries not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newNotifier(t, tt.yaml)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
