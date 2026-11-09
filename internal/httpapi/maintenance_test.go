package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakeMaint struct {
	canOpen            bool
	windows            []plugin.MaintenanceWindow
	upcoming, finished []plugin.MaintenanceWindow
	opened             []string
	closed             []string
}

func (f *fakeMaint) Active(time.Time) []plugin.MaintenanceWindow { return f.windows }
func (f *fakeMaint) Windows(time.Time) (up, fin []plugin.MaintenanceWindow) {
	return f.upcoming, f.finished
}
func (f *fakeMaint) CanOpen() bool { return f.canOpen }
func (f *fakeMaint) Open(p []string, start, end time.Time, reason string, now time.Time) (plugin.MaintenanceWindow, error) {
	if len(p) == 0 {
		return plugin.MaintenanceWindow{}, errors.New("at least one provider is required")
	}
	f.opened = append(f.opened, strings.Join(p, ",")+"/"+start.UTC().Format(time.RFC3339)+"/"+end.Sub(start).String()+"/"+reason)
	return plugin.MaintenanceWindow{ID: "api-1", Providers: p, Start: start, End: end, Source: "api"}, nil
}
func (f *fakeMaint) Close(id string) bool {
	f.closed = append(f.closed, id)
	return id == "api-1"
}

func maintServer(t *testing.T, m MaintenanceControl, user string) http.Handler {
	t.Helper()
	pass := ""
	if user != "" {
		pass = "secret"
	}
	s, err := New(Options{User: user, Password: pass, Maintenance: m, Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if err != nil {
		t.Fatal(err)
	}
	return s.Handler()
}

func mdo(h http.Handler, method, path, ctype, body string, auth bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if auth {
		req.SetBasicAuth("ops", "secret")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMaintenanceAPI(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	fm := &fakeMaint{canOpen: true, windows: []plugin.MaintenanceWindow{{ID: "schedule-w", Providers: []string{"transit-b"}, Start: now, End: now.Add(time.Hour), Source: "schedule"}}}
	h := maintServer(t, fm, "ops")

	rec := mdo(h, "GET", "/api/maintenance", "", "", true)
	var body struct {
		Configured bool                       `json:"configured"`
		OnDemand   bool                       `json:"on_demand"`
		Windows    []plugin.MaintenanceWindow `json:"windows"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != 200 {
		t.Fatalf("GET %d %s", rec.Code, rec.Body)
	}
	if !body.Configured || !body.OnDemand || len(body.Windows) != 1 || body.Windows[0].ID != "schedule-w" {
		t.Fatalf("GET body %+v", body)
	}

	tests := []struct {
		name, method, path, ctype, body string
		auth                            bool
		want                            int
	}{
		{"open", "POST", "/api/maintenance", "application/json", `{"providers":["transit-a"],"duration":"2h","reason":"ticket 1"}`, true, 201},
		{"open needs auth", "POST", "/api/maintenance", "application/json", `{"providers":["transit-a"],"duration":"2h"}`, false, 401},
		{"open needs json", "POST", "/api/maintenance", "application/x-www-form-urlencoded", `providers=transit-a`, true, 415},
		{"open bad duration", "POST", "/api/maintenance", "application/json", `{"providers":["transit-a"],"duration":"soon"}`, true, 400},
		{"open unknown field", "POST", "/api/maintenance", "application/json", `{"providers":["transit-a"],"duration":"1h","x":1}`, true, 400},
		{"open rejected by policy", "POST", "/api/maintenance", "application/json", `{"providers":[],"duration":"1h"}`, true, 400},
		{"close", "DELETE", "/api/maintenance/api-1", "", "", true, 204},
		{"close unknown", "DELETE", "/api/maintenance/api-9", "", "", true, 404},
		{"close needs auth", "DELETE", "/api/maintenance/api-1", "", "", false, 401},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := mdo(h, tt.method, tt.path, tt.ctype, tt.body, tt.auth)
			if rec.Code != tt.want {
				t.Fatalf("%s %s = %d %s, want %d", tt.method, tt.path, rec.Code, rec.Body, tt.want)
			}
		})
	}
	if len(fm.opened) != 1 || !strings.HasSuffix(fm.opened[0], "/2h0m0s/ticket 1") {
		t.Fatalf("opened = %v", fm.opened)
	}
}

// The page sends start and end as RFC 3339; the API passes them through
// unchanged (in UTC), lists upcoming and finished windows, and refuses a
// request that mixes the two forms.
func TestMaintenanceAPIStartEndAndLists(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	fm := &fakeMaint{canOpen: true,
		upcoming: []plugin.MaintenanceWindow{{ID: "api-2", Providers: []string{"transit-b"}, Start: t0.Add(time.Hour), End: t0.Add(2 * time.Hour), Source: "api"}},
		finished: []plugin.MaintenanceWindow{{ID: "schedule-old", Providers: []string{"transit-a"}, Start: t0.Add(-2 * time.Hour), End: t0.Add(-time.Hour), Source: "schedule"}}}
	h := maintServer(t, fm, "ops")

	var body struct {
		Windows, Upcoming, Finished []plugin.MaintenanceWindow
	}
	rec := mdo(h, "GET", "/api/maintenance", "", "", true)
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != 200 {
		t.Fatalf("GET %d %s", rec.Code, rec.Body)
	}
	if len(body.Windows) != 0 || len(body.Upcoming) != 1 || body.Upcoming[0].ID != "api-2" || len(body.Finished) != 1 || body.Finished[0].ID != "schedule-old" {
		t.Fatalf("GET body %+v", body)
	}

	ok := `{"providers":["transit-a"],"start":"2026-09-25T14:00:00+02:00","end":"2026-09-25T13:00:00Z","reason":"fiber"}`
	if rec := mdo(h, "POST", "/api/maintenance", "application/json", ok, true); rec.Code != 201 {
		t.Fatalf("start/end open = %d %s", rec.Code, rec.Body)
	}
	if want := "transit-a/2026-09-25T12:00:00Z/1h0m0s/fiber"; len(fm.opened) != 1 || fm.opened[0] != want {
		t.Fatalf("opened = %v, want %s", fm.opened, want)
	}
	for name, req := range map[string]string{
		"both forms":  `{"providers":["transit-a"],"duration":"1h","start":"2026-09-25T12:00:00Z","end":"2026-09-25T13:00:00Z"}`,
		"start only":  `{"providers":["transit-a"],"start":"2026-09-25T12:00:00Z"}`,
		"neither":     `{"providers":["transit-a"]}`,
		"local time":  `{"providers":["transit-a"],"start":"2026-09-25 12:00","end":"2026-09-25T13:00:00Z"}`,
		"end not RFC": `{"providers":["transit-a"],"start":"2026-09-25T12:00:00Z","end":"1h"}`,
	} {
		if rec := mdo(h, "POST", "/api/maintenance", "application/json", req, true); rec.Code != 400 {
			t.Errorf("%s = %d %s, want 400", name, rec.Code, rec.Body)
		}
	}
	if len(fm.opened) != 1 {
		t.Fatalf("a refused request reached Open: %v", fm.opened)
	}
}

func TestMaintenanceAPIRefusesWithoutAuthOrPolicy(t *testing.T) {
	open := `{"providers":["transit-a"],"duration":"1h"}`
	// No basic auth configured: reads work, writes are forbidden.
	h := maintServer(t, &fakeMaint{canOpen: true}, "")
	if rec := mdo(h, "GET", "/api/maintenance", "", "", false); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"on_demand":false`) {
		t.Fatalf("GET %d %s", rec.Code, rec.Body)
	}
	if rec := mdo(h, "POST", "/api/maintenance", "application/json", open, false); rec.Code != 403 {
		t.Fatalf("POST without auth config = %d", rec.Code)
	}
	if rec := mdo(h, "DELETE", "/api/maintenance/api-1", "", "", false); rec.Code != 403 {
		t.Fatalf("DELETE without auth config = %d", rec.Code)
	}
	// No maintenance policy.
	h = maintServer(t, nil, "ops")
	if rec := mdo(h, "GET", "/api/maintenance", "", "", true); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"configured":false`) {
		t.Fatalf("GET %d %s", rec.Code, rec.Body)
	}
	if rec := mdo(h, "POST", "/api/maintenance", "application/json", open, true); rec.Code != 404 {
		t.Fatalf("POST without policy = %d", rec.Code)
	}
}
