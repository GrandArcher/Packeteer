package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/inbound"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func getInbound(t *testing.T, opt Options) map[string]any {
	t.Helper()
	opt.Snapshot = func() Snapshot { return Snapshot{Mode: "inject"} }
	s, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/inbound", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestInboundEndpoint(t *testing.T) {
	off := getInbound(t, Options{})
	if off["enabled"] != false || len(off["steers"].([]any)) != 0 {
		t.Fatalf("disabled body = %v", off)
	}
	st := inbound.Status{
		Mode: "suggest", Prefixes: []string{"203.0.113.0/24"}, Evaluated: time.Unix(1, 0),
		Steers: []inbound.Steer{{Provider: "transit-a", InMbps95: 150, CommitMbps: 100,
			Action: plugin.InboundAction{Provider: "transit-a", Prepend: 2, Communities: []string{"64512:1102"}}}},
		Announced: []inbound.Route{}, Blocked: []inbound.Blocked{{Provider: "transit-b", Reason: "would steer away from every provider"}},
	}
	on := getInbound(t, Options{Inbound: func() inbound.Status { return st }})
	if on["enabled"] != true || on["inbound_mode"] != "suggest" || on["mode"] != "inject" {
		t.Fatalf("body = %v", on)
	}
	steer := on["steers"].([]any)[0].(map[string]any)
	if steer["provider"] != "transit-a" || steer["action"].(map[string]any)["prepend"] != float64(2) {
		t.Fatalf("steer = %v", steer)
	}
	if len(on["blocked"].([]any)) != 1 || on["evaluated"] == nil {
		t.Fatalf("body = %v", on)
	}
}
