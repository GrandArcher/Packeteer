package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
)

const lookupObserveYAML = `
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
lookup:
  type: peeringdb
  config:
    exchanges:
      - {name: example-ix, ix_id: 1}
`

func TestLookupChangeNeedsRestart(t *testing.T) {
	cur := mustParse(t, lookupObserveYAML[:strings.Index(lookupObserveYAML, "lookup:")])
	next := mustParse(t, lookupObserveYAML)
	restart, online := classify(cur, next)
	if !slices.Contains(restart, "lookup") || len(online) != 0 {
		t.Fatalf("restart %v online %v, want only lookup", restart, online)
	}
	if _, err := planReload(cur, next, nil); err == nil || !strings.Contains(err.Error(), "restart required: changed lookup") {
		t.Fatalf("planReload: %v", err)
	}
}

func TestRunLookupCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(lookupObserveYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut strings.Builder
	if code := run(t.Context(), []string{"-check", "-config", path}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("exit %d stderr %s", code, errOut.String())
	}
	for _, want := range []string{"mode: observe", "lookup: peeringdb (read-only, never announces)", "announce: disabled", "check: ok"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout missing %q:\n%s", want, out.String())
		}
	}
}

func TestWireLookupServesTheView(t *testing.T) {
	cfg := mustParse(t, lookupObserveYAML)
	set, err := pluginhost.Build(cfg, pluginhost.Options{})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := httpapi.New(httpapi.Options{Snapshot: func() httpapi.Snapshot {
		return httpapi.Snapshot{Version: "test", Mode: config.ModeObserve, Started: true}
	}})
	if err != nil {
		t.Fatal(err)
	}
	wireLookup(nil, srv)
	wireLookup(&pluginhost.Set{}, srv)
	wireLookup(set, nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/lookup", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["configured"] != false {
		t.Fatalf("before wiring: %v %s", err, rec.Body)
	}
	wireLookup(set, srv)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/lookup", nil))
	body = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["configured"] != true || body["anonymous"] != true {
		t.Fatalf("after wiring: %v %s", err, rec.Body)
	}
	ex := body["exchanges"].([]any)
	if len(ex) != 1 || ex[0].(map[string]any)["name"] != "example-ix" {
		t.Fatalf("exchanges %v", body["exchanges"])
	}
}
