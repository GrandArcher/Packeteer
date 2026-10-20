package httpapi

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// #155: accepting a discovered exchange member fills a draft peer row in
// the browser. The row goes through the same Apply as any peer; the draft
// flag is accepted and never written, and nothing is saved.
func TestConfigFormDraftExchangePeer(t *testing.T) {
	e := newUI(t)
	admin := plugin.RoleAdmin
	withIX := editorYAML + `exchanges:
  - name: ix-lab
    lans: [203.0.113.0/24]
    peers:
      - name: ix-peer-a
        asn: 64501
        next_hop: 203.0.113.11
        source_ip: 192.0.2.31
bgp:
  neighbors:
    - address: 192.0.2.254
      add_path: true
`
	_, got := e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": withIX})
	fm := got["form"].(map[string]any)
	ex := fm["exchanges"].([]any)[0].(map[string]any)
	draft := map[string]any{"key": "", "name": "", "asn": "64503", "next_hop": "203.0.113.13", "source_ip": "", "cost": "", "draft": true}
	ex["peers"] = append(ex["peers"].([]any), draft)

	rec, _ := e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": withIX, "apply": true, "form": fm})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "name is required") {
		t.Fatalf("unnamed draft: %d %s", rec.Code, rec.Body)
	}

	draft["name"] = "ix-peer-c"
	draft["source_ip"] = "192.0.2.33"
	rec, got = e.do(t, "POST", "/api/config/form", admin, map[string]any{"yaml": withIX, "apply": true, "form": fm})
	if rec.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body)
	}
	yml := got["yaml"].(string)
	for _, want := range []string{"name: ix-peer-c", "asn: 64503", "next_hop: 203.0.113.13", "mode: observe"} {
		if !strings.Contains(yml, want) {
			t.Errorf("merged yaml missing %q:\n%s", want, yml)
		}
	}
	if strings.Contains(yml, "draft") || strings.Contains(yml, "announcer:") {
		t.Fatalf("apply wrote a draft flag or an announcer:\n%s", yml)
	}
	back := got["form"].(map[string]any)["exchanges"].([]any)[0].(map[string]any)["peers"].([]any)
	if len(back) != 2 || back[1].(map[string]any)["draft"] != nil {
		t.Fatalf("read-back = %v", back)
	}
	if disk, _ := os.ReadFile(e.path); string(disk) != editorYAML {
		t.Fatal("apply wrote the file")
	}

	// The page reads the running exchanges with the admin's own session.
	if rec, _ := e.do(t, "GET", "/api/exchanges", admin, nil); rec.Code != http.StatusOK {
		t.Fatalf("admin /api/exchanges: %d", rec.Code)
	}
}

// The page's accept function adds a row and never calls the API, so it
// cannot write a peer, start probing, or announce. The rendered list and the
// accepted row are covered by the UI smoke test in CI (lab/ui-fixtures/exchanges).
func TestSettingsDiscoveredAssets(t *testing.T) {
	e := newUI(t)
	rec, _ := e.do(t, "GET", "/settings.html", plugin.RoleViewer, nil)
	for _, w := range []string{`id="form-ix-discovered"`, `id="ix-refresh"`} {
		if !strings.Contains(rec.Body.String(), w) {
			t.Errorf("settings.html missing %q", w)
		}
	}
	rec, _ = e.do(t, "GET", "/settings.js", plugin.RoleViewer, nil)
	js := rec.Body.String()
	for _, w := range []string{`api("GET", "/api/exchanges")`, `byId("ix-refresh").addEventListener("click", loadDiscovered)`, `draft: true`} {
		if !strings.Contains(js, w) {
			t.Errorf("settings.js missing %q", w)
		}
	}
	i := strings.Index(js, "function acceptDiscovered")
	j := strings.Index(js[i:], "\nfunction ")
	if i < 0 || j < 0 {
		t.Fatal("acceptDiscovered missing")
	}
	body := js[i : i+j]
	if strings.Contains(body, "api(") || strings.Contains(body, "PUT") || strings.Contains(body, "/api/") {
		t.Fatalf("accepting a member calls the API:\n%s", body)
	}
	if !strings.Contains(body, `source_ip: ""`) || !strings.Contains(body, `cost: ""`) || !strings.Contains(body, `name: ""`) {
		t.Fatalf("a draft peer must leave name, probe address, and cost empty:\n%s", body)
	}
}
