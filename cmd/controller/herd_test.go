package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/herd"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const herdPeerKey = "ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

func herdYAML(dir string) string {
	return `
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
bgp:
  neighbors:
    - address: 192.0.2.254
storage:
  type: sqlite
  config: {path: ` + filepath.Join(dir, "h.db") + `}
inbound:
  mode: suggest
  prefixes: [192.0.2.64/26]
  performance: {loss_pct: 5, latency_ms: 50}
herd:
  enabled: true
  share:
    classes: [measurements]
  vantage: {country: US}
  key_file: ` + filepath.Join(dir, "node.key") + `
  listen: 127.0.0.1:0
  peers:
    - url: https://192.0.2.30:9444
      key: ` + herdPeerKey + `
`
}

type stubRIB struct{}

func (stubRIB) Ready() bool                          { return true }
func (stubRIB) Exact(netip.Prefix) (rib.Route, bool) { return rib.Route{}, false }
func (stubRIB) ProviderPaths(netip.Prefix, string) [][]uint32 {
	return nil
}

func TestHerdChangeNeedsRestart(t *testing.T) {
	dir := t.TempDir()
	on := mustParse(t, herdYAML(dir))
	off := mustParse(t, strings.Replace(herdYAML(dir), "herd:\n  enabled: true", "herd:\n  enabled: false", 1))
	restart, online := classify(off, on)
	if !slices.Contains(restart, "herd") || slices.Contains(online, "herd") {
		t.Fatalf("restart %v online %v, want herd in restart only", restart, online)
	}
}

func TestRunHerdCheckNamesWhatIsShared(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(herdYAML(t.TempDir())), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut strings.Builder
	if code := run(t.Context(), []string{"-check", "-config", path}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("exit %d stderr %s", code, errOut.String())
	}
	for _, want := range []string{"herd: on granularity=origin_asn classes=measurements sources=static,vip,outage peers=1 serving=true", "never announces", "announce: disabled"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout missing %q:\n%s", want, out.String())
		}
	}
}

func TestHerdOwnPrefixesCoverInboundFlowAndSpan(t *testing.T) {
	// Parsed only: building the sources would open a listener and an interface.
	cfg := mustParse(t, herdYAML(t.TempDir())+"\n"+`sources:
  - type: flow
    config:
      transit: {customers: [198.51.100.0/25]}
      problems: {local: [203.0.113.0/26]}
  - type: span
    config: {local: [192.0.2.128/25]}
`)
	got := herdOwnPrefixes(cfg)
	for _, want := range []string{"192.0.2.64/26", "198.51.100.0/25", "203.0.113.0/26", "192.0.2.128/25"} {
		if !slices.Contains(got, netip.MustParsePrefix(want)) {
			t.Errorf("own prefixes %v miss %s", got, want)
		}
	}
	rules := herd.NewRules(cfg.Herd, got)
	if rules.Allowed(herd.Route{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Path: []uint32{64501, 64510}, Sources: []string{"static"}}) {
		t.Error("a route covering a customer prefix is shareable")
	}
}

func TestHerdBatchIsOffWhenHerdIsOffAndNeverBlocks(t *testing.T) {
	dir := t.TempDir()
	var ref atomic.Pointer[herd.Herd]
	off := mustParse(t, strings.Replace(herdYAML(dir), "herd:\n  enabled: true", "herd:\n  enabled: false", 1))
	if herdBatch(off, &ref) != nil {
		t.Fatal("OnBatch is set with herd off: the engine would keep raw samples")
	}
	fn := herdBatch(mustParse(t, herdYAML(dir)), &ref)
	if fn == nil {
		t.Fatal("no OnBatch with herd on")
	}
	fn([]probe.Result{{}}) // herd not built yet: the round is dropped
}

func TestNewHerdRefusesAStoreThatCannotKeepRecords(t *testing.T) {
	cfg := mustParse(t, herdYAML(t.TempDir()))
	if _, err := newHerd(cfg, &pluginhost.Set{}, stubRIB{}, nil, func(plugin.Event) {}, nil, nil); err == nil || !strings.Contains(err.Error(), "storage") {
		t.Fatalf("err = %v", err)
	}
	off := mustParse(t, strings.Replace(herdYAML(t.TempDir()), "herd:\n  enabled: true", "herd:\n  enabled: false", 1))
	if h, err := newHerd(off, &pluginhost.Set{}, stubRIB{}, nil, nil, nil, nil); h != nil || err != nil {
		t.Fatalf("herd off built %v, %v", h, err)
	}
}

func TestHerdServesItsStatusPreviewAndMetricsOverTheOpsAPI(t *testing.T) {
	cfg := mustParse(t, herdYAML(t.TempDir()))
	set, err := pluginhost.Build(cfg, pluginhost.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := set.Storage.Plugin.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = set.Storage.Plugin.Stop(ctx) })
	hd, err := startHerd(ctx, cfg, set, nil, nil, func(plugin.Event) {}, nil, nil)
	if hd != nil || err == nil || !strings.Contains(err.Error(), "bgp.neighbors") {
		t.Fatalf("without a RIB view: %v, %v", hd, err)
	}
	hd, err = newHerd(cfg, set, stubRIB{}, nil, func(plugin.Event) {}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := hd.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hd.Stop(ctx) })

	srv, err := httpapi.New(httpapi.Options{Snapshot: func() httpapi.Snapshot {
		return httpapi.Snapshot{Version: "test", Mode: config.ModeObserve, Started: true}
	}})
	if err != nil {
		t.Fatal(err)
	}
	get := func(path string) (int, string) {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code, rec.Body.String()
	}
	if code, body := get("/api/herd"); code != 200 || !strings.Contains(body, `"enabled":false`) {
		t.Fatalf("before wiring: %d %s", code, body)
	}
	if code, _ := get("/api/herd/preview?origin_asn=64510"); code != http.StatusNotFound {
		t.Fatalf("preview with herd off: %d", code)
	}
	srv.SetHerd(hd)

	code, body := get("/api/herd")
	var st map[string]any
	if err := json.Unmarshal([]byte(body), &st); err != nil || code != 200 {
		t.Fatalf("status: %d %v %s", code, err, body)
	}
	if st["enabled"] != true || st["granularity"] != "origin_asn" || st["asn"] != float64(64512) || st["country"] != "US" || len(st["peers"].([]any)) != 1 {
		t.Errorf("status = %s", body)
	}
	if !strings.HasPrefix(st["public_key"].(string), "ed25519:") || len(st["key_id"].(string)) != 64 {
		t.Errorf("key = %v %v", st["public_key"], st["key_id"])
	}
	// The preview is the signed document and the query rules of a real pull.
	code, body = get("/api/herd/preview?doc=status")
	if code != 200 || !strings.Contains(body, `"signature"`) || !strings.Contains(body, `"granularity":"origin_asn"`) {
		t.Errorf("preview status: %d %s", code, body)
	}
	if code, body = get("/api/herd/preview?origin_asn=64510"); code != 200 || !strings.Contains(body, `"records":[]`) {
		t.Errorf("preview records: %d %s", code, body)
	}
	if code, _ = get("/api/herd/preview?bogus=1"); code != http.StatusBadRequest {
		t.Errorf("preview with an unknown parameter: %d", code)
	}
	if code, body = get("/api/herd/vantages"); code != http.StatusBadRequest || !strings.Contains(body, "origin_asn") {
		t.Errorf("vantages without a query: %d %s", code, body)
	}
	if code, body = get("/api/herd/vantages?origin_asn=64510"); code != 200 || !strings.Contains(body, `"vantages":[]`) {
		t.Errorf("vantages: %d %s", code, body)
	}
	_, metrics := get("/metrics")
	for _, want := range []string{"packeteer_herd_store_budget_bytes", "packeteer_herd_records_dropped_total 0", `packeteer_herd_peer_up{peer="`} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics miss %q", want)
		}
	}
}
