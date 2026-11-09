package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/provseries"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func statsRows(t *testing.T, body map[string]any) map[string]map[string]any {
	t.Helper()
	list, ok := body["providers"].([]any)
	if !ok {
		t.Fatalf("providers is %T, want a list: %v", body["providers"], body)
	}
	out := map[string]map[string]any{}
	for _, v := range list {
		row := v.(map[string]any)
		out[row["provider"].(string)] = row
	}
	return out
}

// #349: the endpoint serves each provider's median windows and hourly points
// from the series, adds Mbps only when a flow source reports volume, lists a
// provider that has traffic and no measurement, and gives a path that never
// answered loss with no latency.
func TestProviderStatsEndpoint(t *testing.T) {
	now := time.Date(2026, 3, 17, 12, 7, 0, 0, time.UTC)
	series := provseries.New(func() time.Time { return now })
	for _, m := range []time.Duration{-2 * time.Minute, -7 * time.Minute, -12 * time.Minute} {
		series.Add(probe.Result{Provider: "lab-a", Time: now.Add(m), Stats: probe.Stats{Sent: 10, Received: 9, LossPct: 10, RTTAvg: 120 * time.Millisecond, Jitter: 12 * time.Millisecond}})
		series.Add(probe.Result{Provider: "lab-b", Time: now.Add(m), Stats: probe.Stats{Sent: 10, LossPct: 100}})
	}
	e := newUI(t)
	viewer := plugin.RoleViewer

	// Before anything is installed the list is empty, not null.
	rec, body := e.do(t, "GET", "/api/providers/stats", viewer, nil)
	if rec.Code != http.StatusOK || body["flow"] != false || len(statsRows(t, body)) != 0 {
		t.Fatalf("empty = %d %v", rec.Code, body)
	}

	traffic := func() (map[string]float64, bool) { return nil, false }
	e.srv.SetProviderStats(ProviderStats{Series: series.Stats, Traffic: func() (map[string]float64, bool) { return traffic() }})
	rec, body = e.do(t, "GET", "/api/providers/stats", viewer, nil)
	if rec.Code != http.StatusOK || body["flow"] != false {
		t.Fatalf("no flow = %d %v", rec.Code, body)
	}
	rows := statsRows(t, body)
	a := rows["lab-a"]
	w := a["last_15m"].(map[string]any)
	if w["slots"] != float64(3) || w["rtt_ms"] != float64(120) || w["jitter_ms"] != float64(12) || w["loss_pct"] != float64(10) {
		t.Fatalf("lab-a 15 min = %v", w)
	}
	if _, has := a["mbps"]; has {
		t.Fatalf("Mbps without a flow source: %v", a)
	}
	// The 11:55 slot is in hour 11; 12:00 and 12:05 are in hour 12.
	pts := a["points"].([]any)
	if len(pts) != 2 || pts[0].(map[string]any)["t"] != "2026-03-17T11:00:00Z" || pts[1].(map[string]any)["t"] != "2026-03-17T12:00:00Z" ||
		pts[1].(map[string]any)["rtt_ms"] != float64(120) || pts[1].(map[string]any)["loss_pct"] != float64(10) {
		t.Fatalf("lab-a points = %v", pts)
	}
	b := rows["lab-b"]
	w = b["last_15m"].(map[string]any)
	if w["slots"] != float64(3) || w["loss_pct"] != float64(100) {
		t.Fatalf("lab-b loss = %v", w)
	}
	if _, has := w["rtt_ms"]; has {
		t.Fatalf("a path that never answered has no latency: %v", w)
	}
	for _, p := range b["points"].([]any) {
		if _, has := p.(map[string]any)["rtt_ms"]; has {
			t.Fatalf("a silent hour has no rtt_ms: %v", p)
		}
	}

	traffic = func() (map[string]float64, bool) { return map[string]float64{"lab-a": 12.5, "lab-c": 5}, true }
	_, body = e.do(t, "GET", "/api/providers/stats", viewer, nil)
	rows = statsRows(t, body)
	if body["flow"] != true || rows["lab-a"]["mbps"] != 12.5 || rows["lab-b"]["mbps"] != float64(0) {
		t.Fatalf("with flow = %v", body)
	}
	c, ok := rows["lab-c"]
	if !ok || c["mbps"] != float64(5) || c["last_24h"].(map[string]any)["slots"] != float64(0) || len(c["points"].([]any)) != 0 {
		t.Fatalf("a provider with traffic and no probes = %v", rows["lab-c"])
	}

	// Read-only and behind sign-in.
	if rec, _ := e.do(t, "POST", "/api/providers/stats", plugin.RoleAdmin, "{}"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST = %d, want 405", rec.Code)
	}
	req := httptest.NewRequest("GET", "/api/providers/stats", nil)
	anon := httptest.NewRecorder()
	e.h.ServeHTTP(anon, req)
	if anon.Code != http.StatusUnauthorized {
		t.Errorf("anonymous GET = %d, want 401", anon.Code)
	}
}

// #349: Providers is the first tile, so the eye lands on provider health;
// the mode is in the header chip and the banner, not in a tile. The page
// reads the figures only on the two pages that draw them.
func TestOverviewTilesLeadWithProviders(t *testing.T) {
	app := mustWeb(t, "web/app.js")
	tiles := app[strings.Index(app, "function renderTiles("):]
	tiles = tiles[:strings.Index(tiles, "\n}\n")]
	if strings.Contains(tiles, `tile("Mode"`) {
		t.Error("the Mode tile is back")
	}
	first := strings.Index(tiles, "root.appendChild(tile(")
	if first < 0 || !strings.HasPrefix(tiles[first:], `root.appendChild(tile("Providers"`) {
		t.Errorf("the first tile is not Providers: %.80s", tiles[first:])
	}
	if !strings.Contains(app, `page !== "providers" && page !== "overview"`) {
		t.Error("provider figures are read on pages that do not draw them")
	}
	shell := mustWeb(t, "web/shell.js")
	if !strings.Contains(shell, `"badge mode-"`) {
		t.Error("the header mode chip is gone")
	}
}
