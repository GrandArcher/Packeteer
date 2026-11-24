package httpapi

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/offload"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakeOffload struct{ rep offload.DryRunReport }

func (f fakeOffload) Report() offload.DryRunReport { return f.rep }

func ageOf(s float64) *float64 { return &s }

func sampleOffload() offload.DryRunReport {
	return offload.DryRunReport{Run: "dry_run", Routers: []offload.RouterReport{{
		Neighbor: "192.0.2.1", Profile: "mikrotik-l3hw-lpm", Verdict: offload.VerdictPartial,
		Dimensions: []offload.DimensionReport{
			{Dimension: offload.FIBv4, Known: true, Used: 27200, Cap: 27200, ReadingAgeSeconds: ageOf(12)},
			{Dimension: offload.NextHops, Known: true, Used: 93, Cap: 8192, ReadingAgeSeconds: ageOf(12)},
			{Dimension: offload.CPU, Problem: offload.FreezeMissing},
		},
		Counters: &offload.Counters{IPv4RoutesHW: 37729, IPv4RoutesCPU: 904609, IPv6RoutesCPU: 15, ShortestHWPrefix: 30, RouteQueueLimitHigh: 100000, RouteQueueLimitLow: 50000},
		Freezes:  []offload.Freeze{{Reason: offload.FreezePreCheck}, {Reason: offload.FreezeMissing, Dimension: offload.CPU}},
		Fixes:    []offload.Fix{{Prefix: "198.51.100.0/24", State: offload.FixBlocked}, {Prefix: "203.0.113.0/24", State: offload.FixBlocked}},
	}}}
}

// #738: GET /api/offload is a viewer read, and says so when offload_aware is off.
func TestOffloadEndpoint(t *testing.T) {
	e := newUI(t)
	rec, got := e.do(t, "GET", "/api/offload", plugin.RoleViewer, nil)
	if rec.Code != http.StatusOK || got["available"] != false || got["report"] != nil {
		t.Fatalf("without a source: %d %s", rec.Code, rec.Body)
	}
	if rec, _ = e.do(t, "GET", "/api/offload", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", rec.Code)
	}

	e.srv.SetOffload(fakeOffload{rep: sampleOffload()})
	rec, got = e.do(t, "GET", "/api/offload", plugin.RoleViewer, nil)
	rep, _ := got["report"].(map[string]any)
	routers, _ := rep["routers"].([]any)
	if rec.Code != http.StatusOK || got["available"] != true || rep["run"] != "dry_run" || len(routers) != 1 {
		t.Fatalf("get: %d %s", rec.Code, rec.Body)
	}
	r := routers[0].(map[string]any)
	if r["verdict"] != "partial_default_on_cpu" || r["neighbor"] != "192.0.2.1" || len(r["fixes"].([]any)) != 2 {
		t.Fatalf("router = %v", r)
	}
}

// The Blast radius response carries the dry run only when offload_aware is on.
func TestBlastCarriesTheOffloadSectionOnlyWhenOn(t *testing.T) {
	e, _ := blastUI(t)
	_, got := e.do(t, "GET", "/api/blast", plugin.RoleOperator, nil)
	if _, ok := got["offload"]; ok {
		t.Fatalf("offload section without offload_aware: %v", got)
	}
	e.srv.SetOffload(fakeOffload{rep: sampleOffload()})
	_, got = e.do(t, "GET", "/api/blast", plugin.RoleOperator, nil)
	off, _ := got["offload"].(map[string]any)
	if off["run"] != "dry_run" || len(off["routers"].([]any)) != 1 {
		t.Fatalf("offload section = %v", got["offload"])
	}
}

func TestOffloadMetrics(t *testing.T) {
	text := string(OffloadMetrics(sampleOffload()))
	for _, want := range []string{
		`packeteer_offload_lpm_used{router="192.0.2.1"} 27200`,
		`packeteer_offload_lpm_cap{router="192.0.2.1"} 27200`,
		`packeteer_offload_routes{router="192.0.2.1",family="ipv4",place="hw"} 37729`,
		`packeteer_offload_routes{router="192.0.2.1",family="ipv4",place="cpu"} 904609`,
		`packeteer_offload_routes{router="192.0.2.1",family="ipv6",place="cpu"} 15`,
		`packeteer_offload_shortest_hw_prefix{router="192.0.2.1"} 30`,
		`packeteer_offload_nexthop_used{router="192.0.2.1"} 93`,
		`packeteer_offload_nexthop_cap{router="192.0.2.1"} 8192`,
		`packeteer_offload_route_queue_limit{router="192.0.2.1",bound="high"} 100000`,
		`packeteer_offload_reading_age_seconds{router="192.0.2.1",dimension="fib_v4"} 12`,
		`packeteer_offload_freeze{router="192.0.2.1",reason="pre_check_failed",dimension=""} 1`,
		`packeteer_offload_freeze{router="192.0.2.1",reason="missing",dimension="cpu"} 1`,
		`packeteer_offload_fixes{router="192.0.2.1",state="blocked"} 2`,
		`packeteer_offload_fixes{router="192.0.2.1",state="offload"} 0`,
	} {
		if !strings.Contains(text, want+"\n") {
			t.Errorf("metrics lack %q:\n%s", want, text)
		}
	}
	// The unread CPU dimension has no cap or age to report.
	if strings.Contains(text, `reading_age_seconds{router="192.0.2.1",dimension="cpu"}`) {
		t.Errorf("an unread dimension has an age:\n%s", text)
	}
	if got := string(OffloadMetrics(offload.DryRunReport{})); got != "" {
		t.Errorf("no routers rendered %q", got)
	}
}

// Scrapes carry the series only while offload_aware is on.
func TestMetricsEndpointOffloadSeries(t *testing.T) {
	e := newUI(t)
	if strings.Contains(string(e.srv.metricsText(context.Background())), "packeteer_offload_") {
		t.Fatal("offload series without offload_aware")
	}
	e.srv.SetOffload(fakeOffload{rep: sampleOffload()})
	if !strings.Contains(string(e.srv.metricsText(context.Background())), "packeteer_offload_lpm_used") {
		t.Fatal("no offload series with offload_aware on")
	}
}
