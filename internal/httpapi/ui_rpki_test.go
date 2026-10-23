package httpapi

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/internal/rpki"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// #158: the RPKI validity is rendered on the prefix paths, the decision
// candidates, the exchange peers, and the System page, and none of the
// viewers writes. #200: a path also shows the source that answered and the
// age of its data, and the prefix timeline lists the stored states.
func TestRPKIDisplayAssets(t *testing.T) {
	app := mustWeb(t, "web/app.js")
	exchanges := mustWeb(t, "web/exchanges.js")
	system := mustWeb(t, "web/system.js")
	for _, s := range []string{`rpkiCell(path.rpki, path.rpki_source, path.rpki_updated)`, `"Via", "RPKI"`, `" via " + source`} {
		if !strings.Contains(app, s) {
			t.Errorf("app.js missing %s", s)
		}
	}
	for _, s := range []string{`exRPKICell(p.rpki)`, `"RPKI", "RS feed"`, `function exRPKICell`} {
		if !strings.Contains(exchanges, s) {
			t.Errorf("exchanges.js missing %s", s)
		}
	}
	if prefix := mustWeb(t, "web/prefix.js"); !strings.Contains(prefix, `(data.rpki || []).forEach(function (r) { entries.push(rpkiEntry(r)); })`) {
		t.Error("prefix.js does not list the stored RPKI states")
	}
	if !strings.Contains(system, `["rpki", "RPKI"]`) {
		t.Error("system.js missing the rpki kind title")
	}
	for _, js := range []string{exchanges, system} {
		if strings.Contains(js, "postJSON") || strings.Contains(js, "innerHTML") {
			t.Error("an RPKI viewer writes or builds markup")
		}
	}
}

func rpkiSampleInput() Input {
	p := netip.MustParsePrefix("198.51.100.0/24")
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	return Input{
		Version: "test", Mode: "observe", Started: true, At: at,
		Results: []probe.Result{{
			Provider: "transit-a", Prefix: p, Prober: "icmp",
			Stats: probe.Stats{Sent: 4, Received: 4, RTTAvg: 40 * time.Millisecond}, Time: at,
		}},
		Decisions: []policy.Decision{{
			Prefix: p, Native: "transit-a", Current: "transit-a", Action: policy.ActionNone, Reason: "native path is best",
			Candidates: []policy.Candidate{{Provider: "transit-a", Usable: true, RPKI: plugin.RPKIInvalid, RPKISource: "routinator", RPKIUpdated: at.Add(-time.Minute)}},
		}},
		Paths: map[netip.Prefix][]rib.Route{p: {{
			Prefix: p, NextHop: netip.MustParseAddr("192.0.2.1"), Provider: "transit-a",
			ASPath: []uint32{64500, 64511},
		}}},
		RPKI: func(netip.Prefix, uint32) plugin.RPKIAnswer {
			return plugin.RPKIAnswer{State: plugin.RPKIValid, Source: "routinator", Updated: at.Add(-2 * time.Minute)}
		},
		Exchanges: []exchange.Stats{{
			Name: "ix-lab", Peers: []exchange.PeerStats{{
				Name: "ix-peer-a", NextHop: "203.0.113.11", Prefixes: 3,
				RPKI: &rib.RPKICounts{Valid: 2, Invalid: 1},
			}},
		}},
	}
}

func TestRPKIDisplaySmoke(t *testing.T) {
	e := newUIWith(t, func(o *Options) {
		o.Snapshot = func() Snapshot { return Assemble(rpkiSampleInput()) }
	})
	viewer := plugin.RoleViewer

	rec, _ := e.do(t, "GET", "/api/decisions", viewer, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"rpki":"invalid","rpki_source":"routinator","rpki_updated":"2026-01-02T03:03:05Z"`) {
		t.Fatalf("decisions = %d %s", rec.Code, rec.Body.String())
	}
	rec, _ = e.do(t, "GET", "/api/prefixes", viewer, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"rpki":"valid","rpki_source":"routinator","rpki_updated":"2026-01-02T03:02:05Z"`) {
		t.Fatalf("prefixes = %d %s", rec.Code, rec.Body.String())
	}
	rec, _ = e.do(t, "GET", "/api/exchanges", viewer, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"rpki":{"valid":2,"invalid":1,"notfound":0,"unknown":0}`) {
		t.Fatalf("exchanges = %d %s", rec.Code, rec.Body.String())
	}
	rec, _ = e.do(t, "GET", "/providers.html", viewer, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `<script src="/exchanges.js">`) {
		t.Fatalf("providers page = %d", rec.Code)
	}
}

// #200: the display fallback sends prefixes to an outside service, so only
// /api/prefixes (the prefix list and card) asks it, only for paths the
// sources left unknown, and the snapshot other handlers share keeps the
// sources' label.
func TestRPKIDisplayFallbackOnlyOnPrefixes(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	in := rpkiSampleInput()
	in.RPKI = func(netip.Prefix, uint32) plugin.RPKIAnswer { return plugin.RPKIAnswer{State: plugin.RPKIUnknown} }
	snap := Assemble(in)
	var asked []string
	e := newUIWith(t, func(o *Options) { o.Snapshot = func() Snapshot { return snap } })
	e.srv.SetRPKIDisplay(func(p netip.Prefix, origin uint32) plugin.RPKIAnswer {
		asked = append(asked, fmt.Sprintf("%s AS%d", p, origin))
		return plugin.RPKIAnswer{State: plugin.RPKIValid, Source: "ripestat", Updated: at}
	})
	viewer := plugin.RoleViewer
	for _, path := range []string{"/metrics", "/api/overview", "/api/system", "/api/decisions", "/api/search?q=198.51.100.0/24", "/api/exchanges"} {
		if rec, _ := e.do(t, "GET", path, viewer, nil); rec.Code != 200 {
			t.Fatalf("%s = %d", path, rec.Code)
		}
	}
	if len(asked) != 0 {
		t.Fatalf("display fallback asked outside /api/prefixes: %v", asked)
	}
	rec, _ := e.do(t, "GET", "/api/prefixes?prefix=198.51.100.0/24", viewer, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"rpki":"valid","rpki_source":"ripestat","rpki_updated":"2026-01-02T03:04:05Z"`) {
		t.Fatalf("prefixes = %d %s", rec.Code, rec.Body.String())
	}
	if want := []string{"198.51.100.0/24 AS64511"}; !slices.Equal(asked, want) {
		t.Fatalf("asked = %v, want %v", asked, want)
	}
	if got := snap.Prefixes[0].Paths[0]; got.RPKI != string(plugin.RPKIUnknown) || got.RPKISource != "" {
		t.Fatalf("shared snapshot path relabeled: %+v", got)
	}
}

// #158: the System page has one row per configured RPKI source, and its
// state matches whether lookups use that source's cache: a fresh cache is
// ok while the server is disconnected, a stale or empty one is skipped.
func TestRPKISystemRow(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	facts := []RPKIFact{
		{PluginFact: PluginFact{Name: "routinator", Type: "rtr"}, Up: true, VRPs: 1234, Updated: at},
		{PluginFact: PluginFact{Name: "disconnected", Type: "rtr"}, VRPs: 1234, Updated: at, Err: "connection refused"},
		{PluginFact: PluginFact{Name: "empty", Type: "rtr"}, Up: true, Updated: at},
		{PluginFact: PluginFact{Name: "backup", Type: "rtr"}, Stale: true, VRPs: 10, Updated: at.Add(-2 * time.Hour)},
		{PluginFact: PluginFact{Name: "down", Type: "rtr"}, Stale: true},
	}
	want := map[string]struct{ state, detail string }{
		"routinator":   {StateOK, "1234 VRPs, updated 2026-01-02T03:04:05Z"},
		"disconnected": {StateOK, "1234 VRPs, updated 2026-01-02T03:04:05Z, in use while disconnected"},
		"empty":        {StateDegraded, "0 VRPs, skipped, updated 2026-01-02T03:04:05Z"},
		"backup":       {StateDegraded, "10 VRPs, stale since 2026-01-02T01:04:05Z, skipped"},
		"down":         {StateDown, "no data"},
	}
	sys := BuildSystem(Snapshot{Version: "test", Mode: "observe"}, SystemFacts{RPKI: facts}, nil, nil)
	seen := 0
	for _, c := range sys.Components {
		if c.Kind != KindRPKI {
			continue
		}
		seen++
		w := want[c.Name]
		if c.State != w.state || c.Detail != w.detail {
			t.Fatalf("%s = %s %q, want %s %q", c.Name, c.State, c.Detail, w.state, w.detail)
		}
		if c.Name == "disconnected" && c.Error != "connection refused" {
			t.Fatalf("disconnected error = %q", c.Error)
		}
	}
	if seen != len(want) {
		t.Fatalf("rpki rows = %d, want %d", seen, len(want))
	}
	// Each state agrees with the lookup path: only the ok rows answer.
	for _, f := range facts {
		src := rpki.NewSet([]plugin.RPKI{factSource{f: f}})
		used := src.Validate(netip.MustParsePrefix("198.51.100.0/24"), 64500) != plugin.RPKIUnknown
		if used != (want[f.Name].state == StateOK) {
			t.Fatalf("%s: used by lookups = %v, row state %s", f.Name, used, want[f.Name].state)
		}
	}
}

// factSource is an RPKI source whose Status is one RPKIFact and whose
// lookups are always valid when consulted.
type factSource struct {
	plugin.Base
	f RPKIFact
}

func (s factSource) Validate(netip.Prefix, uint32) plugin.RPKIValidity {
	return plugin.RPKIValid
}
func (s factSource) Status() plugin.RPKIStatus {
	return plugin.RPKIStatus{Source: s.f.Name, Up: s.f.Up, Stale: s.f.Stale, VRPs: s.f.VRPs, Updated: s.f.Updated, Error: s.f.Err}
}

// #200: /metrics carries each source's session state, VRP count, and
// cache age; a source that never fetched has no age sample.
func TestRPKIMetrics(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	got := string(RPKIMetrics([]plugin.RPKIStatus{
		{Source: "routinator", Up: true, VRPs: 1234, Updated: now.Add(-90 * time.Second)},
		{Source: "backup", Stale: true},
	}, now))
	for _, want := range []string{
		`packeteer_rpki_source_up{source="routinator"} 1`,
		`packeteer_rpki_source_up{source="backup"} 0`,
		`packeteer_rpki_vrps{source="routinator"} 1234`,
		`packeteer_rpki_cache_age_seconds{source="routinator"} 90`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("metrics missing %s:\n%s", want, got)
		}
	}
	if strings.Contains(got, `packeteer_rpki_cache_age_seconds{source="backup"}`) {
		t.Errorf("never-fetched source has an age:\n%s", got)
	}
	e := newUIWith(t, func(o *Options) {
		o.Snapshot = func() Snapshot { return Assemble(rpkiSampleInput()) }
	})
	e.srv.SetRPKIStatus(func() []plugin.RPKIStatus { return []plugin.RPKIStatus{{Source: "routinator", Up: true, VRPs: 3}} })
	rec, _ := e.do(t, "GET", "/metrics", plugin.RoleViewer, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `packeteer_rpki_vrps{source="routinator"} 3`) {
		t.Fatalf("/metrics = %d, missing the RPKI gauges", rec.Code)
	}
}
