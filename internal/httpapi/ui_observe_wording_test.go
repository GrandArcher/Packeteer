package httpapi

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// pendingRecommendation is what the engine holds in observe after it
// recommends lab-b over the learned lab-a: its decision names lab-b as the
// exit, and the router still sends traffic through lab-a (#346).
func pendingRecommendation(mode string, routes bool) Input {
	p := netip.MustParsePrefix("198.51.100.0/24")
	at := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	in := Input{
		Version: "test", Mode: mode, Started: true, At: at,
		Results: []probe.Result{
			{Provider: "lab-a", Prefix: p, Prober: "icmp", Time: at, Stats: probe.Stats{Sent: 10, Received: 8, LossPct: 20, RTTAvg: 21 * time.Millisecond}},
			{Provider: "lab-b", Prefix: p, Prober: "icmp", Time: at, Stats: probe.Stats{Sent: 10, Received: 10, RTTAvg: 10 * time.Millisecond}},
		},
		Decisions: []policy.Decision{{
			Prefix: p, Native: "lab-a", Current: "lab-b", Recommended: "lab-b", Action: policy.ActionImprove,
			Candidates: []policy.Candidate{{Provider: "lab-a", Score: 9, Usable: true}, {Provider: "lab-b", Score: 4, Usable: true}},
		}},
		Improvements: []policy.Improvement{{Prefix: p, Provider: "lab-b", Native: "lab-a", Since: at, Reason: "lab-b beats lab-a on loss"}},
	}
	if routes {
		in.Routes = map[netip.Prefix]rib.Route{p: {Prefix: p, NextHop: netip.MustParseAddr("192.0.2.1"), Provider: "lab-a"}}
	}
	return in
}

// #346: in observe and suggest the router keeps its learned path, so the
// API reports it as current and keeps the engine's pick as recommended. In
// inject the engine's choice is the current exit, as before.
func TestObserveCurrentIsLearnedPath(t *testing.T) {
	cases := []struct {
		mode    string
		routes  bool
		current string
		gain    float64
	}{
		{"observe", true, "lab-a", 5},
		{"observe", false, "lab-a", 5},
		{"suggest", true, "lab-a", 5},
		{"inject", true, "lab-b", 0},
	}
	for _, c := range cases {
		snap := Assemble(pendingRecommendation(c.mode, c.routes))
		row := snap.Prefixes[0]
		if row.Current != c.current || row.Recommended != "lab-b" || row.Native != "lab-a" {
			t.Errorf("%s routes=%v: prefix current %q recommended %q native %q", c.mode, c.routes, row.Current, row.Recommended, row.Native)
		}
		if row.Gain != c.gain {
			t.Errorf("%s: gain = %v, want %v", c.mode, row.Gain, c.gain)
		}
		if d := snap.Decisions[0]; d.Current != c.current || d.Recommended != "lab-b" {
			t.Errorf("%s: decision current %q recommended %q", c.mode, d.Current, d.Recommended)
		}
	}
}

// #346: an improvement with no decision row yet still reports the learned
// path, not the recommended provider, as the current exit in observe.
func TestObserveImprovementOnlyRow(t *testing.T) {
	in := pendingRecommendation("observe", false)
	in.Decisions = nil
	if got := Assemble(in).Prefixes[0].Current; got != "lab-a" {
		t.Fatalf("observe current = %q, want lab-a", got)
	}
	in.Mode = "inject"
	if got := Assemble(in).Prefixes[0].Current; got != "lab-b" {
		t.Fatalf("inject current = %q, want lab-b", got)
	}
}

// #346: through the served API, a viewer of an observe controller with one
// pending recommendation sees the router path as current and the
// recommendation as a separate value.
func TestObservePrefixesAPI(t *testing.T) {
	e := newUIWith(t, func(o *Options) {
		o.Snapshot = func() Snapshot { return Assemble(pendingRecommendation("observe", true)) }
	})
	rec, _ := e.do(t, "GET", "/api/prefixes", plugin.RoleViewer, nil)
	if rec.Code != 200 {
		t.Fatalf("prefixes = %d %s", rec.Code, rec.Body.String())
	}
	var page PrefixPage
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Prefixes) != 1 || page.Prefixes[0].Current != "lab-a" || page.Prefixes[0].Recommended != "lab-b" {
		t.Fatalf("prefixes = %+v", page.Prefixes)
	}
	rec, _ = e.do(t, "GET", "/api/prefixes?differs=1", plugin.RoleViewer, nil)
	if !strings.Contains(rec.Body.String(), `"prefix":"198.51.100.0/24"`) {
		t.Fatalf("differs filter lost the pending recommendation: %s", rec.Body.String())
	}
}

// #346: the pages name the two exits "Traffic now (router)" and "Packeteer
// recommends" outside inject, keep Current and Recommended for inject, and
// no page script words a recommendation as steering.
func TestObserveExitLabelsInAssets(t *testing.T) {
	app := mustWeb(t, "web/app.js")
	for _, s := range []string{
		`return {now: "Current", pick: "Recommended"}`,
		`return {now: "Traffic now (router)", pick: "Packeteer recommends"}`,
		`lastProviders.mode === "inject"`,
		`var labels = exitLabels();`,
	} {
		if !strings.Contains(app, s) {
			t.Errorf("app.js missing %s", s)
		}
	}
	if !strings.Contains(mustWeb(t, "web/prefixes.js"), `table(["More", "Prefix", labels.now, labels.pick,`) {
		t.Error("prefixes.js does not use the mode-aware column names")
	}
	if !strings.Contains(mustWeb(t, "web/search.js"), `inject ? "Current" : "Traffic now (router)", inject ? "Steered to" : "Packeteer recommends"`) {
		t.Error("search.js does not use the mode-aware column names")
	}
	for _, name := range []string{"web/prefixes.js", "web/prefix.js", "web/events.js", "web/prefixes.html", "web/events.html"} {
		if strings.Contains(strings.ToLower(mustWeb(t, name)), "steered") {
			t.Errorf("%s says steered", name)
		}
	}
}
