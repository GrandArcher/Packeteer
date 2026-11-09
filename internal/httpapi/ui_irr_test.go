package httpapi

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func irrSampleInput() Input {
	in := rpkiSampleInput()
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	in.Decisions[0].Candidates = []policy.Candidate{{
		Provider: "transit-a", Usable: false, Why: "IRR not registered",
		IRR: plugin.IRRNotRegistered, IRRSource: "radb", IRRUpdated: at.Add(-time.Hour),
	}}
	in.IRR = func(p netip.Prefix, origin uint32, provider string) plugin.IRRAnswer {
		if p != netip.MustParsePrefix("198.51.100.0/24") || origin != 64511 || provider != "transit-a" {
			return plugin.IRRAnswer{State: plugin.IRRUnknown}
		}
		return plugin.IRRAnswer{State: plugin.IRRRegistered, Source: "radb", Database: "RADB", Updated: at.Add(-2 * time.Hour),
			Origins: []uint32{64510, 64511}, ASSet: "AS-EXAMPLE", ASSetState: plugin.IRRNotRegistered, OriginName: "EXAMPLE-NET-AS"}
	}
	return in
}

// #214: each learned path on /api/prefixes carries its IRR state beside
// RPKI, with the source, database, data time, registered origins, the
// provider's as-set membership, and the origin's as-name; decision
// candidates carry the state and why prefer_registered refused one.
func TestIRRDisplaySmoke(t *testing.T) {
	e := newUIWith(t, func(o *Options) {
		o.Snapshot = func() Snapshot { return Assemble(irrSampleInput()) }
	})
	viewer := plugin.RoleViewer
	rec, _ := e.do(t, "GET", "/api/prefixes?prefix=198.51.100.0/24", viewer, nil)
	want := `"rpki":"valid","rpki_source":"routinator","rpki_updated":"2026-01-02T03:02:05Z","irr":"registered","irr_source":"radb","irr_database":"RADB","irr_updated":"2026-01-02T01:04:05Z","irr_origins":[64510,64511],"irr_as_set":"AS-EXAMPLE","irr_as_set_state":"not_registered","irr_origin_as_name":"EXAMPLE-NET-AS"`
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), want) {
		t.Fatalf("prefixes = %d %s", rec.Code, rec.Body.String())
	}
	rec, _ = e.do(t, "GET", "/api/decisions", viewer, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"why":"IRR not registered"`) ||
		!strings.Contains(rec.Body.String(), `"irr":"not_registered","irr_source":"radb","irr_updated":"2026-01-02T02:04:05Z"`) {
		t.Fatalf("decisions = %d %s", rec.Code, rec.Body.String())
	}
	// With IRR off nothing is labelled.
	off := rpkiSampleInput()
	if snap := Assemble(off); snap.Prefixes[0].Paths[0].IRR != "" || snap.Decisions[0].Candidates[0].IRR != "" {
		t.Fatalf("IRR off labelled a path: %+v", snap.Prefixes[0].Paths[0])
	}
}

// The prefix card renders the IRR column beside RPKI from those fields,
// and the System page titles the irr rows. Neither writes.
func TestIRRDisplayAssets(t *testing.T) {
	app := mustWeb(t, "web/app.js")
	for _, s := range []string{
		`"RPKI", "IRR", "MED"`, `tr.appendChild(irrCell(path));`, `path.irr_source`, `path.irr_database`, `ageText(path.irr_updated)`,
		`path.irr_origins`, `path.irr_as_set_state`, `path.irr_origin_as_name`, `state === "not_registered" ? "badge warn"`,
	} {
		if !strings.Contains(app, s) {
			t.Errorf("app.js missing %s", s)
		}
	}
	if system := mustWeb(t, "web/system.js"); !strings.Contains(system, `["irr", "IRR"]`) {
		t.Error("system.js missing the irr kind title")
	}
	i := strings.Index(app, "function irrCell(")
	if i < 0 {
		t.Fatal("no irrCell")
	}
	body := app[i : i+strings.Index(app[i:], "\n}\n")]
	if strings.Contains(body, "innerHTML") || strings.Contains(body, "postJSON") {
		t.Error("irrCell writes or builds markup")
	}
}

// #214: one System row per IRR source from its last lookup.
func TestIRRSystemRow(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	facts := []IRRFact{
		{PluginFact: PluginFact{Name: "radb", Type: "whois"}, Up: true, Updated: at},
		{PluginFact: PluginFact{Name: "ripe", Type: "whois"}, Updated: at, Err: "dial tcp: i/o timeout"},
		{PluginFact: PluginFact{Name: "local", Type: "file"}, Err: "irr file: no such file"},
		{PluginFact: PluginFact{Name: "idle", Type: "whois"}},
	}
	want := map[string]struct{ state, detail string }{
		"radb":  {StateOK, "answering, data time 2026-01-02T03:04:05Z"},
		"ripe":  {StateDegraded, "last lookup failed; cached answers are used until irr.staleness"},
		"local": {StateDown, "no answer yet"},
		"idle":  {StateIdle, "no lookup yet"},
	}
	sys := BuildSystem(Snapshot{Version: "test", Mode: "observe"}, SystemFacts{IRR: facts}, nil, nil)
	seen := 0
	for _, c := range sys.Components {
		if c.Kind != KindIRR {
			continue
		}
		seen++
		if w := want[c.Name]; c.State != w.state || c.Detail != w.detail {
			t.Fatalf("%s = %s %q, want %s %q", c.Name, c.State, c.Detail, w.state, w.detail)
		}
		if c.Name == "ripe" && c.Error != "dial tcp: i/o timeout" {
			t.Fatalf("ripe error = %q", c.Error)
		}
	}
	if seen != len(want) {
		t.Fatalf("irr rows = %d, want %d", seen, len(want))
	}
}
