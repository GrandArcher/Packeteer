package httpapi

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// #158: the RPKI validity is rendered on the prefix paths, the decision
// candidates, the exchange peers, and the System page, and none of the
// viewers writes.
func TestRPKIDisplayAssets(t *testing.T) {
	app := mustWeb(t, "web/app.js")
	exchanges := mustWeb(t, "web/exchanges.js")
	system := mustWeb(t, "web/system.js")
	for _, s := range []string{`path.rpki`, `"Via", "RPKI"`} {
		if !strings.Contains(app, s) {
			t.Errorf("app.js missing %s", s)
		}
	}
	for _, s := range []string{`exRPKICell(p.rpki)`, `"RPKI", "RS feed"`, `function exRPKICell`} {
		if !strings.Contains(exchanges, s) {
			t.Errorf("exchanges.js missing %s", s)
		}
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
			Candidates: []policy.Candidate{{Provider: "transit-a", Usable: true, RPKI: plugin.RPKIInvalid}},
		}},
		Paths: map[netip.Prefix][]rib.Route{p: {{
			Prefix: p, NextHop: netip.MustParseAddr("192.0.2.1"), Provider: "transit-a",
			ASPath: []uint32{64500, 64511},
		}}},
		RPKI: func(netip.Prefix, uint32) plugin.RPKIValidity { return plugin.RPKIValid },
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
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"rpki":"invalid"`) {
		t.Fatalf("decisions = %d %s", rec.Code, rec.Body.String())
	}
	rec, _ = e.do(t, "GET", "/api/prefixes", viewer, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"rpki":"valid"`) {
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

// #158: the System page has one row per configured RPKI source.
func TestRPKISystemRow(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	sys := BuildSystem(Snapshot{Version: "test", Mode: "observe"}, SystemFacts{RPKI: []RPKIFact{
		{PluginFact: PluginFact{Name: "routinator", Type: "rtr"}, Up: true, VRPs: 1234, Updated: at},
		{PluginFact: PluginFact{Name: "backup", Type: "rtr"}, Stale: true, Updated: at.Add(-2 * time.Hour)},
		{PluginFact: PluginFact{Name: "down", Type: "rtr"}},
	}}, nil, nil)
	var states []string
	for _, c := range sys.Components {
		if c.Kind == KindRPKI {
			states = append(states, c.State)
		}
	}
	if len(states) != 3 || states[0] != StateOK || states[1] != StateDegraded || states[2] != StateDown {
		t.Fatalf("rpki rows = %v", states)
	}
}
