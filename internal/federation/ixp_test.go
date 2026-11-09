package federation

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func ixpCfg() Config { return Config{Instance: "site-a", Domain: "site-a"} }

func path(asn uint32, loss, rtt float64, past bool) plugin.FabricPath {
	return plugin.FabricPath{ASN: asn, VLANID: 10, Vantage: "lan1", Family: "ipv4", LossPct: loss, RTTMs: rtt, PastTolerance: past}
}

func healthyIXP() *plugin.FederatedIXP {
	return &plugin.FederatedIXP{
		Round:    t0,
		Vantages: []plugin.FabricVantageStatus{{Name: "lan1", Up: true}},
		Members:  []plugin.FabricPath{path(64496, 0, 0.4, false), path(64497, 0, 0.5, false)},
		Groups:   []plugin.CorrelationGroup{},
		Core:     []plugin.CoreLinkStatus{},
	}
}

func fresh1(name string, x *plugin.FederatedIXP) plugin.PeerState {
	return plugin.PeerState{Name: name, Fresh: true, LastSeen: t0,
		Snapshot: plugin.InstanceSnapshot{Instance: name, Domain: name, Time: t0, IXP: x}}
}

func stale(name, errText string) plugin.PeerState {
	return plugin.PeerState{Name: name, Error: errText}
}

func localSnap(x *plugin.FederatedIXP) *plugin.InstanceSnapshot {
	return &plugin.InstanceSnapshot{Instance: "site-a", Domain: "site-a", Time: t0, IXP: x}
}

func site(t *testing.T, v IXPSitesView, name string) SiteHealth {
	t.Helper()
	for _, s := range v.Sites {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no site %s in %+v", name, v.Sites)
	return SiteHealth{}
}

func link(name, peer string, loss, rtt float64, degraded bool) plugin.CoreLinkStatus {
	return plugin.CoreLinkStatus{Name: name, Peer: peer, Address: "192.0.2.40", Sent: 5, LossPct: loss, RTTMs: rtt, Up: loss < 100, Degraded: degraded, At: t0}
}

func TestIXPSnapshotWorstPathAndRouteServers(t *testing.T) {
	x := IXPSnapshot(IXPInput{
		Fabric: plugin.FabricView{Configured: true, Round: t0, Vantages: []plugin.FabricVantageStatus{{Name: "lan1", Up: true}},
			Samples: []plugin.FabricSample{
				{ASN: 64496, VLANID: 10, Vantage: "lan1", Family: "ipv4", Address: "192.0.2.20", LossPct: 0, RTTMs: 0.4},
				{ASN: 64496, VLANID: 10, Vantage: "lan1", Family: "ipv4", Address: "192.0.2.21", LossPct: 40, RTTMs: 310, PastTolerance: true},
				{ASN: 64497, VLANID: 10, Vantage: "lan1", Family: "ipv4", Address: "192.0.2.22", Error: "no route"},
			}},
		RouteServer: plugin.RouteServerView{Configured: true, Servers: []plugin.RouteServerStatus{{Name: "rs1", Up: true}, {Name: "rs2"}}},
	})
	if len(x.Members) != 1 || x.Members[0].ASN != 64496 || x.Members[0].LossPct != 40 || x.Members[0].RTTMs != 310 || !x.Members[0].PastTolerance {
		t.Fatalf("members = %+v", x.Members)
	}
	if x.RouteServers != 2 || x.RouteServersDown != 1 || !x.Round.Equal(t0) {
		t.Fatalf("snapshot = %+v", x)
	}
	if x.Groups == nil || x.Core == nil || x.Vantages == nil {
		t.Fatalf("nil slices would encode as null: %+v", x)
	}
}

func TestSnapshotCarriesIXPAndPublishDownDoesNot(t *testing.T) {
	x := healthyIXP()
	s := Snapshot(ixpCfg(), SnapshotInput{Mode: "observe", Now: t0, IXP: x})
	if s.IXP != x {
		t.Fatalf("IXP = %+v", s.IXP)
	}
	if s := Snapshot(ixpCfg(), SnapshotInput{Mode: "observe", Now: t0}); s.IXP != nil {
		t.Fatalf("a snapshot with no IXP input carries %+v", s.IXP)
	}
}

func TestIXPSitesAllHealthy(t *testing.T) {
	x := healthyIXP()
	x.Core = []plugin.CoreLinkStatus{link("a-to-b", "site-b", 0, 3.2, false)}
	y := healthyIXP()
	y.Core = []plugin.CoreLinkStatus{link("b-to-a", "site-a", 0, 3.3, false)}
	v := IXPSites(ixpCfg(), localSnap(x), []plugin.PeerState{fresh1("site-b", y)})
	if !v.Enabled || len(v.Incidents) != 0 || len(v.Sites) != 2 || len(v.Links) != 2 {
		t.Fatalf("view = %+v", v)
	}
	a, b := site(t, v, "site-a"), site(t, v, "site-b")
	if !a.Self || b.Self || a.Status != StatusOK || b.Status != StatusOK || a.Members != 2 || a.VantagesUp != 1 || a.Vantages != 1 {
		t.Fatalf("a = %+v b = %+v", a, b)
	}
	if v.Links[0].Site != "site-a" || v.Links[1].Site != "site-b" || v.Links[1].Peer != "site-a" {
		t.Fatalf("links = %+v", v.Links)
	}
}

func TestIXPSitesFabricIncidentIsAtTheSiteThatReportsIt(t *testing.T) {
	y := healthyIXP()
	y.Members = []plugin.FabricPath{path(64496, 0, 0.4, false), path(64497, 35, 400, true), path(64497, 30, 380, true), path(64498, 50, 410, true)}
	y.Groups = []plugin.CorrelationGroup{
		{Scope: plugin.ScopeSwitch, Name: "sw2", Members: 4, Degraded: 3, Active: true},
		{Scope: plugin.ScopeSwitch, Name: "sw1", Members: 4, Degraded: 1},
	}
	v := IXPSites(ixpCfg(), localSnap(healthyIXP()), []plugin.PeerState{fresh1("site-b", y)})
	if got := site(t, v, "site-a").Status; got != StatusOK {
		t.Fatalf("site-a = %s, want ok: %+v", got, v.Incidents)
	}
	b := site(t, v, "site-b")
	if b.Status != StatusDegraded || b.Members != 3 || b.MembersPast != 2 || len(b.PastTolerance) != 3 {
		t.Fatalf("site-b = %+v", b)
	}
	if len(v.Incidents) != 1 {
		t.Fatalf("incidents = %+v", v.Incidents)
	}
	in := v.Incidents[0]
	if in.Site != "site-b" || in.Scope != ScopeFabric || in.Detail != "switch sw2: 3 of 4 members degraded" {
		t.Fatalf("incident = %+v", in)
	}
}

func TestIXPSitesVantageRouteServerAndStaleMemberList(t *testing.T) {
	x := healthyIXP()
	x.Vantages = []plugin.FabricVantageStatus{{Name: "lan1", Up: true}, {Name: "lan2", Error: "every probe failed"}}
	x.RouteServers, x.RouteServersDown = 2, 1
	v := IXPSites(ixpCfg(), localSnap(x), nil)
	var scopes []string
	for _, in := range v.Incidents {
		scopes = append(scopes, in.Scope+":"+in.Detail)
	}
	want := []string{"vantage:vantage lan2 is down: every probe failed", "route_server:1 of 2 route servers are not answering"}
	if !slices.Equal(scopes, want) {
		t.Fatalf("incidents = %q, want %q", scopes, want)
	}
	if a := site(t, v, "site-a"); a.Status != StatusDegraded || a.VantagesUp != 1 || a.RouteServersDown != 1 {
		t.Fatalf("site-a = %+v", a)
	}

	s := healthyIXP()
	s.Stale = true
	s.Vantages = []plugin.FabricVantageStatus{{Name: "lan1"}}
	v = IXPSites(ixpCfg(), localSnap(s), nil)
	if len(v.Incidents) != 1 || !strings.Contains(v.Incidents[0].Detail, "member list is stale") {
		t.Fatalf("a stale member list is one incident, not one per down vantage: %+v", v.Incidents)
	}
}

func TestIXPSitesDegradedCoreLinkIsACoreIncidentNotASiteFault(t *testing.T) {
	x := healthyIXP()
	x.Core = []plugin.CoreLinkStatus{link("a-to-b", "site-b", 40, 90, true)}
	v := IXPSites(ixpCfg(), localSnap(x), []plugin.PeerState{fresh1("site-b", healthyIXP())})
	if len(v.Incidents) != 1 {
		t.Fatalf("incidents = %+v", v.Incidents)
	}
	in := v.Incidents[0]
	if in.Site != "site-a" || in.Peer != "site-b" || in.Scope != ScopeCore || in.Detail != "core link a-to-b: loss 40%, RTT 90.00 ms" {
		t.Fatalf("incident = %+v", in)
	}
	if site(t, v, "site-a").Status != StatusOK || site(t, v, "site-b").Status != StatusOK {
		t.Fatalf("a core fault is not a site fault: %+v", v.Sites)
	}

	x.Core = []plugin.CoreLinkStatus{{Name: "a-to-b", Peer: "site-b", Error: "source address unavailable", Degraded: true}}
	v = IXPSites(ixpCfg(), localSnap(x), nil)
	if !strings.Contains(v.Incidents[0].Detail, "could not be probed: source address unavailable") {
		t.Fatalf("incident = %+v", v.Incidents)
	}
	x.Core = []plugin.CoreLinkStatus{link("a-to-b", "site-b", 100, 0, true)}
	v = IXPSites(ixpCfg(), localSnap(x), nil)
	if v.Incidents[0].Detail != "core link a-to-b has no reply" {
		t.Fatalf("incident = %+v", v.Incidents)
	}
}

func TestIXPSitesStalePeerIsAttributedByTheCoreLinkToIt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		link   plugin.CoreLinkStatus
		detail string
	}{
		{"core bad", link("a-to-b", "site-b", 100, 0, true), "the core link from site-a is degraded, so the site or the core is down"},
		{"core good", link("a-to-b", "site-b", 0, 3, false), "the core link from site-a is healthy, so the site's instance or federation is down"},
	} {
		x := healthyIXP()
		x.Core = []plugin.CoreLinkStatus{tc.link}
		v := IXPSites(ixpCfg(), localSnap(x), []plugin.PeerState{stale("site-b", "connection refused")})
		b := site(t, v, "site-b")
		if b.Status != StatusUnreachable || b.Fresh || len(b.PastTolerance) != 0 {
			t.Fatalf("%s: site-b = %+v", tc.name, b)
		}
		var got []SiteIncident
		for _, in := range v.Incidents {
			if in.Scope == ScopeSite {
				got = append(got, in)
			}
		}
		want := "no fresh federation snapshot (connection refused); " + tc.detail
		if len(got) != 1 || got[0].Site != "site-b" || got[0].Detail != want {
			t.Fatalf("%s: site incidents = %+v, want %q", tc.name, got, want)
		}
	}

	v := IXPSites(ixpCfg(), localSnap(healthyIXP()), []plugin.PeerState{stale("site-b", "")})
	if d := v.Incidents[0].Detail; d != "no fresh federation snapshot; no core link measures this site" {
		t.Fatalf("detail = %q", d)
	}
}

func TestIXPSitesIgnoresAStalePeersOldData(t *testing.T) {
	old := plugin.PeerState{Name: "site-b", Fresh: false, LastSeen: t0.Add(-time.Hour),
		Snapshot: plugin.InstanceSnapshot{Instance: "site-b", Domain: "site-b", IXP: &plugin.FederatedIXP{
			Core: []plugin.CoreLinkStatus{link("b-to-a", "site-a", 0, 3, false)}, Members: []plugin.FabricPath{path(64496, 90, 500, true)}}}}
	v := IXPSites(ixpCfg(), localSnap(healthyIXP()), []plugin.PeerState{old})
	if len(v.Links) != 0 {
		t.Fatalf("a stale peer's links are listed: %+v", v.Links)
	}
	if b := site(t, v, "site-b"); b.Members != 0 || b.Status != StatusUnreachable {
		t.Fatalf("site-b = %+v", b)
	}
}

func TestIXPSitesNoDataAndBeforeFirstPublish(t *testing.T) {
	v := IXPSites(ixpCfg(), nil, []plugin.PeerState{fresh1("site-b", nil)})
	for _, n := range []string{"site-a", "site-b"} {
		if s := site(t, v, n); s.Status != StatusNoData || !s.Fresh || s.PastTolerance == nil {
			t.Fatalf("%s = %+v", n, s)
		}
	}
	if len(v.Incidents) != 0 {
		t.Fatalf("incidents = %+v", v.Incidents)
	}
}
