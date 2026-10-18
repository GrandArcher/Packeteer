package federation

import (
	"fmt"
	"strconv"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// IXPInput is the state of this site's IXP sources. A source that is not
// configured is its zero view.
type IXPInput struct {
	Fabric      plugin.FabricView
	Correlation plugin.CorrelationView
	RouteServer plugin.RouteServerView
	Core        plugin.CoreView
}

// IXPSnapshot reduces an IXP-mode site's views to what it publishes to
// its peers (#167). It reads views only and announces nothing.
func IXPSnapshot(in IXPInput) *plugin.FederatedIXP {
	x := &plugin.FederatedIXP{
		Round: in.Fabric.Round, Stale: in.Fabric.Stale,
		Vantages: in.Fabric.Vantages, Members: plugin.WorstFabricPaths(in.Fabric.Samples),
		Groups: in.Correlation.Groups, Core: in.Core.Links,
		RouteServers: len(in.RouteServer.Servers),
	}
	for _, s := range in.RouteServer.Servers {
		if !s.Up {
			x.RouteServersDown++
		}
	}
	if x.Vantages == nil {
		x.Vantages = []plugin.FabricVantageStatus{}
	}
	if x.Groups == nil {
		x.Groups = []plugin.CorrelationGroup{}
	}
	if x.Core == nil {
		x.Core = []plugin.CoreLinkStatus{}
	}
	return x
}

// Site statuses.
const (
	StatusOK          = "ok"
	StatusDegraded    = "degraded"
	StatusUnreachable = "unreachable"
	// StatusNoData is a fresh peer that publishes no IXP data.
	StatusNoData = "no_data"
)

// Incident scopes.
const (
	ScopeFabric      = "fabric"
	ScopeVantage     = "vantage"
	ScopeRouteServer = "route_server"
	ScopeCore        = "core"
	ScopeSite        = "site"
)

// SiteHealth is one site in the sites view.
type SiteHealth struct {
	Name     string    `json:"name"`
	Domain   string    `json:"domain,omitempty"`
	Self     bool      `json:"self"`
	Fresh    bool      `json:"fresh"`
	LastSeen time.Time `json:"last_seen,omitzero"`
	Error    string    `json:"error,omitempty"`
	Status   string    `json:"status"`
	// Round is the site's fabric round, on this instance's clock.
	Round            time.Time `json:"round,omitzero"`
	Members          int       `json:"members_measured"`
	MembersPast      int       `json:"members_past_tolerance"`
	Vantages         int       `json:"vantages"`
	VantagesUp       int       `json:"vantages_up"`
	RouteServers     int       `json:"route_servers"`
	RouteServersDown int       `json:"route_servers_down"`
	// PastTolerance lists the member paths past tolerance, in the order
	// the site published them (ASN, VLAN, vantage, family).
	PastTolerance []plugin.FabricPath `json:"past_tolerance"`
}

// SiteLink is a core link measured from one site to another.
type SiteLink struct {
	Site string `json:"site"`
	plugin.CoreLinkStatus
}

// SiteIncident says where something is wrong. Site is the site it is at;
// for a core link it is the site that measured it and Peer is the other
// end. Scope is one of the Scope constants.
type SiteIncident struct {
	Site   string `json:"site"`
	Peer   string `json:"peer,omitempty"`
	Scope  string `json:"scope"`
	Detail string `json:"detail"`
}

// IXPSitesView is the multi-site fabric health view (#167): this site and
// every federation peer, the core links each measured, and where the
// incidents are.
type IXPSitesView struct {
	Enabled   bool           `json:"enabled"`
	Sites     []SiteHealth   `json:"sites"`
	Links     []SiteLink     `json:"links"`
	Incidents []SiteIncident `json:"incidents"`
}

// IXPSites builds the sites view from this site's published snapshot and
// the peers' last snapshots. A stale peer's data is not used: it is
// reported unreachable, and the core links other sites measure to it say
// whether the site or its federation is the problem.
func IXPSites(cfg Config, local *plugin.InstanceSnapshot, peers []plugin.PeerState) IXPSitesView {
	v := IXPSitesView{Enabled: true, Sites: []SiteHealth{}, Links: []SiteLink{}, Incidents: []SiteIncident{}}
	type site struct {
		health SiteHealth
		ixp    *plugin.FederatedIXP
	}
	self := site{health: SiteHealth{Name: cfg.Instance, Domain: cfg.Domain, Self: true, Fresh: true}}
	if local != nil {
		self.health.LastSeen, self.ixp = local.Time, local.IXP
	}
	sites := []site{self}
	for _, p := range peers {
		h := SiteHealth{Name: p.Name, Domain: p.Snapshot.Domain, Fresh: p.Fresh, LastSeen: p.LastSeen, Error: p.Error}
		var x *plugin.FederatedIXP
		if p.Fresh {
			x = p.Snapshot.IXP
		}
		sites = append(sites, site{h, x})
	}

	for i := range sites {
		s := &sites[i]
		h := &s.health
		if !h.Fresh {
			h.Status = StatusUnreachable
			h.PastTolerance = []plugin.FabricPath{}
			continue
		}
		x := s.ixp
		if x == nil {
			h.Status = StatusNoData
			h.PastTolerance = []plugin.FabricPath{}
			continue
		}
		h.Round = x.Round
		h.Vantages, h.RouteServers, h.RouteServersDown = len(x.Vantages), x.RouteServers, x.RouteServersDown
		h.PastTolerance = []plugin.FabricPath{}
		measured, past := map[uint32]bool{}, map[uint32]bool{}
		for _, m := range x.Members {
			measured[m.ASN] = true
			if m.PastTolerance {
				past[m.ASN] = true
				h.PastTolerance = append(h.PastTolerance, m)
			}
		}
		h.Members, h.MembersPast = len(measured), len(past)
		before := len(v.Incidents)
		if x.Stale {
			v.Incidents = append(v.Incidents, SiteIncident{Site: h.Name, Scope: ScopeFabric, Detail: "member list is stale, so the fabric is not probed"})
		}
		for _, vt := range x.Vantages {
			h.VantagesUp += b2i(vt.Up)
			if !vt.Up && !x.Stale {
				d := "vantage " + vt.Name + " is down"
				if vt.Error != "" {
					d += ": " + vt.Error
				}
				v.Incidents = append(v.Incidents, SiteIncident{Site: h.Name, Scope: ScopeVantage, Detail: d})
			}
		}
		for _, g := range x.Groups {
			if g.Active {
				v.Incidents = append(v.Incidents, SiteIncident{Site: h.Name, Scope: ScopeFabric,
					Detail: fmt.Sprintf("%s %s: %d of %d members degraded", g.Scope, g.Name, g.Degraded, g.Members)})
			}
		}
		if x.RouteServersDown > 0 {
			v.Incidents = append(v.Incidents, SiteIncident{Site: h.Name, Scope: ScopeRouteServer,
				Detail: fmt.Sprintf("%d of %d route servers are not answering", x.RouteServersDown, x.RouteServers)})
		}
		h.Status = StatusOK
		if len(v.Incidents) > before {
			h.Status = StatusDegraded
		}
		for _, l := range x.Core {
			v.Links = append(v.Links, SiteLink{Site: h.Name, CoreLinkStatus: l})
			if l.Degraded {
				v.Incidents = append(v.Incidents, SiteIncident{Site: h.Name, Peer: l.Peer, Scope: ScopeCore, Detail: coreDetail(l)})
			}
		}
	}
	for _, s := range sites {
		if !s.health.Fresh {
			v.Incidents = append(v.Incidents, SiteIncident{Site: s.health.Name, Scope: ScopeSite, Detail: unreachableDetail(s.health, v.Links)})
		}
		v.Sites = append(v.Sites, s.health)
	}
	return v
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func coreDetail(l plugin.CoreLinkStatus) string {
	switch {
	case l.Error != "":
		return "core link " + l.Name + " could not be probed: " + l.Error
	case !l.Up:
		return "core link " + l.Name + " has no reply"
	}
	return fmt.Sprintf("core link %s: loss %s%%, RTT %s ms", l.Name, strconv.FormatFloat(l.LossPct, 'f', -1, 64), strconv.FormatFloat(l.RTTMs, 'f', 2, 64))
}

// unreachableDetail says what the other sites' core links show about a
// site that has no fresh snapshot: a bad core link to it points at the
// site or the core, a good one points at its instance or federation.
func unreachableDetail(h SiteHealth, links []SiteLink) string {
	d := "no fresh federation snapshot"
	if h.Error != "" {
		d += " (" + h.Error + ")"
	}
	var seen, bad []string
	for _, l := range links {
		if l.Peer != h.Name {
			continue
		}
		seen = append(seen, l.Site)
		if l.Degraded {
			bad = append(bad, l.Site)
		}
	}
	switch {
	case len(seen) == 0:
		return d + "; no core link measures this site"
	case len(bad) > 0:
		return d + fmt.Sprintf("; the core link from %s is degraded, so the site or the core is down", bad[0])
	}
	return d + fmt.Sprintf("; the core link from %s is healthy, so the site's instance or federation is down", seen[0])
}
