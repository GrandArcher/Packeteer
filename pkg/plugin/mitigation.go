package plugin

import (
	"context"
	"net/netip"
	"slices"
)

// ---- Mitigation announcer ----

// Mitigation actions (#28).
const (
	// MitigationBlackhole is RTBH: the route carries the blackhole
	// communities (RFC 7999 BLACKHOLE by default) and the announcer's
	// discard next hop, so the edge drops traffic toward the prefix.
	MitigationBlackhole = "blackhole"
	// MitigationRedirect is BGP redirect: the route points at a named
	// target's next hop (a scrubbing center or sinkhole) with that
	// target's communities.
	MitigationRedirect = "redirect"
)

// MitigationTarget is a named redirect destination from the announcer's
// catalog.
type MitigationTarget struct {
	Name        string     `json:"name"`
	NextHop     netip.Addr `json:"next_hop"`
	Communities []string   `json:"communities,omitempty"`
}

// MitigationCatalog is what a mitigation announcer can announce.
type MitigationCatalog struct {
	// Blackhole is true when RTBH is configured. BlackholeNextHops are its
	// discard next hops (one IPv4, optionally one IPv6).
	Blackhole            bool         `json:"blackhole"`
	BlackholeNextHops    []netip.Addr `json:"blackhole_next_hops,omitempty"`
	BlackholeCommunities []string     `json:"blackhole_communities,omitempty"`
	// Targets are the redirect targets, sorted by name.
	Targets []MitigationTarget `json:"targets"`
}

// Target returns the redirect target called name.
func (c MitigationCatalog) Target(name string) (MitigationTarget, bool) {
	for _, t := range c.Targets {
		if t.Name == name {
			return t, true
		}
	}
	return MitigationTarget{}, false
}

// NextHops lists every next hop the catalog can put on a route, sorted.
// The core refuses a catalog that reuses a provider's next hop.
func (c MitigationCatalog) NextHops() []netip.Addr {
	out := slices.Clone(c.BlackholeNextHops)
	for _, t := range c.Targets {
		out = append(out, t.NextHop)
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

// MitigationRoute asks the edge to blackhole or redirect one prefix.
// Prefix must be the exact prefix learned from the RIB; the core checks
// that before it calls Announce.
type MitigationRoute struct {
	Prefix netip.Prefix
	// Action is MitigationBlackhole or MitigationRedirect.
	Action string
	// Target names a catalog entry. Required for redirect, empty for
	// blackhole.
	Target    string
	LocalPref uint32
	// Community is the configured packeteer community. It is required.
	Community string
}

// MitigationAnnouncer publishes RTBH and redirect routes. Like Announcer it
// runs in-process only: an out-of-process plugin must never inject routes.
// Every route carries the packeteer community, the announcer's marker, and
// NO_EXPORT. It must enforce its own allowlist and rule cap (given when it
// is bound), withdraw everything on Stop, and must not use graceful
// restart.
type MitigationAnnouncer interface {
	Lifecycle
	// Catalog describes the configured actions. It does not change after
	// the factory returns.
	Catalog() MitigationCatalog
	// Announce advertises r, replacing any mitigation route for the same
	// prefix in place.
	Announce(ctx context.Context, r MitigationRoute) error
	Withdraw(ctx context.Context, p netip.Prefix) error
	WithdrawAll(ctx context.Context) error
}

// MitigationAnnouncers is the registry for mitigation announcers (kind
// announcer). There is no exec type: mitigation routes are injected routes.
var MitigationAnnouncers = NewRegistry[MitigationAnnouncer](KindAnnouncer)
