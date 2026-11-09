package plugin

import (
	"context"
	"net/netip"
)

// Kinds for the non-BGP mode (#300).
const (
	// KindSteerer is the router driver of a site whose router has no BGP:
	// it installs static routes through the router's API or on this host.
	KindSteerer Kind = "steerer"
	// KindCovering finds the prefix the Internet announces for an address.
	KindCovering Kind = "covering"
)

// Global registries for the non-BGP mode.
var (
	Steerers  = NewRegistry[Steerer](KindSteerer)
	Coverings = NewRegistry[Covering](KindCovering)
)

// SteerRoute is one static route: traffic to Prefix leaves through
// NextHop, the gateway of Provider. Everything else stays on the router's
// default route.
type SteerRoute struct {
	Prefix   netip.Prefix
	NextHop  netip.Addr
	Provider string
}

// Steerer installs static routes on a router that has no BGP session with
// Packeteer. Steerers run in-process only, like announcers: an
// out-of-process plugin must never change a router's routes.
//
// Every route a Steerer installs carries a tag the router keeps (a comment
// or a protocol number), so Owned finds them again, including those left by
// a previous process that died without withdrawing. A Steerer must touch
// no route without that tag.
type Steerer interface {
	Lifecycle
	// Install adds the route, or replaces the tagged route for the same
	// prefix.
	Install(ctx context.Context, r SteerRoute) error
	// Remove deletes the tagged route for p. A route that is already gone
	// is not an error.
	Remove(ctx context.Context, p netip.Prefix) error
	// Owned lists the tagged routes now on the router.
	Owned(ctx context.Context) ([]netip.Prefix, error)
}

// Announced is a prefix announced on the Internet and its origin AS.
type Announced struct {
	Prefix netip.Prefix
	// Origin is the origin AS, or 0 when the data names none or several.
	Origin uint32
}

// Covering answers with the prefix announced on the Internet that contains
// addr (RIS or RouteViews data, or a registry), the upper bound for a
// synthetic route. It is read-only and must not announce.
type Covering interface {
	Lifecycle
	// Covering returns the announced prefix containing addr, or an error
	// when none is known.
	Covering(ctx context.Context, addr netip.Addr) (Announced, error)
}
