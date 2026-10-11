package plugin

import "net/netip"

// KindLeakSource is the leak watch extension point (#199).
const KindLeakSource Kind = "leak_source"

// LeakSources holds the leak source plugin types.
var LeakSources = NewRegistry[LeakSource](KindLeakSource)

// LeakSighting is one route announcement seen outside Packeteer's iBGP
// sessions: in a public collector, in an outside router's Adj-RIB-In, or
// in the Adj-RIB-Out of the operator's own router toward an eBGP peer.
type LeakSighting struct {
	Prefix netip.Prefix
	// ASPath is the path as seen, left to right, with AS_SETs flattened.
	ASPath []uint32
	// Communities are RFC 1997 communities as asn<<16|value.
	Communities []uint32
	// LargeCommunities are RFC 8092 communities, "global:data1:data2".
	LargeCommunities []string
	// Seen names the vantage point: a collector peer or a router address.
	Seen string
	// OurExport is set when the sighting is the operator's own router
	// sending the route to an eBGP peer. Routers differ on whether the
	// local ASN is already in such a path, so only the Packeteer community
	// marks it as a leak.
	OurExport bool
}

// LeakSource reports sightings to the sink set before Start. The sink
// never blocks and may be called from any goroutine. A leak source only
// reads: it cannot announce, and it cannot name a route to withdraw. The
// core decides from the sighting which of its own routes to hold out. It
// is in-process only, because its output ends a route.
type LeakSource interface {
	Lifecycle
	SetLeakSink(func(LeakSighting))
	// Healthy reports whether the feed is connected now. A feed that is
	// down or has not connected yet is unknown, not clean.
	Healthy() bool
}
