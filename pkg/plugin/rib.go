package plugin

import "net/netip"

// KindRIBSource is the extension point for route feeds outside the iBGP
// session (BMP, #26).
const KindRIBSource Kind = "rib_source"

// RIBEventKind says what a RIBEvent reports.
type RIBEventKind int

// RIB event kinds.
const (
	// RIBRouterDown: the monitoring session to Router is gone. Every path
	// learned from that router is dropped.
	RIBRouterDown RIBEventKind = iota
	// RIBPeerUp: Router reports a BGP session to Peer is up.
	RIBPeerUp
	// RIBPeerDown: Router reports the session to Peer is down (or its data
	// can no longer be trusted). Every path from that peer is dropped.
	RIBPeerDown
	// RIBPaths: announcements and withdrawals from Peer's Adj-RIB-In (or
	// the router's Loc-RIB when Peer.LocRIB is set).
	RIBPaths
)

// RIBPeer is one BGP session on a monitored router, or its Loc-RIB.
type RIBPeer struct {
	// Address is the router's BGP neighbor (a transit or IX peer). It is
	// unset for a Loc-RIB.
	Address netip.Addr
	ASN     uint32
	// BGPID is the peer's BGP identifier. The RIB view ignores a peer whose
	// BGPID is Packeteer's own router ID: that is Packeteer's iBGP session,
	// and its paths are Packeteer's injected routes.
	BGPID netip.Addr
	// LocRIB marks the router's own selected routes (BMP peer type 3,
	// RFC 9069) rather than one neighbor's Adj-RIB-In.
	LocRIB bool
}

// RIBPath is one path for a prefix. Withdraw removes the prefix from that
// peer.
type RIBPath struct {
	Prefix  netip.Prefix
	NextHop netip.Addr
	ASPath  []uint32
	// Communities are the RFC 1997 communities, as uint32 (asn<<16|value).
	// A path tagged with packeteer_community is Packeteer's own route and
	// is ignored by the RIB view.
	Communities []uint32
	Withdraw    bool
}

// RIBEvent is one change reported by a RIB source.
type RIBEvent struct {
	Kind   RIBEventKind
	Router netip.Addr // the monitored edge router
	Peer   RIBPeer    // unset for RIBRouterDown
	Paths  []RIBPath  // RIBPaths only
}

// RIBSource feeds routes the edge routers learned into the RIB view. It is
// learn-only and in-process only: it never announces, and an out-of-process
// plugin cannot be one. SetRIBSink is called once before Start. Events from
// one router must be delivered in order. When a router's session ends the
// source must send RIBRouterDown so its paths do not go stale.
type RIBSource interface {
	Lifecycle
	SetRIBSink(func(RIBEvent))
}

// RIBSources is the registry for RIB source plugins.
var RIBSources = NewRegistry[RIBSource](KindRIBSource)
