package plugin

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// KindIRR is the extension point for IRR sources (#214). A source answers
// route/route6, as-set, and aut-num lookups from an IRR server or a local
// file. It is read-only: it never announces and never changes the learned
// RIB.
const KindIRR Kind = "irr"

// IRRState is whether a path's origin is registered in the IRR.
type IRRState string

// IRR states.
const (
	// IRRRegistered: a route or route6 object for exactly the prefix
	// names the origin AS (for an as-set: the origin is a member).
	IRRRegistered IRRState = "registered"
	// IRRNotRegistered: every source answered and none has such an object.
	IRRNotRegistered IRRState = "not_registered"
	// IRRUnknown: no usable answer (no source answered, data past the
	// staleness limit, or IRR is off). It is the fail-open state.
	IRRUnknown IRRState = "unknown"
)

// IRRRoute is one route or route6 object.
type IRRRoute struct {
	Prefix netip.Prefix
	Origin uint32
	// Database is the object's RPSL source attribute (RADB, RIPE, ...).
	// Empty when the data does not say (a bgpq4 file).
	Database string
}

// ErrIRRUnsupported is returned by a source for a lookup its data cannot
// answer (a bgpq4 file has no as-set or aut-num objects). The source is
// left out of that answer instead of making it unknown.
var ErrIRRUnsupported = errors.New("irr: lookup not served by this source")

// IRR answers IRR lookups. Each returns the data time: the query time for
// a server, the file time for a local file. Not found is an empty answer
// and a nil error; an error means the source did not answer.
type IRR interface {
	Lifecycle
	// Routes returns the route and route6 objects whose prefix is exactly
	// prefix.
	Routes(ctx context.Context, prefix netip.Prefix) ([]IRRRoute, time.Time, error)
	// ASSetMembers returns the AS numbers in an as-set, expanded
	// recursively.
	ASSetMembers(ctx context.Context, name string) ([]uint32, time.Time, error)
	// ASName returns the as-name of the aut-num object for asn, empty
	// when there is none.
	ASName(ctx context.Context, asn uint32) (string, time.Time, error)
}

// IRRAnswer is the IRR view of one path: the origin's registration for
// the prefix and the data behind it.
type IRRAnswer struct {
	State IRRState
	// Source is the irr.sources entry that answered: the first one with a
	// matching object, else the first that answered. Empty when unknown.
	Source string
	// Database is the RPSL source of the matching object.
	Database string
	// Updated is the data time of the answer; for not_registered the
	// oldest among the sources.
	Updated time.Time
	// Origins are the origin ASes registered for the prefix, sorted.
	Origins []uint32
	// ASSet is the provider's as-set from irr.as_sets, and ASSetState
	// whether the origin is a member. Empty when none is configured.
	ASSet      string
	ASSetState IRRState
	// OriginName is the as-name of the origin's aut-num object. Empty when
	// there is none or no source answered.
	OriginName string
}

// IRRs is the registry for IRR sources.
var IRRs = NewRegistry[IRR](KindIRR)
