package plugin

import (
	"net/netip"
	"time"
)

// KindRPKI is the extension point for RPKI origin-validation sources
// (#158). A source validates the origin AS of a learned path against
// validated ROA payloads. It is read-only: it never announces and never
// changes the learned RIB.
const KindRPKI Kind = "rpki"

// RPKIValidity is the RFC 6811 origin-validation state of one path.
type RPKIValidity string

// Origin-validation states.
const (
	// RPKIValid: a VRP covers the prefix and its ASN matches the origin.
	RPKIValid RPKIValidity = "valid"
	// RPKIInvalid: a VRP covers the prefix but none matches the origin.
	RPKIInvalid RPKIValidity = "invalid"
	// RPKINotFound: no VRP covers the prefix.
	RPKINotFound RPKIValidity = "notfound"
	// RPKIUnknown: no usable data (the source is down or stale, or RPKI
	// is off). It is the fail-open state.
	RPKIUnknown RPKIValidity = "unknown"
)

// RPKIStatus is the health of one origin-validation source.
type RPKIStatus struct {
	// Source is the source's instance name.
	Source string
	// Up is true after the cache completed a fetch and false while it is
	// disconnected.
	Up bool
	// Stale is true when no fresh cache is available: never fetched, or
	// older than the source's staleness limit.
	Stale bool
	// VRPs is the number of validated ROA payloads in the cache.
	VRPs int
	// Updated is when the cache last completed a fetch.
	Updated time.Time
	// Error is the last fetch error, empty when healthy.
	Error string
}

// RPKIAnswer is one origin-validation state and the data behind it, so a
// caller can show which source answered and how old its data was.
type RPKIAnswer struct {
	State RPKIValidity
	// Source is the instance name of the source that answered; empty when
	// none had usable data.
	Source string
	// Updated is when that source last completed a fetch.
	Updated time.Time
}

// RPKI validates the origin AS of a prefix. It is read-only and in-process.
// An implementation returns RPKIUnknown when it has no fresh data, so a
// caller can fall back to another source and fail open.
type RPKI interface {
	Lifecycle
	// Validate returns the origin-validation state of origin for prefix.
	Validate(prefix netip.Prefix, origin uint32) RPKIValidity
	// Status reports the source's health.
	Status() RPKIStatus
}

// RPKIs is the registry for origin-validation plugins.
var RPKIs = NewRegistry[RPKI](KindRPKI)
