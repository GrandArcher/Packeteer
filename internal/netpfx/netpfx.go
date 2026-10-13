// Package netpfx holds small netip.Prefix helpers shared by the routing
// packages.
package netpfx

import (
	"net/netip"
	"sort"
)

// Less orders prefixes by address, then by prefix length.
func Less(a, b netip.Prefix) bool {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c < 0
	}
	return a.Bits() < b.Bits()
}

// Sort sorts ps in place by Less.
func Sort(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool { return Less(ps[i], ps[j]) })
}

// CoveredBy reports whether p equals or falls inside a prefix in list.
func CoveredBy(list []netip.Prefix, p netip.Prefix) bool {
	for _, a := range list {
		if a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// How a prefix relates to a searched one (Relation).
const (
	RelExact        = "exact"
	RelCovering     = "covering"
	RelMoreSpecific = "more-specific"
)

// Relation says how p relates to the searched prefix q: equal, a covering
// prefix of q, or a more specific inside q. It is "" for an unrelated
// prefix or one of the other address family. A default route is not a
// covering match, since it would match every search.
func Relation(q, p netip.Prefix) string {
	q, p = q.Masked(), p.Masked()
	switch {
	case p == q:
		return RelExact
	case p.Bits() > 0 && p.Bits() < q.Bits() && p.Contains(q.Addr()):
		return RelCovering
	case p.Bits() > q.Bits() && q.Contains(p.Addr()):
		return RelMoreSpecific
	}
	return ""
}
