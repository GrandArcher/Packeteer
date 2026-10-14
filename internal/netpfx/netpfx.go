// Package netpfx holds small prefix and AS number helpers shared by the
// routing packages.
package netpfx

import (
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// ParseASN reads an AS number written as 64500 or AS64500, ignoring case and
// surrounding space. Zero is not an AS number.
func ParseASN(s string) (uint32, bool) {
	n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), "AS"), 10, 32)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint32(n), true
}

// LastAS is the origin of an AS path, or 0 for an empty path.
func LastAS(path []uint32) uint32 {
	if len(path) == 0 {
		return 0
	}
	return path[len(path)-1]
}

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

// Match reports how p relates to the searched prefix q (empty when q is
// invalid or only an origin matched), and whether the row belongs to a
// search at all: p relates to q, or one of its origins is in asns.
func Match(q netip.Prefix, asns []uint32, p netip.Prefix, origins ...uint32) (string, bool) {
	rel := ""
	if q.IsValid() {
		rel = Relation(q, p)
	}
	if rel != "" {
		return rel, true
	}
	for _, o := range origins {
		if o != 0 && slices.Contains(asns, o) {
			return "", true
		}
	}
	return "", false
}
