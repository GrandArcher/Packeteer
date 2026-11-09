package herd

import (
	"net/netip"
	"slices"
)

// Route is one learned route that went into a record: the exact prefix in
// the RIB view, the local provider it was probed through, the AS path
// learned through that provider as the RIB holds it, and the types of the
// target sources that listed it. A node keeps the routes behind each of its
// own records (never served) so the RIB check, the exclude list, and the
// source opt-in apply to data stored earlier.
type Route struct {
	Prefix   netip.Prefix `json:"prefix"`
	Provider string       `json:"provider,omitempty"`
	Path     []uint32     `json:"path,omitempty"`
	Sources  []string     `json:"sources,omitempty"`
}

// neverShare is address space that no record may name: default routes,
// private, loopback, link-local, multicast, and unspecified space.
var neverShare = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/8"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// Shareable reports whether p may appear in a record at all: not a default
// route, and not equal to or inside never-shared space.
func Shareable(p netip.Prefix) bool {
	if !p.IsValid() || p.Bits() == 0 {
		return false
	}
	p = p.Masked()
	return !slices.ContainsFunc(neverShare, func(n netip.Prefix) bool {
		return p.Addr().Is4() == n.Addr().Is4() && p.Bits() >= n.Bits() && n.Contains(p.Addr())
	})
}

// overlaps reports whether a and b are equal, or one holds the other.
func overlaps(a, b netip.Prefix) bool {
	a, b = a.Masked(), b.Masked()
	if a.Addr().Is4() != b.Addr().Is4() {
		return false
	}
	return a.Contains(b.Addr()) || b.Contains(a.Addr())
}

// asnShared reports whether an AS number may be named in a record. Private
// use and reserved numbers are stripped. Documentation numbers are kept so
// that a lab, which may use only those, can run; they occur on no real path.
func asnShared(a uint32) bool {
	switch {
	case a == 0, a == 23456, a == 65535, a == 4294967295:
		return false
	case a >= 64512 && a <= 65534:
		return false
	case a >= 65552 && a <= 131071:
		return false
	case a >= 4200000000:
		return false
	}
	return true
}

// publicPath removes private-use and reserved ASNs from path. Prepends of
// the remaining ASNs stay as learned.
func publicPath(path []uint32) []uint32 {
	out := make([]uint32, 0, len(path))
	for _, a := range path {
		if asnShared(a) {
			out = append(out, a)
		}
	}
	return out
}

// Rules decide which routes may be shared. They are applied before a
// record is written and again when one is served.
type Rules struct {
	// Prefixes are the operator's exclude prefixes and its own and its
	// customers' prefixes (inbound prefixes, flow transit customers, span
	// local). Each excludes every route equal to, inside, or covering it.
	Prefixes []netip.Prefix
	ASNs     map[uint32]bool
	// Sources are the target source types that may produce shared records.
	Sources map[string]bool
}

// Allowed reports whether rt may be shared. A route is shared only when it
// is shareable space, matches no excluded prefix or ASN (anywhere in its
// AS path), and at least one source that listed it is opted in.
func (r *Rules) Allowed(rt Route) bool {
	if !Shareable(rt.Prefix) {
		return false
	}
	for _, p := range r.Prefixes {
		if overlaps(rt.Prefix, p) {
			return false
		}
	}
	for _, a := range rt.Path {
		if r.ASNs[a] {
			return false
		}
	}
	return slices.ContainsFunc(rt.Sources, func(s string) bool { return r.Sources[s] })
}
