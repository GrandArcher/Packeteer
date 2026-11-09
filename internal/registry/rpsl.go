package registry

import (
	"fmt"
	"net/netip"
	"strings"
)

// routeObject is the RPSL text of a route or route6 object. mntBy is left
// out when empty.
func routeObject(p netip.Prefix, origin uint32, source, mntBy string) string {
	class := "route"
	if p.Addr().Is6() {
		class = "route6"
	}
	var b strings.Builder
	attr := func(name, value string) { fmt.Fprintf(&b, "%-16s%s\n", name+":", value) }
	attr(class, p.String())
	attr("descr", fmt.Sprintf("Announced by AS%d", origin))
	attr("origin", fmt.Sprintf("AS%d", origin))
	if mntBy != "" {
		attr("mnt-by", mntBy)
	}
	attr("source", source)
	return b.String()
}

// routeKey is the primary key of a route object: the prefix followed by
// the origin, as the RIPE database writes it.
func routeKey(p netip.Prefix, origin uint32) string {
	return fmt.Sprintf("%sAS%d", p, origin)
}

// asSetMember is the RPSL lines that add or remove one member of an as-set.
func asSetMember(set string, asn uint32, add bool) string {
	sign := "+"
	if !add {
		sign = "-"
	}
	return fmt.Sprintf("as-set: %s\n%s members: AS%d\n", set, sign, asn)
}
