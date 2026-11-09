package plugin

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
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

// ---- FlowSpec (#28, second half) ----

// FlowSpec actions. A FlowSpec rule (RFC 8955) matches traffic toward an
// exact learned prefix, optionally narrowed by source, protocol, and ports,
// and tells the edge to drop it, rate-limit it, or redirect it to a VRF.
const (
	// MitigationFlowSpecDrop sets traffic-rate 0: the edge discards
	// matching packets.
	MitigationFlowSpecDrop = "flowspec_drop"
	// MitigationFlowSpecRateLimit sets traffic-rate to the rule's rate.
	MitigationFlowSpecRateLimit = "flowspec_rate_limit"
	// MitigationFlowSpecRedirect sets a redirect route target from the
	// announcer's catalog: the edge forwards matching packets into the VRF
	// that imports it (a scrubbing VRF).
	MitigationFlowSpecRedirect = "flowspec_redirect"
)

// IsFlowSpec reports whether action is a FlowSpec action.
func IsFlowSpec(action string) bool {
	switch action {
	case MitigationFlowSpecDrop, MitigationFlowSpecRateLimit, MitigationFlowSpecRedirect:
		return true
	}
	return false
}

// FlowSpec match bounds. They keep one NLRI small and readable on the edge.
const (
	MaxFlowSpecProtocols = 8
	MaxFlowSpecPorts     = 8
	// MaxFlowSpecRateMbps bounds a rate limit (100 Gbit/s).
	MaxFlowSpecRateMbps = 100000
)

// FlowSpecTarget is a named FlowSpec redirect: a route target
// ("asn:value", two-octet AS) that the edge maps to a VRF.
type FlowSpecTarget struct {
	Name        string `json:"name"`
	RouteTarget string `json:"route_target"`
}

// FlowSpecCatalog is the FlowSpec part of a mitigation catalog.
type FlowSpecCatalog struct {
	// Enabled is true when the announcer publishes FlowSpec (drop and
	// rate-limit are then always available).
	Enabled bool `json:"enabled"`
	// Targets are the FlowSpec redirect targets, sorted by name.
	Targets []FlowSpecTarget `json:"targets"`
}

// Target returns the FlowSpec redirect target called name.
func (c FlowSpecCatalog) Target(name string) (FlowSpecTarget, bool) {
	for _, t := range c.Targets {
		if t.Name == name {
			return t, true
		}
	}
	return FlowSpecTarget{}, false
}

// PortRange is one port or an inclusive range. As text it is "53" or
// "1000-2000".
type PortRange struct {
	From, To uint16
}

// String is the text form.
func (r PortRange) String() string {
	if r.From == r.To {
		return strconv.Itoa(int(r.From))
	}
	return strconv.Itoa(int(r.From)) + "-" + strconv.Itoa(int(r.To))
}

// MarshalText implements encoding.TextMarshaler.
func (r PortRange) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (r *PortRange) UnmarshalText(b []byte) error {
	lo, hi, rng := strings.Cut(strings.TrimSpace(string(b)), "-")
	from, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	if err != nil {
		return fmt.Errorf("port %q: want 0-65535 or a range like 1000-2000", string(b))
	}
	to := from
	if rng {
		if to, err = strconv.ParseUint(strings.TrimSpace(hi), 10, 16); err != nil || to < from {
			return fmt.Errorf("port range %q: want low-high with low <= high <= 65535", string(b))
		}
	}
	*r = PortRange{From: uint16(from), To: uint16(to)}
	return nil
}

// UnmarshalJSON accepts a string ("53", "1000-2000") or a number (53).
func (r *PortRange) UnmarshalJSON(b []byte) error { return r.UnmarshalText(jsonScalar(b)) }

// jsonScalar is a JSON string's contents, or a bare number as is.
func jsonScalar(b []byte) []byte {
	if len(b) >= 2 && b[0] == '"' && b[len(b)-1] == '"' {
		return b[1 : len(b)-1]
	}
	return b
}

// IPProtocol is an IP protocol number. As text it is a name (tcp, udp,
// icmp, icmpv6, gre, esp, ah, sctp) or a number 0-255.
type IPProtocol uint8

var protocolNames = map[string]IPProtocol{"icmp": 1, "tcp": 6, "udp": 17, "gre": 47, "esp": 50, "ah": 51, "icmpv6": 58, "sctp": 132}

// String is the name when there is one, else the number.
func (p IPProtocol) String() string {
	for n, v := range protocolNames {
		if v == p {
			return n
		}
	}
	return strconv.Itoa(int(p))
}

// MarshalText implements encoding.TextMarshaler.
func (p IPProtocol) MarshalText() ([]byte, error) { return []byte(p.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (p *IPProtocol) UnmarshalText(b []byte) error {
	s := strings.ToLower(strings.TrimSpace(string(b)))
	if v, ok := protocolNames[s]; ok {
		*p = v
		return nil
	}
	n, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return fmt.Errorf("protocol %q: want a name (tcp, udp, icmp, ...) or 0-255", string(b))
	}
	*p = IPProtocol(n)
	return nil
}

// UnmarshalJSON accepts a string ("udp", "17") or a number (17).
func (p *IPProtocol) UnmarshalJSON(b []byte) error { return p.UnmarshalText(jsonScalar(b)) }

// FlowSpecMatch narrows a FlowSpec rule beyond its destination prefix.
// Every set field must match (AND); within a list any entry matches (OR).
// A zero match is all traffic toward the destination.
type FlowSpecMatch struct {
	Source           netip.Prefix `json:"source,omitzero"`
	Protocols        []IPProtocol `json:"protocols,omitempty"`
	DestinationPorts []PortRange  `json:"destination_ports,omitempty"`
	SourcePorts      []PortRange  `json:"source_ports,omitempty"`
}

// Normalize sorts and de-duplicates the lists, so equal matches have
// equal keys.
func (m FlowSpecMatch) Normalize() FlowSpecMatch {
	out := FlowSpecMatch{Source: m.Source}
	out.Protocols = slices.Compact(slices.Sorted(slices.Values(m.Protocols)))
	ports := func(in []PortRange) []PortRange {
		o := slices.Clone(in)
		slices.SortFunc(o, func(a, b PortRange) int {
			if a.From != b.From {
				return int(a.From) - int(b.From)
			}
			return int(a.To) - int(b.To)
		})
		return slices.Compact(o)
	}
	out.DestinationPorts = ports(m.DestinationPorts)
	out.SourcePorts = ports(m.SourcePorts)
	if len(out.Protocols) == 0 {
		out.Protocols = nil
	}
	if len(out.DestinationPorts) == 0 {
		out.DestinationPorts = nil
	}
	if len(out.SourcePorts) == 0 {
		out.SourcePorts = nil
	}
	return out
}

// Validate checks m for a rule toward dst.
func (m FlowSpecMatch) Validate(dst netip.Prefix) error {
	if m.Source.IsValid() {
		if m.Source != m.Source.Masked() {
			return fmt.Errorf("source %s has host bits set (did you mean %s?)", m.Source, m.Source.Masked())
		}
		if m.Source.Addr().Is4() != dst.Addr().Is4() {
			return fmt.Errorf("source %s and destination %s are different address families", m.Source, dst)
		}
	}
	if len(m.Protocols) > MaxFlowSpecProtocols {
		return fmt.Errorf("at most %d protocols", MaxFlowSpecProtocols)
	}
	if len(m.DestinationPorts) > MaxFlowSpecPorts || len(m.SourcePorts) > MaxFlowSpecPorts {
		return fmt.Errorf("at most %d destination and %d source ports", MaxFlowSpecPorts, MaxFlowSpecPorts)
	}
	for _, r := range append(slices.Clone(m.DestinationPorts), m.SourcePorts...) {
		if r.To < r.From {
			return fmt.Errorf("port range %s is backwards", r)
		}
	}
	return nil
}

// Key is a canonical text form of the normalized match.
func (m FlowSpecMatch) Key() string {
	m = m.Normalize()
	var b strings.Builder
	if m.Source.IsValid() {
		b.WriteString("src=" + m.Source.String() + " ")
	}
	join := func(label string, n int, at func(int) string) {
		if n == 0 {
			return
		}
		parts := make([]string, n)
		for i := range parts {
			parts[i] = at(i)
		}
		b.WriteString(label + "=" + strings.Join(parts, ",") + " ")
	}
	join("proto", len(m.Protocols), func(i int) string { return strconv.Itoa(int(m.Protocols[i])) })
	join("dport", len(m.DestinationPorts), func(i int) string { return m.DestinationPorts[i].String() })
	join("sport", len(m.SourcePorts), func(i int) string { return m.SourcePorts[i].String() })
	return strings.TrimSpace(b.String())
}

// FlowSpecRoute is one FlowSpec rule on the wire. Destination must be the
// exact prefix learned from the RIB; the core checks that before it calls
// AnnounceFlowSpec.
type FlowSpecRoute struct {
	Destination netip.Prefix
	Match       FlowSpecMatch
	// Action is one of the FlowSpec actions.
	Action string
	// Target names a FlowSpec catalog entry (redirect only).
	Target string
	// RateMbps is the rate limit in Mbit/s (rate-limit only).
	RateMbps  float64
	LocalPref uint32
	// Community is the configured packeteer community. It is required.
	Community string
}

// Key identifies the route's NLRI: two routes with the same key replace
// each other.
func (r FlowSpecRoute) Key() string {
	k := "dst=" + r.Destination.String()
	if m := r.Match.Key(); m != "" {
		k += " " + m
	}
	return k
}

// FlowSpecAnnouncer is implemented by a mitigation announcer that can
// publish FlowSpec rules. The same allowlist and rule cap cover its
// FlowSpec and its RTBH/redirect routes, and WithdrawAll and Stop remove
// both.
type FlowSpecAnnouncer interface {
	FlowSpecCatalog() FlowSpecCatalog
	// AnnounceFlowSpec advertises r, replacing a route with the same Key.
	AnnounceFlowSpec(ctx context.Context, r FlowSpecRoute) error
	// WithdrawFlowSpec removes the route with key. Unknown keys are a
	// no-op.
	WithdrawFlowSpec(ctx context.Context, key string) error
}
