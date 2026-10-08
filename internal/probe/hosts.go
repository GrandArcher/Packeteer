package probe

import (
	"net/netip"

	"github.com/GrandArcher/Packeteer/internal/exchange"
)

// maxProbeHosts caps how many addresses one provider probes for one
// prefix. A handful, not the prefix.
const maxProbeHosts = 4

// maxInPrefix is how many of those addresses sit inside the prefix. One
// slot is left for the far-side gateway when it can be used. A flow
// candidate takes the first of these slots.
const maxInPrefix = 3

// ProbeHosts picks the addresses to measure for one prefix on one provider.
//
// pin, when valid, is the only target. An operator host (static, vip,
// traceroute) is a pin and wins over detection.
//
// candidates, busiest first, are probed first when they sit inside the
// prefix. They are not pins. At most maxInPrefix of them are kept. The
// automatic in-prefix addresses are added only when fewer than that were
// named, and a usable gateway still takes the last slot under
// maxProbeHosts. A candidate that is already an automatic address is not
// duplicated, so the later automatic address stays when there is room.
//
// Otherwise the list is a few addresses inside the prefix plus gateway when
// that address looks like the far side of this provider: unicast, the same
// family as the prefix, and not the probe source. gateway is the provider
// next hop (the hop just past the edge toward that provider). It is not a
// new provider, and choosing it does not announce anything.
func ProbeHosts(prefix netip.Prefix, pin netip.Addr, candidates []netip.Addr, gateway, source netip.Addr) []netip.Addr {
	prefix = prefix.Masked()
	if !prefix.IsValid() {
		if pin.IsValid() {
			return []netip.Addr{pin}
		}
		for _, c := range candidates {
			if c.IsValid() {
				return []netip.Addr{c}
			}
		}
		return nil
	}
	if pin.IsValid() {
		return []netip.Addr{pin}
	}
	gwOK := usableGateway(gateway, source, prefix)
	// A usable gateway keeps its slot. In-prefix addresses fill what remains.
	limit := maxProbeHosts
	if gwOK {
		limit = maxInPrefix
	}
	hosts := make([]netip.Addr, 0, maxProbeHosts)
	seen := make(map[netip.Addr]bool, maxProbeHosts)
	add := func(a netip.Addr) bool {
		if !a.IsValid() || seen[a] || !prefix.Contains(a) {
			return false
		}
		seen[a] = true
		hosts = append(hosts, a)
		return true
	}
	nFlow := 0
	for _, c := range candidates {
		if nFlow >= maxInPrefix {
			break
		}
		if add(c) {
			nFlow++
		}
	}
	// Automatic .1 / quarter / half points fill only when flow named
	// fewer than three destinations.
	if nFlow < maxInPrefix {
		for _, a := range autoHosts(prefix) {
			if len(hosts) >= limit {
				break
			}
			add(a)
		}
	}
	if len(hosts) > limit {
		hosts = hosts[:limit]
	}
	if len(hosts) >= maxProbeHosts || !gwOK {
		return hosts
	}
	for _, h := range hosts {
		if h == gateway {
			return hosts
		}
	}
	return append(hosts, gateway)
}

// omitLANHosts removes addresses that sit on an exchange peering LAN.
// gateway is kept: it is the provider's far-side next hop, probed on
// purpose, not an IX service. An empty lans list returns hosts unchanged.
func omitLANHosts(hosts []netip.Addr, gateway netip.Addr, lans []netip.Prefix) []netip.Addr {
	if len(lans) == 0 || len(hosts) == 0 {
		return hosts
	}
	var gw netip.Addr
	if gateway.IsValid() {
		gw = gateway.Unmap()
	}
	out := make([]netip.Addr, 0, len(hosts))
	for _, h := range hosts {
		if h.IsValid() && h.Unmap() != gw && exchange.ContainsAddr(lans, h) {
			continue
		}
		out = append(out, h)
	}
	return out
}

// usableGateway reports whether gateway can be probed as the far side of
// the provider. The probe source is our side of the link, not the far side.
func usableGateway(gateway, source netip.Addr, prefix netip.Prefix) bool {
	if !gateway.IsValid() || !prefix.IsValid() {
		return false
	}
	if gateway.Is4() != prefix.Addr().Is4() {
		return false
	}
	if source.IsValid() && gateway.Unmap() == source.Unmap() {
		return false
	}
	if gateway.IsUnspecified() || gateway.IsLoopback() || gateway.IsMulticast() || gateway.IsLinkLocalUnicast() {
		return false
	}
	if gateway.Is4() && gateway.As4() == ([4]byte{255, 255, 255, 255}) {
		return false
	}
	return true
}

// autoHosts returns at most maxInPrefix addresses inside p. The first is
// the usual ".1". Larger prefixes also contribute a quarter point and a
// halfway point so the samples are not three adjacent dead addresses.
// Host routes contribute the address itself. The prefix is not scanned.
func autoHosts(p netip.Prefix) []netip.Addr {
	p = p.Masked()
	if !p.IsValid() {
		return nil
	}
	base := p.Addr()
	hostBits := base.BitLen() - p.Bits()
	if hostBits <= 0 {
		return []netip.Addr{base}
	}
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, off := range autoOffsets(hostBits) {
		h := addOffset(base, off)
		if !h.IsValid() || !p.Contains(h) || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
		if len(out) == maxInPrefix {
			break
		}
	}
	if len(out) == 0 {
		return []netip.Addr{DefaultHost(p)}
	}
	return out
}

// autoOffsets lists host-part offsets from the network address. Offsets
// that do not fit in the prefix are omitted. Prefixes wider than 2^63
// hosts use three fixed offsets so the choice does not walk the prefix.
func autoOffsets(hostBits int) []uint64 {
	if hostBits <= 0 {
		return []uint64{0}
	}
	if hostBits >= 63 {
		return []uint64{1, 1 << 20, 1 << 30}
	}
	var offs []uint64
	add := func(o uint64) {
		if o == 0 || o >= 1<<uint(hostBits) {
			return
		}
		for _, e := range offs {
			if e == o {
				return
			}
		}
		offs = append(offs, o)
	}
	add(1)
	if hostBits >= 3 {
		add(uint64(1) << uint(hostBits-2))
	}
	if hostBits >= 2 {
		add(uint64(1) << uint(hostBits-1))
	}
	return offs
}

func addOffset(a netip.Addr, off uint64) netip.Addr {
	if a.Is4() {
		b := a.As4()
		v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		v += uint32(off)
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	b := a.As16()
	carry := off
	for i := 15; i >= 0 && carry > 0; i-- {
		sum := uint64(b[i]) + carry
		b[i] = byte(sum)
		carry = sum >> 8
	}
	return netip.AddrFrom16(b)
}
