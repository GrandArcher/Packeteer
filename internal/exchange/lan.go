package exchange

import (
	"net/netip"
	"sync/atomic"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// lanDrops counts probe targets omitted because they sit on an exchange
// peering LAN (#145). It is a process total. Metrics read it.
var lanDrops atomic.Uint64

// LANDrops is the number of probe targets omitted since the process started.
func LANDrops() uint64 { return lanDrops.Load() }

// NoteDrops adds n omitted targets. Zero and negative values do nothing.
func NoteDrops(n int) {
	if n > 0 {
		lanDrops.Add(uint64(n))
	}
}

// ContainsAddr reports whether a is inside any peering LAN.
func ContainsAddr(lans []netip.Prefix, a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	for _, l := range lans {
		if l.IsValid() && l.Contains(a) {
			return true
		}
	}
	return false
}

// Covering is the longest peering LAN that contains a.
func Covering(lans []netip.Prefix, a netip.Addr) (netip.Prefix, bool) {
	var best netip.Prefix
	if !a.IsValid() {
		return best, false
	}
	a = a.Unmap()
	for _, l := range lans {
		l = l.Masked()
		if !l.IsValid() || !l.Contains(a) {
			continue
		}
		if !best.IsValid() || l.Bits() > best.Bits() {
			best = l
		}
	}
	return best, best.IsValid()
}

// PrefixInside reports whether p is equal to a peering LAN or more
// specific and inside one. A wider prefix that merely contains a LAN
// is not inside it.
func PrefixInside(lans []netip.Prefix, p netip.Prefix) bool {
	p = p.Masked()
	if !p.IsValid() {
		return false
	}
	for _, l := range lans {
		l = l.Masked()
		if !l.IsValid() || l.Addr().BitLen() != p.Addr().BitLen() {
			continue
		}
		if l.Bits() <= p.Bits() && l.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// Overlaps reports whether a and b share any address. Different address
// families do not overlap. Both prefixes should be masked.
func Overlaps(a, b netip.Prefix) bool {
	a, b = a.Masked(), b.Masked()
	if !a.IsValid() || !b.IsValid() || a.Addr().BitLen() != b.Addr().BitLen() {
		return false
	}
	if a.Bits() > b.Bits() {
		a, b = b, a
	}
	return a.Contains(b.Addr())
}

// FilterTargets drops probe targets a source should not return (#145).
// A prefix inside a peering LAN is dropped. A host inside a LAN is not
// probed: an explicit host (not a flow candidate) drops the target,
// because that host would be the only address; a candidate is cleared
// so the prefix can still be measured at other addresses. The input
// slice is not modified. The omission count is added to LANDrops.
func FilterTargets(lans []netip.Prefix, in []plugin.Target) []plugin.Target {
	if len(lans) == 0 || len(in) == 0 {
		return in
	}
	out := make([]plugin.Target, 0, len(in))
	dropped := 0
	changed := false
	for _, t := range in {
		t.Prefix = t.Prefix.Masked()
		if PrefixInside(lans, t.Prefix) {
			dropped++
			changed = true
			continue
		}
		if t.Host.IsValid() && ContainsAddr(lans, t.Host) {
			if t.Candidate {
				t.Host = netip.Addr{}
				t.Candidate = false
				dropped++
				changed = true
			} else {
				dropped++
				changed = true
				continue
			}
		}
		out = append(out, t)
	}
	if !changed {
		return in
	}
	NoteDrops(dropped)
	return out
}

// FilterNormalized is FilterTargets for a list the probe engine has
// already normalized. Pinned is set, and an empty host has been replaced
// with a representative address that is not a pin. A pinned host on a
// LAN drops the target. A candidate on a LAN is unmarked but the address
// stays so the provider address-family check still sees it; the probe
// list then skips LAN addresses. A representative address that merely
// falls on a LAN does not drop the prefix.
func FilterNormalized(lans []netip.Prefix, in []plugin.Target) []plugin.Target {
	if len(lans) == 0 || len(in) == 0 {
		return in
	}
	out := make([]plugin.Target, 0, len(in))
	dropped := 0
	changed := false
	for _, t := range in {
		t.Prefix = t.Prefix.Masked()
		if PrefixInside(lans, t.Prefix) {
			dropped++
			changed = true
			continue
		}
		if t.Host.IsValid() && ContainsAddr(lans, t.Host) {
			if t.Pinned {
				dropped++
				changed = true
				continue
			}
			if t.Candidate {
				t.Candidate = false
				dropped++
				changed = true
			}
		}
		out = append(out, t)
	}
	if !changed {
		return in
	}
	NoteDrops(dropped)
	return out
}
