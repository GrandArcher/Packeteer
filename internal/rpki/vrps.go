// Package rpki is the shared RPKI origin-validation source (#158). It
// holds a VRP cache with RFC 6811 validation and an ordered fallback over
// one or more RPKI plugins. It is read-only: it never announces and never
// changes the learned RIB.
package rpki

import (
	"net/netip"
	"sync"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// vrp is one validated ROA payload: a prefix, the longest prefix length it
// covers, and the origin AS it authorizes.
type vrp struct {
	maxLen uint8
	asn    uint32
}

// VRPs is a VRP cache for RFC 6811 origin validation. It is keyed by the
// announced prefix; a lookup walks the covering prefixes of the queried
// prefix (at most 33 for IPv4, 129 for IPv6), so a full cache does not need
// a linear scan. It is safe for concurrent use.
type VRPs struct {
	mu sync.RWMutex
	m  map[netip.Prefix][]vrp
	n  int
}

// NewVRPs returns an empty cache.
func NewVRPs() *VRPs { return &VRPs{m: map[netip.Prefix][]vrp{}} }

// Len is the number of payloads in the cache.
func (t *VRPs) Len() int {
	if t == nil {
		return 0
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.n
}

// Change is one RTR Prefix PDU: an announcement or, with Withdraw set, a
// withdrawal of one payload.
type Change struct {
	Prefix   netip.Prefix
	MaxLen   uint8
	ASN      uint32
	Withdraw bool
}

// Apply applies RTR Prefix PDUs in order under a single lock, so a
// concurrent Validate sees the cache before or after a whole serial delta
// and never a part of it. An announcement is idempotent: RTR re-sends a
// serial's records after a reconnect or a lost End of Data, and a stored
// duplicate would outlive one withdrawal.
func (t *VRPs) Apply(changes []Change) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, c := range changes {
		if c.Withdraw {
			t.removeLocked(c.Prefix, c.MaxLen, c.ASN)
		} else {
			t.addLocked(c.Prefix, c.MaxLen, c.ASN)
		}
	}
}

func (t *VRPs) addLocked(prefix netip.Prefix, maxLen uint8, asn uint32) {
	if !prefix.IsValid() {
		return
	}
	prefix = prefix.Masked()
	for _, e := range t.m[prefix] {
		if e.maxLen == maxLen && e.asn == asn {
			return
		}
	}
	t.m[prefix] = append(t.m[prefix], vrp{maxLen: maxLen, asn: asn})
	t.n++
}

// removeLocked does nothing when the payload is not in the cache.
func (t *VRPs) removeLocked(prefix netip.Prefix, maxLen uint8, asn uint32) {
	if !prefix.IsValid() {
		return
	}
	prefix = prefix.Masked()
	entries, found := t.m[prefix]
	if !found {
		return
	}
	matched := false
	for i, e := range entries {
		if e.maxLen == maxLen && e.asn == asn {
			entries = append(entries[:i], entries[i+1:]...)
			matched = true
			break
		}
	}
	if !matched {
		return
	}
	if len(entries) == 0 {
		delete(t.m, prefix)
	} else {
		t.m[prefix] = entries
	}
	t.n--
}

// Validate applies RFC 6811 to prefix and origin: valid when a covering
// payload authorizes the origin at a max length no shorter than the prefix,
// invalid when a payload covers the prefix but none matches (a prefix
// longer than every matching max length is invalid), and not-found when
// nothing covers it. An invalid prefix argument is unknown.
func (t *VRPs) Validate(prefix netip.Prefix, origin uint32) plugin.RPKIValidity {
	if t == nil || !prefix.IsValid() {
		return plugin.RPKIUnknown
	}
	prefix = prefix.Masked()
	bits := prefix.Bits()
	t.mu.RLock()
	defer t.mu.RUnlock()
	covered := false
	for i := 0; i <= bits; i++ {
		cover := netip.PrefixFrom(prefix.Addr(), i).Masked()
		for _, e := range t.m[cover] {
			covered = true
			if e.asn == origin && int(e.maxLen) >= bits {
				return plugin.RPKIValid
			}
		}
	}
	if covered {
		return plugin.RPKIInvalid
	}
	return plugin.RPKINotFound
}

// Covering returns every payload whose prefix covers prefix, shortest
// first.
func (t *VRPs) Covering(prefix netip.Prefix) []plugin.RPKIVRP {
	if t == nil || !prefix.IsValid() {
		return nil
	}
	prefix = prefix.Masked()
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []plugin.RPKIVRP
	for i := 0; i <= prefix.Bits(); i++ {
		cover := netip.PrefixFrom(prefix.Addr(), i).Masked()
		for _, e := range t.m[cover] {
			out = append(out, plugin.RPKIVRP{Prefix: cover, MaxLen: e.maxLen, ASN: e.asn})
		}
	}
	return out
}
