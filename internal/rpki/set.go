package rpki

import (
	"net/netip"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Set is the configured RPKI source: an ordered list of origin-validation
// plugins. The first source with a fresh, non-empty cache answers; a stale
// or empty source is skipped, so a second server can take over. It never
// announces and never changes the learned RIB.
type Set struct {
	sources []plugin.RPKI
}

// NewSet wraps the configured sources in order.
func NewSet(sources []plugin.RPKI) *Set { return &Set{sources: sources} }

// Enabled reports whether any source is configured. An empty set returns
// unknown for every lookup and is treated as RPKI off by the controller.
func (s *Set) Enabled() bool { return s != nil && len(s.sources) > 0 }

// Version is a fingerprint of the data the set serves. A caller that
// caches results built from Validate (the exchange next-hop counts) keys
// on it, because a completed fetch or the staleness flip changes the
// answers without changing the RIB generation.
func (s *Set) Version() uint64 {
	if s == nil || len(s.sources) == 0 {
		return 0
	}
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	mix := func(v uint64) { h = (h ^ v) * prime64 }
	for _, src := range s.sources {
		st := src.Status()
		mix(uint64(st.VRPs))
		mix(uint64(st.Updated.UnixNano()))
		if st.Stale {
			mix(1)
		}
	}
	return h
}

// Validate applies the first fresh, non-empty source. Without one it
// returns RPKIUnknown, which is the fail-open state: it never blocks a
// withdraw.
func (s *Set) Validate(prefix netip.Prefix, origin uint32) plugin.RPKIValidity {
	if s == nil {
		return plugin.RPKIUnknown
	}
	for _, src := range s.sources {
		st := src.Status()
		// An empty cache has nothing to apply. Skipping it lets the next
		// source answer; a zero-VRP End of Data must not hide one.
		if st.Stale || st.VRPs == 0 {
			continue
		}
		return src.Validate(prefix, origin)
	}
	return plugin.RPKIUnknown
}
