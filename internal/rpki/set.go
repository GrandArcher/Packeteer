package rpki

import (
	"net/netip"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Set is the configured RPKI source: an ordered list of origin-validation
// plugins. The first source with a fresh cache answers; a stale or empty
// source is skipped, so a second server can take over. It never announces
// and never changes the learned RIB.
type Set struct {
	sources []plugin.RPKI
}

// NewSet wraps the configured sources in order.
func NewSet(sources []plugin.RPKI) *Set { return &Set{sources: sources} }

// Enabled reports whether any source is configured. An empty set returns
// unknown for every lookup and is treated as RPKI off by the controller.
func (s *Set) Enabled() bool { return s != nil && len(s.sources) > 0 }

// Validate applies the first fresh source. Without one it returns
// RPKIUnknown, which is the fail-open state: it never blocks a withdraw.
func (s *Set) Validate(prefix netip.Prefix, origin uint32) plugin.RPKIValidity {
	if s == nil {
		return plugin.RPKIUnknown
	}
	for _, src := range s.sources {
		if src.Status().Stale {
			continue
		}
		return src.Validate(prefix, origin)
	}
	return plugin.RPKIUnknown
}
