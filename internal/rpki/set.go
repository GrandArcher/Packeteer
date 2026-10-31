package rpki

import (
	"net/netip"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Set is the configured RPKI source: an ordered list of origin-validation
// plugins. The first source with a fresh, non-empty cache answers; a stale
// or empty source is skipped, so a second server can take over. It never
// announces and never changes the learned RIB.
type Set struct {
	sources []plugin.RPKI
	// display is asked by LookupDisplay only, after the sources.
	display Answerer
}

// Answerer is a display-only lookup whose answers each carry their own
// age (rpki.display_fallback). The ripestat plugin implements it.
type Answerer interface {
	Answer(prefix netip.Prefix, origin uint32) plugin.RPKIAnswer
}

// NewSet wraps the configured sources in order.
func NewSet(sources []plugin.RPKI) *Set { return &Set{sources: sources} }

// SetDisplay installs the display-only fallback. Call it before the set
// is used.
func (s *Set) SetDisplay(a Answerer) { s.display = a }

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

// active is the first fresh, non-empty source. An empty cache has nothing
// to apply: skipping it lets the next source answer, and a zero-VRP End of
// Data must not hide one.
func (s *Set) active() (plugin.RPKI, plugin.RPKIStatus, bool) {
	if s == nil {
		return nil, plugin.RPKIStatus{}, false
	}
	for _, src := range s.sources {
		st := src.Status()
		if !st.Stale && st.VRPs != 0 {
			return src, st, true
		}
	}
	return nil, plugin.RPKIStatus{}, false
}

// Lookup applies the first fresh, non-empty source and says which one
// answered and its data time. Without one it returns
// RPKIUnknown, which is the fail-open state: it never blocks a withdraw.
// It never asks the display fallback.
func (s *Set) Lookup(prefix netip.Prefix, origin uint32) plugin.RPKIAnswer {
	src, st, ok := s.active()
	if !ok {
		return plugin.RPKIAnswer{State: plugin.RPKIUnknown}
	}
	return plugin.RPKIAnswer{State: src.Validate(prefix, origin), Source: st.Source, Updated: st.Updated}
}

// Validate is Lookup's state.
func (s *Set) Validate(prefix netip.Prefix, origin uint32) plugin.RPKIValidity {
	return s.Lookup(prefix, origin).State
}

// Updated is the data time of the source Validate uses. It is zero while
// no source is fresh.
func (s *Set) Updated() time.Time {
	_, st, _ := s.active()
	return st.Updated
}

// LookupDisplay is Lookup, then the display fallback when no source has
// usable data. Only a display may use it: Decide, avoid_invalid, leak
// watch, and the exchange counts use Lookup.
func (s *Set) LookupDisplay(prefix netip.Prefix, origin uint32) plugin.RPKIAnswer {
	a := s.Lookup(prefix, origin)
	if a.State != plugin.RPKIUnknown || s == nil || s.display == nil {
		return a
	}
	if d := s.display.Answer(prefix, origin); d.State != plugin.RPKIUnknown {
		return d
	}
	return a
}

// Covering lists the payloads covering prefix in the source Lookup would
// use. It is nil when that source cannot list them.
func (s *Set) Covering(prefix netip.Prefix) []plugin.RPKIVRP {
	src, _, ok := s.active()
	if !ok {
		return nil
	}
	if c, ok := src.(plugin.RPKICovering); ok {
		return c.Covering(prefix)
	}
	return nil
}
