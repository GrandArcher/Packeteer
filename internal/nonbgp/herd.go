package nonbgp

import (
	"net/netip"

	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
)

// HerdView is what the herd checks a record against in place of a RIB view
// (#300). A prefix is "learned" only when it is the announced prefix of a
// current synthetic prefix, and the path through a provider is that
// provider's AS and the announced prefix's origin. A provider with no
// asn has no path, so nothing is shared through it.
type HerdView struct {
	Table       *Table
	ProviderASN map[string]uint32
}

// Ready is always true: the table has no session that can go stale. A
// prefix that ages out of it stops being served at once through Exact.
func (HerdView) Ready() bool { return true }

// Exact reports whether p is a current announced prefix.
func (v HerdView) Exact(p netip.Prefix) (rib.Route, bool) {
	if _, ok := v.Table.IsAnnounced(p); !ok {
		return rib.Route{}, false
	}
	return rib.Route{Prefix: p.Masked(), Source: SourceSynthetic}, true
}

// ProviderPaths is the origin AS of p alone: no learned path exists here, so
// no adjacency to the provider is claimed. A provider with no configured AS
// gets none, because the herd record needs it.
func (v HerdView) ProviderPaths(p netip.Prefix, provider string) [][]uint32 {
	origin, ok := v.Table.IsAnnounced(p)
	asn := v.ProviderASN[provider]
	if !ok || origin == 0 || asn == 0 {
		return nil
	}
	return [][]uint32{{origin}}
}

// ForHerd maps a probe round to what may be shared: each result is
// rewritten to the announced prefix that bounds its synthetic prefix, and
// one with no announced prefix is left out. Two synthetic prefixes in one
// announced prefix give one result per provider. A synthetic prefix and
// the addresses behind it never reach the herd.
func ForHerd(t *Table, batch []probe.Result) []probe.Result {
	type key struct {
		prefix   netip.Prefix
		provider string
	}
	seen := map[key]bool{}
	var out []probe.Result
	for _, r := range batch {
		a, ok := t.Announced(r.Prefix)
		if !ok {
			continue
		}
		k := key{a.Prefix, r.Provider}
		if seen[k] {
			continue
		}
		seen[k] = true
		r.Prefix = a.Prefix
		out = append(out, r)
	}
	return out
}
