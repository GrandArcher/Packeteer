package rib

import (
	"net/netip"
	"slices"
)

// readChunk is how many prefixes a chunked reader handles per read lock,
// so a full-table read leaves gaps for BGP updates to apply.
const readChunk = 1024

// A full-table read must not hold mu while BGP updates wait. Readers work
// from snapshot(), a slice of the selected routes sorted by prefix. The
// Route values it points to are never modified (republishLocked stores a
// new one per change), so the slice is read with no lock.
//
// Writers record each changed prefix in dirty once a snapshot exists. A
// refresh reads only those prefixes under the read lock and merges them
// into the previous snapshot after the lock is released. If the changes
// pass a share of the table, the snapshot is dropped instead, so a view
// that nobody reads does not keep replaced routes alive. The next read then
// rebuilds it from a pointer walk of the table and sorts outside the lock.

// dirtyLimit is how many changed prefixes a snapshot tolerates for a
// table of n routes.
func dirtyLimit(n int) int { return n/8 + readChunk }

// markDirtyLocked records a change to the route for p. Caller holds mu.
func (v *View) markDirtyLocked(p netip.Prefix) {
	v.dirtyMu.Lock()
	defer v.dirtyMu.Unlock()
	if v.dirty == nil {
		return
	}
	if len(v.dirty) >= dirtyLimit(len(v.routes)) {
		v.snap, v.dirty = nil, nil
		return
	}
	v.dirty[p] = struct{}{}
}

// dropSnapshot discards the snapshot. Caller holds mu.
func (v *View) dropSnapshot() {
	v.dirtyMu.Lock()
	v.snap, v.dirty = nil, nil
	v.dirtyMu.Unlock()
}

type routeChange struct {
	prefix netip.Prefix
	route  *Route // nil: the prefix has no selected route
}

func cmpPrefix(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}

// snapshot returns the selected routes sorted by prefix, current as of the
// call. The slice and the routes it points to must not be modified.
func (v *View) snapshot() []*Route {
	v.snapMu.Lock()
	defer v.snapMu.Unlock()

	v.dirtyMu.Lock()
	if v.snap != nil && len(v.dirty) == 0 {
		defer v.dirtyMu.Unlock()
		return v.snap
	}
	v.dirtyMu.Unlock()

	var base, all []*Route
	var changes []routeChange
	v.mu.RLock()
	v.dirtyMu.Lock()
	if v.snap != nil && v.dirty != nil {
		base = v.snap
		changes = make([]routeChange, 0, len(v.dirty))
		for p := range v.dirty {
			changes = append(changes, routeChange{p, v.routes[p]})
		}
	} else {
		all = make([]*Route, 0, len(v.routes))
		for _, r := range v.routes {
			all = append(all, r)
		}
	}
	v.dirty = map[netip.Prefix]struct{}{}
	v.dirtyMu.Unlock()
	v.mu.RUnlock()

	var snap []*Route
	if base != nil {
		snap = mergeChanges(base, changes)
	} else {
		slices.SortFunc(all, func(a, b *Route) int { return cmpPrefix(a.Prefix, b.Prefix) })
		snap = all
	}

	v.dirtyMu.Lock()
	// A nil dirty set means writers passed the limit while this refresh
	// ran and dropped the snapshot; what was built is still right for this
	// caller but must not be kept.
	if v.dirty != nil {
		v.snap = snap
	}
	v.dirtyMu.Unlock()
	return snap
}

// mergeChanges applies changes to the sorted base and returns a new sorted
// slice. base is not modified: readers may still hold it.
func mergeChanges(base []*Route, changes []routeChange) []*Route {
	slices.SortFunc(changes, func(a, b routeChange) int { return cmpPrefix(a.prefix, b.prefix) })
	out := make([]*Route, 0, len(base)+len(changes))
	i := 0
	for _, c := range changes {
		for i < len(base) && cmpPrefix(base[i].Prefix, c.prefix) < 0 {
			out = append(out, base[i])
			i++
		}
		if i < len(base) && base[i].Prefix == c.prefix {
			i++
		}
		if c.route != nil {
			out = append(out, c.route)
		}
	}
	return append(out, base[i:]...)
}
