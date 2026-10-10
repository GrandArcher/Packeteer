package rib

import "net/netip"

// pathSet is the iBGP paths for one prefix.
//
// A full table is almost all single-path prefixes (no add-path). Those
// are stored inline. A map per prefix is a few hundred bytes of header
// on top of the route, and at a million prefixes that header is a large
// part of the heap the load test measures. A second path promotes the
// set to a map; dropping back to one path releases it.
type pathSet struct {
	n    int
	key  adjKey
	one  Route
	many map[adjKey]Route
}

func (s *pathSet) set(k adjKey, rt Route) {
	if s.n == 0 {
		s.key, s.one, s.n = k, rt, 1
		return
	}
	if s.many == nil {
		if s.key == k {
			s.one = rt
			return
		}
		s.many = make(map[adjKey]Route, 2)
		s.many[s.key] = s.one
		s.one = Route{}
	}
	s.many[k] = rt
	s.n = len(s.many)
}

// del removes k. It reports whether the set is now empty.
func (s *pathSet) del(k adjKey) bool {
	if s.n == 0 {
		return true
	}
	if s.many == nil {
		if s.key != k {
			return false
		}
		*s = pathSet{}
		return true
	}
	if _, ok := s.many[k]; !ok {
		return false
	}
	delete(s.many, k)
	switch len(s.many) {
	case 0:
		*s = pathSet{}
		return true
	case 1:
		for kk, rt := range s.many {
			s.key, s.one = kk, rt
		}
		s.many = nil
		s.n = 1
		return false
	default:
		s.n = len(s.many)
		return false
	}
}

func (s *pathSet) has(k adjKey) bool {
	if s.n == 0 {
		return false
	}
	if s.many == nil {
		return s.key == k
	}
	_, ok := s.many[k]
	return ok
}

func (s *pathSet) update(k adjKey, rt Route) {
	if s.many == nil {
		if s.n == 1 && s.key == k {
			s.one = rt
		}
		return
	}
	if _, ok := s.many[k]; ok {
		s.many[k] = rt
	}
}

func (s *pathSet) each(fn func(adjKey, Route)) {
	if s == nil || s.n == 0 {
		return
	}
	if s.many == nil {
		fn(s.key, s.one)
		return
	}
	for k, rt := range s.many {
		fn(k, rt)
	}
}

// putAdj replaces the iBGP paths for p. Tests build a view without a
// session. An empty paths map removes p.
func (v *View) putAdj(p netip.Prefix, paths map[adjKey]Route) {
	var s pathSet
	for k, rt := range paths {
		s.set(k, rt)
	}
	if s.n == 0 {
		delete(v.adj, p)
		return
	}
	v.adj[p] = s
}
