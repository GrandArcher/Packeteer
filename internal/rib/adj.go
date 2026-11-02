package rib

import "slices"

// pathSet is the paths for one prefix from one kind of source, keyed by
// adjKey (iBGP) or bmpPathKey (BMP).
//
// A full table is almost all single-path prefixes (no add-path, or one
// BMP peer per prefix). Those are stored inline. Several paths (add-path,
// or BMP Adj-RIB-In next to Loc-RIB) are a small slice searched in order:
// a map per prefix is a few hundred bytes of header on top of the routes,
// and at a million prefixes that header is a large part of the heap the
// load test measures. Dropping back to one path stores it inline again.
type pathSet[K comparable] struct {
	n    int
	key  K
	one  Route
	many []keyedRoute[K]
}

type keyedRoute[K comparable] struct {
	key K
	rt  Route
}

func (s *pathSet[K]) find(k K) int {
	return slices.IndexFunc(s.many, func(e keyedRoute[K]) bool { return e.key == k })
}

func (s *pathSet[K]) set(k K, rt Route) {
	if s.n == 0 {
		s.key, s.one, s.n = k, rt, 1
		return
	}
	if s.many == nil {
		if s.key == k {
			s.one = rt
			return
		}
		s.many = make([]keyedRoute[K], 1, 2)
		s.many[0] = keyedRoute[K]{s.key, s.one}
		var zero K
		s.key, s.one = zero, Route{}
	}
	if i := s.find(k); i >= 0 {
		s.many[i].rt = rt
	} else {
		s.many = append(s.many, keyedRoute[K]{k, rt})
	}
	s.n = len(s.many)
}

// del removes k. It reports whether the set is now empty.
func (s *pathSet[K]) del(k K) bool {
	if s.n == 0 {
		return true
	}
	if s.many == nil {
		if s.key != k {
			return false
		}
		*s = pathSet[K]{}
		return true
	}
	i := s.find(k)
	if i < 0 {
		return false
	}
	s.many = slices.Delete(s.many, i, i+1)
	switch len(s.many) {
	case 0:
		*s = pathSet[K]{}
		return true
	case 1:
		s.key, s.one = s.many[0].key, s.many[0].rt
		s.many = nil
		s.n = 1
		return false
	default:
		s.n = len(s.many)
		return false
	}
}

func (s *pathSet[K]) has(k K) bool {
	if s.n == 0 {
		return false
	}
	if s.many == nil {
		return s.key == k
	}
	return s.find(k) >= 0
}

func (s *pathSet[K]) update(k K, rt Route) {
	if s.many == nil {
		if s.n == 1 && s.key == k {
			s.one = rt
		}
		return
	}
	if i := s.find(k); i >= 0 {
		s.many[i].rt = rt
	}
}

func (s *pathSet[K]) each(fn func(K, Route)) {
	if s == nil || s.n == 0 {
		return
	}
	if s.many == nil {
		fn(s.key, s.one)
		return
	}
	for _, e := range s.many {
		fn(e.key, e.rt)
	}
}
