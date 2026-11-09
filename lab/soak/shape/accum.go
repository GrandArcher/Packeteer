package shape

import (
	"hash/fnv"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

// Accumulator counts one peer's routes. It keeps a 64-bit fingerprint per
// distinct attribute set and nothing else about a route.
type Accumulator struct {
	s    Shape
	sets map[uint64]struct{}
}

func NewAccumulator() *Accumulator {
	return &Accumulator{
		s: Shape{
			IPv4:             Family{Length: map[int]int{}},
			IPv6:             Family{Length: map[int]int{}},
			ASPathLength:     map[int]int{},
			Communities:      map[int]int{},
			LargeCommunities: map[int]int{},
			Origin:           map[int]int{},
		},
		sets: map[uint64]struct{}{},
	}
}

// Routes is the number of routes added so far.
func (a *Accumulator) Routes() int { return a.s.Routes }

// Add counts one route: its family, prefix length, and path attributes.
func (a *Accumulator) Add(v6 bool, plen int, attrs []bgp.PathAttributeInterface) {
	a.s.Routes++
	if v6 {
		a.s.IPv6.Prefixes++
		a.s.IPv6.Length[plen]++
	} else {
		a.s.IPv4.Prefixes++
		a.s.IPv4.Length[plen]++
	}
	hops, comms, large := 0, 0, 0
	origin := 2
	h := fnv.New64a()
	for _, attr := range attrs {
		// An MRT RIB entry's MP_REACH_NLRI carries the entry's own prefix,
		// which is not part of the attribute set.
		if mp, ok := attr.(*bgp.PathAttributeMpReachNLRI); ok {
			_, _ = h.Write(mp.Nexthop)
		} else if b, err := attr.Serialize(); err == nil {
			_, _ = h.Write(b)
		}
		switch v := attr.(type) {
		case *bgp.PathAttributeOrigin:
			origin = min(int(v.Value), 2)
		case *bgp.PathAttributeAsPath:
			for _, p := range v.Value {
				if p.GetType() == bgp.BGP_ASPATH_ATTR_TYPE_SET || p.GetType() == bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET {
					hops++ // RFC 4271 section 9.1.2.2: a set counts as one
				} else {
					hops += len(p.GetAS())
				}
			}
		case *bgp.PathAttributeMultiExitDisc:
			a.s.MEDRoutes++
		case *bgp.PathAttributeCommunities:
			comms = len(v.Value)
		case *bgp.PathAttributeLargeCommunities:
			large = len(v.Values)
		}
	}
	a.s.Origin[origin]++
	a.s.ASPathLength[min(hops, MaxASPath)]++
	a.s.Communities[min(comms, MaxCommunities)]++
	a.s.LargeCommunities[min(large, MaxLargeCommunities)]++
	a.sets[h.Sum64()] = struct{}{}
}

// Shape returns the counts so far for this one peer.
func (a *Accumulator) Shape() Shape {
	s := a.s
	s.AttributeSets = len(a.sets)
	return s
}
