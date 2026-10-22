package main

import (
	"encoding/binary"
	"math"
	"math/bits"
	"math/rand/v2"
	"net/netip"
	"sort"

	"github.com/GrandArcher/Packeteer/lab/soak/shape"
)

// Documentation space only. The IPv4 part is every prefix from /24 to /32
// inside the three RFC 5737 blocks; the rest of the table is 2001:db8::/32
// (RFC 3849). The IPv4 share of a real table cannot be matched: the three
// blocks hold 1,533 prefixes. The IPv6 part follows the length mix of the
// shape file (lab/soak/shape), moved to longer lengths until it fits.
var (
	docV4 = []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
	}
	docV6 = netip.MustParsePrefix("2001:db8::/32")
)

// v4Count is the number of IPv4 prefixes the table uses before IPv6.
const v4Count = 3 * 511

// Documentation ASNs for AS paths (RFC 5398): 64496-64511 and 65536-65551.
// The first 16 also fit a 16-bit community.
var docASNs = [...]uint32{64496, 64497, 64498, 64499, 64500, 64501, 64502, 64503,
	64504, 64505, 64506, 64507, 64508, 64509, 64510, 64511, 65536, 65537, 65538, 65539,
	65540, 65541, 65542, 65543, 65544, 65545, 65546, 65547, 65548, 65549, 65550, 65551}

// commValues is how many community values each documentation ASN uses.
const commValues = 2000

// table is a synthetic full table of n prefixes shaped like the shape file.
// Entry i is computed, not stored, so the harness holds no copy beyond the
// router's own.
type table struct {
	n  int
	v6 *v6Layout // nil when n does not fit

	setLen int // consecutive prefixes that share one attribute set

	pathLen, comms, large, origin shape.Dist
	medRoutes, routes             uint64
}

func newTable(n int) table {
	sh := shape.Default()
	t := table{
		n:         n,
		setLen:    max(1, int(math.Round(1e6/sh.SetsPerMillion()))),
		pathLen:   shape.NewDist(sh.ASPathLength),
		comms:     shape.NewDist(sh.Communities),
		large:     shape.NewDist(sh.LargeCommunities),
		origin:    shape.NewDist(sh.Origin),
		medRoutes: uint64(sh.MEDRoutes),
		routes:    uint64(sh.Routes),
	}
	if n > v4Count {
		t.v6 = layoutV6(sh.IPv6.Length, n-v4Count)
	}
	return t
}

func (t table) valid() bool { return t.n > 0 && (t.n <= v4Count || t.v6 != nil) }

// patternLen is the number of IPv6 entries in one repeating pattern of
// prefix lengths. A real table interleaves lengths, so entry order carries
// no length.
const patternLen = 4096

type v6Class struct {
	bits     int    // prefix length
	perCycle int    // entries of this length in one pattern
	base     uint64 // first address of the class, in /64 units after /32
}

// v6Layout places the IPv6 entries in 2001:db8::/32. The pattern says which
// length class entry j is in; the k-th entry of a class is the k-th prefix
// of that length inside the class's own address range, so no entry nests in
// another and a flow to an entry's host matches that entry. shift is how
// many bits longer than the shape's own the lengths had to be for every
// class to fit (a /48 holds only 65,536 prefixes of a /32).
type v6Layout struct {
	shift   int
	classes []v6Class
	pattern [patternLen]uint8
	rank    [patternLen]uint16 // entries of the same class before this one
}

// layoutV6 spreads m entries over the length histogram h, or returns nil
// when m is more than 2001:db8::/32 holds.
func layoutV6(h map[int]int, m int) *v6Layout {
	if m > maxV6 {
		return nil
	}
	quota := quotas(h, patternLen)
	cycles := uint64((m + patternLen - 1) / patternLen)
	for shift := 0; shift <= 64; shift++ {
		merged := map[int]int{}
		for l, q := range quota {
			merged[min(64, max(32, l+shift))] += q
		}
		lens := make([]int, 0, len(merged))
		for d := range merged {
			lens = append(lens, d)
		}
		// Shortest first: each class then starts on a multiple of its own
		// size, because everything before it is a multiple of a larger one.
		sort.Ints(lens)
		lay := &v6Layout{shift: shift}
		var used uint64
		for _, d := range lens {
			lay.classes = append(lay.classes, v6Class{bits: d, perCycle: merged[d], base: used})
			used += cycles * uint64(merged[d]) << (64 - d)
		}
		if used > 1<<32 {
			continue
		}
		lay.fill()
		return lay
	}
	return nil
}

// quotas splits total slots over h by largest remainder.
func quotas(h map[int]int, total int) map[int]int {
	sum := 0
	for _, c := range h {
		sum += c
	}
	out := map[int]int{}
	type rem struct{ l, r int }
	var rems []rem
	left := total
	for l, c := range h {
		q := total * c / sum
		out[l] = q
		left -= q
		rems = append(rems, rem{l, total * c % sum})
	}
	sort.Slice(rems, func(i, j int) bool {
		if rems[i].r != rems[j].r {
			return rems[i].r > rems[j].r
		}
		return rems[i].l < rems[j].l
	})
	for i := 0; i < left; i++ {
		out[rems[i].l]++
	}
	for l, q := range out {
		if q == 0 {
			delete(out, l)
		}
	}
	return out
}

// fill orders the pattern by smooth weighted round-robin, so each class is
// spread evenly through it.
func (l *v6Layout) fill() {
	credit := make([]int, len(l.classes))
	seen := make([]int, len(l.classes))
	for pos := range patternLen {
		best := 0
		for c, cl := range l.classes {
			credit[c] += cl.perCycle
			if credit[c] > credit[best] {
				best = c
			}
		}
		credit[best] -= patternLen
		l.pattern[pos] = uint8(best)
		l.rank[pos] = uint16(seen[best])
		seen[best]++
	}
}

// prefix returns IPv6 entry j (counted from the first IPv6 entry).
func (l *v6Layout) prefix(j int) netip.Prefix {
	pos := j % patternLen
	cl := l.classes[l.pattern[pos]]
	k := uint64(j/patternLen)*uint64(cl.perCycle) + uint64(l.rank[pos])
	hi := uint64(0x20010db8)<<32 | (cl.base + k<<(64-cl.bits))
	var a [16]byte
	binary.BigEndian.PutUint64(a[:8], hi)
	return netip.PrefixFrom(netip.AddrFrom16(a), cl.bits)
}

// maxV6 is the most IPv6 prefixes the table can hold (2001:db8::/32 split
// at /64), less the rounding of the last pattern.
const maxV6 = 1<<32 - patternLen

// prefix returns entry i.
func (t table) prefix(i int) netip.Prefix {
	if i < v4Count {
		block := docV4[i/511]
		j := i % 511               // 0: the /24, 1-2: /25s, 3-6: /26s, ...
		l := bits.Len(uint(j + 1)) // 1 for the /24
		k := j + 1 - 1<<(l-1)      // index within that length
		bitsLen := 24 + l - 1
		a := block.Addr().As4()
		a[3] = byte(k << (32 - bitsLen))
		return netip.PrefixFrom(netip.AddrFrom4(a), bitsLen)
	}
	return t.v6.prefix(i - v4Count)
}

// host is a destination address inside entry i, for flow records.
func (t table) host(i int) netip.Addr {
	p := t.prefix(i)
	if p.Addr().Is4() {
		if p.Bits() == 32 {
			return p.Addr()
		}
		return p.Addr().Next()
	}
	return p.Addr().Next()
}

// group is the run of consecutive entries that share attributes, the way a
// real table has runs of prefixes with one attribute set. The router packs
// a group into one UPDATE.
func (t table) group(i int) int { return i / t.setLen }

// provider is the index (0 or 1) of the provider entry i is native on.
func (t table) provider(i int) int { return t.group(i) & 1 }

// attrSet is the path attributes of one group, besides the next hop.
type attrSet struct {
	path   []uint32
	origin uint8
	med    uint32
	hasMED bool
	comms  []uint32
	large  [][3]uint32
}

// attrs derives the attribute set of entry i from its group number and the
// shape: AS path length, origin, MED, communities and large communities are
// drawn from the dump's counts. Every AS number is a documentation ASN.
func (t table) attrs(i int) attrSet {
	g := uint64(t.group(i))
	rng := rand.New(rand.NewPCG(g, 341))
	var a attrSet
	a.path = make([]uint32, t.pathLen.Pick(rng.Uint64()))
	for j := range a.path {
		a.path[j] = docASNs[rng.IntN(len(docASNs))]
	}
	a.origin = uint8(t.origin.Pick(rng.Uint64()))
	if rng.Uint64N(t.routes) < t.medRoutes {
		a.hasMED, a.med = true, uint32(10*rng.IntN(100))
	}
	for range t.comms.Pick(rng.Uint64()) {
		a.comms = append(a.comms, docASNs[rng.IntN(16)]<<16|uint32(100+rng.IntN(commValues)))
	}
	for range t.large.Pick(rng.Uint64()) {
		a.large = append(a.large, [3]uint32{docASNs[rng.IntN(len(docASNs))], uint32(rng.IntN(1000)), uint32(rng.IntN(1000))})
	}
	return a
}

// index is the entry whose prefix is p, the inverse of prefix. ok is false
// when p is not in the table.
func (t table) index(p netip.Prefix) (i int, ok bool) {
	if p.Addr().Is4() {
		for b, block := range docV4 {
			if !block.Contains(p.Addr()) || p.Bits() < 24 {
				continue
			}
			l := p.Bits() - 23
			k := int(p.Addr().As4()[3]) >> (32 - p.Bits())
			i = b*511 + 1<<(l-1) - 1 + k
			return i, i < t.n && t.prefix(i) == p
		}
		return 0, false
	}
	if t.v6 == nil || !docV6.Contains(p.Addr()) {
		return 0, false
	}
	j, ok := t.v6.index(p)
	if !ok || v4Count+j >= t.n {
		return 0, false
	}
	return v4Count + j, true
}

// index is the IPv6 entry (counted from the first IPv6 entry) whose prefix
// is p.
func (l *v6Layout) index(p netip.Prefix) (int, bool) {
	a := p.Addr().As16()
	off := binary.BigEndian.Uint64(a[:8]) & (1<<32 - 1)
	for c, cl := range l.classes {
		if cl.bits != p.Bits() || off < cl.base {
			continue
		}
		k := (off - cl.base) >> (64 - cl.bits)
		cycle, rank := k/uint64(cl.perCycle), k%uint64(cl.perCycle)
		pos, ok := l.slot(uint8(c), uint16(rank))
		if !ok {
			return 0, false
		}
		j := cycle*patternLen + uint64(pos)
		if j > uint64(maxV6) || l.prefix(int(j)) != p {
			return 0, false
		}
		return int(j), true
	}
	return 0, false
}

// slot is the pattern position of the rank-th entry of class c. A scan
// of the 4096 positions is cheap at the rate Packeteer sends routes.
func (l *v6Layout) slot(c uint8, rank uint16) (int, bool) {
	for pos := range patternLen {
		if l.pattern[pos] == c && l.rank[pos] == rank {
			return pos, true
		}
	}
	return 0, false
}
