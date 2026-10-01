package main

import (
	"math/bits"
	"net/netip"
)

// Documentation space only. The IPv4 part is every prefix from /24 to /32
// inside the three RFC 5737 blocks; the rest of the table is 2001:db8::/32
// (RFC 3849) split evenly at the shortest length that holds it.
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

// Documentation and private-use ASNs for AS paths (RFC 5398, RFC 6996).
var docASNs = []uint32{64496, 64497, 64498, 64499, 64500, 64501, 64502, 64503,
	64504, 64505, 64506, 64507, 64508, 64509, 64510, 64511, 65536, 65537, 65538}

// table is a synthetic full table of n prefixes. Entry i is computed, not
// stored, so the harness holds no copy beyond the router's own.
type table struct {
	n      int
	v6Bits int // length of the IPv6 prefixes
}

func newTable(n int) table {
	t := table{n: n, v6Bits: 32}
	if m := n - v4Count; m > 0 {
		t.v6Bits = 32 + bits.Len(uint(m-1))
		if t.v6Bits > 64 {
			t.v6Bits = 64
		}
	}
	return t
}

// maxV6 is the most IPv6 prefixes the table can hold (2001:db8::/32 split
// at /64).
const maxV6 = 1 << 32

func (t table) valid() bool { return t.n > 0 && t.n-v4Count <= maxV6 }

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
	k := uint64(i - v4Count)
	a := docV6.Addr().As16()
	// Index k sits in the bits right after /32, left-aligned to v6Bits.
	shift := uint(64 - t.v6Bits) // bits of the upper 64 left of the index
	hi := uint64(0x20010db8)<<32 | k<<shift
	for b := 0; b < 8; b++ {
		a[b] = byte(hi >> (56 - 8*b))
	}
	return netip.PrefixFrom(netip.AddrFrom16(a), t.v6Bits)
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

// group is the run of 64 consecutive entries that share attributes, the
// way a real table has runs of prefixes from one origin. The router packs
// a group into one UPDATE.
func (t table) group(i int) int { return i >> 6 }

// provider is the index (0 or 1) of the provider entry i is native on.
func (t table) provider(i int) int { return t.group(i) & 1 }

// asPath is a documentation-ASN path of length 1 to 4 for entry i.
func (t table) asPath(i int) []uint32 {
	g := t.group(i)
	out := make([]uint32, 1+g%4)
	for j := range out {
		out[j] = docASNs[(g/4+j*7)%len(docASNs)]
	}
	return out
}
