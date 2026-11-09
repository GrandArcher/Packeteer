package main

import (
	"bufio"
	"bytes"
	"cmp"
	"compress/bzip2"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/bits"
	"net/netip"
	"os"
	"slices"
	"sort"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/packet/mrt"
)

// A real table (#342) is one peer's full view from a RIPE RIS or
// RouteViews MRT TABLE_DUMP_V2 file that the caller downloaded. It lives
// only in memory: nothing here writes a prefix to a file, and no error or
// log line names one. The router plays it exactly as it plays the
// synthetic table, with next hops rewritten to the lab provider addresses.

// realEntry is one prefix and the attribute set it carries.
type realEntry struct {
	prefix netip.Prefix
	set    uint32
}

// realTable is one session's view: a peer's routes, IPv4 first. Within a
// family the entries are ordered by attribute set, so a router packs a set
// into UPDATEs the way a router that groups its table dump by attributes
// does.
type realTable struct {
	entries []realEntry
	sets    [][]bgp.PathAttributeInterface // sorted by type code, with LOCAL_PREF; shared by every view
	v4      int                            // entries[:v4] are IPv4
	// pinned makes every route of this view use provider via as its next
	// hop. Several views are several providers' routes to the same
	// prefixes; one view alone keeps the next hop by attribute set.
	pinned bool
	via    int
}

// realSet is what a dump gave the lab: one view per session, over the same
// prefixes (a view lacks the prefixes its peer did not carry).
type realSet struct {
	views    []*realTable
	prefixes int // distinct prefixes over all views
	paths    int // routes over all views
	peers    int // peers in the dump with at least one route
	skipped  int // routes left out: malformed prefix or attributes
	derived  int // prefixes added by realOpts.scaleTo
	v4       int // distinct IPv4 prefixes
}

func (r *realSet) info() *TableInfo {
	return &TableInfo{Peers: r.peers, Views: len(r.views), IPv4: r.v4, IPv6: r.prefixes - r.v4,
		Sets: len(r.views[0].sets), Skipped: r.skipped, Derived: r.derived, Paths: r.paths}
}

// attrs is the attribute set of entry i. The slice has no spare capacity,
// so a caller's append (the next hop) never writes into the shared set.
func (t *realTable) attrs(i int) []bgp.PathAttributeInterface {
	return slices.Clip(t.sets[t.entries[i].set])
}

// keptTypes are the attributes a lab router passes on. The next hop is
// rewritten, LOCAL_PREF is set for the iBGP session, MP_REACH_NLRI is the
// session's own, and AS4_PATH and AS4_AGGREGATOR are for peers without
// four-octet AS numbers, which the lab session is not.
var keptTypes = map[uint8]bool{
	uint8(bgp.BGP_ATTR_TYPE_ORIGIN):               true,
	uint8(bgp.BGP_ATTR_TYPE_AS_PATH):              true,
	uint8(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC):      true,
	uint8(bgp.BGP_ATTR_TYPE_ATOMIC_AGGREGATE):     true,
	uint8(bgp.BGP_ATTR_TYPE_AGGREGATOR):           true,
	uint8(bgp.BGP_ATTR_TYPE_COMMUNITIES):          true,
	uint8(bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES): true,
	uint8(bgp.BGP_ATTR_TYPE_LARGE_COMMUNITY):      true,
}

// realOpts says which views of the dump to play.
type realOpts struct {
	// peers is how many peers' views to play, the ones with the most
	// routes, each on its own session. At least 1.
	peers int
	// scaleTo, when above the dump's prefix count, adds more-specifics of
	// the dump's own prefixes (each half of a prefix, with the parent's
	// attributes in every view that has the parent) until the table has
	// this many prefixes. IPv4 stops at /24 and IPv6 at /48. Zero keeps the
	// dump's table.
	scaleTo int
}

// realRow is one prefix over all views.
type realRow struct {
	prefix netip.Prefix
	sets   [maxViews]uint32 // per view: attribute set + 1; 0 when that peer has no route
}

// loadReal reads the dump at path and returns the views of the o.peers
// peers with the most routes.
func loadReal(path string, o realOpts) (*realSet, error) {
	if o.peers < 1 || o.peers > maxViews {
		return nil, fmt.Errorf("peers %d: want 1 to %d", o.peers, maxViews)
	}
	counts, err := peerRoutes(path)
	if err != nil {
		return nil, err
	}
	if len(counts) == 0 {
		return nil, errors.New("no IPv4 or IPv6 unicast routes in the dump")
	}
	if len(counts) < o.peers {
		return nil, fmt.Errorf("the dump has %d peers with routes, fewer than the %d views asked for", len(counts), o.peers)
	}
	ranked := slices.Collect(maps.Keys(counts))
	slices.SortFunc(ranked, func(a, b uint16) int { return cmp.Or(cmp.Compare(counts[b], counts[a]), cmp.Compare(a, b)) })
	view := map[uint16]int{}
	for k, peer := range ranked[:o.peers] {
		view[peer] = k
	}
	out := &realSet{peers: len(counts)}
	var sets [][]bgp.PathAttributeInterface
	ids := map[string]uint32{}
	var rows []realRow
	err = eachRoute(path, func(p netip.Prefix, entries []byte, n int) error {
		row := realRow{prefix: p}
		found := false
		for range n {
			peer, attrs, rest, err := nextEntry(entries)
			if err != nil {
				return err
			}
			entries = rest
			k, ok := view[peer]
			if !ok {
				continue
			}
			key, kept, err := splitAttrs(attrs)
			if err != nil {
				out.skipped++
				continue
			}
			id, ok := ids[key]
			if !ok {
				set, err := parseSet(kept)
				if err != nil {
					out.skipped++
					continue
				}
				id = uint32(len(sets))
				ids[key] = id
				sets = append(sets, set)
			}
			row.sets[k], found = id+1, true
		}
		if found {
			rows = append(rows, row)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errors.New("the played peers have no usable routes")
	}
	if o.scaleTo > 0 {
		base := len(rows)
		if rows, err = growRows(rows, o.scaleTo); err != nil {
			return nil, err
		}
		out.derived = len(rows) - base
	}
	out.prefixes = len(rows)
	for _, r := range rows {
		if r.prefix.Addr().Is4() {
			out.v4++
		}
	}
	for k := range o.peers {
		v := &realTable{sets: sets, pinned: o.peers > 1, via: k}
		for _, r := range rows {
			if id := r.sets[k]; id != 0 {
				v.entries = append(v.entries, realEntry{r.prefix, id - 1})
			}
		}
		slices.SortFunc(v.entries, func(a, b realEntry) int {
			return cmp.Or(
				cmp.Compare(a.prefix.Addr().BitLen(), b.prefix.Addr().BitLen()), // 32 before 128
				cmp.Compare(a.set, b.set),
				a.prefix.Addr().Compare(b.prefix.Addr()),
				cmp.Compare(a.prefix.Bits(), b.prefix.Bits()))
		})
		for v.v4 < len(v.entries) && v.entries[v.v4].prefix.Addr().Is4() {
			v.v4++
		}
		out.paths += len(v.entries)
		out.views = append(out.views, v)
	}
	return out, nil
}

// Splitting stops at the longest prefix a public table carries.
const (
	maxSplitV4 = 24
	maxSplitV6 = 48
	minSplit   = 8
)

func splittable(p netip.Prefix) bool {
	if p.Bits() < minSplit {
		return false
	}
	if p.Addr().Is4() {
		return p.Bits() < maxSplitV4
	}
	return p.Bits() < maxSplitV6
}

// halves are the two prefixes one bit longer than p.
func halves(p netip.Prefix) [2]netip.Prefix {
	b := p.Bits()
	if p.Addr().Is4() {
		a := p.Addr().As4()
		a[b/8] |= 0x80 >> (b % 8)
		return [2]netip.Prefix{netip.PrefixFrom(p.Addr(), b+1), netip.PrefixFrom(netip.AddrFrom4(a), b+1)}
	}
	a := p.Addr().As16()
	a[b/8] |= 0x80 >> (b % 8)
	return [2]netip.Prefix{netip.PrefixFrom(p.Addr(), b+1), netip.PrefixFrom(netip.AddrFrom16(a), b+1)}
}

// spread orders prefixes pseudo-randomly but the same way every run, so
// the more-specifics are spread over the whole table and not the low end
// of the address space.
func spread(p netip.Prefix) uint64 {
	a := p.Addr().As16()
	x := binary.BigEndian.Uint64(a[:8]) ^ bits.RotateLeft64(binary.BigEndian.Uint64(a[8:]), 21) ^ uint64(p.Bits())<<56
	x = (x ^ x>>30) * 0xbf58476d1ce4e5b9
	x = (x ^ x>>27) * 0x94d049bb133111eb
	return x ^ x>>31
}

// growRows adds more-specifics to rows until there are target prefixes. A
// generation splits each prefix that can still be split, in spread order;
// the children it adds are split in the next. A half the dump already has
// is left as the dump has it.
func growRows(rows []realRow, target int) ([]realRow, error) {
	if target < len(rows) {
		return nil, fmt.Errorf("scale_to %d is below the dump's %d prefixes", target, len(rows))
	}
	have := make(map[netip.Prefix]struct{}, target)
	var frontier []int
	for i, r := range rows {
		have[r.prefix] = struct{}{}
		if splittable(r.prefix) {
			frontier = append(frontier, i)
		}
	}
	rows = slices.Grow(rows, target-len(rows))
	for len(rows) < target {
		if len(frontier) == 0 {
			return nil, fmt.Errorf("the dump cannot reach %d prefixes: splitting down to /%d and /%d stops at %d", target, maxSplitV4, maxSplitV6, len(rows))
		}
		slices.SortFunc(frontier, func(a, b int) int { return cmp.Compare(spread(rows[a].prefix), spread(rows[b].prefix)) })
		var next []int
		for _, pi := range frontier {
			parent := rows[pi]
			for _, c := range halves(parent.prefix) {
				if len(rows) == target {
					break
				}
				if _, ok := have[c]; ok {
					continue
				}
				have[c] = struct{}{}
				rows = append(rows, realRow{prefix: c, sets: parent.sets})
				if splittable(c) {
					next = append(next, len(rows)-1)
				}
			}
		}
		frontier = next
	}
	return rows, nil
}

// peerRoutes counts the routes of every peer in the dump.
func peerRoutes(path string) (map[uint16]int, error) {
	counts := map[uint16]int{}
	err := eachRoute(path, func(_ netip.Prefix, entries []byte, n int) error {
		for range n {
			peer, _, rest, err := nextEntry(entries)
			if err != nil {
				return err
			}
			counts[peer]++
			entries = rest
		}
		return nil
	})
	return counts, err
}

// eachRoute calls fn for every IPv4 and IPv6 unicast RIB record with its
// prefix, the entry count, and the bytes of the entries.
func eachRoute(path string, fn func(p netip.Prefix, entries []byte, n int) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 1<<20)
	var r io.Reader = br
	head, _ := br.Peek(3)
	switch {
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		gz, err := gzip.NewReader(br)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = gz
	case bytes.HasPrefix(head, []byte("BZh")):
		r = bzip2.NewReader(br)
	}
	r = bufio.NewReaderSize(r, 1<<20)
	hdr := make([]byte, mrt.MRT_COMMON_HEADER_LEN)
	var body []byte
	for {
		if _, err := io.ReadFull(r, hdr); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		h := &mrt.MRTHeader{}
		if err := h.DecodeFromBytes(hdr); err != nil {
			return err
		}
		if h.Len > maxRecord {
			return fmt.Errorf("MRT record of %d bytes", h.Len)
		}
		body = slices.Grow(body[:0], int(h.Len))[:h.Len]
		if _, err := io.ReadFull(r, body); err != nil {
			return err
		}
		if h.Type != mrt.TABLE_DUMPv2 {
			continue
		}
		var v6 bool
		switch mrt.MRTSubTypeTableDumpv2(h.SubType) {
		case mrt.RIB_IPV4_UNICAST:
		case mrt.RIB_IPV6_UNICAST:
			v6 = true
		default:
			continue
		}
		p, entries, n, err := ribRecord(body, v6)
		if err != nil {
			return err
		}
		if err := fn(p, entries, n); err != nil {
			return err
		}
	}
}

// maxRecord bounds one MRT record. A RIB record holds one prefix and an
// entry per peer, well under this.
const maxRecord = 1 << 24

var errShort = errors.New("MRT record is shorter than its fields")

// ribRecord splits a RIB_IPV4_UNICAST or RIB_IPV6_UNICAST body: a sequence
// number, the prefix, and the entries.
func ribRecord(b []byte, v6 bool) (p netip.Prefix, entries []byte, n int, err error) {
	if len(b) < 5 {
		return p, nil, 0, errShort
	}
	bitsLen, width := int(b[4]), 4
	if v6 {
		width = 16
	}
	size := (bitsLen + 7) / 8
	if bitsLen > width*8 || len(b) < 5+size+2 {
		return p, nil, 0, fmt.Errorf("MRT record has a prefix length of %d bits", bitsLen)
	}
	var a [16]byte
	copy(a[:], b[5:5+size])
	addr := netip.AddrFrom4([4]byte(a[:4]))
	if v6 {
		addr = netip.AddrFrom16(a)
	}
	p = netip.PrefixFrom(addr, bitsLen).Masked()
	n = int(binary.BigEndian.Uint16(b[5+size:]))
	return p, b[5+size+2:], n, nil
}

// nextEntry reads one RIB entry: the peer index, the originated time, and
// the attributes.
func nextEntry(b []byte) (peer uint16, attrs, rest []byte, err error) {
	if len(b) < 8 {
		return 0, nil, nil, errShort
	}
	n := int(binary.BigEndian.Uint16(b[6:8]))
	if len(b) < 8+n {
		return 0, nil, nil, errShort
	}
	return binary.BigEndian.Uint16(b), b[8 : 8+n], b[8+n:], nil
}

// splitAttrs returns the attributes worth keeping, each with its header,
// and their bytes as a key, so equal sets share one entry whatever next hop
// the dump carried.
func splitAttrs(b []byte) (key string, kept [][]byte, err error) {
	var k []byte
	for len(b) > 0 {
		if len(b) < 3 {
			return "", nil, errShort
		}
		hdr, n := 3, int(b[2])
		if bgp.BGPAttrFlag(b[0])&bgp.BGP_ATTR_FLAG_EXTENDED_LENGTH != 0 {
			if len(b) < 4 {
				return "", nil, errShort
			}
			hdr, n = 4, int(binary.BigEndian.Uint16(b[2:4]))
		}
		if len(b) < hdr+n {
			return "", nil, errShort
		}
		if keptTypes[b[1]] {
			kept = append(kept, b[:hdr+n])
			k = append(k, b[:hdr+n]...)
		}
		b = b[hdr+n:]
	}
	return string(k), kept, nil
}

// parseSet decodes the kept attributes and adds LOCAL_PREF. The lab session
// negotiates four-octet AS numbers, so the AS path and the aggregator are
// rebuilt in that form, whatever width the dump used.
func parseSet(kept [][]byte) ([]bgp.PathAttributeInterface, error) {
	var set []bgp.PathAttributeInterface
	for _, raw := range kept {
		raw = slices.Clone(raw) // the dump's read buffer is reused
		a, err := bgp.GetPathAttribute(raw)
		if err != nil {
			return nil, err
		}
		if err := a.DecodeFromBytes(raw); err != nil {
			return nil, err
		}
		switch v := a.(type) {
		case *bgp.PathAttributeAsPath:
			params := make([]bgp.AsPathParamInterface, len(v.Value))
			for i, p := range v.Value {
				params[i] = bgp.NewAs4PathParam(p.GetType(), p.GetAS())
			}
			a = bgp.NewPathAttributeAsPath(params)
		case *bgp.PathAttributeAggregator:
			if v.Value.Address.To4() == nil {
				continue
			}
			a = bgp.NewPathAttributeAggregator(v.Value.AS, v.Value.Address.String())
		}
		set = append(set, a)
	}
	set = append(set, bgp.NewPathAttributeLocalPref(100))
	sort.SliceStable(set, func(i, j int) bool { return set[i].GetType() < set[j].GetType() })
	return set, nil
}
