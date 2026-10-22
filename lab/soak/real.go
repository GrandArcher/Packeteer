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

// realTable is the chosen peer's routes, IPv4 first. Within a family the
// entries are ordered by attribute set, so a router packs a set into
// UPDATEs the way a router that groups its table dump by attributes does.
type realTable struct {
	entries []realEntry
	sets    [][]bgp.PathAttributeInterface // sorted by type code, with LOCAL_PREF
	v4      int                            // entries[:v4] are IPv4
	peers   int                            // peers in the dump with at least one route
	skipped int                            // routes left out: malformed prefix or attributes
}

func (t *realTable) info() *TableInfo {
	return &TableInfo{Peers: t.peers, IPv4: t.v4, IPv6: len(t.entries) - t.v4, Sets: len(t.sets), Skipped: t.skipped}
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

// loadReal reads the dump at path and returns the view of the peer with
// the most routes.
func loadReal(path string) (*realTable, error) {
	counts, err := peerRoutes(path)
	if err != nil {
		return nil, err
	}
	best, most := -1, 0
	for peer, n := range counts {
		if n > most || (n == most && int(peer) < best) {
			best, most = int(peer), n
		}
	}
	if best < 0 {
		return nil, errors.New("no IPv4 or IPv6 unicast routes in the dump")
	}
	t := &realTable{peers: len(counts)}
	ids := map[string]uint32{}
	err = eachRoute(path, func(p netip.Prefix, entries []byte, n int) error {
		for range n {
			peer, attrs, rest, err := nextEntry(entries)
			if err != nil {
				return err
			}
			entries = rest
			if int(peer) != best {
				continue
			}
			key, kept, err := splitAttrs(attrs)
			if err != nil {
				t.skipped++
				continue
			}
			id, ok := ids[key]
			if !ok {
				set, err := parseSet(kept)
				if err != nil {
					t.skipped++
					continue
				}
				id = uint32(len(t.sets))
				ids[key] = id
				t.sets = append(t.sets, set)
			}
			t.entries = append(t.entries, realEntry{p, id})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(t.entries, func(a, b realEntry) int {
		return cmp.Or(
			cmp.Compare(a.prefix.Addr().BitLen(), b.prefix.Addr().BitLen()), // 32 before 128
			cmp.Compare(a.set, b.set),
			a.prefix.Addr().Compare(b.prefix.Addr()),
			cmp.Compare(a.prefix.Bits(), b.prefix.Bits()))
	})
	for t.v4 < len(t.entries) && t.entries[t.v4].prefix.Addr().Is4() {
		t.v4++
	}
	if len(t.entries) == 0 {
		return nil, errors.New("the largest peer has no usable routes")
	}
	return t, nil
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
