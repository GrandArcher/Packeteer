// Package geoiptest writes tiny MaxMind-format country databases for tests
// and the FRR lab. Entries map a documentation prefix to an ISO code. Real
// GeoIP data is never committed to the repository.
package geoiptest

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"sort"
)

// Build returns a database mapping each prefix in entries (CIDR) to
// country.iso_code. Invalid prefixes panic: this is test tooling.
func Build(entries map[string]string) []byte {
	type node struct {
		kids [2]*node
		data int
	}
	newNode := func() *node { return &node{data: -1} }
	root := newNode()

	var data bytes.Buffer
	offsets := map[string]int{}
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		code := entries[k]
		off, ok := offsets[code]
		if !ok {
			off = data.Len()
			offsets[code] = off
			writeMap(&data, 1)
			writeString(&data, "country")
			writeMap(&data, 1)
			writeString(&data, "iso_code")
			writeString(&data, code)
		}
		p := netip.MustParsePrefix(k)
		var bits [16]byte
		depth := p.Bits()
		if p.Addr().Is4() {
			a4 := p.Addr().As4()
			copy(bits[12:], a4[:])
			depth += 96
		} else {
			bits = p.Addr().As16()
		}
		n := root
		for i := 0; i < depth; i++ {
			b := (bits[i/8] >> (7 - uint(i%8))) & 1
			if i == depth-1 {
				leaf := newNode()
				leaf.data = off
				n.kids[b] = leaf
				break
			}
			if n.kids[b] == nil || n.kids[b].data >= 0 {
				n.kids[b] = newNode()
			}
			n = n.kids[b]
		}
	}

	// Number interior nodes breadth first.
	var order []*node
	index := map[*node]int{}
	queue := []*node{root}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		index[n] = len(order)
		order = append(order, n)
		for _, k := range n.kids {
			if k != nil && k.data < 0 {
				queue = append(queue, k)
			}
		}
	}
	count := len(order)
	var tree bytes.Buffer
	for _, n := range order {
		for _, k := range n.kids {
			v := count // empty
			switch {
			case k == nil:
			case k.data >= 0:
				v = count + 16 + k.data
			default:
				v = index[k]
			}
			tree.Write([]byte{byte(v >> 16), byte(v >> 8), byte(v)})
		}
	}

	var out bytes.Buffer
	out.Write(tree.Bytes())
	out.Write(make([]byte, 16))
	out.Write(data.Bytes())
	out.WriteString("\xab\xcd\xefMaxMind.com")
	writeMap(&out, 7)
	writeString(&out, "node_count")
	writeUint(&out, 6, uint64(count))
	writeString(&out, "record_size")
	writeUint(&out, 5, 24)
	writeString(&out, "ip_version")
	writeUint(&out, 5, 6)
	writeString(&out, "database_type")
	writeString(&out, "Packeteer-Test-Country")
	writeString(&out, "binary_format_major_version")
	writeUint(&out, 5, 2)
	writeString(&out, "binary_format_minor_version")
	writeUint(&out, 5, 0)
	writeString(&out, "build_epoch")
	writeUint(&out, 9, 1)
	return out.Bytes()
}

func writeCtrl(w *bytes.Buffer, typ, size int) {
	if size >= 29 {
		panic("geoiptest: size too large")
	}
	if typ <= 7 {
		w.WriteByte(byte(typ<<5 | size))
		return
	}
	w.WriteByte(byte(size))
	w.WriteByte(byte(typ - 7))
}

func writeString(w *bytes.Buffer, s string) {
	writeCtrl(w, 2, len(s))
	w.WriteString(s)
}

func writeMap(w *bytes.Buffer, n int) { writeCtrl(w, 7, n) }

func writeUint(w *bytes.Buffer, typ int, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	i := 0
	for i < 8 && b[i] == 0 {
		i++
	}
	writeCtrl(w, typ, 8-i)
	w.Write(b[i:])
}
