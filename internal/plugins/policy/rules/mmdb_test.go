package rules

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// writeCountryDB writes a tiny MaxMind-format country database for tests.
// It maps each documentation prefix to country.iso_code. Real GeoIP data is
// never committed to the repository.
func writeCountryDB(t *testing.T, entries map[string]string) string {
	t.Helper()
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
			mmdbMap(&data, 1)
			mmdbString(&data, "country")
			mmdbMap(&data, 1)
			mmdbString(&data, "iso_code")
			mmdbString(&data, code)
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
	mmdbMap(&out, 7)
	mmdbString(&out, "node_count")
	mmdbUint(&out, 6, uint64(count))
	mmdbString(&out, "record_size")
	mmdbUint(&out, 5, 24)
	mmdbString(&out, "ip_version")
	mmdbUint(&out, 5, 6)
	mmdbString(&out, "database_type")
	mmdbString(&out, "Packeteer-Test-Country")
	mmdbString(&out, "binary_format_major_version")
	mmdbUint(&out, 5, 2)
	mmdbString(&out, "binary_format_minor_version")
	mmdbUint(&out, 5, 0)
	mmdbString(&out, "build_epoch")
	mmdbUint(&out, 9, 1)

	path := filepath.Join(t.TempDir(), "country.mmdb")
	if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func mmdbCtrl(w *bytes.Buffer, typ, size int) {
	if size >= 29 {
		panic("mmdb test writer: size too large")
	}
	if typ <= 7 {
		w.WriteByte(byte(typ<<5 | size))
		return
	}
	w.WriteByte(byte(size))
	w.WriteByte(byte(typ - 7))
}

func mmdbString(w *bytes.Buffer, s string) {
	mmdbCtrl(w, 2, len(s))
	w.WriteString(s)
}

func mmdbMap(w *bytes.Buffer, n int) { mmdbCtrl(w, 7, n) }

func mmdbUint(w *bytes.Buffer, typ int, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	i := 0
	for i < 8 && b[i] == 0 {
		i++
	}
	mmdbCtrl(w, typ, 8-i)
	w.Write(b[i:])
}

func writeFile(path, s string) error { return os.WriteFile(path, []byte(s), 0o644) }
