package rib

import (
	"net/netip"
	"runtime"
	"testing"
)

func TestLookupSkipsEmptyLengths(t *testing.T) {
	v, err := New(Options{
		ASN: 64512, RouterID: netip.MustParseAddr("192.0.2.10"),
		Neighbors: []Neighbor{{Address: netip.MustParseAddr("192.0.2.1")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	pfx := netip.MustParsePrefix("198.51.100.0/24")
	v.routes[pfx] = Route{Prefix: pfx, Provider: "transit-a"}
	v.routeLens[24] = 1
	if rt, ok := v.Lookup(netip.MustParseAddr("198.51.100.9")); !ok || rt.Prefix != pfx {
		t.Fatalf("lookup = %+v %v", rt, ok)
	}
	// Nothing longer is learned, so the /24 still covers .200.
	if rt, ok := v.Lookup(netip.MustParseAddr("198.51.100.200")); !ok || rt.Prefix != pfx {
		t.Fatalf("cover = %+v %v", rt, ok)
	}
	if c, ok := v.Covering(netip.MustParsePrefix("198.51.100.128/25")); !ok || c.Prefix != pfx {
		t.Fatalf("covering = %+v %v", c, ok)
	}
	v.routeLens[24] = 0
	if _, ok := v.Lookup(netip.MustParseAddr("198.51.100.9")); ok {
		t.Fatal("length index said the /24 was absent and lookup still hit it")
	}
}

func TestPathSetPromoteAndDemote(t *testing.T) {
	var s pathSet
	k1 := adjKey{id: 1}
	k2 := adjKey{id: 2}
	s.set(k1, Route{PathID: 1})
	if s.many != nil || !s.has(k1) || s.n != 1 {
		t.Fatalf("single = %+v", s)
	}
	s.set(k2, Route{PathID: 2})
	if s.many == nil || s.n != 2 {
		t.Fatalf("promoted = %+v", s.n)
	}
	if s.del(k2) || s.many != nil || s.n != 1 || !s.has(k1) {
		t.Fatalf("demoted many=%v n=%d", s.many != nil, s.n)
	}
	if !s.del(k1) || s.n != 0 {
		t.Fatal("not empty")
	}
}

// TestSinglePathAdjIsCompact locks the full-table layout: one path per
// prefix stays inline. The old map-per-prefix was about 700 bytes.
func TestSinglePathAdjIsCompact(t *testing.T) {
	const n = 50000
	v := &View{adj: map[netip.Prefix]pathSet{}}
	nh := netip.MustParseAddr("192.0.2.1")
	nbr := netip.MustParseAddr("192.0.2.254")
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < n; i++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(i >> 16), byte(i >> 8), byte(i), 0}), 24)
		v.putAdj(p, map[adjKey]Route{
			{neighbor: nbr}: {Prefix: p, NextHop: nh, ASPath: []uint32{64496, 64500}},
		})
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	per := float64(after.HeapAlloc-before.HeapAlloc) / n
	t.Logf("single-path adj %.0f bytes/prefix", per)
	if per > 520 {
		t.Fatalf("single-path adj is %.0f bytes/prefix; want <= 520", per)
	}
	if len(v.adj) != n {
		t.Fatalf("len = %d", len(v.adj))
	}
}

func BenchmarkLookup(b *testing.B) {
	const n = 20000
	v := &View{routes: map[netip.Prefix]Route{}, adj: map[netip.Prefix]pathSet{}}
	addrs := make([]netip.Addr, n)
	for i := 0; i < n; i++ {
		a := netip.AddrFrom4([4]byte{byte(i >> 16), byte(i >> 8), byte(i), 1})
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(i >> 16), byte(i >> 8), byte(i), 0}), 24)
		v.routes[p] = Route{Prefix: p, Provider: "transit-a"}
		v.routeLens[24]++
		addrs[i] = a
	}
	b.ReportAllocs()
	b.ResetTimer()
	var sink Route
	for i := 0; i < b.N; i++ {
		sink, _ = v.lookupLocked(addrs[i%n], 32)
	}
	if sink.Prefix.Bits() == 0 && b.N > 0 {
		b.Fatal("lookup missed")
	}
}
