package flow

import (
	"net/netip"
	"runtime"
	"testing"
	"time"
)

// BenchmarkCellBytes reports the heap one exact prefix cell costs in a
// full bucket; docs/performance.md sizes max_prefixes from it.
func BenchmarkCellBytes(b *testing.B) {
	const cells = 200_000
	at := time.Unix(1_700_000_000, 0)
	host := netip.MustParseAddr("192.0.2.1")
	var before, after runtime.MemStats
	for range b.N {
		s := newSlide(5*time.Minute, cells)
		runtime.GC()
		runtime.ReadMemStats(&before)
		for i := range cells {
			p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 32)
			s.add(at, p, host, 100, trafficUnknown)
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/cells, "B/cell")
		runtime.KeepAlive(s)
	}
}
