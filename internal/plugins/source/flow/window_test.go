package flow

import (
	"runtime"
	"testing"
	"time"

	"net/netip"
)

func TestAggregateKeepsBusiestAndMust(t *testing.T) {
	s := newSlide(time.Minute, 100)
	now := time.Unix(1_700_000_000, 0)
	var small netip.Prefix
	for i := 1; i <= 30; i++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), 32)
		host := netip.AddrFrom4([4]byte{203, 0, 113, byte(i)})
		s.add(now, p, host, uint64(i)*1000, trafficUnknown)
		if i == 1 {
			small = p
		}
	}
	absent := netip.MustParsePrefix("192.0.2.0/24")
	rows, total, overflow := s.aggregate(now, 5, []netip.Prefix{small, absent})
	if overflow {
		t.Fatal("overflow")
	}
	// 1000 * (1+...+30) includes the prefixes left out of rows.
	if total != 465_000 {
		t.Fatalf("total %d, want 465000", total)
	}
	if len(rows) != 6 {
		t.Fatalf("rows %d, want the busiest 5 plus the must prefix", len(rows))
	}
	for i := 0; i < 5; i++ {
		want := uint64(30-i) * 1000
		if rows[i].bytes != want {
			t.Fatalf("row %d bytes %d, want %d", i, rows[i].bytes, want)
		}
	}
	if rows[5].prefix != small {
		t.Fatalf("must prefix = %s", rows[5].prefix)
	}
	got := rows[5].hosts
	wantHost := netip.AddrFrom4([4]byte{203, 0, 113, 1})
	if len(got) != 1 || got[0] != wantHost {
		t.Fatalf("must hosts %v", got)
	}
	// 50% of the whole window, not of the returned rows. The busiest
	// prefix is 30000/465000, under half, so the floor fails.
	if passesFloor(rows[0].bytes, total, overflow, 0, 500_000) {
		t.Fatal("percent floor used the truncated rows")
	}
}

func TestAggregateMergesHostsAcrossBuckets(t *testing.T) {
	s := newSlide(time.Minute, 100)
	p := netip.MustParsePrefix("203.0.113.0/24")
	h1 := netip.MustParseAddr("203.0.113.10")
	h2 := netip.MustParseAddr("203.0.113.20")
	t0 := time.Unix(1_700_000_000, 0)
	s.add(t0, p, h1, 100, trafficLocal)
	s.add(t0.Add(2*time.Second), p, h2, 300, trafficTransit)
	rows, total, overflow := s.aggregate(t0.Add(2*time.Second), 10, nil)
	if overflow || total != 400 || len(rows) != 1 {
		t.Fatalf("rows=%d total=%d overflow=%v", len(rows), total, overflow)
	}
	r := rows[0]
	if r.bytes != 400 || r.local != 100 || r.transit != 300 {
		t.Fatalf("bytes=%d local=%d transit=%d", r.bytes, r.local, r.transit)
	}
	if len(r.hosts) != 2 || r.hosts[0] != h2 || r.hosts[1] != h1 {
		t.Fatalf("hosts %v", r.hosts)
	}
}

func TestAggregateTieBreaksByPrefixText(t *testing.T) {
	s := newSlide(time.Minute, 100)
	now := time.Unix(1_700_000_000, 0)
	// "203.0.113.1/32" < "203.0.113.10/32" < "203.0.113.2/32".
	a := netip.MustParsePrefix("203.0.113.1/32")
	b := netip.MustParsePrefix("203.0.113.10/32")
	c := netip.MustParsePrefix("203.0.113.2/32")
	s.add(now, c, netip.Addr{}, 50, trafficUnknown)
	s.add(now, b, netip.Addr{}, 50, trafficUnknown)
	s.add(now, a, netip.Addr{}, 50, trafficUnknown)
	rows, total, overflow := s.aggregate(now, 2, nil)
	if overflow || total != 150 || len(rows) != 2 {
		t.Fatalf("rows=%d total=%d overflow=%v", len(rows), total, overflow)
	}
	if rows[0].prefix != a || rows[1].prefix != b {
		t.Fatalf("order %s %s", rows[0].prefix, rows[1].prefix)
	}
}

func TestAggregateHostListsStayBounded(t *testing.T) {
	s := newSlide(5*time.Minute, 20000)
	base := time.Unix(1_700_000_000, 0)
	const buckets = 30
	const per = 5000
	for b := range buckets {
		at := base.Add(time.Duration(b) * 10 * time.Second)
		for i := range per {
			var a [16]byte
			a[0], a[1], a[2], a[3] = 0x20, 0x01, 0x0d, 0xb8
			a[4] = byte(b)
			a[6], a[7] = byte(i>>8), byte(i)
			p := netip.PrefixFrom(netip.AddrFrom16(a), 64)
			s.add(at, p, netip.AddrFrom16(a), 1, trafficUnknown)
		}
	}
	now := base.Add(29 * 10 * time.Second)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	rows, total, overflow := s.aggregate(now, 100, nil)
	runtime.ReadMemStats(&after)
	if overflow {
		t.Fatal("overflow")
	}
	if len(rows) != 100 {
		t.Fatalf("rows %d", len(rows))
	}
	if total != buckets*per {
		t.Fatalf("total %d, want %d", total, buckets*per)
	}
	// One host map per prefix is about 50 MiB before the sort. The sum
	// of bytes is a fraction of that. A regression that materializes
	// every host list fails this ceiling.
	delta := after.TotalAlloc - before.TotalAlloc
	if delta > 48<<20 {
		t.Fatalf("aggregate allocated %d bytes", delta)
	}
}
