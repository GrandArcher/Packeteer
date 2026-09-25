package flow

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// slide sums bytes per prefix over a window of fixed buckets. Each bucket
// keeps at most max prefixes so a scan of unique destinations cannot grow
// memory without bound. Raw flow records are not retained.
type slide struct {
	mu     sync.Mutex
	window time.Duration
	bucket time.Duration
	max    int
	slots  map[int64]*bucket
}

type bucket struct {
	cells map[netip.Prefix]*cell
	minP  netip.Prefix
	minB  uint64
	minOK bool
}

type cell struct {
	bytes     uint64
	host      netip.Addr
	hostBytes uint64
}

type rank struct {
	prefix netip.Prefix
	host   netip.Addr
	bytes  uint64
}

func newSlide(window time.Duration, max int) *slide {
	b := window / 30
	if b < time.Second {
		b = time.Second
	}
	if max < 1 {
		max = 1
	}
	return &slide{window: window, bucket: b, max: max, slots: map[int64]*bucket{}}
}

func (s *slide) add(at time.Time, p netip.Prefix, host netip.Addr, n uint64) {
	if n == 0 || !p.IsValid() {
		return
	}
	p = p.Masked()
	s.mu.Lock()
	defer s.mu.Unlock()
	slot := at.UnixNano() / int64(s.bucket)
	b := s.slots[slot]
	if b == nil {
		b = &bucket{cells: map[netip.Prefix]*cell{}}
		s.slots[slot] = b
	}
	b.add(p, host, n, s.max)
	s.prune(at)
}

func (b *bucket) add(p netip.Prefix, host netip.Addr, n uint64, max int) {
	if c, ok := b.cells[p]; ok {
		c.bytes += n
		if host.IsValid() && host == c.host {
			c.hostBytes += n
		} else if host.IsValid() && n >= c.hostBytes {
			c.host = host
			c.hostBytes = n
		}
		if b.minOK && p == b.minP {
			b.minOK = false
		}
		return
	}
	if len(b.cells) >= max {
		if !b.minOK {
			b.recomputeMin()
		}
		if b.minOK && n <= b.minB {
			return
		}
		if b.minOK {
			delete(b.cells, b.minP)
			b.minOK = false
		}
	}
	c := &cell{bytes: n}
	if host.IsValid() {
		c.host = host
		c.hostBytes = n
	}
	b.cells[p] = c
}

func (b *bucket) recomputeMin() {
	first := true
	for p, c := range b.cells {
		if first || c.bytes < b.minB || (c.bytes == b.minB && p.String() < b.minP.String()) {
			b.minP = p
			b.minB = c.bytes
			first = false
		}
	}
	b.minOK = !first
}

func (s *slide) prune(now time.Time) {
	cutoff := now.Add(-s.window)
	for slot := range s.slots {
		start := time.Unix(0, slot*int64(s.bucket))
		if !start.Add(s.bucket).After(cutoff) {
			delete(s.slots, slot)
		}
	}
}

func (s *slide) top(now time.Time, n int, minBytes uint64) []rank {
	rows := s.aggregate(now)
	out := make([]rank, 0, len(rows))
	for _, r := range rows {
		if r.bytes == 0 || r.bytes < minBytes {
			continue
		}
		out = append(out, r)
	}
	if n < len(out) {
		out = out[:n]
	}
	return out
}

// totals returns every prefix in the window, largest first, capped at max.
// Unlike top, it does not apply min_bytes: commit control needs the volume
// of a prefix another source is already probing.
func (s *slide) totals(now time.Time, max int) []rank {
	rows := s.aggregate(now)
	if max > 0 && len(rows) > max {
		rows = rows[:max]
	}
	return rows
}

func (s *slide) aggregate(now time.Time) []rank {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(now)
	acc := map[netip.Prefix]*cell{}
	for _, b := range s.slots {
		for p, c := range b.cells {
			a := acc[p]
			if a == nil {
				a = &cell{}
				acc[p] = a
			}
			a.bytes += c.bytes
			if c.host.IsValid() && c.hostBytes >= a.hostBytes {
				a.host = c.host
				a.hostBytes = c.hostBytes
			}
		}
	}
	out := make([]rank, 0, len(acc))
	for p, a := range acc {
		if a.bytes == 0 {
			continue
		}
		out = append(out, rank{prefix: p, host: a.host, bytes: a.bytes})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].bytes != out[j].bytes {
			return out[i].bytes > out[j].bytes
		}
		return out[i].prefix.String() < out[j].prefix.String()
	})
	return out
}
