package flow

import (
	"net/netip"
	"slices"
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
	// local and transit are the bytes whose source was classified; both
	// stay zero without a transit block.
	local   uint64
	transit uint64
}

type rank struct {
	prefix  netip.Prefix
	host    netip.Addr
	bytes   uint64
	local   uint64
	transit uint64
}

// traffic is the class of one observation's source.
type traffic uint8

const (
	trafficUnknown traffic = iota
	trafficLocal
	trafficTransit
)

func (c *cell) note(n uint64, t traffic) {
	switch t {
	case trafficLocal:
		c.local += n
	case trafficTransit:
		c.transit += n
	}
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

func (s *slide) add(at time.Time, p netip.Prefix, host netip.Addr, n uint64, t traffic) {
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
	b.add(p, host, n, t, s.max)
	s.prune(at)
}

func (b *bucket) add(p netip.Prefix, host netip.Addr, n uint64, t traffic, max int) {
	if c, ok := b.cells[p]; ok {
		c.bytes += n
		c.note(n, t)
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
	if len(b.cells) >= max && !b.evict(max/16+1, n) {
		return
	}
	c := &cell{bytes: n}
	c.note(n, t)
	if host.IsValid() {
		c.host = host
		c.hostBytes = n
	}
	b.cells[p] = c
}

// evict makes room in a full bucket for a prefix with n bytes. It drops up
// to k of the smallest cells, but only cells smaller than n, and reports
// whether any room was made. Freeing a batch at once keeps a full bucket
// from rescanning every cell on each new prefix: with a full-table flow
// mix nearly every record is a new prefix (#51).
func (b *bucket) evict(k int, n uint64) bool {
	if b.minOK && n <= b.minB {
		return false
	}
	vals := make([]uint64, 0, len(b.cells))
	for _, c := range b.cells {
		vals = append(vals, c.bytes)
	}
	slices.Sort(vals)
	// Only cells smaller than n may go, at most k of them.
	k = min(k, sort.Search(len(vals), func(i int) bool { return vals[i] >= n }))
	if k == 0 {
		// Nothing smaller than n: remember the minimum so the next
		// small prefix is refused without a scan.
		for p, c := range b.cells {
			if c.bytes == vals[0] {
				b.minP, b.minB, b.minOK = p, c.bytes, true
				break
			}
		}
		return false
	}
	thr := vals[k-1]
	ties := k - sort.Search(k, func(i int) bool { return vals[i] >= thr })
	for p, c := range b.cells {
		switch {
		case c.bytes < thr:
			delete(b.cells, p)
		case c.bytes == thr && ties > 0:
			delete(b.cells, p)
			ties--
		}
	}
	b.minOK = false
	return true
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
			a.local += c.local
			a.transit += c.transit
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
		out = append(out, rank{prefix: p, host: a.host, bytes: a.bytes, local: a.local, transit: a.transit})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].bytes != out[j].bytes {
			return out[i].bytes > out[j].bytes
		}
		return out[i].prefix.String() < out[j].prefix.String()
	})
	return out
}
