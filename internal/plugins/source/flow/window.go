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

// maxFlowHosts is how many destinations one prefix keeps. The probe
// engine takes three (#119). Each bucket stores only that many, so a
// prefix full of unique addresses cannot grow the window.
const maxFlowHosts = 3

type cell struct {
	bytes uint64
	// hosts is the busiest destinations in this bucket, largest first
	// is not required; aggregate sorts. nHosts is how many slots are used.
	hosts  [maxFlowHosts]hostCount
	nHosts int
	// local and transit are the bytes whose source was classified; both
	// stay zero without a transit block.
	local   uint64
	transit uint64
}

type hostCount struct {
	addr  netip.Addr
	bytes uint64
}

type rank struct {
	prefix  netip.Prefix
	host    netip.Addr
	hosts   []netip.Addr // busiest first, at most maxFlowHosts
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
		c.noteHost(host, n)
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
	c.noteHost(host, n)
	b.cells[p] = c
}

// noteHost keeps the busiest destinations in this bucket. A host already
// in the set accumulates. A new host takes a free slot, or replaces the
// smallest slot when this observation is at least that large. Bytes from
// a destination that never makes the set are not recovered later.
func (c *cell) noteHost(host netip.Addr, n uint64) {
	if !host.IsValid() || n == 0 {
		return
	}
	for i := 0; i < c.nHosts; i++ {
		if c.hosts[i].addr == host {
			c.hosts[i].bytes += n
			return
		}
	}
	if c.nHosts < maxFlowHosts {
		c.hosts[c.nHosts] = hostCount{addr: host, bytes: n}
		c.nHosts++
		return
	}
	small := 0
	for i := 1; i < c.nHosts; i++ {
		if c.hosts[i].bytes < c.hosts[small].bytes {
			small = i
		}
	}
	if n >= c.hosts[small].bytes {
		c.hosts[small] = hostCount{addr: host, bytes: n}
	}
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
	type acc struct {
		bytes, local, transit uint64
		hosts                 map[netip.Addr]uint64
	}
	sum := map[netip.Prefix]*acc{}
	for _, b := range s.slots {
		for p, c := range b.cells {
			a := sum[p]
			if a == nil {
				a = &acc{hosts: map[netip.Addr]uint64{}}
				sum[p] = a
			}
			a.bytes += c.bytes
			a.local += c.local
			a.transit += c.transit
			for i := 0; i < c.nHosts; i++ {
				h := c.hosts[i]
				if h.addr.IsValid() && h.bytes > 0 {
					a.hosts[h.addr] += h.bytes
				}
			}
		}
	}
	out := make([]rank, 0, len(sum))
	for p, a := range sum {
		if a.bytes == 0 {
			continue
		}
		hosts := topHosts(a.hosts)
		var host netip.Addr
		if len(hosts) > 0 {
			host = hosts[0]
		}
		out = append(out, rank{prefix: p, host: host, hosts: hosts, bytes: a.bytes, local: a.local, transit: a.transit})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].bytes != out[j].bytes {
			return out[i].bytes > out[j].bytes
		}
		return out[i].prefix.String() < out[j].prefix.String()
	})
	return out
}

// topHosts returns at most maxFlowHosts addresses, largest byte total
// first. Equal totals break by address so the order is stable.
func topHosts(sums map[netip.Addr]uint64) []netip.Addr {
	if len(sums) == 0 {
		return nil
	}
	list := make([]hostCount, 0, len(sums))
	for a, b := range sums {
		if a.IsValid() && b > 0 {
			list = append(list, hostCount{addr: a, bytes: b})
		}
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].bytes != list[j].bytes {
			return list[i].bytes > list[j].bytes
		}
		return list[i].addr.Compare(list[j].addr) < 0
	})
	if len(list) > maxFlowHosts {
		list = list[:maxFlowHosts]
	}
	out := make([]netip.Addr, len(list))
	for i, h := range list {
		out[i] = h.addr
	}
	return out
}
