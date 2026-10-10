package flow

import (
	"bytes"
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
	// subCap is how many sub-ranges one prefix tracks per bucket (#121).
	// Zero turns sub-range counting off.
	subCap int
	// scratch is the eviction sort buffer. add holds mu, so one slice
	// serves every bucket and a full table does not allocate it per record.
	scratch []uint64
}

type bucket struct {
	cells map[netip.Prefix]*cell
	minP  netip.Prefix
	minB  uint64
	minOK bool
	// seen counts every prefix offered to this bucket, including ones the
	// exact map refused. It is a fixed-size sketch (#125).
	seen hll
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
	// subs are the busiest sub-ranges in this bucket (#121), at most the
	// slide's subCap. Nil unless sub-ranges are on and the prefix is
	// wider than the sub-range length.
	subs []subCount
}

// subCount is one sub-range's bytes in a bucket and its busiest
// destination in that bucket.
type subCount struct {
	prefix    netip.Prefix
	bytes     uint64
	host      netip.Addr
	hostBytes uint64
}

// subRank is one sub-range's window total and busiest destination.
type subRank struct {
	prefix netip.Prefix
	host   netip.Addr
	bytes  uint64
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
	subs    []subRank // busiest first; empty unless sub-ranges are on
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
	s.addSub(at, p, netip.Prefix{}, host, n, t)
}

// addSub is add with the destination's sub-range (#121). An invalid sub,
// or subCap zero, counts no sub-range.
func (s *slide) addSub(at time.Time, p, sub netip.Prefix, host netip.Addr, n uint64, t traffic) {
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
	b.add(p, sub, host, n, t, s.max, s.subCap, &s.scratch)
	s.prune(at)
}

func (b *bucket) add(p, sub netip.Prefix, host netip.Addr, n uint64, t traffic, max, subCap int, scratch *[]uint64) {
	b.seen.add(p)
	if c, ok := b.cells[p]; ok {
		c.bytes += n
		c.note(n, t)
		c.noteHost(host, n)
		c.noteSub(sub, host, n, subCap)
		if b.minOK && p == b.minP {
			b.minOK = false
		}
		return
	}
	if len(b.cells) >= max && !b.evict(max/16+1, n, scratch) {
		return
	}
	c := &cell{bytes: n}
	c.note(n, t)
	c.noteHost(host, n)
	c.noteSub(sub, host, n, subCap)
	b.cells[p] = c
}

// noteSub keeps the busiest sub-ranges in this bucket, the same way
// noteHost keeps destinations: a known sub-range accumulates, a new one
// takes a free slot or replaces the smallest when it is at least that
// large. Each sub-range keeps the destination with the most bytes seen
// in one step as its probe address.
func (c *cell) noteSub(sub netip.Prefix, host netip.Addr, n uint64, subCap int) {
	if subCap <= 0 || !sub.IsValid() || n == 0 {
		return
	}
	for i := range c.subs {
		sc := &c.subs[i]
		if sc.prefix != sub {
			continue
		}
		sc.bytes += n
		switch {
		case host == sc.host:
			sc.hostBytes += n
		case host.IsValid() && n > sc.hostBytes:
			sc.host, sc.hostBytes = host, n
		}
		return
	}
	nc := subCount{prefix: sub, bytes: n, host: host, hostBytes: n}
	if len(c.subs) < subCap {
		c.subs = append(c.subs, nc)
		return
	}
	small := 0
	for i := 1; i < len(c.subs); i++ {
		if c.subs[i].bytes < c.subs[small].bytes {
			small = i
		}
	}
	if n >= c.subs[small].bytes {
		c.subs[small] = nc
	}
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
func (b *bucket) evict(k int, n uint64, scratch *[]uint64) bool {
	if b.minOK && n <= b.minB {
		return false
	}
	vals := (*scratch)[:0]
	if cap(vals) < len(b.cells) {
		vals = make([]uint64, 0, len(b.cells))
	}
	for _, c := range b.cells {
		vals = append(vals, c.bytes)
	}
	slices.Sort(vals)
	*scratch = vals
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

// tracked is the distinct prefixes observed in the current window,
// including prefixes the exact cells did not keep.
func (s *slide) tracked(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(now)
	var acc hll
	for _, b := range s.slots {
		acc.merge(&b.seen)
	}
	return int(acc.estimate())
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
	rows, _, _ := s.aggregate(now, n, nil)
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

// totals returns the busiest prefixes in the window, largest first, capped
// at max. Unlike top, it does not apply min_bytes: commit control needs the
// volume of a prefix another source is already probing. max <= 0 returns
// every prefix.
func (s *slide) totals(now time.Time, max int) []rank {
	rows, _, _ := s.aggregate(now, max, nil)
	return rows
}

// tot is one prefix's bytes across the window, before any host list exists.
type tot struct {
	bytes, local, transit uint64
}

// aggregate merges the live buckets. limit is how many of the busiest
// prefixes receive a host list and a sub-range list. Zero keeps every
// prefix. must prefixes are kept as well when they have bytes, so a
// problem prefix outside the busiest set still has its flow hosts.
// total is every byte in the window, including prefixes left out of rows,
// so a percent floor is a share of the whole window. Host lists are not
// built for the prefixes left out: a full table would otherwise allocate
// one map per destination.
func (s *slide) aggregate(now time.Time, limit int, must []netip.Prefix) (rows []rank, total uint64, overflow bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(now)

	sum := make(map[netip.Prefix]tot)
	for _, b := range s.slots {
		for p, c := range b.cells {
			t := sum[p]
			t.bytes += c.bytes
			t.local += c.local
			t.transit += c.transit
			sum[p] = t
			if overflow || c.bytes > ^uint64(0)-total {
				total, overflow = ^uint64(0), true
				continue
			}
			total += c.bytes
		}
	}
	keep := pickTotals(sum, limit, must)

	type subAcc struct {
		bytes uint64
		hosts map[netip.Addr]uint64
	}
	type acc struct {
		tot
		hosts map[netip.Addr]uint64
		subs  map[netip.Prefix]*subAcc
	}
	full := make(map[netip.Prefix]*acc, len(keep))
	for p := range keep {
		t := sum[p]
		if t.bytes == 0 {
			continue
		}
		full[p] = &acc{tot: t}
	}
	for _, b := range s.slots {
		for p, c := range b.cells {
			a := full[p]
			if a == nil {
				continue
			}
			for i := 0; i < c.nHosts; i++ {
				h := c.hosts[i]
				if !h.addr.IsValid() || h.bytes == 0 {
					continue
				}
				if a.hosts == nil {
					a.hosts = map[netip.Addr]uint64{}
				}
				a.hosts[h.addr] += h.bytes
			}
			for _, sc := range c.subs {
				if a.subs == nil {
					a.subs = map[netip.Prefix]*subAcc{}
				}
				sa := a.subs[sc.prefix]
				if sa == nil {
					sa = &subAcc{hosts: map[netip.Addr]uint64{}}
					a.subs[sc.prefix] = sa
				}
				sa.bytes += sc.bytes
				if sc.host.IsValid() && sc.hostBytes > 0 {
					sa.hosts[sc.host] += sc.hostBytes
				}
			}
		}
	}
	out := make([]rank, 0, len(full))
	for p, a := range full {
		hosts := topHosts(a.hosts)
		var host netip.Addr
		if len(hosts) > 0 {
			host = hosts[0]
		}
		var subs []subRank
		for sp, sa := range a.subs {
			sh := topHosts(sa.hosts)
			if sa.bytes == 0 || len(sh) == 0 {
				continue
			}
			subs = append(subs, subRank{prefix: sp, host: sh[0], bytes: sa.bytes})
		}
		sort.Slice(subs, func(i, j int) bool {
			if subs[i].bytes != subs[j].bytes {
				return subs[i].bytes > subs[j].bytes
			}
			return subs[i].prefix.Addr().Compare(subs[j].prefix.Addr()) < 0
		})
		out = append(out, rank{prefix: p, host: host, hosts: hosts, bytes: a.bytes, local: a.local, transit: a.transit, subs: subs})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].bytes != out[j].bytes {
			return out[i].bytes > out[j].bytes
		}
		return prefixTextLess(out[i].prefix, out[j].prefix)
	})
	return out, total, overflow
}

// prefixTextLess is prefix text order without allocating the strings.
// Equal byte totals break by that order (#118).
func prefixTextLess(a, b netip.Prefix) bool {
	var ab, bb [64]byte
	as := a.AppendTo(ab[:0])
	bs := b.AppendTo(bb[:0])
	return bytes.Compare(as, bs) < 0
}

// totKey is a prefix and its window bytes, used to choose the busiest set.
type totKey struct {
	prefix netip.Prefix
	bytes  uint64
}

// worse is the eviction order for that set: fewer bytes, then a greater
// prefix text. The same order as the sorted ranks, reversed.
func worse(a, b totKey) bool {
	if a.bytes != b.bytes {
		return a.bytes < b.bytes
	}
	return prefixTextLess(b.prefix, a.prefix)
}

func siftUp(h []totKey, i int) {
	for i > 0 {
		p := (i - 1) / 2
		if !worse(h[i], h[p]) {
			break
		}
		h[i], h[p] = h[p], h[i]
		i = p
	}
}

func siftDown(h []totKey, i int) {
	n := len(h)
	for {
		l := 2*i + 1
		if l >= n {
			return
		}
		c := l
		if r := l + 1; r < n && worse(h[r], h[l]) {
			c = r
		}
		if !worse(h[c], h[i]) {
			return
		}
		h[i], h[c] = h[c], h[i]
		i = c
	}
}

func consider(h []totKey, limit int, x totKey) []totKey {
	if len(h) < limit {
		h = append(h, x)
		siftUp(h, len(h)-1)
		return h
	}
	if len(h) == 0 || !worse(h[0], x) {
		return h
	}
	h[0] = x
	siftDown(h, 0)
	return h
}

// pickTotals chooses the prefixes that receive a host list. limit <= 0
// keeps every prefix that has bytes. Otherwise it keeps limit of the
// busiest, plus any must prefix that has bytes.
func pickTotals(sum map[netip.Prefix]tot, limit int, must []netip.Prefix) map[netip.Prefix]struct{} {
	keep := make(map[netip.Prefix]struct{})
	if limit <= 0 {
		for p, t := range sum {
			if t.bytes > 0 {
				keep[p] = struct{}{}
			}
		}
		return keep
	}
	for _, p := range must {
		if t, ok := sum[p]; ok && t.bytes > 0 {
			keep[p] = struct{}{}
		}
	}
	h := make([]totKey, 0, min(limit, len(sum)))
	for p, t := range sum {
		if t.bytes == 0 {
			continue
		}
		if _, ok := keep[p]; ok {
			continue
		}
		h = consider(h, limit, totKey{prefix: p, bytes: t.bytes})
	}
	for _, k := range h {
		keep[k.prefix] = struct{}{}
	}
	return keep
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
