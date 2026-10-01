package main

import (
	"context"
	"encoding/binary"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

// IPFIX information elements the exporter sends (RFC 7012).
const (
	ieOctets   = 1
	ieProtocol = 4
	ieSrcV4    = 8
	ieDstV4    = 12
	ieSrcV6    = 27
	ieDstV6    = 28

	tmplV4 = 256
	tmplV6 = 257

	recV4 = 8 + 1 + 4 + 4 // octets, protocol, src, dst
	recV6 = 8 + 1 + 16 + 16

	maxPayload = 1400
)

// Flow sources: the lab's own documentation addresses.
var (
	flowSrcV4 = netip.MustParseAddr("192.0.2.200").As4()
	flowSrcV6 = netip.MustParseAddr("2001:db8:ffff:ffff::200").As16()
)

// exporter sends IPFIX for destinations across the table. Half the
// records go to a hot set (the first hot entries), so the busiest
// prefixes stay stable, and half are spread over the whole table.
type exporter struct {
	tbl table
	hot int
	rng *rand.Rand
	seq uint32
	// next is an entry picked for the previous message that did not fit
	// its family; -1 when none.
	next int
	sent atomic.Uint64 // records
	pkts atomic.Uint64
}

func newExporter(tbl table, hot int) *exporter {
	if hot <= 0 || hot > tbl.n {
		hot = tbl.n
	}
	return &exporter{tbl: tbl, hot: hot, rng: rand.New(rand.NewPCG(51, 51)), next: -1}
}

func (e *exporter) pick() int {
	if e.rng.IntN(2) == 0 {
		return e.rng.IntN(e.hot)
	}
	return e.rng.IntN(e.tbl.n)
}

func header(b []byte, length int, seq uint32, now time.Time) {
	binary.BigEndian.PutUint16(b[0:], 10)
	binary.BigEndian.PutUint16(b[2:], uint16(length))
	binary.BigEndian.PutUint32(b[4:], uint32(now.Unix()))
	binary.BigEndian.PutUint32(b[8:], seq)
	binary.BigEndian.PutUint32(b[12:], 51) // observation domain
}

// templates is one IPFIX message with both templates.
func (e *exporter) templates(now time.Time) []byte {
	field := func(b []byte, ie, l uint16) []byte {
		b = binary.BigEndian.AppendUint16(b, ie)
		return binary.BigEndian.AppendUint16(b, l)
	}
	b := make([]byte, 16, 64)
	b = binary.BigEndian.AppendUint16(b, 2) // template set
	setLen := len(b)
	b = append(b, 0, 0)
	for _, t := range []struct {
		id       uint16
		src, dst uint16
		l        uint16
	}{{tmplV4, ieSrcV4, ieDstV4, 4}, {tmplV6, ieSrcV6, ieDstV6, 16}} {
		b = binary.BigEndian.AppendUint16(b, t.id)
		b = binary.BigEndian.AppendUint16(b, 4)
		b = field(b, ieOctets, 8)
		b = field(b, ieProtocol, 1)
		b = field(b, t.src, t.l)
		b = field(b, t.dst, t.l)
	}
	binary.BigEndian.PutUint16(b[setLen:], uint16(len(b)-setLen+2))
	header(b, len(b), e.seq, now)
	return b
}

// data builds one message of up to maxPayload bytes with n records at
// most, all of one family. It returns the message and the records in it.
func (e *exporter) data(now time.Time, n int) ([]byte, int) {
	b := make([]byte, 16, maxPayload)
	b = append(b, 0, 0, 0, 0) // set header
	v6 := -1
	recs := 0
	for recs < n {
		i := e.next
		if i < 0 {
			i = e.pick()
		}
		dst := e.tbl.host(i)
		is6 := dst.Is6()
		size := recV4
		if is6 {
			size = recV6
		}
		if v6 == -1 {
			v6 = 0
			if is6 {
				v6 = 1
			}
		} else if is6 != (v6 == 1) || len(b)+size > maxPayload {
			e.next = i // one family per set; this one starts the next message
			break
		}
		e.next = -1
		b = binary.BigEndian.AppendUint64(b, uint64(1000+e.rng.IntN(64000)))
		proto := byte(6)
		if i%3 == 0 {
			proto = 17
		}
		b = append(b, proto)
		if is6 {
			b = append(b, flowSrcV6[:]...)
			a := dst.As16()
			b = append(b, a[:]...)
		} else {
			b = append(b, flowSrcV4[:]...)
			a := dst.As4()
			b = append(b, a[:]...)
		}
		recs++
	}
	id := uint16(tmplV4)
	if v6 == 1 {
		id = tmplV6
	}
	binary.BigEndian.PutUint16(b[16:], id)
	binary.BigEndian.PutUint16(b[18:], uint16(len(b)-16))
	header(b, len(b), e.seq, now)
	e.seq += uint32(recs)
	return b, recs
}

// run sends rate records per second to addr until ctx ends, with the
// templates once a second.
func (e *exporter) run(ctx context.Context, addr string, rate int) error {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	const tick = 10 * time.Millisecond
	t := time.NewTicker(tick)
	defer t.Stop()
	var owed float64
	lastTmpl := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-t.C:
			if now.Sub(lastTmpl) >= time.Second {
				if _, err := conn.Write(e.templates(now)); err == nil {
					lastTmpl = now
				}
			}
			owed += float64(rate) * tick.Seconds()
			for owed >= 1 {
				msg, n := e.data(now, int(owed))
				if n == 0 {
					break
				}
				// A send error (the collector is not up yet: ICMP port
				// unreachable) is not fatal; the records count as sent and
				// show up as loss.
				_, _ = conn.Write(msg)
				owed -= float64(n)
				e.sent.Add(uint64(n))
				e.pkts.Add(1)
			}
		}
	}
}
