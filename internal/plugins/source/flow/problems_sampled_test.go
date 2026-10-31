package flow

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

var (
	sLocal  = netip.MustParseAddr("192.0.2.10")
	sBad    = netip.MustParseAddr("203.0.113.20")
	sGood   = netip.MustParseAddr("198.51.100.10")
	sBad24  = netip.MustParsePrefix("203.0.113.0/24")
	sGood24 = netip.MustParsePrefix("198.51.100.0/24")
)

// sflowTCPHeader is an sFlow raw-header record holding an Ethernet frame
// with an IPv4 or IPv6 header and the first 20 bytes of a TCP header.
func sflowTCPHeader(src, dst netip.Addr, flags uint8) []byte {
	var hdr []byte
	if src.Is4() {
		hdr = make([]byte, 14+20+20)
		hdr[12], hdr[13] = 0x08, 0x00
		ip := hdr[14:]
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], 40)
		ip[9] = 6
		copy(ip[12:16], src.AsSlice())
		copy(ip[16:20], dst.AsSlice())
		ip[20+13] = flags
	} else {
		hdr = make([]byte, 14+40+20)
		hdr[12], hdr[13] = 0x86, 0xdd
		ip := hdr[14:]
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:], 20)
		ip[6] = 6
		copy(ip[8:24], src.AsSlice())
		copy(ip[24:40], dst.AsSlice())
		ip[40+13] = flags
	}
	raw := make([]byte, 16+len(hdr))
	binary.BigEndian.PutUint32(raw[0:], sflowHeaderEthernet)
	binary.BigEndian.PutUint32(raw[4:], uint32(len(hdr)))
	binary.BigEndian.PutUint32(raw[12:], uint32(len(hdr)))
	copy(raw[16:], hdr)
	return record(sflowRawHeader, raw)
}

// sflowPackets is one datagram of single-packet samples, one per flag byte.
func sflowPackets(rate uint32, src, dst netip.Addr, flags ...uint8) []byte {
	var samples [][]byte
	for _, f := range flags {
		samples = append(samples, flowSampleBody(rate, sflowTCPHeader(src, dst, f)))
	}
	return sflowDatagram(samples...)
}

func repeat(f uint8, n int) []uint8 {
	out := make([]uint8, n)
	for i := range out {
		out[i] = f
	}
	return out
}

func TestSFlowDecodesTCPFlags(t *testing.T) {
	dec := func(b []byte) observation {
		t.Helper()
		obs, err := (&decoder{}).decode(netip.MustParseAddr("192.0.2.8"), b)
		if err != nil || len(obs) != 1 {
			t.Fatalf("decode = %v, %v", obs, err)
		}
		return obs[0]
	}
	rst := dec(sflowPackets(512, sBad, sLocal, tcpRST|tcpACK))
	if !rst.haveFlags || rst.tcpFlags != tcpRST|tcpACK || rst.proto != 6 || !rst.sampled || rst.rate != 512 || rst.src != sBad {
		t.Fatalf("raw header v4 = %+v", rst)
	}
	v6 := dec(sflowPackets(1, netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8:1::2"), tcpSYN))
	if !v6.haveFlags || v6.tcpFlags != tcpSYN || !v6.sampled || v6.rate != 1 {
		t.Fatalf("raw header v6 = %+v", v6)
	}

	// The explicit sampled IPv4 and IPv6 records carry the flags in a word.
	v4rec := sampledV4Record(sBad, sLocal, 40)
	binary.BigEndian.PutUint32(v4rec[8+24:], tcpRST)
	if o := dec(sflowDatagram(flowSampleBody(100, v4rec))); !o.haveFlags || o.tcpFlags != tcpRST || o.proto != 6 {
		t.Fatalf("sampled ipv4 record = %+v", o)
	}
	body6 := make([]byte, 56)
	binary.BigEndian.PutUint32(body6[0:], 40)
	binary.BigEndian.PutUint32(body6[4:], 6)
	copy(body6[8:24], netip.MustParseAddr("2001:db8::1").AsSlice())
	copy(body6[24:40], netip.MustParseAddr("2001:db8:1::2").AsSlice())
	binary.BigEndian.PutUint32(body6[48:], tcpRST)
	if o := dec(sflowDatagram(flowSampleBody(100, record(sflowSampledIPv6, body6)))); !o.haveFlags || o.tcpFlags != tcpRST {
		t.Fatalf("sampled ipv6 record = %+v", o)
	}
}

func TestSFlowNoFlagsWithoutATCPHeader(t *testing.T) {
	rec := func(mut func(raw []byte)) observation {
		t.Helper()
		r := sflowTCPHeader(sBad, sLocal, tcpRST)
		mut(r[8:])
		obs, err := (&decoder{}).decode(netip.MustParseAddr("192.0.2.8"), sflowDatagram(flowSampleBody(100, r)))
		if err != nil || len(obs) != 1 {
			t.Fatalf("decode = %v, %v", obs, err)
		}
		return obs[0]
	}
	// IPv4 header at raw[16+14]: byte 9 is the protocol, 6:8 the fragment field.
	cases := map[string]func(raw []byte){
		"udp":            func(raw []byte) { raw[16+14+9] = 17 },
		"later fragment": func(raw []byte) { raw[16+14+7] = 0x10 },
		"cut before flags": func(raw []byte) {
			binary.BigEndian.PutUint32(raw[12:], 14+20+10) // header bytes kept
		},
	}
	for name, mut := range cases {
		if o := rec(mut); o.haveFlags {
			t.Errorf("%s: flags taken from %+v", name, o)
		}
	}
}

// problemsFrom builds a flow source with problems on and the clock pinned.
func problemsFrom(t *testing.T) (*Source, time.Time) {
	t.Helper()
	s := mustSource(t, problemsYAML)
	now := time.Unix(1_700_000_000, 0)
	pin(s, now)
	return s, now
}

func TestSFlowResetStormIsAProblem(t *testing.T) {
	s, now := problemsFrom(t)
	exp := netip.MustParseAddr("192.0.2.8")
	// Remote 203.0.113.0/24 resets 12 of 20 sampled packets; 198.51.100.0/24
	// resets 1 of 40 and sends 8 SYN-only packets, which prove nothing.
	s.ingest(now, exp, sflowPackets(1000, sBad, sLocal, repeat(tcpRST|tcpACK, 12)...))
	s.ingest(now, exp, sflowPackets(1000, sLocal, sBad, repeat(tcpACK, 8)...))
	s.ingest(now, exp, sflowPackets(1000, sGood, sLocal, append(repeat(tcpACK|0x08, 27), tcpRST)...))
	s.ingest(now, exp, sflowPackets(1000, sLocal, sGood, append(repeat(tcpACK, 4), repeat(tcpSYN, 8)...)...))

	tot := s.prob.win.Totals(now)
	bad, good := tot[sBad24].Counts, tot[sGood24].Counts
	if bad.Samples != 20 || bad.Flows != 20_000 || bad.Resets != 12_000 || bad.Timeouts != 0 {
		t.Fatalf("bad = %+v", bad)
	}
	if good.Samples != 40 || good.Flows != 40_000 || good.Resets != 1000 || good.Timeouts != 0 {
		t.Fatalf("good = %+v", good)
	}
	if sig := s.PassiveSignals(); len(sig) != 2 || !sig[sBad24] || sig[sGood24] {
		t.Fatalf("signals = %v", sig)
	}
	ts := targetsOf(t, s)
	if len(ts) == 0 || ts[0].Prefix != sBad24 || ts[0].Host != sBad || ts[0].Weight != 3 {
		t.Fatalf("targets = %+v", ts)
	}
}

func TestSFlowFewSamplesAreNotJudged(t *testing.T) {
	s, now := problemsFrom(t)
	// Three resets at 1:1000 stand for 3000 flows, past min_flows, but are
	// only three samples.
	s.ingest(now, netip.MustParseAddr("192.0.2.8"), sflowPackets(1000, sBad, sLocal, repeat(tcpRST, 3)...))
	if c := s.prob.win.Totals(now)[sBad24].Counts; c.Flows != 3000 || c.Resets != 3000 || c.Samples != 3 {
		t.Fatalf("counts = %+v", c)
	}
	if sig := s.PassiveSignals(); len(sig) != 0 {
		t.Fatalf("judged on three samples: %v", sig)
	}
	for _, tg := range targetsOf(t, s) {
		if tg.Prefix == sBad24 {
			t.Fatalf("target from three samples: %+v", tg)
		}
	}
}

func TestSFlowPerPacketAtRateOneIsStillSampled(t *testing.T) {
	s, now := problemsFrom(t)
	exp := netip.MustParseAddr("192.0.2.8")
	// Every packet seen, yet a lone SYN is one packet, not a failed
	// connection.
	s.ingest(now, exp, sflowPackets(1, sLocal, sBad, repeat(tcpSYN, 20)...))
	c := s.prob.win.Totals(now)[sBad24].Counts
	if c.Flows != 20 || c.Samples != 20 || c.Timeouts != 0 {
		t.Fatalf("counts = %+v", c)
	}
	if sig := s.PassiveSignals(); sig[sBad24] {
		t.Fatal("SYN-only packets marked a problem")
	}
}

func TestSampledIPFIXResetStorm(t *testing.T) {
	s, now := problemsFrom(t)
	exp := netip.MustParseAddr("192.0.2.8")
	tmpl := tmplSetIPFIX(300, [][2]uint16{{ieSrcV4, 4}, {ieDstV4, 4}, {ieProtocol, 1}, {ieTCPFlags, 1}, {ieInBytes, 4}, {ieSamplingInterval, 4}})
	rec := func(src, dst netip.Addr, flags uint8, rate uint32) []byte {
		b := append(append([]byte{}, src.AsSlice()...), dst.AsSlice()...)
		b = append(b, 6, flags)
		return append(append(b, putU32(1500)...), putU32(rate)...)
	}
	var data [][]byte
	// 203.0.113.0/24: 6 reset records and 8 SYN-only ones out of 20 sampled
	// records. The SYN-only ones are not timeouts but they are in the total.
	for range 6 {
		data = append(data, rec(sBad, sLocal, tcpRST|tcpACK, 200))
	}
	for range 8 {
		data = append(data, rec(sLocal, sBad, tcpSYN, 200))
	}
	for range 6 {
		data = append(data, rec(sLocal, sBad, tcpSYN|tcpACK, 200))
	}
	// 198.51.100.0/24: ordinary traffic, a quarter of the records SYN-only
	// (short connections), no resets.
	for range 24 {
		data = append(data, rec(sLocal, sGood, tcpACK|0x08, 200))
	}
	for range 8 {
		data = append(data, rec(sLocal, sGood, tcpSYN, 200))
	}
	s.ingest(now, exp, buildIPFIX(1, tmpl, dataSet(300, data...)))

	tot := s.prob.win.Totals(now)
	bad, good := tot[sBad24].Counts, tot[sGood24].Counts
	if bad.Samples != 20 || bad.Flows != 4000 || bad.Resets != 1200 || bad.Timeouts != 0 {
		t.Fatalf("bad = %+v", bad)
	}
	if good.Samples != 32 || good.Flows != 6400 || good.Resets != 0 || good.Timeouts != 0 {
		t.Fatalf("good = %+v", good)
	}
	if sig := s.PassiveSignals(); len(sig) != 2 || !sig[sBad24] || sig[sGood24] {
		t.Fatalf("signals = %v", sig)
	}
	if ts := targetsOf(t, s); len(ts) == 0 || ts[0].Prefix != sBad24 || ts[0].Host != sBad {
		t.Fatalf("targets = %+v", ts)
	}
}

func TestSampledNetFlowV5ResetStorm(t *testing.T) {
	s, now := problemsFrom(t)
	var recs []v5tcp
	for range 12 {
		recs = append(recs, v5tcp{src: sBad, dst: sLocal, flags: tcpRST})
	}
	for range 18 {
		recs = append(recs, v5tcp{src: sLocal, dst: sBad, flags: tcpSYN | tcpACK | 0x08})
	}
	for range 40 {
		recs = append(recs, v5tcp{src: sLocal, dst: sGood, flags: tcpSYN})
	}
	s.ingest(now, netip.MustParseAddr("192.0.2.8"), buildV5TCP(100, recs))
	tot := s.prob.win.Totals(now)
	if c := tot[sBad24].Counts; c.Samples != 30 || c.Flows != 3000 || c.Resets != 1200 {
		t.Fatalf("bad = %+v", c)
	}
	// A prefix that only ever saw sampled SYNs is not a problem.
	if c := tot[sGood24].Counts; c.Timeouts != 0 || c.Resets != 0 {
		t.Fatalf("good = %+v", c)
	}
	if sig := s.PassiveSignals(); !sig[sBad24] || sig[sGood24] {
		t.Fatalf("signals = %v", sig)
	}
}

func TestSampledTrafficRaisesNothing(t *testing.T) {
	s, now := problemsFrom(t)
	exp := netip.MustParseAddr("192.0.2.8")
	// 300 sampled packets in both directions, 2 resets in 300.
	s.ingest(now, exp, sflowPackets(512, sGood, sLocal, append(repeat(tcpACK, 148), tcpRST)...))
	s.ingest(now, exp, sflowPackets(512, sLocal, sGood, append(repeat(tcpACK|0x08, 145), repeat(tcpSYN|tcpACK, 5)...)...))
	s.ingest(now, exp, sflowPackets(512, sGood, sLocal, tcpRST))
	var recs []v5tcp
	for range 40 {
		recs = append(recs, v5tcp{src: sLocal, dst: sBad, flags: tcpACK | 0x08})
	}
	s.ingest(now, exp, buildV5TCP(64, recs))
	if p := s.prob.win.Problems(now, s.prob.th, 0); len(p) != 0 {
		t.Fatalf("problems = %+v", p)
	}
	var seen bool
	for _, tg := range targetsOf(t, s) {
		if tg.Prefix == sGood24 {
			seen = true
			if tg.Weight < 100_000 {
				t.Fatalf("good target is not volume weighted: %+v", tg)
			}
		}
	}
	if !seen {
		t.Fatal("good prefix missing from targets")
	}
}

func TestSampledIsIgnoredWithoutProblems(t *testing.T) {
	s := mustSource(t, "listen: 127.0.0.1:2055\n")
	now := time.Unix(1_700_000_000, 0)
	pin(s, now)
	s.ingest(now, netip.MustParseAddr("192.0.2.8"), sflowPackets(1000, sBad, sLocal, repeat(tcpRST, 30)...))
	if s.prob != nil || len(s.PassiveSignals()) != 0 {
		t.Fatal("problem state without a problems block")
	}
}
