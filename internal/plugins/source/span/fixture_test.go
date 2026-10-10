package span

import (
	"bytes"
	"encoding/binary"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// The pcap fixture is synthetic: documentation prefixes only, built by the
// code below. Regenerate it with:
//
//	go test ./internal/plugins/source/span -run TestFixtureUpToDate -update
var update = flag.Bool("update", false, "rewrite testdata/problems.pcap")

const fixturePath = "testdata/problems.pcap"

var (
	localV4    = netip.MustParseAddr("192.0.2.10")
	localV6    = netip.MustParseAddr("2001:db8:1::10")
	retransV4  = netip.MustParseAddr("198.51.100.10") // 13% retransmissions
	failV4     = netip.MustParseAddr("203.0.113.20")  // SYN timeouts and resets
	healthyV6  = netip.MustParseAddr("2001:db8:ffff::20")
	inboundV6  = netip.MustParseAddr("2001:db8:eeee::30") // never ACKs our SYN-ACK
	privateV4  = netip.MustParseAddr("10.0.0.5")          // dropped: not a probe target
	otherLocal = netip.MustParseAddr("192.0.2.99")        // local to local: ignored
)

type pkt struct {
	at    time.Duration
	src   netip.AddrPort
	dst   netip.AddrPort
	seq   uint32
	flags uint8
	data  int
	vlan  uint16
	udp   bool
}

func ap(a netip.Addr, port uint16) netip.AddrPort { return netip.AddrPortFrom(a, port) }

// fixturePackets builds the synthetic traffic. Times are offsets from the
// first packet.
func fixturePackets() []pkt {
	var ps []pkt
	add := func(p pkt) { ps = append(ps, p) }
	ms := time.Millisecond

	// A: 12 outbound connections to 198.51.100.10:443. RTT 40ms, 20 data
	// segments each, three of them sent twice. Connection 0 is VLAN-tagged.
	for i := 0; i < 12; i++ {
		base := time.Duration(i) * 100 * ms
		l, r := ap(localV4, uint16(40000+i)), ap(retransV4, 443)
		var vlan uint16
		if i == 0 {
			vlan = 100
		}
		add(pkt{at: base, src: l, dst: r, seq: 1000, flags: flagSYN, vlan: vlan})
		add(pkt{at: base + 40*ms, src: r, dst: l, seq: 5000, flags: flagSYN | flagACK, vlan: vlan})
		add(pkt{at: base + 41*ms, src: l, dst: r, seq: 1001, flags: flagACK, vlan: vlan})
		t := base + 42*ms
		for k := 0; k < 20; k++ {
			add(pkt{at: t, src: l, dst: r, seq: 1001 + uint32(k)*100, flags: flagACK, data: 100, vlan: vlan})
			t += ms / 4
			if k == 5 || k == 10 || k == 15 {
				add(pkt{at: t, src: l, dst: r, seq: 1001 + uint32(k)*100, flags: flagACK, data: 100, vlan: vlan})
				t += ms / 4
			}
		}
		add(pkt{at: t, src: l, dst: r, seq: 3001, flags: flagFIN | flagACK, vlan: vlan})
	}

	// B: 10 outbound connections to 203.0.113.20:443. Six SYNs are never
	// answered (one retry each), two are refused with RST, two succeed.
	for i := 0; i < 10; i++ {
		base := 2*time.Second + time.Duration(i)*10*ms
		l, r := ap(localV4, uint16(41000+i)), ap(failV4, 443)
		add(pkt{at: base, src: l, dst: r, seq: 7000, flags: flagSYN})
		switch {
		case i < 6:
			add(pkt{at: base + time.Second, src: l, dst: r, seq: 7000, flags: flagSYN})
		case i < 8:
			add(pkt{at: base + 30*ms, src: r, dst: l, seq: 0, flags: flagRST | flagACK})
		default:
			add(pkt{at: base + 30*ms, src: r, dst: l, seq: 9000, flags: flagSYN | flagACK})
			add(pkt{at: base + 31*ms, src: l, dst: r, seq: 7001, flags: flagACK})
		}
	}

	// C: 12 healthy IPv6 connections, 10 segments each, RTT 20ms.
	for i := 0; i < 12; i++ {
		base := 3*time.Second + time.Duration(i)*50*ms
		l, r := ap(localV6, uint16(42000+i)), ap(healthyV6, 443)
		add(pkt{at: base, src: l, dst: r, seq: 100, flags: flagSYN})
		add(pkt{at: base + 20*ms, src: r, dst: l, seq: 200, flags: flagSYN | flagACK})
		add(pkt{at: base + 21*ms, src: l, dst: r, seq: 101, flags: flagACK})
		for k := 0; k < 10; k++ {
			add(pkt{at: base + 22*ms + time.Duration(k)*ms, src: l, dst: r, seq: 101 + uint32(k)*100, flags: flagACK, data: 100})
		}
	}

	// D: 10 inbound IPv6 connections whose client never ACKs our SYN-ACK.
	for i := 0; i < 10; i++ {
		base := 4*time.Second + time.Duration(i)*10*ms
		r, l := ap(inboundV6, uint16(50000+i)), ap(localV6, 22)
		add(pkt{at: base, src: r, dst: l, seq: 300, flags: flagSYN})
		add(pkt{at: base + ms, src: l, dst: r, seq: 400, flags: flagSYN | flagACK})
	}

	// E: noise the tracker must ignore.
	for i := 0; i < 10; i++ {
		base := 5*time.Second + time.Duration(i)*10*ms
		add(pkt{at: base, src: ap(localV4, uint16(43000+i)), dst: ap(privateV4, 443), seq: 1, flags: flagSYN})
		add(pkt{at: base, src: ap(localV4, uint16(44000+i)), dst: ap(otherLocal, 443), seq: 1, flags: flagSYN})
		add(pkt{at: base, src: ap(localV4, 53), dst: ap(failV4, 53), data: 40, udp: true})
	}

	sort.SliceStable(ps, func(i, j int) bool { return ps[i].at < ps[j].at })
	return ps
}

var (
	macA = []byte{0x02, 0, 0, 0, 0, 0x01}
	macB = []byte{0x02, 0, 0, 0, 0, 0x02}
)

// frame renders one packet as an Ethernet frame.
func frame(p pkt) []byte {
	var l4 []byte
	proto := byte(protoTCP)
	if p.udp {
		proto = 17
		l4 = make([]byte, 8+p.data)
		binary.BigEndian.PutUint16(l4[0:2], p.src.Port())
		binary.BigEndian.PutUint16(l4[2:4], p.dst.Port())
		binary.BigEndian.PutUint16(l4[4:6], uint16(len(l4)))
	} else {
		l4 = make([]byte, 20+p.data)
		binary.BigEndian.PutUint16(l4[0:2], p.src.Port())
		binary.BigEndian.PutUint16(l4[2:4], p.dst.Port())
		binary.BigEndian.PutUint32(l4[4:8], p.seq)
		l4[12] = 5 << 4
		l4[13] = p.flags
		binary.BigEndian.PutUint16(l4[14:16], 65535)
	}
	var ip []byte
	var et uint16
	if p.src.Addr().Is4() {
		et = etherIPv4
		ip = make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(l4)))
		ip[8] = 64
		ip[9] = proto
		s, d := p.src.Addr().As4(), p.dst.Addr().As4()
		copy(ip[12:16], s[:])
		copy(ip[16:20], d[:])
		var sum uint32
		for i := 0; i < 20; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
		}
		for sum > 0xffff {
			sum = sum&0xffff + sum>>16
		}
		binary.BigEndian.PutUint16(ip[10:12], ^uint16(sum))
	} else {
		et = etherIPv6
		ip = make([]byte, 40)
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:6], uint16(len(l4)))
		ip[6] = proto
		ip[7] = 64
		s, d := p.src.Addr().As16(), p.dst.Addr().As16()
		copy(ip[8:24], s[:])
		copy(ip[24:40], d[:])
	}
	var b bytes.Buffer
	b.Write(macB)
	b.Write(macA)
	if p.vlan != 0 {
		_ = binary.Write(&b, binary.BigEndian, uint16(etherVLAN))
		_ = binary.Write(&b, binary.BigEndian, p.vlan)
	}
	_ = binary.Write(&b, binary.BigEndian, et)
	b.Write(ip)
	b.Write(l4)
	return b.Bytes()
}

// fixtureEpoch is the capture time of the first packet.
var fixtureEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// writePcap renders packets as a little-endian, microsecond pcap.
func writePcap(ps []pkt) []byte {
	var b bytes.Buffer
	le := binary.LittleEndian
	_ = binary.Write(&b, le, uint32(0xa1b2c3d4))
	_ = binary.Write(&b, le, uint16(2))
	_ = binary.Write(&b, le, uint16(4))
	_ = binary.Write(&b, le, int32(0))
	_ = binary.Write(&b, le, uint32(0))
	_ = binary.Write(&b, le, uint32(65535))
	_ = binary.Write(&b, le, uint32(linkEthernet))
	for _, p := range ps {
		f := frame(p)
		ts := fixtureEpoch.Add(p.at)
		_ = binary.Write(&b, le, uint32(ts.Unix()))
		_ = binary.Write(&b, le, uint32(ts.Nanosecond()/1000))
		_ = binary.Write(&b, le, uint32(len(f)))
		_ = binary.Write(&b, le, uint32(len(f)))
		b.Write(f)
	}
	return b.Bytes()
}

// TestFixtureUpToDate keeps testdata/problems.pcap in step with the
// builder, so the committed capture is reproducible and reviewable.
func TestFixtureUpToDate(t *testing.T) {
	want := writePcap(fixturePackets())
	if *update {
		if err := os.WriteFile(fixturePath, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is out of date; run go test -run TestFixtureUpToDate -update", fixturePath)
	}
}

func fixtureAbs(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
