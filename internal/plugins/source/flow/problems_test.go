package flow

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

const problemsYAML = "listen: 127.0.0.1:2055\nproblems:\n  local: [192.0.2.0/24, \"2001:db8:1::/48\"]\n"

type v5tcp struct {
	src, dst netip.Addr
	flags    uint8
	proto    uint8
}

// buildV5TCP builds a NetFlow v5 export with source, protocol, and TCP
// flags set. Documentation prefixes only.
func buildV5TCP(sampling uint16, recs []v5tcp) []byte {
	b := make([]byte, 24+48*len(recs))
	binary.BigEndian.PutUint16(b[0:], 5)
	binary.BigEndian.PutUint16(b[2:], uint16(len(recs)))
	binary.BigEndian.PutUint16(b[22:], sampling)
	for i, r := range recs {
		o := 24 + 48*i
		copy(b[o:o+4], r.src.AsSlice())
		copy(b[o+4:o+8], r.dst.AsSlice())
		binary.BigEndian.PutUint32(b[o+20:], 100)
		b[o+37] = r.flags
		proto := r.proto
		if proto == 0 {
			proto = 6
		}
		b[o+38] = proto
	}
	return b
}

func TestFlowProblemsFromNetFlowV5(t *testing.T) {
	s := mustSource(t, problemsYAML)
	now := time.Unix(1_700_000_000, 0)
	pin(s, now)
	exp := netip.MustParseAddr("192.0.2.8")
	local := netip.MustParseAddr("192.0.2.10")
	bad := netip.MustParseAddr("203.0.113.20")
	good := netip.MustParseAddr("198.51.100.10")
	var recs []v5tcp
	for i := 0; i < 10; i++ {
		f := uint8(tcpSYN | tcpACK | 0x01)
		if i < 6 {
			f = tcpSYN // never answered
		}
		recs = append(recs, v5tcp{src: local, dst: bad, flags: f})
		recs = append(recs, v5tcp{src: local, dst: good, flags: tcpSYN | tcpACK})
	}
	// One remote reset toward each: 7/10 for bad, 1/10 for good.
	recs = append(recs,
		v5tcp{src: bad, dst: local, flags: tcpRST | tcpACK},
		v5tcp{src: good, dst: local, flags: tcpRST},
		v5tcp{src: good, dst: local, flags: tcpACK},                              // inbound without RST: ignored
		v5tcp{src: local, dst: netip.MustParseAddr("192.0.2.99"), flags: tcpSYN}, // local to local
		v5tcp{src: local, dst: good, flags: tcpSYN, proto: 17},                   // UDP
	)
	s.ingest(now, exp, buildV5TCP(0, recs))
	// Sampled exports are skipped: a sampled record may hold only a SYN.
	var sampled []v5tcp
	for i := 0; i < 20; i++ {
		sampled = append(sampled, v5tcp{src: local, dst: good, flags: tcpSYN})
	}
	s.ingest(now, exp, buildV5TCP(100, sampled))

	tot := s.prob.win.Totals(now)
	b, g := tot[netip.MustParsePrefix("203.0.113.0/24")].Counts, tot[netip.MustParsePrefix("198.51.100.0/24")].Counts
	if b.Flows != 10 || b.Timeouts != 6 || b.Resets != 1 || g.Flows != 10 || g.Timeouts != 0 || g.Resets != 1 {
		t.Fatalf("counts bad %+v good %+v", b, g)
	}
	// The inbound records also count as volume toward 192.0.2.0/24; the
	// volume list does not read problems.local (use exclude for that).
	ts := targetsOf(t, s)
	if len(ts) != 3 {
		t.Fatalf("targets = %+v", ts)
	}
	if ts[0].Prefix.String() != "203.0.113.0/24" || ts[0].Host != bad || ts[0].Weight != 3.5 {
		t.Fatalf("problem target = %+v", ts[0])
	}
	if ts[1].Prefix.String() != "198.51.100.0/24" || ts[1].Weight <= 100 {
		t.Fatalf("volume target = %+v", ts[1])
	}
}

func TestFlowProblemsFromIPFIXAndV9(t *testing.T) {
	s := mustSource(t, problemsYAML+"  min_flows: 2\n")
	now := time.Unix(1_700_000_000, 0)
	pin(s, now)
	exp := netip.MustParseAddr("192.0.2.8")
	local6 := netip.MustParseAddr("2001:db8:1::10")
	remote6 := netip.MustParseAddr("2001:db8:ffff::20")
	rec6 := func(src, dst netip.Addr, flags uint16) []byte {
		b := append(append([]byte{}, src.AsSlice()...), dst.AsSlice()...)
		b = append(b, 6, byte(flags>>8), byte(flags))
		return append(b, make([]byte, 8)...)
	}
	withBytes := func(b []byte) []byte { b[len(b)-1] = 64; return b }
	tmpl := tmplSetIPFIX(300, [][2]uint16{{ieSrcV6, 16}, {ieDstV6, 16}, {ieProtocol, 1}, {ieTCPFlags, 2}, {ieInBytes, 8}})
	s.ingest(now, exp, buildIPFIX(1, tmpl, dataSet(300,
		withBytes(rec6(local6, remote6, tcpSYN)),
		withBytes(rec6(local6, remote6, tcpSYN)),
	)))

	// NetFlow v9 with one-byte flags.
	local4 := netip.MustParseAddr("192.0.2.10")
	remote4 := netip.MustParseAddr("198.51.100.30")
	rec4 := func(src, dst netip.Addr, flags uint8) []byte {
		b := append(append([]byte{}, src.AsSlice()...), dst.AsSlice()...)
		return append(b, 6, flags, 0, 0, 0, 50)
	}
	t9 := tmplSetV9(256, [][2]uint16{{ieSrcV4, 4}, {ieDstV4, 4}, {ieProtocol, 1}, {ieTCPFlags, 1}, {ieInBytes, 4}})
	s.ingest(now, exp, buildV9(2, t9, dataSet(256,
		rec4(local4, remote4, tcpSYN|tcpACK),
		rec4(local4, remote4, tcpSYN|tcpACK),
		rec4(remote4, local4, tcpRST),
	)))
	tot := s.prob.win.Totals(now)
	v6 := tot[netip.MustParsePrefix("2001:db8:ffff::/48")].Counts
	v4 := tot[netip.MustParsePrefix("198.51.100.0/24")].Counts
	if v6.Flows != 2 || v6.Timeouts != 2 || v4.Flows != 2 || v4.Resets != 1 {
		t.Fatalf("v6 %+v v4 %+v", v6, v4)
	}
	ts := targetsOf(t, s)
	if len(ts) < 2 || ts[0].Prefix.String() != "2001:db8:ffff::/48" || ts[1].Prefix.String() != "198.51.100.0/24" {
		t.Fatalf("targets = %+v", ts)
	}
}

func TestFlowWithoutProblemsIgnoresFlags(t *testing.T) {
	s := mustSource(t, "listen: 127.0.0.1:2055\n")
	if s.prob != nil {
		t.Fatal("problems on without config")
	}
	now := time.Unix(1_700_000_000, 0)
	pin(s, now)
	local := netip.MustParseAddr("192.0.2.10")
	var recs []v5tcp
	for i := 0; i < 20; i++ {
		recs = append(recs, v5tcp{src: local, dst: netip.MustParseAddr("203.0.113.20"), flags: tcpSYN})
	}
	s.ingest(now, netip.MustParseAddr("192.0.2.8"), buildV5TCP(0, recs))
	ts := targetsOf(t, s)
	if len(ts) != 1 || ts[0].Weight != 2000 {
		t.Fatalf("targets = %+v", ts)
	}
}

func TestFlowProblemsConfig(t *testing.T) {
	for _, y := range []string{
		"listen: 127.0.0.1:2055\nproblems: {}\n",
		"listen: 127.0.0.1:2055\nproblems:\n  local: [0.0.0.0/0]\n",
		"listen: 127.0.0.1:2055\nproblems:\n  local: [192.0.2.1/24]\n",
		problemsYAML + "  failure_pct: 101\n",
		problemsYAML + "  max_targets: 10001\n",
		problemsYAML + "  retrans_pct: 5\n", // not measurable from flows
	} {
		if _, err := build(y); err == nil {
			t.Errorf("accepted %q", y)
		}
	}
	s := mustSource(t, problemsYAML)
	if s.prob.th.FailurePct != 20 || s.prob.th.MinFlows != 10 || s.prob.maxTargets != 100 || s.prob.win.Window() != 5*time.Minute {
		t.Fatalf("defaults = %+v", s.prob)
	}
}
