package span

import (
	"bytes"
	"context"
	"encoding/binary"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/passive"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func quiet() plugin.Env {
	return plugin.Env{Logger: slog.New(slog.DiscardHandler), PluginDir: "/etc/packeteer/plugins"}
}

func build(y string) (plugin.TargetSource, error) {
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		return nil, err
	}
	return plugin.Sources.New(TypeName, c, quiet())
}

func mustSource(t *testing.T, y string) *Source {
	t.Helper()
	s, err := build(y)
	if err != nil {
		t.Fatal(err)
	}
	return s.(*Source)
}

const baseYAML = "interface: eth1\nlocal: [192.0.2.0/24, \"2001:db8:1::/48\"]\n"

func pin(s *Source, at time.Time) { s.now = func() time.Time { return at } }

// replayFixture feeds testdata/problems.pcap with its first packet at start.
func replayFixture(t *testing.T, s *Source, start time.Time) int {
	t.Helper()
	f, err := os.Open(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pr, err := newPcapReader(f)
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.replay(pr, start)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func targets(t *testing.T, s *Source) []plugin.Target {
	t.Helper()
	ts, err := s.Targets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func TestExchangeLANRemoteNotKept(t *testing.T) {
	s := mustSource(t, baseYAML)
	s.SetExchangeLANs([]netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8:1:2::/64"),
	})
	before := exchange.LANDrops()
	if s.keep(netip.MustParseAddr("203.0.113.10")) {
		t.Fatal("IPv4 LAN remote kept")
	}
	if s.keep(netip.MustParseAddr("2001:db8:1:2::5")) {
		t.Fatal("IPv6 LAN remote kept")
	}
	if !s.keep(netip.MustParseAddr("198.51.100.10")) {
		t.Fatal("customer remote dropped")
	}
	if ts := targets(t, s); len(ts) != 0 {
		t.Fatalf("targets = %+v", ts)
	}
	if got := exchange.LANDrops() - before; got != 2 {
		t.Fatalf("drops = %d, want 2", got)
	}
}

func TestFixtureProblems(t *testing.T) {
	s := mustSource(t, baseYAML)
	start := time.Unix(1_800_000_000, 0)
	if n := replayFixture(t, s, start); n != len(fixturePackets()) {
		t.Fatalf("replayed %d packets", n)
	}
	pin(s, start.Add(10*time.Second))
	ps := s.Problems()
	got := map[string]passive.Problem{}
	var order []string
	for _, p := range ps {
		got[p.Prefix.String()] = p
		order = append(order, p.Prefix.String())
	}
	want := []string{"2001:db8:eeee::/48", "203.0.113.0/24", "198.51.100.0/24"}
	if strings.Join(order, " ") != strings.Join(want, " ") {
		t.Fatalf("problems = %v, want %v (all: %+v)", order, want, ps)
	}

	r := got["198.51.100.0/24"].Counts
	if r.Flows != 12 || r.Segments != 276 || r.Retrans != 36 || r.Timeouts != 0 || r.Resets != 0 {
		t.Fatalf("retrans prefix counts = %+v", r)
	}
	if r.RTTSamples != 12 || r.RTTAvg() != 40*time.Millisecond {
		t.Fatalf("retrans prefix rtt = %d samples avg %s", r.RTTSamples, r.RTTAvg())
	}
	if got["198.51.100.0/24"].Reasons[0] != passive.ReasonRetrans || got["198.51.100.0/24"].Host != retransV4 {
		t.Fatalf("retrans problem = %+v", got["198.51.100.0/24"])
	}

	f := got["203.0.113.0/24"].Counts
	if f.Flows != 10 || f.Timeouts != 6 || f.Resets != 2 || f.RTTSamples != 2 {
		t.Fatalf("failure prefix counts = %+v", f)
	}
	if got["203.0.113.0/24"].Host != failV4 || got["203.0.113.0/24"].Score != 4 {
		t.Fatalf("failure problem = %+v", got["203.0.113.0/24"])
	}

	in := got["2001:db8:eeee::/48"].Counts
	if in.Flows != 10 || in.Timeouts != 10 || in.RTTSamples != 0 {
		t.Fatalf("inbound prefix counts = %+v", in)
	}

	// The healthy prefix was measured but is not a problem.
	tot := s.win.Totals(s.now())
	h := tot[netip.MustParsePrefix("2001:db8:ffff::/48")].Counts
	if h.Flows != 12 || h.Segments != 120 || h.Retrans != 0 || h.RTTAvg() != 20*time.Millisecond {
		t.Fatalf("healthy prefix counts = %+v", h)
	}
	// Private, local-to-local, and UDP traffic is not counted.
	for p := range tot {
		if p.Addr().IsPrivate() || p.Contains(otherLocal) {
			t.Fatalf("counted %s", p)
		}
	}
	if len(tot) != 4 {
		t.Fatalf("totals = %v", tot)
	}
}

func TestTargetsUrgentOnceAndWindowExpiry(t *testing.T) {
	s := mustSource(t, baseYAML+"window: 1m\n")
	start := time.Unix(1_800_000_000, 0)
	replayFixture(t, s, start)
	pin(s, start.Add(10*time.Second))

	ts := targets(t, s)
	if len(ts) != 3 {
		t.Fatalf("targets = %+v", ts)
	}
	for _, tg := range ts {
		if !tg.Urgent || tg.Weight < 1 || !tg.Prefix.Contains(tg.Host) || tg.Interval != 0 {
			t.Fatalf("first read target = %+v", tg)
		}
	}
	if ts[0].Host != inboundV6 {
		t.Fatalf("worst target = %+v", ts[0])
	}
	for _, tg := range targets(t, s) {
		if tg.Urgent {
			t.Fatalf("second read is still urgent: %+v", tg)
		}
	}
	// Past the window the counters age out and the list is empty.
	pin(s, start.Add(2*time.Minute))
	if ts := targets(t, s); len(ts) != 0 {
		t.Fatalf("targets after window = %+v", ts)
	}
	// Idle connections were forgotten.
	pin(s, start.Add(10*time.Minute))
	s.trk.sweep(s.now())
	if n := s.trk.size(); n != 0 {
		t.Fatalf("tracked flows after idle = %d", n)
	}
}

func TestThresholdsFromConfig(t *testing.T) {
	// Raising every threshold past the fixture leaves nothing.
	s := mustSource(t, baseYAML+"retrans_pct: 50\nfailure_pct: 100\nmin_flows: 11\n")
	start := time.Unix(1_800_000_000, 0)
	replayFixture(t, s, start)
	pin(s, start.Add(10*time.Second))
	// 198.51.100.0/24: retrans 13% < 50%. The others have 10 flows < 11.
	if ps := s.Problems(); len(ps) != 0 {
		t.Fatalf("problems = %+v", ps)
	}

	// max_targets caps the list, worst first.
	s = mustSource(t, baseYAML+"max_targets: 1\n")
	replayFixture(t, s, start)
	pin(s, start.Add(10*time.Second))
	if ps := s.Problems(); len(ps) != 1 || ps[0].Prefix.String() != "2001:db8:eeee::/48" {
		t.Fatalf("capped problems = %+v", ps)
	}
}

func TestRTTThreshold(t *testing.T) {
	s := mustSource(t, baseYAML+"retrans_pct: 100\nfailure_pct: 100\nrtt_ms: 30\nmin_flows: 2\n")
	at := time.Unix(1_800_000_000, 0)
	l := func(i int) netip.AddrPort { return ap(localV4, uint16(40000+i)) }
	slow, fast := ap(retransV4, 443), ap(failV4, 443)
	for i := 0; i < 3; i++ {
		s.trk.observe(at, segment{src: l(i).Addr(), sport: l(i).Port(), dst: slow.Addr(), dport: 443, flags: flagSYN})
		s.trk.observe(at.Add(80*time.Millisecond), segment{src: slow.Addr(), sport: 443, dst: l(i).Addr(), dport: l(i).Port(), flags: flagSYN | flagACK})
		s.trk.observe(at, segment{src: l(i + 10).Addr(), sport: l(i + 10).Port(), dst: fast.Addr(), dport: 443, flags: flagSYN})
		s.trk.observe(at.Add(5*time.Millisecond), segment{src: fast.Addr(), sport: 443, dst: l(i + 10).Addr(), dport: l(i + 10).Port(), flags: flagSYN | flagACK})
	}
	pin(s, at.Add(time.Second))
	ps := s.Problems()
	if len(ps) != 1 || ps[0].Prefix.String() != "198.51.100.0/24" || ps[0].Reasons[0] != passive.ReasonRTT {
		t.Fatalf("problems = %+v", ps)
	}
}

func TestTrackerSequenceEdges(t *testing.T) {
	s := mustSource(t, baseYAML)
	at := time.Unix(1_800_000_000, 0)
	l, r := ap(localV4, 40000), ap(retransV4, 443)
	out := func(seq uint32, flags uint8, n uint32) {
		s.trk.observe(at, segment{src: l.Addr(), sport: l.Port(), dst: r.Addr(), dport: r.Port(), seq: seq, flags: flags, payload: n})
	}
	in := func(flags uint8) {
		s.trk.observe(at, segment{src: r.Addr(), sport: r.Port(), dst: l.Addr(), dport: l.Port(), flags: flags})
	}
	// Mid-stream pickup across the 32-bit wrap.
	out(0xffffff00, flagACK, 0x80)
	out(0xffffff80, flagACK, 0x100) // wraps to 0x80
	out(0x80, flagACK, 0x100)
	out(0x17f, flagACK, 1)         // keepalive: repeats the last byte
	out(0xffffff80, flagACK, 0x10) // real retransmission
	out(0x100, flagACK, 0x100)     // partial overlap: retransmission, advances
	in(flagACK)
	out(0, flagRST, 0) // local abort forgets the connection
	c := s.win.Totals(at)[netip.MustParsePrefix("198.51.100.0/24")].Counts
	if c.Segments != 6 || c.Retrans != 2 || c.Flows != 1 || c.Resets != 0 {
		t.Fatalf("counts = %+v", c)
	}
	if s.trk.size() != 0 {
		t.Fatal("local RST did not forget the connection")
	}
	// A remote RST for a connection that was never seen is not counted.
	in(flagRST)
	if c := s.win.Totals(at)[netip.MustParsePrefix("198.51.100.0/24")].Counts; c.Resets != 0 || c.Flows != 1 {
		t.Fatalf("stray RST counted: %+v", c)
	}
	// A late SYN after a timeout is neither a second timeout nor an RTT.
	out(1, flagSYN, 0)
	s.trk.sweep(at.Add(4 * time.Second))
	out(1, flagSYN, 0)
	s.trk.sweep(at.Add(8 * time.Second))
	in(flagSYN | flagACK)
	c = s.win.Totals(at.Add(8 * time.Second))[netip.MustParsePrefix("198.51.100.0/24")].Counts
	if c.Timeouts != 1 || c.RTTSamples != 0 {
		t.Fatalf("late SYN counts = %+v", c)
	}
}

func TestMaxFlowsAndPrefixLookup(t *testing.T) {
	s := mustSource(t, baseYAML+"max_flows: 2\n")
	// The RIB covers 198.51.100.0/25; the other half aggregates to /24.
	rib := netip.MustParsePrefix("198.51.100.0/25")
	s.SetPrefixLookup(func(a netip.Addr) (netip.Prefix, bool) { return rib, rib.Contains(a) })
	at := time.Unix(1_800_000_000, 0)
	for i, dst := range []string{"198.51.100.10", "198.51.100.200", "203.0.113.5"} {
		s.trk.observe(at, segment{src: localV4, sport: uint16(40000 + i), dst: netip.MustParseAddr(dst), dport: 443, flags: flagSYN})
	}
	tot := s.win.Totals(at)
	if _, ok := tot[rib]; !ok {
		t.Fatalf("RIB prefix not used: %v", tot)
	}
	if _, ok := tot[netip.MustParsePrefix("198.51.100.0/24")]; !ok {
		t.Fatalf("aggregate not used: %v", tot)
	}
	if len(tot) != 2 || s.trk.size() != 2 || s.trk.dropped != 1 {
		t.Fatalf("max_flows not enforced: %v size %d dropped %d", tot, s.trk.size(), s.trk.dropped)
	}
}

func TestStartReplaysPcapFile(t *testing.T) {
	s := mustSource(t, "pcap_file: "+fixtureAbs(t)+"\nlocal: [192.0.2.0/24, \"2001:db8:1::/48\"]\n")
	start := time.Unix(1_800_000_000, 0)
	pin(s, start)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	s.wg.Wait() // replay finishes on its own
	pin(s, start.Add(10*time.Second))
	if ts := targets(t, s); len(ts) != 3 {
		t.Fatalf("targets = %+v", ts)
	}
	if err := s.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestStartErrors(t *testing.T) {
	s := mustSource(t, "pcap_file: /nonexistent/packeteer.pcap\nlocal: [192.0.2.0/24]\n")
	if err := s.Start(context.Background()); err == nil {
		t.Fatal("missing pcap started")
	}
	dir := t.TempDir()
	bad := dir + "/bad.pcap"
	if err := os.WriteFile(bad, []byte("\x0a\x0d\x0d\x0a not a classic pcap....."), 0o644); err != nil {
		t.Fatal(err)
	}
	s = mustSource(t, "pcap_file: "+bad+"\nlocal: [192.0.2.0/24]\n")
	if err := s.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "pcapng") {
		t.Fatalf("pcapng err = %v", err)
	}
	s = mustSource(t, "interface: pk-missing0\nlocal: [192.0.2.0/24]\n")
	if err := s.Start(context.Background()); err == nil {
		t.Fatal("missing interface started")
	}
	_ = s.Stop(context.Background())
}

func TestConfigValidation(t *testing.T) {
	bad := map[string]string{
		"no capture":         "local: [192.0.2.0/24]\n",
		"both captures":      "interface: eth1\npcap_file: /x.pcap\nlocal: [192.0.2.0/24]\n",
		"relative pcap":      "pcap_file: x.pcap\nlocal: [192.0.2.0/24]\n",
		"promisc with pcap":  "pcap_file: /x.pcap\npromiscuous: false\nlocal: [192.0.2.0/24]\n",
		"bad iface":          "interface: ../eth1\nlocal: [192.0.2.0/24]\n",
		"no local":           "interface: eth1\n",
		"default local":      "interface: eth1\nlocal: [0.0.0.0/0]\n",
		"host bits":          "interface: eth1\nlocal: [192.0.2.1/24]\n",
		"dup local":          "interface: eth1\nlocal: [192.0.2.0/24, 192.0.2.0/24]\n",
		"bad exclude":        baseYAML + "exclude: [nope]\n",
		"short window":       baseYAML + "window: 1s\n",
		"retrans range":      baseYAML + "retrans_pct: 101\n",
		"failure negative":   baseYAML + "failure_pct: -1\n",
		"rtt negative":       baseYAML + "rtt_ms: -1\n",
		"syn timeout":        baseYAML + "syn_timeout: 10ms\n",
		"idle under syn":     baseYAML + "syn_timeout: 5s\nflow_idle: 5s\n",
		"max flows":          baseYAML + "max_flows: -1\n",
		"max targets":        baseYAML + "max_targets: 10001\n",
		"agg v4":             baseYAML + "aggregate_v4: 33\n",
		"agg v6":             baseYAML + "aggregate_v6: 129\n",
		"unknown field":      baseYAML + "nope: 1\n",
		"prefix not a CIDR":  "interface: eth1\nlocal: [192.0.2.1]\n",
		"interface too long": "interface: abcdefghijklmnop\nlocal: [192.0.2.0/24]\n",
	}
	for name, y := range bad {
		if _, err := build(y); err == nil {
			t.Errorf("%s: accepted %q", name, y)
		}
	}
	s := mustSource(t, baseYAML)
	if s.th.RetransPct != DefaultRetransPct || s.th.FailurePct != DefaultFailurePct || s.th.RTT != 0 ||
		s.th.MinSegments != DefaultMinSegments || s.th.MinFlows != DefaultMinFlows || s.maxTargets != DefaultMaxTargets ||
		s.trk.synTimeout != DefaultSYNTimeout || s.trk.idle != DefaultFlowIdle || s.trk.maxFlows != DefaultMaxFlows ||
		s.win.Window() != DefaultWindow || !s.promisc {
		t.Fatalf("defaults = %+v %+v", s.th, s.trk)
	}
	if !s.Fresh() {
		t.Fatal("span must be read every round")
	}
}

func TestDecodeLinkTypes(t *testing.T) {
	p := pkt{src: ap(localV4, 40000), dst: ap(retransV4, 443), seq: 7, flags: flagSYN | flagACK, data: 3}
	eth := frame(p)
	want := segment{src: localV4, dst: retransV4, sport: 40000, dport: 443, seq: 7, flags: flagSYN | flagACK, payload: 3}
	if got, ok := decodeFrame(linkEthernet, eth); !ok || got != want {
		t.Fatalf("ethernet = %+v %v", got, ok)
	}
	ipPkt := eth[14:]
	for _, link := range []int{linkRaw, linkIPv4} {
		if got, ok := decodeFrame(link, ipPkt); !ok || got != want {
			t.Fatalf("link %d = %+v %v", link, got, ok)
		}
	}
	sll := append(make([]byte, 14), 0x08, 0x00)
	sll = append(sll, ipPkt...)
	if got, ok := decodeFrame(linkLinuxSLL, sll); !ok || got != want {
		t.Fatalf("sll = %+v %v", got, ok)
	}
	// Truncated capture: the payload length still comes from the IP header.
	if got, ok := decodeFrame(linkEthernet, eth[:14+20+20]); !ok || got.payload != 3 {
		t.Fatalf("truncated = %+v %v", got, ok)
	}
	// IPv6 with a destination-options header before TCP.
	p6 := pkt{src: ap(localV6, 1), dst: ap(healthyV6, 2), seq: 9, flags: flagACK, data: 5}
	f6 := frame(p6)
	ip6 := append([]byte(nil), f6[14:14+40]...)
	tcp := f6[14+40:]
	ip6[6] = 60
	binary.BigEndian.PutUint16(ip6[4:6], uint16(len(tcp)+8))
	ext := []byte{protoTCP, 0, 1, 4, 0, 0, 0, 0}
	raw6 := append(append(ip6, ext...), tcp...)
	if got, ok := decodeFrame(linkIPv6, raw6); !ok || got.dst != healthyV6 || got.payload != 5 || got.seq != 9 {
		t.Fatalf("ipv6 ext = %+v %v", got, ok)
	}
	// Non-first IPv4 fragment, UDP, garbage, and unknown links are skipped.
	frag := bytes.Clone(ipPkt)
	frag[7] = 1
	for name, c := range map[string]struct {
		link int
		b    []byte
	}{
		"fragment": {linkRaw, frag},
		"udp":      {linkEthernet, frame(pkt{src: ap(localV4, 1), dst: ap(failV4, 2), udp: true})},
		"short":    {linkEthernet, eth[:20]},
		"arp":      {linkEthernet, append(append([]byte(nil), eth[:12]...), 0x08, 0x06)},
		"unknown":  {147, ipPkt},
		"empty":    {linkRaw, nil},
	} {
		if got, ok := decodeFrame(c.link, c.b); ok {
			t.Errorf("%s decoded: %+v", name, got)
		}
	}
}

func TestPcapReaderFormats(t *testing.T) {
	be := binary.BigEndian
	f := frame(pkt{src: ap(localV4, 1), dst: ap(retransV4, 2), flags: flagSYN})
	var b bytes.Buffer
	for _, v := range []any{uint32(0xa1b23c4d), uint16(2), uint16(4), int32(0), uint32(0), uint32(65535), uint32(linkEthernet),
		uint32(10), uint32(123), uint32(len(f)), uint32(len(f))} {
		_ = binary.Write(&b, be, v)
	}
	b.Write(f)
	pr, err := newPcapReader(bytes.NewReader(b.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	ts, got, err := pr.next()
	if err != nil || !bytes.Equal(got, f) || ts != time.Unix(10, 123) {
		t.Fatalf("next = %v %x %v", ts, got, err)
	}
	if _, _, err := pr.next(); err == nil {
		t.Fatal("expected EOF")
	}
	// A truncated record is an error, not EOF.
	pr, _ = newPcapReader(bytes.NewReader(b.Bytes()[:b.Len()-3]))
	if _, _, err := pr.next(); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("truncated err = %v", err)
	}
	// Unsupported link type.
	hdr := bytes.Clone(b.Bytes()[:24])
	be.PutUint32(hdr[20:24], 105)
	if _, err := newPcapReader(bytes.NewReader(hdr)); err == nil {
		t.Fatal("802.11 accepted")
	}
}
