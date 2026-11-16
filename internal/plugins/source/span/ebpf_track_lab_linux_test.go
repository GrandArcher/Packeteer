//go:build linux

package span

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/ebpfpath/labtest"
	"github.com/GrandArcher/Packeteer/internal/passive"
)

// rttTolerance is how far the kernel's handshake RTT average may be from
// the userspace tracker's on the veth pair. The userspace tracker stamps a
// frame when its reader wakes, the kernel stamps it in the tc hook.
const rttTolerance = 10 * time.Millisecond

// paced sends the packets at their fixture offsets in real time, so
// handshake round trips are real. VLAN tags are dropped: the eBPF path
// does not parse them.
func paced(t *testing.T, j *injector, ps []pkt) {
	t.Helper()
	start := time.Now()
	for _, p := range ps {
		if d := time.Until(start.Add(p.at)); d > 0 {
			time.Sleep(d)
		}
		p.vlan = 0
		if err := j.send(frame(p)); err != nil {
			t.Fatal(err)
		}
	}
}

func totals(s *Source) map[netip.Prefix]passive.Counts {
	now := s.now()
	s.sweep(now)
	out := map[netip.Prefix]passive.Counts{}
	for p, pr := range s.win.Totals(now) {
		out[p] = pr.Counts
	}
	return out
}

func sameCounts(want, got map[netip.Prefix]passive.Counts) (string, bool) {
	if len(want) != len(got) {
		return "prefix sets differ", false
	}
	for p, w := range want {
		g, ok := got[p]
		if !ok {
			return p.String() + " missing", false
		}
		diff := w.RTTAvg() - g.RTTAvg()
		if diff < 0 {
			diff = -diff
		}
		w.RTTSum, g.RTTSum = 0, 0
		if w != g {
			return p.String() + " counts differ", false
		}
		if diff > rttTolerance {
			return p.String() + " RTT differs by " + diff.String(), false
		}
	}
	return "", true
}

// The kernel tracker and the userspace tracker read the same synthetic
// traffic on a veth pair and agree: connections, segments, retransmissions,
// resets, handshake timeouts exactly, handshake RTT within rttTolerance
// (#631). The traffic is the pcap fixture: IPv4 and IPv6, retransmissions,
// unanswered SYNs and SYN-ACKs, resets, and noise that must be ignored.
func TestEBPFTrackVethSameCountsAsUserspace(t *testing.T) {
	labtest.RequireRoot(t)
	dev, _ := labtest.Veth(t, "192.0.2.1/24")
	y := "interface: " + dev + "\npromiscuous: false\nsyn_timeout: 500ms\nlocal: [192.0.2.0/24, \"2001:db8:1::/48\"]\n"
	user := startSource(t, mustSource(t, y+"ebpf: true\n"))
	kern := startSource(t, mustSource(t, y+"ebpf: true\nebpf_track: true\n"))
	if kern.kt == nil {
		t.Fatal("ebpf_track: true did not load the kernel tracker; the lab kernel must support TCX (Linux 6.6)")
	}
	if user.kt != nil {
		t.Fatal("ebpf_track off used the kernel tracker")
	}

	paced(t, newInjector(t, dev), fixturePackets())
	time.Sleep(time.Second)

	deadline := time.Now().Add(10 * time.Second)
	var why string
	var want, got map[netip.Prefix]passive.Counts
	for time.Now().Before(deadline) {
		want, got = totals(user), totals(kern)
		var ok bool
		if why, ok = sameCounts(want, got); ok && len(want) == 4 {
			c := want[netip.MustParsePrefix("198.51.100.0/24")]
			if c.Segments != 276 || c.Retrans != 36 || c.Flows != 12 || c.RTTSamples != 12 {
				t.Fatalf("userspace tracker counted %+v for the retransmission prefix", c)
			}
			if f := want[netip.MustParsePrefix("203.0.113.0/24")]; f.Timeouts != 6 || f.Resets != 2 {
				t.Fatalf("userspace tracker counted %+v for the failing prefix", f)
			}
			for p, w := range want {
				t.Logf("%s userspace rtt_avg=%v kernel rtt_avg=%v counts=%+v", p, w.RTTAvg(), got[p].RTTAvg(), got[p])
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s\nuserspace: %+v\nkernel:    %+v", why, want, got)
}

// Sequence numbers that wrap, a keepalive probe, and a partial overlap give
// the kernel tracker and the userspace tracker the same verdicts (#631).
func TestEBPFTrackSequenceEdgesMatchUserspace(t *testing.T) {
	labtest.RequireRoot(t)
	dev, _ := labtest.Veth(t, "192.0.2.1/24")
	y := "interface: " + dev + "\npromiscuous: false\nlocal: [192.0.2.0/24]\n"
	user := startSource(t, mustSource(t, y+"ebpf: true\n"))
	kern := startSource(t, mustSource(t, y+"ebpf: true\nebpf_track: true\n"))
	if kern.kt == nil {
		t.Fatal("kernel tracker not loaded")
	}

	l, r := ap(localV4, 45000), ap(netip.MustParseAddr("198.51.100.77"), 443)
	var first uint32 = 0xffffff01
	var ps []pkt
	add := func(p pkt) { ps = append(ps, p) }
	add(pkt{src: l, dst: r, seq: first - 1, flags: flagSYN})
	add(pkt{src: r, dst: l, seq: 9, flags: flagSYN | flagACK})
	add(pkt{src: l, dst: r, seq: first, flags: flagACK})
	// Six segments of 100 bytes; the third crosses 2^32.
	for k := range 6 {
		add(pkt{src: l, dst: r, seq: first + uint32(k)*100, flags: flagACK, data: 100})
	}
	next := first + 600
	add(pkt{src: l, dst: r, seq: first + 400, flags: flagACK, data: 100}) // repeat after the wrap
	add(pkt{src: l, dst: r, seq: next - 1, flags: flagACK, data: 1})      // keepalive probe
	add(pkt{src: l, dst: r, seq: next - 50, flags: flagACK, data: 100})   // overlaps old and new bytes
	add(pkt{src: l, dst: r, seq: next + 50, flags: flagACK, data: 100})   // new bytes
	add(pkt{src: l, dst: r, seq: next + 150, flags: flagFIN | flagACK})
	paced(t, newInjector(t, dev), ps)

	deadline := time.Now().Add(5 * time.Second)
	var want, got map[netip.Prefix]passive.Counts
	for time.Now().Before(deadline) {
		want, got = totals(user), totals(kern)
		if _, ok := sameCounts(want, got); ok && len(want) == 1 {
			c := want[netip.MustParsePrefix("198.51.100.0/24")]
			if c.Segments != 10 || c.Retrans != 2 {
				t.Fatalf("userspace tracker counted %+v, want 10 segments and 2 retransmissions", c)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("userspace: %+v\nkernel:    %+v", want, got)
}

// A full connection table counts the connections it turned away, as
// max_flows does for the userspace tracker.
func TestEBPFTrackMaxFlowsMatchesUserspace(t *testing.T) {
	labtest.RequireRoot(t)
	dev, _ := labtest.Veth(t, "192.0.2.1/24")
	y := "interface: " + dev + "\npromiscuous: false\nmax_flows: 2\nlocal: [192.0.2.0/24]\n"
	user := startSource(t, mustSource(t, y+"ebpf: true\n"))
	kern := startSource(t, mustSource(t, y+"ebpf: true\nebpf_track: true\n"))
	var ps []pkt
	for i := range 5 {
		ps = append(ps, pkt{src: ap(localV4, uint16(46000+i)), dst: ap(retransV4, 443), seq: 1, flags: flagSYN})
	}
	paced(t, newInjector(t, dev), ps)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if user.Truncated()["max_flows"] == 3 && kern.Truncated()["max_flows"] == 3 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("max_flows: userspace %d, kernel %d, want 3", user.Truncated()["max_flows"], kern.Truncated()["max_flows"])
}

// A device the program cannot attach to leaves the userspace tracker in
// charge, without an error.
func TestEBPFTrackUnsupportedDeviceFallsBack(t *testing.T) {
	labtest.RequireRoot(t)
	dev := labtest.Tun(t)
	s := startSource(t, mustSource(t, "interface: "+dev+"\npromiscuous: false\nebpf: true\nebpf_track: true\nlocal: [192.0.2.0/24]\n"))
	if s.kt != nil {
		t.Fatal("kernel tracker attached to a device without an Ethernet header")
	}
	if s.cap == nil {
		t.Fatal("no capture after fallback")
	}
}

// TestEBPFTrackCPUPerGbit prints the CPU cost of following one busy
// connection on each path: seconds of process CPU above a run with no
// capture, per gigabit of frames sent. The three paths are AF_PACKET with
// the userspace tracker, the eBPF ring buffer with the userspace tracker,
// and the kernel tracker.
func TestEBPFTrackCPUPerGbit(t *testing.T) {
	labtest.RequireRoot(t)
	const (
		segments = 200000
		payload  = 1448
	)
	dev, _ := labtest.Veth(t, "192.0.2.1/24")
	j := newInjector(t, dev)
	l, r := ap(localV4, 47000), ap(retransV4, 443)
	var frames [][]byte
	frames = append(frames, frame(pkt{src: l, dst: r, seq: 999, flags: flagSYN}),
		frame(pkt{src: r, dst: l, seq: 5, flags: flagSYN | flagACK}),
		frame(pkt{src: l, dst: r, seq: 1000, flags: flagACK}))
	seq := uint32(1000)
	retrans := 0
	for i := range segments {
		frames = append(frames, frame(pkt{src: l, dst: r, seq: seq, flags: flagACK, data: payload}))
		if i%100 == 99 { // every 100th segment goes out twice
			frames = append(frames, frames[len(frames)-1])
			retrans++
		}
		seq += payload
	}
	frames = append(frames, frame(pkt{src: l, dst: r, seq: seq, flags: flagFIN | flagACK}))
	var bits int
	for _, f := range frames {
		bits += len(f) * 8
	}
	gbit := float64(bits) / 1e9
	wantSegs := uint64(segments + retrans)

	send := func() (cpu time.Duration) {
		before := cpuTime(t)
		for _, f := range frames {
			_ = j.send(f)
		}
		return cpuTime(t) - before
	}
	base := send()

	run := func(extra string) (time.Duration, passive.Counts) {
		s := mustSource(t, "interface: "+dev+"\npromiscuous: false\nlocal: [192.0.2.0/24]\n"+extra)
		before := cpuTime(t)
		if err := s.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		send()
		var c passive.Counts
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			c = totals(s)[netip.MustParsePrefix("198.51.100.0/24")]
			if c.Segments >= wantSegs {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		cpu := cpuTime(t) - before
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Stop(stop); err != nil {
			t.Errorf("stop: %v", err)
		}
		return cpu, c
	}

	t.Logf("%d frames, %.2f Gbit per run, %d data segments of which %d repeated; sending alone costs %.2fs CPU", len(frames), gbit, wantSegs, retrans, base.Seconds())
	for _, m := range []struct{ name, cfg string }{
		{"af_packet + userspace tracker", ""},
		{"ebpf ring + userspace tracker", "ebpf: true\n"},
		{"ebpf kernel tracker", "ebpf: true\nebpf_track: true\n"},
	} {
		cpu, c := run(m.cfg)
		above := cpu - base
		t.Logf("%-30s %d segments %d retransmissions, %.2fs CPU above sending alone, %.2f CPU-seconds per Gbit", m.name, c.Segments, c.Retrans, above.Seconds(), above.Seconds()/gbit)
		if m.cfg == "ebpf: true\nebpf_track: true\n" && (c.Segments != wantSegs || c.Retrans != uint64(retrans)) {
			t.Errorf("kernel tracker counted %d segments and %d retransmissions, want %d and %d", c.Segments, c.Retrans, wantSegs, retrans)
		}
	}
}

// Idle connections leave the kernel table, with their last counts scored
// first, and the table read sees live ones.
func TestEBPFTrackIdleConnectionsAreForgotten(t *testing.T) {
	labtest.RequireRoot(t)
	dev, _ := labtest.Veth(t, "192.0.2.1/24")
	s := startSource(t, mustSource(t, "interface: "+dev+"\npromiscuous: false\nebpf: true\nebpf_track: true\n"+
		"syn_timeout: 100ms\nflow_idle: 1s\nlocal: [192.0.2.0/24]\n"))
	if s.kt == nil {
		t.Fatal("kernel tracker not loaded")
	}
	l, r := ap(localV4, 48000), ap(retransV4, 443)
	paced(t, newInjector(t, dev), []pkt{
		{src: l, dst: r, seq: 1, flags: flagSYN},
		{at: time.Millisecond, src: l, dst: r, seq: 2, flags: flagACK, data: 100},
		{at: 2 * time.Millisecond, src: l, dst: r, seq: 102, flags: flagACK, data: 100},
	})
	live := func() int {
		st, err := s.kt.flows()
		if err != nil {
			t.Fatal(err)
		}
		return len(st)
	}
	deadline := time.Now().Add(5 * time.Second)
	for live() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("the connection never reached the kernel table")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(1200 * time.Millisecond)
	s.sweep(s.now())
	if n := live(); n != 0 {
		t.Fatalf("%d connections still in the table after the idle time", n)
	}
	if c := prefixTotals(s, "198.51.100.0/24"); c.Segments != 2 || c.Flows != 1 || c.Timeouts != 1 {
		t.Fatalf("counts = %+v, want 2 segments and 1 timeout in 1 flow", c)
	}
}
