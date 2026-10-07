package probe

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func noReplies(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	return plugin.ProbeResult{Sent: req.Count}, nil
}

func allReplies(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	rtts := make([]time.Duration, req.Count)
	for i := range rtts {
		rtts[i] = time.Millisecond
	}
	return plugin.ProbeResult{Sent: req.Count, RTTs: rtts}, nil
}

func TestSecondRunStartsAtRememberedProber(t *testing.T) {
	icmp := &fakeProber{fn: noReplies}
	tcp := &fakeProber{fn: allReplies}
	e := newChain(t, opts(), icmp, tcp, plugin.Target{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.1")})
	e.RunOnce(context.Background())
	e.RunOnce(context.Background())
	if icmp.calls.Load() != 1 {
		t.Fatalf("icmp calls = %d, want 1 (second run starts at tcp)", icmp.calls.Load())
	}
	if tcp.calls.Load() != 2 {
		t.Fatalf("tcp calls = %d, want 2", tcp.calls.Load())
	}
	rs := e.Results()
	if len(rs) != 1 || rs[0].Prober != "tcp" || !rs[0].OK() || rs[0].Stats.Received == 0 {
		t.Fatalf("result = %+v", rs)
	}
	if got := e.proberMem[netip.MustParseAddr("198.51.100.1")].name; got != "tcp" {
		t.Fatalf("remembered prober = %q", got)
	}
}

func TestTCPOnlyPacketCountDrops(t *testing.T) {
	icmp := &fakeProber{fn: noReplies}
	tcp := &fakeProber{fn: allReplies}
	var sent atomic.Int32
	count := func(fn func(context.Context, plugin.ProbeRequest) (plugin.ProbeResult, error)) func(context.Context, plugin.ProbeRequest) (plugin.ProbeResult, error) {
		return func(ctx context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
			sent.Add(int32(req.Count))
			return fn(ctx, req)
		}
	}
	icmp.fn = count(noReplies)
	tcp.fn = count(allReplies)
	lim := &countingLimiter{}
	o := opts()
	o.Packets = 4
	o.Limiter = lim
	e := newChain(t, o, icmp, tcp, plugin.Target{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.10")})

	e.RunOnce(context.Background())
	firstSent, firstLim := sent.Load(), lim.total
	e.RunOnce(context.Background())
	secondSent, secondLim := sent.Load()-firstSent, lim.total-firstLim

	if firstSent != int32(2*o.Packets) || firstLim != 2*o.Packets {
		t.Fatalf("first round packets sent=%d limiter=%d, want %d", firstSent, firstLim, 2*o.Packets)
	}
	if secondSent != int32(o.Packets) || secondLim != o.Packets {
		t.Fatalf("second round packets sent=%d limiter=%d, want %d", secondSent, secondLim, o.Packets)
	}
	if secondSent >= firstSent {
		t.Fatalf("packet count did not drop: %d then %d", firstSent, secondSent)
	}
}

func TestProberRecheckStartsAtChainHead(t *testing.T) {
	var icmpAnswers atomic.Bool
	icmp := &fakeProber{fn: func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		if icmpAnswers.Load() {
			return allReplies(nil, req)
		}
		return noReplies(nil, req)
	}}
	tcp := &fakeProber{fn: allReplies}
	o := opts()
	o.ProberRecheckRounds = 3
	o.Workers = 1
	e := newChain(t, o, icmp, tcp, plugin.Target{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.1")})

	// Probes 1, 4, 7, ... start at icmp. 2 and 3 start at the remembered prober.
	var icmpAt []int32
	for round := 1; round <= 5; round++ {
		if round == 4 {
			icmpAnswers.Store(true)
		}
		before := icmp.calls.Load()
		tcpBefore := tcp.calls.Load()
		e.RunOnce(context.Background())
		icmpAt = append(icmpAt, icmp.calls.Load()-before)
		tcpDelta := tcp.calls.Load() - tcpBefore
		switch round {
		case 1:
			if icmpAt[0] != 1 || tcpDelta != 1 {
				t.Fatalf("round 1 icmp=%d tcp=%d", icmpAt[0], tcpDelta)
			}
		case 2, 3:
			if icmpAt[round-1] != 0 || tcpDelta != 1 {
				t.Fatalf("round %d icmp=%d tcp=%d, want stick on tcp", round, icmpAt[round-1], tcpDelta)
			}
		case 4:
			if icmpAt[round-1] != 1 || tcpDelta != 0 {
				t.Fatalf("round 4 icmp=%d tcp=%d, want chain head and icmp replies", icmpAt[round-1], tcpDelta)
			}
			if e.Results()[0].Prober != "icmp" {
				t.Fatalf("round 4 prober = %s", e.Results()[0].Prober)
			}
		case 5:
			if icmpAt[round-1] != 1 || tcpDelta != 0 {
				t.Fatalf("round 5 icmp=%d tcp=%d, want to stay on icmp", icmpAt[round-1], tcpDelta)
			}
		}
	}
}

func TestProberMemoryBounded(t *testing.T) {
	hosts := []netip.Addr{
		netip.MustParseAddr("198.51.100.1"),
		netip.MustParseAddr("203.0.113.1"),
		netip.MustParseAddr("192.0.2.50"),
	}
	prefixes := []netip.Prefix{pfx1, pfx2, netip.MustParsePrefix("192.0.2.0/24")}
	var targets []plugin.Target
	for i, h := range hosts {
		targets = append(targets, plugin.Target{Prefix: prefixes[i], Host: h})
	}
	var icmpTargets []netip.Addr
	icmp := &fakeProber{fn: func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		icmpTargets = append(icmpTargets, req.Target)
		return noReplies(nil, req)
	}}
	tcp := &fakeProber{fn: allReplies}
	o := opts()
	o.ProberMemory = 2
	o.Workers = 1
	e := newChain(t, o, icmp, tcp, targets...)
	e.RunOnce(context.Background())
	if len(e.proberMem) != 2 {
		t.Fatalf("memory len = %d, want 2: %+v", len(e.proberMem), e.proberMem)
	}
	if _, ok := e.proberMem[hosts[0]]; ok {
		t.Fatalf("least recently probed host kept: %+v", e.proberMem)
	}
	for _, h := range hosts[1:] {
		if e.proberMem[h].name != "tcp" {
			t.Fatalf("host %s = %+v", h, e.proberMem[h])
		}
	}
	icmpTargets = nil
	e.RunOnce(context.Background())
	if len(e.proberMem) > o.ProberMemory {
		t.Fatalf("memory len = %d, cap %d", len(e.proberMem), o.ProberMemory)
	}
	if len(icmpTargets) != 1 || icmpTargets[0] != hosts[0] {
		t.Fatalf("second round icmp targets = %v, want the evicted host", icmpTargets)
	}
}

func TestProberMemoryDropsHostNoLongerProbed(t *testing.T) {
	h1 := netip.MustParseAddr("198.51.100.1")
	h2 := netip.MustParseAddr("203.0.113.1")
	src := &countingSource{fresh: true, targets: []plugin.Target{
		{Prefix: pfx1, Host: h1},
		{Prefix: pfx2, Host: h2},
	}}
	icmp := &fakeProber{fn: noReplies}
	tcp := &fakeProber{fn: allReplies}
	o := opts()
	o.Workers = 1
	e, err := New([]Provider{provA}, []NamedProber{{"icmp", icmp}, {"tcp", tcp}},
		[]NamedSource{{Name: "static", Source: src}}, o)
	if err != nil {
		t.Fatal(err)
	}
	e.RunOnce(context.Background())
	if e.proberMem[h1].name != "tcp" || e.proberMem[h2].name != "tcp" {
		t.Fatalf("memory = %+v", e.proberMem)
	}

	src.targets = []plugin.Target{{Prefix: pfx1, Host: h1}}
	before := icmp.calls.Load()
	e.RunOnce(context.Background())
	if _, ok := e.proberMem[h2]; ok {
		t.Fatalf("host that left the probe set kept: %+v", e.proberMem)
	}
	if e.proberMem[h1].name != "tcp" {
		t.Fatalf("h1 = %+v", e.proberMem[h1])
	}
	if icmp.calls.Load() != before {
		t.Fatalf("icmp calls %d -> %d while h1 still answers tcp", before, icmp.calls.Load())
	}

	// An improvement keeps the prefix probed, so the host keeps its prober.
	e.SetRetained([]netip.Prefix{pfx1})
	src.targets = nil
	before = icmp.calls.Load()
	e.RunOnce(context.Background())
	if e.proberMem[h1].name != "tcp" {
		t.Fatalf("retained host = %+v", e.proberMem[h1])
	}
	if icmp.calls.Load() != before {
		t.Fatalf("retained host retried icmp: calls %d -> %d", before, icmp.calls.Load())
	}

	e.SetRetained(nil)
	e.RunOnce(context.Background())
	if len(e.proberMem) != 0 {
		t.Fatalf("memory after the prefix left = %+v", e.proberMem)
	}
}

func TestProberMemoryKeepsHostThatIsNotDue(t *testing.T) {
	h1 := netip.MustParseAddr("198.51.100.1")
	h2 := netip.MustParseAddr("203.0.113.1")
	e := newChain(t, opts(), &fakeProber{fn: noReplies}, &fakeProber{fn: allReplies},
		plugin.Target{Prefix: pfx1, Host: h1}, plugin.Target{Prefix: pfx2, Host: h2})
	e.RunOnce(context.Background())
	probes := e.proberMem[h2].probes
	_, done := e.runRound(context.Background(), func(t plugin.Target) bool {
		return t.Prefix == pfx1
	}, true)
	if !done {
		t.Fatal("round did not finish")
	}
	slot, ok := e.proberMem[h2]
	if !ok || slot.name != "tcp" || slot.probes != probes {
		t.Fatalf("not-due host = %+v ok=%v, want tcp probes %d", slot, ok, probes)
	}
}

func TestProberMemorySharedAcrossProviders(t *testing.T) {
	icmp := &fakeProber{fn: func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		if req.Provider == provA.Name {
			return allReplies(nil, req)
		}
		return noReplies(nil, req)
	}}
	tcp := &fakeProber{fn: allReplies}
	o := opts()
	o.Workers = 2
	host := netip.MustParseAddr("198.51.100.1")
	e, err := New([]Provider{provA, provB}, []NamedProber{{"icmp", icmp}, {"tcp", tcp}},
		src(plugin.Target{Prefix: pfx1, Host: host}), o)
	if err != nil {
		t.Fatal(err)
	}
	e.RunOnce(context.Background())
	// transit-a answered icmp. transit-b needed tcp. The later prober is remembered.
	if e.proberMem[host].name != "tcp" {
		t.Fatalf("remembered = %q", e.proberMem[host].name)
	}
	if icmp.calls.Load() != 2 || tcp.calls.Load() != 1 {
		t.Fatalf("round 1 icmp=%d tcp=%d", icmp.calls.Load(), tcp.calls.Load())
	}
	e.RunOnce(context.Background())
	if icmp.calls.Load() != 2 {
		t.Fatalf("round 2 icmp calls = %d, want 2", icmp.calls.Load())
	}
	if tcp.calls.Load() != 3 {
		t.Fatalf("round 2 tcp calls = %d, want 3", tcp.calls.Load())
	}
	for _, r := range e.Results() {
		if r.Prober != "tcp" {
			t.Fatalf("provider %s prober = %s", r.Provider, r.Prober)
		}
	}
}

func TestProberMemoryMovesForward(t *testing.T) {
	var tcpSilent atomic.Bool
	icmp := &fakeProber{fn: noReplies}
	tcp := &fakeProber{fn: func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		if tcpSilent.Load() {
			return noReplies(nil, req)
		}
		return allReplies(nil, req)
	}}
	udp := &fakeProber{fn: allReplies}
	o := opts()
	o.Workers = 1
	e, err := New([]Provider{provA}, []NamedProber{{"icmp", icmp}, {"tcp", tcp}, {"udp", udp}},
		src(plugin.Target{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.1")}), o)
	if err != nil {
		t.Fatal(err)
	}
	e.RunOnce(context.Background())
	if icmp.calls.Load() != 1 || tcp.calls.Load() != 1 || udp.calls.Load() != 0 {
		t.Fatalf("round 1 icmp=%d tcp=%d udp=%d", icmp.calls.Load(), tcp.calls.Load(), udp.calls.Load())
	}
	tcpSilent.Store(true)
	e.RunOnce(context.Background())
	if icmp.calls.Load() != 1 {
		t.Fatalf("icmp was retried before the schedule: calls=%d", icmp.calls.Load())
	}
	if tcp.calls.Load() != 2 || udp.calls.Load() != 1 {
		t.Fatalf("round 2 tcp=%d udp=%d", tcp.calls.Load(), udp.calls.Load())
	}
	if e.proberMem[netip.MustParseAddr("198.51.100.1")].name != "udp" {
		t.Fatalf("remembered = %+v", e.proberMem)
	}
	e.RunOnce(context.Background())
	if icmp.calls.Load() != 1 || tcp.calls.Load() != 2 || udp.calls.Load() != 2 {
		t.Fatalf("round 3 icmp=%d tcp=%d udp=%d", icmp.calls.Load(), tcp.calls.Load(), udp.calls.Load())
	}
}

func TestRetryStaysOnRememberedProber(t *testing.T) {
	icmp := &fakeProber{fn: noReplies}
	var tcpCalls atomic.Int32
	tcp := &fakeProber{fn: func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		n := tcpCalls.Add(1)
		if n == 1 {
			return allReplies(nil, req)
		}
		// Second round's first sample is lossy. The retry must stay on tcp.
		if n == 2 {
			return plugin.ProbeResult{Sent: req.Count, RTTs: ms(5)}, nil
		}
		return allReplies(nil, req)
	}}
	lim := &countingLimiter{}
	o := opts()
	o.Packets = 4
	o.RetryLossPct = 50
	o.RetryPackets = 4
	o.Limiter = lim
	o.Workers = 1
	e := newChain(t, o, icmp, tcp, plugin.Target{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.1")})
	e.RunOnce(context.Background())
	if icmp.calls.Load() != 1 {
		t.Fatalf("learn round icmp = %d", icmp.calls.Load())
	}
	lim.total = 0
	e.RunOnce(context.Background())
	if icmp.calls.Load() != 1 {
		t.Fatalf("retry walked icmp, calls=%d", icmp.calls.Load())
	}
	if tcpCalls.Load() != 3 {
		t.Fatalf("tcp calls = %d, want 3", tcpCalls.Load())
	}
	// First sample plus retry, tcp only. Both waits are the packet counts.
	if lim.total != o.Packets+o.RetryPackets {
		t.Fatalf("retry tokens = %d, want %d", lim.total, o.Packets+o.RetryPackets)
	}
	slot := e.proberMem[netip.MustParseAddr("198.51.100.1")]
	if slot.name != "tcp" || slot.probes != 2 {
		t.Fatalf("slot = %+v, retry should not consume an extra round", slot)
	}
}

func TestRememberedProberSourceDownFailsClosed(t *testing.T) {
	var down atomic.Bool
	icmp := &fakeProber{fn: noReplies}
	tcp := &fakeProber{fn: func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		if down.Load() {
			return plugin.ProbeResult{}, fmt.Errorf("%w: 192.0.2.11", plugin.ErrSourceUnavailable)
		}
		return allReplies(nil, req)
	}}
	e := newChain(t, opts(), icmp, tcp, plugin.Target{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.1")})
	e.RunOnce(context.Background())
	down.Store(true)
	e.RunOnce(context.Background())
	if icmp.calls.Load() != 1 {
		t.Fatalf("icmp calls = %d, source failure must not walk the chain", icmp.calls.Load())
	}
	r := e.Results()[0]
	if r.OK() || !strings.Contains(r.Err, "probe source address unavailable") {
		t.Fatalf("result = %+v", r)
	}
	if e.Providers()[0].Up {
		t.Fatal("provider should be down")
	}
}

func TestProberRecheckEveryRoundStartsAtHead(t *testing.T) {
	icmp := &fakeProber{fn: noReplies}
	tcp := &fakeProber{fn: allReplies}
	o := opts()
	o.ProberRecheckRounds = 1
	e := newChain(t, o, icmp, tcp, plugin.Target{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.1")})
	e.RunOnce(context.Background())
	e.RunOnce(context.Background())
	if icmp.calls.Load() != 2 || tcp.calls.Load() != 2 {
		t.Fatalf("icmp=%d tcp=%d, want both rounds from the chain head", icmp.calls.Load(), tcp.calls.Load())
	}
}

func TestProberMemoryOptionBounds(t *testing.T) {
	probers := []NamedProber{{"icmp", &fakeProber{fn: allReplies}}}
	sources := src(plugin.Target{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.1")})
	e, err := New([]Provider{provA}, probers, sources, opts())
	if err != nil {
		t.Fatal(err)
	}
	if e.opt.ProberRecheckRounds != DefaultProberRecheckRounds || e.opt.ProberMemory != DefaultProberMemory {
		t.Fatalf("defaults = %d hosts, every %d", e.opt.ProberMemory, e.opt.ProberRecheckRounds)
	}
	o := opts()
	o.ProberMemory = -1
	if _, err := New([]Provider{provA}, probers, sources, o); err == nil {
		t.Fatal("negative memory accepted")
	}
	o = opts()
	o.ProberRecheckRounds = MaxProberRecheckRounds + 1
	if _, err := New([]Provider{provA}, probers, sources, o); err == nil {
		t.Fatal("recheck above the max accepted")
	}
}

func newChain(t *testing.T, o Options, icmp, tcp plugin.Prober, targets ...plugin.Target) *Engine {
	t.Helper()
	e, err := New([]Provider{provA}, []NamedProber{{"icmp", icmp}, {"tcp", tcp}}, src(targets...), o)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
