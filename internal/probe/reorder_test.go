package probe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestComputeReorder(t *testing.T) {
	cases := []struct {
		name  string
		sent  int
		order []int
		want  ReorderStats
	}{
		{"in order", 4, []int{0, 1, 2, 3}, ReorderStats{Sent: 4, Received: 4}},
		{"order unknown", 4, nil, ReorderStats{Sent: 4}},
		{"loss keeps order", 5, []int{0, 2, 4}, ReorderStats{Sent: 5, Received: 3}},
		// netem "reorder gap 5": packet 5 jumps ahead of packet 4.
		{"one swap", 5, []int{0, 1, 2, 4, 3}, ReorderStats{Sent: 5, Received: 5, Reordered: 1, RatioPct: 20, Extent: 1, NReordering: 1}},
		// The first packet arrives last: three later-sent packets before it.
		{"first last", 4, []int{1, 2, 3, 0}, ReorderStats{Sent: 4, Received: 4, Reordered: 1, RatioPct: 25, Extent: 3, NReordering: 3}},
		// Extent counts from the earliest later-sent arrival; n-reordering
		// only the later-sent run right before the packet (RFC 4737 5.1).
		{"extent beyond n", 5, []int{2, 0, 3, 1, 4}, ReorderStats{Sent: 5, Received: 5, Reordered: 2, RatioPct: 40, Extent: 3, NReordering: 1}},
		{"two swaps", 4, []int{1, 0, 3, 2}, ReorderStats{Sent: 4, Received: 4, Reordered: 2, RatioPct: 50, Extent: 1, NReordering: 1}},
	}
	for _, c := range cases {
		if got := ComputeReorder(c.sent, c.order); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

// trainProber records every request and answers from a script keyed by
// provider: each call takes the next arrival order for that provider.
type trainProber struct {
	mu     sync.Mutex
	reqs   []plugin.ProbeRequest
	orders map[string][][]int
	err    map[string]error
}

func (p *trainProber) Start(context.Context) error { return nil }
func (p *trainProber) Stop(context.Context) error  { return nil }
func (p *trainProber) Probe(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reqs = append(p.reqs, req)
	if err := p.err[req.Provider]; err != nil {
		return plugin.ProbeResult{}, err
	}
	q := p.orders[req.Provider]
	if len(q) == 0 {
		return plugin.ProbeResult{Sent: req.Count}, nil
	}
	order := q[0]
	p.orders[req.Provider] = q[1:]
	res := plugin.ProbeResult{Sent: req.Count, Order: order}
	for range order {
		res.RTTs = append(res.RTTs, 10*time.Millisecond)
	}
	return res, nil
}

type countLimiter struct {
	mu    sync.Mutex
	waits []int
}

func (l *countLimiter) WaitN(_ context.Context, n int) error {
	l.mu.Lock()
	l.waits = append(l.waits, n)
	l.mu.Unlock()
	return nil
}

var (
	reflectorAddr = netip.MustParseAddr("203.0.113.9")
	echoAddr      = netip.MustParseAddr("198.51.100.1")
	reProvA       = Provider{Name: "transit-a", Source: netip.MustParseAddr("192.0.2.11")}
	reProvB       = Provider{Name: "transit-b", Source: netip.MustParseAddr("192.0.2.12")}
)

func TestReorderMonitorRunOnce(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	twampP := &trainProber{orders: map[string][][]int{
		"transit-a": {{0, 1, 2, 3, 4}, {0, 1, 2, 3, 4}},
		// Flow 1 is a clean member, flow 2 the reordering one.
		"transit-b": {{0, 1, 2, 3, 4}, {0, 1, 2, 4, 3}},
	}}
	icmpP := &trainProber{orders: map[string][][]int{
		"transit-a": {{1, 0, 2, 3, 4}},
		"transit-b": {{0, 1, 2, 3, 4}},
	}}
	lim := &countLimiter{}
	m, err := NewReorderMonitor(ReorderOptions{
		Providers: []Provider{reProvA, reProvB},
		Responders: []Responder{
			{Address: reflectorAddr, Port: 862, Type: ResponderTWAMP, Prober: twampP},
			{Address: echoAddr, Type: ResponderICMP, Prober: icmpP},
		},
		Packets: 5, Spacing: 20 * time.Millisecond, Timeout: time.Second, Interval: time.Minute, Flows: 2,
		Limiter: lim, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	m.RunOnce(context.Background())

	// Two flows per provider toward the reflector, one toward the echo host.
	if len(twampP.reqs) != 4 || len(icmpP.reqs) != 2 {
		t.Fatalf("twamp requests %d, icmp requests %d", len(twampP.reqs), len(icmpP.reqs))
	}
	for _, r := range twampP.reqs {
		if r.Port != 862 || r.Count != 5 || r.Spacing != 20*time.Millisecond || r.Timeout != time.Second || r.Target != reflectorAddr {
			t.Fatalf("request %+v", r)
		}
	}
	if twampP.reqs[0].Source != reProvA.Source || twampP.reqs[2].Source != reProvB.Source {
		t.Fatalf("sources %s %s", twampP.reqs[0].Source, twampP.reqs[2].Source)
	}
	if icmpP.reqs[0].Port != 0 {
		t.Fatalf("icmp request carries port %d", icmpP.reqs[0].Port)
	}
	// Every train waited on the global budget for its packets.
	if len(lim.waits) != 6 {
		t.Fatalf("limiter waits %v", lim.waits)
	}
	for _, n := range lim.waits {
		if n != 5 {
			t.Fatalf("limiter waits %v", lim.waits)
		}
	}

	rs := m.Results()
	if len(rs) != 4 {
		t.Fatalf("results %+v", rs)
	}
	// Sorted by provider then responder: a/echo, a/reflector, b/echo, b/reflector.
	aEcho, aRef, bEcho, bRef := rs[0], rs[1], rs[2], rs[3]
	if aEcho.Responder != echoAddr || aRef.Responder != reflectorAddr || bRef.Provider != "transit-b" {
		t.Fatalf("order %+v", rs)
	}
	if !aRef.OK() || aRef.Estimate || aRef.Worst.RatioPct != 0 || aRef.WorstFlow != 1 || len(aRef.Flows) != 2 || aRef.Port != 862 || !aRef.Time.Equal(now) {
		t.Fatalf("transit-a reflector %+v", aRef)
	}
	if !bRef.OK() || bRef.WorstFlow != 2 || bRef.Worst.RatioPct != 20 || bRef.Worst.Extent != 1 || bRef.Worst.NReordering != 1 {
		t.Fatalf("transit-b reflector %+v", bRef)
	}
	if bRef.Flows[0].RatioPct != 0 || bRef.Flows[1].RatioPct != 20 || bRef.Flows[1].Flow != 2 {
		t.Fatalf("transit-b flows %+v", bRef.Flows)
	}
	if !aEcho.Estimate || !aEcho.OK() || aEcho.Worst.RatioPct != 20 || len(aEcho.Flows) != 1 || aEcho.Type != ResponderICMP {
		t.Fatalf("transit-a echo %+v", aEcho)
	}
	if !bEcho.Estimate || bEcho.Worst.RatioPct != 0 {
		t.Fatalf("transit-b echo %+v", bEcho)
	}

	// Decide sees the reflector readings only: the transit-a estimate of
	// 20% does not count.
	got := m.Scored(now, 5*time.Minute)
	if len(got) != 2 || got["transit-a"] != 0 || got["transit-b"] != 20 {
		t.Fatalf("scored %v", got)
	}
	if got := m.Scored(now.Add(10*time.Minute), 5*time.Minute); len(got) != 0 {
		t.Fatalf("stale readings scored: %v", got)
	}
}

func TestReorderMonitorFailures(t *testing.T) {
	now := time.Now()
	silent := &trainProber{orders: map[string][][]int{}}
	down := &trainProber{err: map[string]error{"transit-a": fmt.Errorf("%w: 192.0.2.11", plugin.ErrSourceUnavailable)}}
	broken := &trainProber{err: map[string]error{"transit-a": errors.New("socket: boom")}}
	noOrder := &noOrderProber{}
	excluded := netip.MustParseAddr("203.0.113.200")
	m, err := NewReorderMonitor(ReorderOptions{
		Providers: []Provider{reProvA},
		Responders: []Responder{
			{Address: netip.MustParseAddr("203.0.113.1"), Port: 862, Type: ResponderTWAMP, Prober: silent},
			{Address: netip.MustParseAddr("203.0.113.2"), Port: 862, Type: ResponderTWAMP, Prober: down},
			{Address: netip.MustParseAddr("203.0.113.3"), Port: 862, Type: ResponderTWAMP, Prober: broken},
			{Address: netip.MustParseAddr("203.0.113.4"), Port: 862, Type: ResponderTWAMP, Prober: noOrder},
			{Address: excluded, Port: 862, Type: ResponderTWAMP, Prober: silent},
		},
		Packets: 5, Spacing: time.Millisecond, Timeout: time.Millisecond, Interval: time.Minute, Flows: 3,
		Exclude: &Exclusion{Prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.192/26")}},
		Now:     func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	m.RunOnce(context.Background())
	rs := m.Results()
	if len(rs) != 5 {
		t.Fatalf("results %d", len(rs))
	}
	if rs[0].Err != "no reply" || len(rs[0].Flows) != 3 || rs[0].WorstFlow != 0 {
		t.Fatalf("silent: %+v", rs[0])
	}
	// A source that cannot be used fails the whole result at the first
	// train; no further train is sent from it.
	if !strings.Contains(rs[1].Err, plugin.ErrSourceUnavailable.Error()) || len(rs[1].Flows) != 0 || len(down.reqs) != 1 {
		t.Fatalf("down: %+v, requests %d", rs[1], len(down.reqs))
	}
	if rs[2].Err != "socket: boom" || len(rs[2].Flows) != 3 || rs[2].Flows[2].Err != "socket: boom" {
		t.Fatalf("broken: %+v", rs[2])
	}
	if rs[3].Err != "prober reports no arrival order" || rs[3].Flows[0].Sent != 5 || rs[3].Flows[0].Received != 0 {
		t.Fatalf("no order: %+v", rs[3])
	}
	if rs[4].Err != "excluded by probe.exclude" || len(silent.reqs) != 3 {
		t.Fatalf("excluded: %+v, silent requests %d", rs[4], len(silent.reqs))
	}
	if got := m.Scored(now, time.Minute); len(got) != 0 {
		t.Fatalf("failed readings scored: %v", got)
	}
}

// noOrderProber answers like a prober that cannot tell which request a
// reply answers (the exec protocol): RTTs without Order.
type noOrderProber struct{ plugin.Base }

func (noOrderProber) Probe(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	res := plugin.ProbeResult{Sent: req.Count}
	for range req.Count {
		res.RTTs = append(res.RTTs, time.Millisecond)
	}
	return res, nil
}

func TestReorderMonitorRun(t *testing.T) {
	p := &trainProber{orders: map[string][][]int{}}
	var rounds int
	ctx, cancel := context.WithCancel(context.Background())
	var slept []time.Duration
	now := time.Now()
	m, err := NewReorderMonitor(ReorderOptions{
		Providers:  []Provider{reProvA},
		Responders: []Responder{{Address: reflectorAddr, Port: 862, Type: ResponderTWAMP, Prober: p}},
		Packets:    2, Spacing: time.Millisecond, Timeout: time.Millisecond, Interval: 30 * time.Second, Flows: 1,
		Now: func() time.Time { return now },
		Sleep: func(_ context.Context, d time.Duration) error {
			slept = append(slept, d)
			rounds++
			if rounds == 3 {
				cancel()
				return ctx.Err()
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v", err)
	}
	if len(p.reqs) != 3 || len(slept) != 3 || slept[0] != 30*time.Second {
		t.Fatalf("trains %d, sleeps %v", len(p.reqs), slept)
	}
}

func TestNewReorderMonitorRejects(t *testing.T) {
	ok := ReorderOptions{Packets: 2, Spacing: time.Millisecond, Timeout: time.Millisecond, Interval: time.Second, Flows: 1}
	if _, err := NewReorderMonitor(ok); err != nil {
		t.Fatal(err)
	}
	bad := ok
	bad.Packets = 1
	if _, err := NewReorderMonitor(bad); err == nil {
		t.Fatal("one packet accepted")
	}
	bad = ok
	bad.Responders = []Responder{{Address: reflectorAddr}}
	if _, err := NewReorderMonitor(bad); err == nil {
		t.Fatal("responder without prober accepted")
	}
	bad.Responders = []Responder{{Address: reflectorAddr, Type: "udp", Prober: &trainProber{}}}
	if _, err := NewReorderMonitor(bad); err == nil || !strings.Contains(err.Error(), `type "udp"`) {
		t.Fatalf("unknown responder type: %v", err)
	}
}
