package probe

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var (
	wide  = netip.MustParsePrefix("198.51.100.0/24")
	sub1  = netip.MustParsePrefix("198.51.100.0/26")
	sub2  = netip.MustParsePrefix("198.51.100.192/26")
	host1 = netip.MustParseAddr("198.51.100.10")
	host2 = netip.MustParseAddr("198.51.100.202")
)

func twoSubranges(w1, w2 float64) []plugin.Subrange {
	return []plugin.Subrange{{Prefix: sub1, Host: host1, Weight: w1}, {Prefix: sub2, Host: host2, Weight: w2}}
}

func TestCleanSubranges(t *testing.T) {
	in := []plugin.Subrange{
		{Prefix: sub1, Host: host1, Weight: 5},
		{Prefix: sub1, Host: netip.MustParseAddr("198.51.100.11"), Weight: 5}, // duplicate sub-range
		{Prefix: wide, Host: host2, Weight: 5},                                // not more specific
		{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Host: netip.MustParseAddr("203.0.113.1"), Weight: 5},
		{Prefix: sub2, Host: host1, Weight: 5}, // host outside the sub-range
		{Prefix: netip.MustParsePrefix("198.51.100.64/26"), Host: netip.MustParseAddr("198.51.100.65"), Weight: 0},
		{Prefix: netip.MustParsePrefix("198.51.100.201/26"), Host: host2, Weight: 3}, // masked
	}
	got := cleanSubranges(wide, in)
	if len(got) != 2 || got[0].Prefix != sub1 || got[1].Prefix != sub2 || got[1].Weight != 3 {
		t.Fatalf("clean = %+v", got)
	}
	if got := cleanSubranges(wide, in[:3]); got != nil {
		t.Fatalf("one usable sub-range kept: %+v", got)
	}
	var many []plugin.Subrange
	for i := 0; i < 40; i++ {
		a := netip.AddrFrom4([4]byte{198, 51, 100, byte(i*4 + 1)})
		many = append(many, plugin.Subrange{Prefix: netip.PrefixFrom(a, 30).Masked(), Host: a, Weight: 1})
	}
	if got := cleanSubranges(wide, many); len(got) != plugin.MaxSubranges {
		t.Fatalf("cap = %d", len(got))
	}
}

func TestCombineSubrangesWeighted(t *testing.T) {
	subs := []SubrangeResult{
		{Prefix: sub1, Target: host1, Weight: 3, Stats: Stats{Sent: 4, Received: 4, RTTMin: 10 * time.Millisecond, RTTAvg: 10 * time.Millisecond, RTTMax: 10 * time.Millisecond}},
		{Prefix: sub2, Target: host2, Weight: 1, Stats: Stats{Sent: 4, Received: 0, LossPct: 100}},
		{Prefix: netip.MustParsePrefix("198.51.100.64/26"), Target: netip.MustParseAddr("198.51.100.65"), Weight: 4, Err: "no route"},
	}
	r, ok := combineSubranges("transit-a", wide, subs)
	if !ok {
		t.Fatal("not ok")
	}
	// Loss is weighted over every sub-range, the errored one as full
	// loss (5 of 8 parts lost all), RTT over the ones that answered.
	// Targets lists only the measured hosts.
	if r.Stats.LossPct != 62.5 || r.Stats.RTTAvg != 10*time.Millisecond || r.Stats.Sent != 8 || r.Stats.Received != 4 || r.Target != host1 ||
		len(r.Targets) != 2 || r.Targets[0] != host1 || r.Targets[1] != host2 {
		t.Fatalf("combined = %+v", r)
	}
	if _, ok := combineSubranges("transit-a", wide, subs[2:]); ok {
		t.Fatal("ok with no measured sub-range")
	}
}

// hostProber answers per target. Hosts in dead get errors.
type hostProber struct {
	plugin.Base
	mu   sync.Mutex
	rtt  map[netip.Addr]float64
	dead map[netip.Addr]bool
	seen []netip.Addr
	down bool
}

func (p *hostProber) Probe(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen = append(p.seen, req.Target)
	if p.down {
		return plugin.ProbeResult{}, plugin.ErrSourceUnavailable
	}
	if p.dead[req.Target] {
		return plugin.ProbeResult{}, context.DeadlineExceeded
	}
	rtt := p.rtt[req.Target]
	if rtt == 0 {
		rtt = 50
	}
	return plugin.ProbeResult{Sent: req.Count, RTTs: ms(rtt)[:1]}, nil
}

func TestEngineSubranges(t *testing.T) {
	t.Run("measured per sub-range", func(t *testing.T) {
		p := &hostProber{rtt: map[netip.Addr]float64{host1: 10, host2: 30}}
		o := opts()
		o.Packets = 1
		e, err := New([]Provider{provA}, []NamedProber{{Name: "h", Prober: p}},
			src(plugin.Target{Prefix: wide, Host: host1, Candidate: true, Subranges: twoSubranges(1, 1)}), o)
		if err != nil {
			t.Fatal(err)
		}
		e.RunOnce(context.Background())
		rs := e.Results()
		if len(rs) != 1 || len(rs[0].Subranges) != 2 || rs[0].Stats.RTTAvg != 20*time.Millisecond {
			t.Fatalf("results = %+v", rs)
		}
		if len(p.seen) != 2 {
			t.Fatalf("probed = %v", p.seen)
		}
	})

	t.Run("pin ignores sub-ranges", func(t *testing.T) {
		p := &hostProber{}
		pinHost := netip.MustParseAddr("198.51.100.129")
		e, err := New([]Provider{provA}, []NamedProber{{Name: "h", Prober: p}},
			src(plugin.Target{Prefix: wide, Host: pinHost, Subranges: twoSubranges(1, 1)}), opts())
		if err != nil {
			t.Fatal(err)
		}
		e.RunOnce(context.Background())
		rs := e.Results()
		if len(rs) != 1 || len(rs[0].Subranges) != 0 || len(p.seen) != 1 || p.seen[0] != pinHost {
			t.Fatalf("results = %+v probed %v", rs, p.seen)
		}
	})

	t.Run("no sub-range measured falls back to hosts", func(t *testing.T) {
		p := &hostProber{dead: map[netip.Addr]bool{host1: true, host2: true}}
		e, err := New([]Provider{provA}, []NamedProber{{Name: "h", Prober: p}},
			src(plugin.Target{Prefix: wide, Subranges: twoSubranges(1, 1)}), opts())
		if err != nil {
			t.Fatal(err)
		}
		e.RunOnce(context.Background())
		rs := e.Results()
		if len(rs) != 1 || !rs[0].OK() || len(rs[0].Subranges) != 0 || rs[0].Target.String() != "198.51.100.1" {
			t.Fatalf("results = %+v", rs)
		}
	})

	t.Run("dead probe source fails closed", func(t *testing.T) {
		p := &hostProber{down: true}
		e, err := New([]Provider{provA}, []NamedProber{{Name: "h", Prober: p}},
			src(plugin.Target{Prefix: wide, Subranges: twoSubranges(1, 1)}), opts())
		if err != nil {
			t.Fatal(err)
		}
		e.RunOnce(context.Background())
		if st := e.Providers(); st[0].Up {
			t.Fatalf("provider up after source loss: %+v", st)
		}
		if len(p.seen) != 1 {
			t.Fatalf("kept probing after source loss: %v", p.seen)
		}
	})

	t.Run("exchange LAN host dropped", func(t *testing.T) {
		p := &hostProber{}
		o := opts()
		o.ExchangeLANs = []netip.Prefix{sub2}
		subs := append(twoSubranges(1, 1), plugin.Subrange{Prefix: netip.MustParsePrefix("198.51.100.64/26"), Host: netip.MustParseAddr("198.51.100.65"), Weight: 1})
		e, err := New([]Provider{provA}, []NamedProber{{Name: "h", Prober: p}},
			src(plugin.Target{Prefix: wide, Subranges: subs}), o)
		if err != nil {
			t.Fatal(err)
		}
		e.RunOnce(context.Background())
		for _, h := range p.seen {
			if h == host2 {
				t.Fatalf("probed a peering LAN host: %v", p.seen)
			}
		}
		if rs := e.Results(); len(rs) != 1 || len(rs[0].Subranges) != 2 {
			t.Fatalf("results = %+v", rs)
		}
	})
}

// TestErroredSubrangeCountsAgainstProvider checks that a provider which
// errors on the busiest sub-range does not score better than one that
// answers everywhere by having that sub-range left out.
func TestErroredSubrangeCountsAgainstProvider(t *testing.T) {
	ok := func(rtt time.Duration) Stats {
		return Stats{Sent: 4, Received: 4, RTTMin: rtt, RTTAvg: rtt, RTTMax: rtt}
	}
	a, _ := combineSubranges("transit-a", wide, []SubrangeResult{
		{Prefix: sub1, Target: host1, Weight: 9, Err: "no route"},
		{Prefix: sub2, Target: host2, Weight: 1, Stats: ok(5 * time.Millisecond)},
	})
	b, _ := combineSubranges("transit-b", wide, []SubrangeResult{
		{Prefix: sub1, Target: host1, Weight: 9, Stats: ok(30 * time.Millisecond)},
		{Prefix: sub2, Target: host2, Weight: 1, Stats: ok(30 * time.Millisecond)},
	})
	if a.Stats.LossPct != 90 || b.Stats.LossPct != 0 {
		t.Fatalf("loss a=%v b=%v", a.Stats.LossPct, b.Stats.LossPct)
	}
}

func TestRetainedDropsSubranges(t *testing.T) {
	// A retained prefix no source lists any more is measured on its
	// hosts, not on sub-range weights from traffic that may be gone.
	r := rememberedTarget(normalizeTarget(plugin.Target{Prefix: wide, Host: host1, Candidate: true, Subranges: twoSubranges(2, 1)}))
	if len(r.Subranges) != 0 || r.Host != host1 || !r.Candidate {
		t.Fatalf("remembered = %+v", r)
	}
}

func manySubranges(n int) []plugin.Subrange {
	out := make([]plugin.Subrange, n)
	for i := range out {
		a := netip.AddrFrom4([4]byte{198, 51, 100, byte(i*16 + 1)})
		out[i] = plugin.Subrange{Prefix: netip.PrefixFrom(a, 28).Masked(), Host: a, Weight: 1}
	}
	return out
}

func TestSubrangeJobStopsAtSilentProvider(t *testing.T) {
	subs := manySubranges(8)
	run := func(t *testing.T, fn func(context.Context, plugin.ProbeRequest) (plugin.ProbeResult, error), down bool) (*fakeProber, Result) {
		t.Helper()
		pr := &fakeProber{fn: fn}
		o := opts()
		o.Packets = 1
		e, err := New([]Provider{provA}, []NamedProber{{Name: "p", Prober: pr}}, nil, o)
		if err != nil {
			t.Fatal(err)
		}
		j := job{provider: provA, target: plugin.Target{Prefix: wide, Subranges: subs}, subs: subs}
		res, isDown, ok := e.probeSubranges(context.Background(), j, func(string) bool { return down })
		if isDown || !ok {
			t.Fatalf("down=%v ok=%v", isDown, ok)
		}
		return pr, res
	}

	t.Run("provider looks down", func(t *testing.T) {
		pr, res := run(t, noReplies, true)
		if got := int(pr.calls.Load()); got != silentHostLimit {
			t.Fatalf("probed %d sub-range hosts, want %d", got, silentHostLimit)
		}
		if len(res.Subranges) != silentHostLimit || res.Stats.LossPct != 100 {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("healthy provider probes every sub-range", func(t *testing.T) {
		pr, res := run(t, noReplies, false)
		if got := int(pr.calls.Load()); got != len(subs) {
			t.Fatalf("probed %d sub-range hosts, want %d", got, len(subs))
		}
		if len(res.Subranges) != len(subs) {
			t.Fatalf("sub-ranges = %d", len(res.Subranges))
		}
	})
	t.Run("an answer keeps the job going", func(t *testing.T) {
		var n atomic.Int32
		fn := func(ctx context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
			if n.Add(1) == 2 {
				return allReplies(ctx, req)
			}
			return noReplies(ctx, req)
		}
		pr, res := run(t, fn, true)
		if got := int(pr.calls.Load()); got != len(subs) {
			t.Fatalf("probed %d sub-range hosts, want %d", got, len(subs))
		}
		if res.Stats.Received == 0 {
			t.Fatalf("result = %+v", res)
		}
	})
}

// TestSortJobsUsesReloadedInterval checks that job order ranks against the
// interval in force after a timing reload, not the one at start.
func TestSortJobsUsesReloadedInterval(t *testing.T) {
	long := netip.MustParseAddr("198.51.100.1")
	plain := netip.MustParseAddr("203.0.113.1")
	pr := &hostProber{}
	o := opts()
	o.Workers = 1
	o.Packets = 1
	o.Interval = time.Second
	e, err := New([]Provider{provA}, []NamedProber{{Name: "h", Prober: pr}}, src(
		plugin.Target{Prefix: netip.PrefixFrom(plain, 32), Host: plain},
		plugin.Target{Prefix: netip.PrefixFrom(long, 32), Host: long, Interval: 5 * time.Second},
	), o)
	if err != nil {
		t.Fatal(err)
	}
	tm := e.TimingNow()
	tm.Interval = time.Minute
	e.SetTiming(tm)
	e.RunOnce(context.Background())
	// Under the new base the 5s target is the shorter interval (VIP tier).
	if len(pr.seen) != 2 || pr.seen[0] != long {
		t.Fatalf("probe order = %v, want %s first", pr.seen, long)
	}
}
