package probe

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var (
	wide  = netip.MustParsePrefix("198.51.0.0/16")
	sub1  = netip.MustParsePrefix("198.51.100.0/24")
	sub2  = netip.MustParsePrefix("198.51.200.0/24")
	host1 = netip.MustParseAddr("198.51.100.10")
	host2 = netip.MustParseAddr("198.51.200.10")
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
		{Prefix: netip.MustParsePrefix("198.51.7.0/24"), Host: netip.MustParseAddr("198.51.7.1"), Weight: 0},
		{Prefix: netip.MustParsePrefix("198.51.200.9/24"), Host: host2, Weight: 3}, // masked
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
		a := netip.AddrFrom4([4]byte{198, 51, byte(i), 1})
		many = append(many, plugin.Subrange{Prefix: netip.PrefixFrom(a, 24).Masked(), Host: a, Weight: 1})
	}
	if got := cleanSubranges(wide, many); len(got) != plugin.MaxSubranges {
		t.Fatalf("cap = %d", len(got))
	}
}

func TestCombineSubrangesWeighted(t *testing.T) {
	subs := []SubrangeResult{
		{Prefix: sub1, Target: host1, Weight: 3, Stats: Stats{Sent: 4, Received: 4, RTTMin: 10 * time.Millisecond, RTTAvg: 10 * time.Millisecond, RTTMax: 10 * time.Millisecond}},
		{Prefix: sub2, Target: host2, Weight: 1, Stats: Stats{Sent: 4, Received: 0, LossPct: 100}},
		{Prefix: netip.MustParsePrefix("198.51.7.0/24"), Weight: 100, Err: "no route"},
	}
	r, ok := combineSubranges("transit-a", wide, []netip.Addr{host1, host2}, subs)
	if !ok {
		t.Fatal("not ok")
	}
	// Loss is weighted over measured sub-ranges (1 of 4 parts lost all),
	// RTT over the ones that answered. The errored one is left out.
	if r.Stats.LossPct != 25 || r.Stats.RTTAvg != 10*time.Millisecond || r.Stats.Sent != 8 || r.Stats.Received != 4 || r.Target != host1 {
		t.Fatalf("combined = %+v", r)
	}
	if _, ok := combineSubranges("transit-a", wide, nil, subs[2:]); ok {
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
		e, err := New([]Provider{provA}, []NamedProber{{"h", p}},
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
		pinHost := netip.MustParseAddr("198.51.1.1")
		e, err := New([]Provider{provA}, []NamedProber{{"h", p}},
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
		e, err := New([]Provider{provA}, []NamedProber{{"h", p}},
			src(plugin.Target{Prefix: wide, Subranges: twoSubranges(1, 1)}), opts())
		if err != nil {
			t.Fatal(err)
		}
		e.RunOnce(context.Background())
		rs := e.Results()
		if len(rs) != 1 || !rs[0].OK() || len(rs[0].Subranges) != 0 || rs[0].Target.String() != "198.51.0.1" {
			t.Fatalf("results = %+v", rs)
		}
	})

	t.Run("dead probe source fails closed", func(t *testing.T) {
		p := &hostProber{down: true}
		e, err := New([]Provider{provA}, []NamedProber{{"h", p}},
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
		subs := append(twoSubranges(1, 1), plugin.Subrange{Prefix: netip.MustParsePrefix("198.51.7.0/24"), Host: netip.MustParseAddr("198.51.7.1"), Weight: 1})
		e, err := New([]Provider{provA}, []NamedProber{{"h", p}},
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

func TestRetainedKeepsSubranges(t *testing.T) {
	r := rememberedTarget(normalizeTarget(plugin.Target{Prefix: wide, Host: host1, Candidate: true, Subranges: twoSubranges(2, 1)}))
	if len(r.Subranges) != 2 {
		t.Fatalf("remembered = %+v", r)
	}
	if r := rememberedTarget(normalizeTarget(plugin.Target{Prefix: wide, Host: host1, Subranges: twoSubranges(2, 1)})); len(r.Subranges) != 0 {
		t.Fatalf("pin remembered sub-ranges: %+v", r)
	}
}
