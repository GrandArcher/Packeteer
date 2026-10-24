package probe

import (
	"context"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// recordingProber keeps every address a probe request named.
type recordingProber struct {
	plugin.Base
	mu      sync.Mutex
	targets []netip.Addr
	times   []time.Time
}

func (r *recordingProber) Probe(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	r.mu.Lock()
	r.targets = append(r.targets, req.Target)
	r.times = append(r.times, time.Now())
	r.mu.Unlock()
	return plugin.ProbeResult{Sent: req.Count, RTTs: ms(1)}, nil
}

func (r *recordingProber) seen() []netip.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.targets)
}

// originIn maps a prefix to the origin ASN of the documentation block that
// contains it, the way the RIB lookup would.
func originIn(blocks map[string]uint32) func(netip.Prefix) uint32 {
	var ps []netip.Prefix
	var asns []uint32
	for s, asn := range blocks {
		ps = append(ps, netip.MustParsePrefix(s))
		asns = append(asns, asn)
	}
	return func(p netip.Prefix) uint32 {
		for i, b := range ps {
			if b.Contains(p.Addr()) {
				return asns[i]
			}
		}
		return 0
	}
}

func TestExcludedDestinationsGetNoPackets(t *testing.T) {
	byPrefix := netip.MustParsePrefix("203.0.113.0/24")
	byASN := netip.MustParsePrefix("192.0.2.0/24")
	allowed := netip.MustParsePrefix("198.51.100.0/24")
	covering := netip.MustParsePrefix("203.0.112.0/23")
	x := &Exclusion{Prefixes: []netip.Prefix{byPrefix}, ASNs: map[uint32]bool{64500: true},
		Origin: originIn(map[string]uint32{"192.0.2.0/24": 64500, "198.51.100.0/24": 64501})}
	o := opts()
	o.Exclude = x
	pr := &recordingProber{}
	// Every source kind lists the excluded prefix: a pin, a flow candidate
	// with extra hosts, a shorter interval with an urgent mark, and a
	// prefix whose origin is the excluded ASN.
	static := &fakeSource{targets: []plugin.Target{
		{Prefix: byPrefix, Host: netip.MustParseAddr("203.0.113.9")},
		{Prefix: allowed, Host: netip.MustParseAddr("198.51.100.9")},
		{Prefix: byASN, Host: netip.MustParseAddr("192.0.2.9")},
	}}
	flow := &fakeSource{targets: []plugin.Target{
		{Prefix: byPrefix, Host: netip.MustParseAddr("203.0.113.20"), Candidate: true, Hosts: []netip.Addr{netip.MustParseAddr("203.0.113.21")}},
		{Prefix: covering, Host: netip.MustParseAddr("203.0.113.30"), Candidate: true,
			Hosts: []netip.Addr{netip.MustParseAddr("203.0.113.31"), netip.MustParseAddr("203.0.112.31")}},
	}}
	vip := &fakeSource{targets: []plugin.Target{{Prefix: byPrefix, Interval: 200 * time.Millisecond, Urgent: true}}}
	e, err := New([]Provider{provA}, []NamedProber{{Name: "p", Prober: pr}},
		[]NamedSource{{Name: "static", Source: static}, {Name: "flow", Source: flow}, {Name: "vip", Source: vip}}, o)
	if err != nil {
		t.Fatal(err)
	}
	// A retained improvement and the operator's queue cannot bring one back.
	e.SetRetained([]netip.Prefix{byPrefix, byASN})
	if err := e.QueueManual(byPrefix, time.Minute); err != nil {
		t.Fatal(err)
	}
	ts := e.Targets(context.Background())
	var kept []string
	for _, tg := range ts {
		kept = append(kept, tg.Prefix.String())
	}
	sort.Strings(kept)
	if want := []string{allowed.String(), covering.String()}; !slices.Equal(kept, want) {
		t.Fatalf("targets = %v, want %v", kept, want)
	}
	e.RunOnce(context.Background())
	seen := pr.seen()
	if len(seen) == 0 {
		t.Fatal("nothing probed")
	}
	probed := map[netip.Prefix]bool{}
	for _, a := range seen {
		if byPrefix.Contains(a) || byASN.Contains(a) {
			t.Fatalf("packet toward excluded address %s", a)
		}
		for _, r := range e.Results() {
			if r.Target == a {
				probed[r.Prefix] = true
			}
		}
	}
	if !probed[allowed] || !probed[covering] {
		t.Fatalf("allowed prefixes not measured: %v (seen %v)", probed, seen)
	}
	for _, r := range e.Results() {
		if r.Prefix == covering && !covering.Contains(r.Target) {
			t.Fatalf("covering prefix measured outside itself: %+v", r)
		}
	}
}

func TestProbeOneRefusesExcludedHost(t *testing.T) {
	x := &Exclusion{Prefixes: []netip.Prefix{pfx2}}
	o := opts()
	o.Exclude = x
	pr := &fakeProber{fn: ok(1)}
	e, err := New([]Provider{provA}, []NamedProber{{Name: "p", Prober: pr}}, nil, o)
	if err != nil {
		t.Fatal(err)
	}
	res, down := e.probeOne(context.Background(), provA, pfx2, netip.MustParseAddr("203.0.113.1"), 1)
	if down || res.OK() || res.Err != "excluded by probe.exclude" || pr.calls.Load() != 0 {
		t.Fatalf("res=%+v down=%v calls=%d", res, down, pr.calls.Load())
	}
	res, _ = e.probeOne(context.Background(), provA, pfx1, netip.MustParseAddr("198.51.100.1"), 1)
	if !res.OK() || pr.calls.Load() != 1 {
		t.Fatalf("allowed host: res=%+v calls=%d", res, pr.calls.Load())
	}
}

func TestExclusionRules(t *testing.T) {
	var none *Exclusion
	if none.Prefix(pfx1) || none.Addr(netip.MustParseAddr("198.51.100.1")) || !none.Empty() {
		t.Fatal("nil exclusion matched")
	}
	x := &Exclusion{Prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/48"), pfx2},
		ASNs: map[uint32]bool{64500: true}, Origin: originIn(map[string]uint32{"192.0.2.0/24": 64500, "198.51.100.0/24": 64501})}
	cases := []struct {
		p    string
		want bool
	}{
		{"203.0.113.0/24", true}, {"203.0.113.128/25", true}, {"203.0.112.0/23", false},
		{"2001:db8:1:2::/64", true}, {"2001:db8:2::/48", false},
		{"192.0.2.0/25", true}, {"198.51.100.0/24", false},
	}
	for _, c := range cases {
		if got := x.Prefix(netip.MustParsePrefix(c.p)); got != c.want {
			t.Errorf("Prefix(%s) = %v, want %v", c.p, got, c.want)
		}
	}
	for a, want := range map[string]bool{"203.0.113.7": true, "::ffff:203.0.113.7": true, "192.0.2.7": true, "198.51.100.7": false, "2001:db8:1::7": true} {
		if got := x.Addr(netip.MustParseAddr(a)); got != want {
			t.Errorf("Addr(%s) = %v, want %v", a, got, want)
		}
	}
	// Without an origin lookup the ASN list cannot match and the prefixes still do.
	y := &Exclusion{ASNs: map[uint32]bool{64500: true}, Prefixes: []netip.Prefix{pfx2}}
	if y.Prefix(netip.MustParsePrefix("192.0.2.0/24")) || !y.Prefix(pfx2) {
		t.Fatal("ASN rule matched without an origin lookup")
	}
}

func TestNewValidationExclusionAndCap(t *testing.T) {
	pr := []NamedProber{{Name: "p", Prober: &fakeProber{fn: ok(1)}}}
	o := opts()
	o.PerASNPPS = -1
	if _, err := New([]Provider{provA}, pr, nil, o); err == nil {
		t.Fatal("negative per-ASN rate accepted")
	}
	o = opts()
	o.PerASNPPS = 10
	if _, err := New([]Provider{provA}, pr, nil, o); err == nil {
		t.Fatal("per-ASN rate without origin lookup accepted")
	}
	o = opts()
	o.Exclude = &Exclusion{ASNs: map[uint32]bool{64500: true}}
	if _, err := New([]Provider{provA}, pr, nil, o); err == nil {
		t.Fatal("excluded ASNs without origin lookup accepted")
	}
	o = opts()
	o.PerASNPPS = 10
	o.Origin = func(netip.Prefix) uint32 { return 0 }
	if _, err := New([]Provider{provA}, pr, nil, o); err != nil {
		t.Fatal(err)
	}
}

// TestPerASNCapHoldsUnderLoad runs sixteen workers over three groups of
// pinned hosts: two origin ASNs under a 20 pps cap and one with no learned
// origin. No one-second window toward a capped ASN may hold more than the
// burst plus one second of refill, the uncapped group finishes at once,
// and every packet still passes the global limiter.
func TestPerASNCapHoldsUnderLoad(t *testing.T) {
	const pps, perGroup = 20, 60
	o := opts()
	o.Packets = 1
	o.Workers = 16
	o.PerTargetConcurrency = 4
	o.Interval = 10 * time.Second
	o.PerASNPPS = pps
	o.Origin = originIn(map[string]uint32{"198.51.100.0/24": 64500, "203.0.113.0/24": 64501})
	global := &countingLimiter{}
	o.Limiter = global
	groups := map[string]uint32{"198.51.100.0/24": 64500, "203.0.113.0/24": 64501, "192.0.2.0/24": 0}
	var targets []plugin.Target
	for s := range groups {
		base := netip.MustParsePrefix(s).Addr().As4()
		for i := 1; i <= perGroup; i++ {
			base[3] = byte(i)
			a := netip.AddrFrom4(base)
			targets = append(targets, plugin.Target{Prefix: netip.PrefixFrom(a, 32), Host: a})
		}
	}
	pr := &recordingProber{}
	e, err := New([]Provider{provA}, []NamedProber{{Name: "p", Prober: pr}}, src(targets...), o)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	e.RunOnce(context.Background())
	pr.mu.Lock()
	defer pr.mu.Unlock()
	if len(pr.targets) != 3*perGroup || global.total != 3*perGroup {
		t.Fatalf("packets = %d, global tokens = %d, want %d", len(pr.targets), global.total, 3*perGroup)
	}
	byGroup := map[string][]time.Time{}
	for i, a := range pr.targets {
		for s := range groups {
			if netip.MustParsePrefix(s).Contains(a) {
				byGroup[s] = append(byGroup[s], pr.times[i])
			}
		}
	}
	for s, asn := range groups {
		ts := byGroup[s]
		sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
		span := ts[len(ts)-1].Sub(ts[0])
		if asn == 0 {
			if span > 500*time.Millisecond {
				t.Fatalf("uncapped group %s took %s", s, span)
			}
			continue
		}
		// 60 packets at burst 20 and 20 per second need two seconds.
		if span < 1500*time.Millisecond {
			t.Fatalf("capped group %s (AS%d) finished in %s", s, asn, span)
		}
		for i := range ts {
			n := 0
			for j := i; j < len(ts) && ts[j].Sub(ts[i]) < time.Second; j++ {
				n++
			}
			if n > 2*pps+1 {
				t.Fatalf("AS%d: %d packets inside one second, cap %d burst %d", asn, n, pps, pps)
			}
		}
	}
	// Two seconds of cap plus slack, well inside the ten-second round budget.
	if took := time.Since(start); took > 9*time.Second {
		t.Fatalf("round took %s", took)
	}
}

func TestASNLimitsEvictLeastRecentlyUsed(t *testing.T) {
	l := newASNLimits(5, 3, func(netip.Prefix) uint32 { return 0 })
	if l.burst != 5 {
		t.Fatalf("burst = %d, want the rate when it is larger than the packet count", l.burst)
	}
	for asn := uint32(1); asn <= maxASNLimiters; asn++ {
		l.limiter(asn)
	}
	l.limiter(1) // touched again: stays
	l.limiter(maxASNLimiters + 1)
	if len(l.m) != maxASNLimiters {
		t.Fatalf("limiters = %d, want %d", len(l.m), maxASNLimiters)
	}
	if _, ok := l.m[1]; !ok {
		t.Fatal("recently used ASN evicted")
	}
	if _, ok := l.m[2]; ok {
		t.Fatal("least recently used ASN kept")
	}
	// No learned origin: nothing to wait on.
	if err := l.wait(context.Background(), netip.MustParseAddr("192.0.2.1"), 100); err != nil {
		t.Fatal(err)
	}
}
