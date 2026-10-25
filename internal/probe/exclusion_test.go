package probe

import (
	"context"
	"maps"
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
}

func (r *recordingProber) Probe(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	r.mu.Lock()
	r.targets = append(r.targets, req.Target)
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

func TestNewRefusesExcludedASNsWithoutOrigin(t *testing.T) {
	pr := []NamedProber{{Name: "p", Prober: &fakeProber{fn: ok(1)}}}
	o := opts()
	o.Exclude = &Exclusion{ASNs: map[uint32]bool{64500: true}}
	if _, err := New([]Provider{provA}, pr, nil, o); err == nil {
		t.Fatal("excluded ASNs without origin lookup accepted")
	}
	o.Exclude.Origin = func(netip.Prefix) uint32 { return 0 }
	if _, err := New([]Provider{provA}, pr, nil, o); err != nil {
		t.Fatal(err)
	}
}

// frozenWaits records what a frozenASNLimits was asked.
type frozenWaits struct {
	mu     sync.Mutex
	asked  map[netip.Addr]int
	delays []time.Duration
}

func (f *frozenWaits) snapshot() (map[netip.Addr]int, []time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return maps.Clone(f.asked), slices.Clone(f.delays)
}

// frozenASNLimits is an ASNLimits whose clock never moves. A wait does not
// sleep; it records the delay its bucket asked for, so the schedule every
// packet would keep is exact however the workers interleave.
func frozenASNLimits(pps, burst int, origin func(netip.Prefix) uint32) (*ASNLimits, *frozenWaits) {
	f := &frozenWaits{asked: map[netip.Addr]int{}}
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	l := NewASNLimits(pps, burst, func(p netip.Prefix) uint32 {
		f.mu.Lock()
		f.asked[p.Addr()]++
		f.mu.Unlock()
		return origin(p)
	})
	l.now = func() time.Time { return t0 }
	l.sleep = func(_ context.Context, d time.Duration) error {
		f.mu.Lock()
		f.delays = append(f.delays, d.Round(time.Millisecond))
		f.mu.Unlock()
		return nil
	}
	return l, f
}

// TestPerASNCapHoldsUnderLoad runs sixteen workers over three groups of
// sixty pinned hosts: two origin ASNs under a 20 pps cap and one with no
// learned origin. Each capped ASN lets its burst of 20 go at once and
// spaces the other 40 at 50 ms, the uncapped group never waits, and every
// packet still passes the global limiter.
func TestPerASNCapHoldsUnderLoad(t *testing.T) {
	const pps, perGroup = 20, 60
	o := opts()
	o.Packets = 1
	o.Workers = 16
	o.PerTargetConcurrency = 4
	perASN, waits := frozenASNLimits(pps, o.Packets, originIn(map[string]uint32{"198.51.100.0/24": 64500, "203.0.113.0/24": 64501}))
	o.PerASN = perASN
	global := &countingLimiter{}
	o.Limiter = global
	var targets []plugin.Target
	for _, s := range []string{"198.51.100.0/24", "203.0.113.0/24", "192.0.2.0/24"} {
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
	e.RunOnce(context.Background())
	if got := len(pr.seen()); got != 3*perGroup || global.total != 3*perGroup {
		t.Fatalf("packets = %d, global tokens = %d, want %d", got, global.total, 3*perGroup)
	}
	asked, delays := waits.snapshot()
	if len(asked) != 3*perGroup {
		t.Fatalf("per-ASN waits named %d hosts, want every one of %d", len(asked), 3*perGroup)
	}
	var want []time.Duration
	for k := 1; k <= perGroup-pps; k++ {
		d := time.Duration(k) * time.Second / pps
		want = append(want, d, d) // one per capped ASN
	}
	slices.Sort(delays)
	if !slices.Equal(delays, want) {
		t.Fatalf("waits = %v, want %v", delays, want)
	}
}

// probe.indirect traces count every TTL packet against the destination's
// origin ASN before the global limit (#203).
func TestIndirectTracesWaitPerASN(t *testing.T) {
	hop := twoPaths()
	global := &countingLimiter{}
	e, _ := indirectEngine(t, hop, &hopProber{}, global)
	ctx := context.Background()
	e.RunOnce(ctx)
	// Attached after the round, so only trace packets reach it.
	perASN, waits := frozenASNLimits(1, 1, originIn(map[string]uint32{"198.51.100.0/24": 64500}))
	e.opt.PerASN = perASN
	before := global.total
	if n := e.IndirectPass(ctx); n != 2 {
		t.Fatalf("pass finished %d traces, want 2", n)
	}
	sent := hop.total()
	asked, delays := waits.snapshot()
	if sent == 0 || asked[silentIn] != sent || len(asked) != 1 || global.total-before != sent {
		t.Fatalf("trace packets %d, per-ASN waits %v, global tokens %d", sent, asked, global.total-before)
	}
	// One bucket at 1 pps with burst 1: every packet after the first waits
	// one second longer than the one before it.
	if len(delays) != sent-1 || delays[len(delays)-1] != time.Duration(sent-1)*time.Second {
		t.Fatalf("delays = %v for %d packets", delays, sent)
	}
}

func TestASNLimitsWait(t *testing.T) {
	if NewASNLimits(0, 10, func(netip.Prefix) uint32 { return 64500 }) != nil {
		t.Fatal("a zero cap built a limiter")
	}
	var off *ASNLimits
	if err := off.Wait(context.Background(), netip.MustParseAddr("192.0.2.1"), 5); err != nil {
		t.Fatal(err)
	}
	l, waits := frozenASNLimits(2, 2, func(netip.Prefix) uint32 { return 64500 })
	host := netip.MustParseAddr("192.0.2.1")
	if err := l.Wait(context.Background(), host, 3); err == nil {
		t.Fatal("a wait larger than the burst passed")
	}
	if err := l.Wait(context.Background(), host, 2); err != nil {
		t.Fatal(err)
	}
	// A cancelled wait gives its tokens back: the next one asks for the
	// same delay instead of a longer one.
	l.sleep = func(ctx context.Context, d time.Duration) error {
		waits.mu.Lock()
		waits.delays = append(waits.delays, d)
		waits.mu.Unlock()
		return context.Canceled
	}
	for range 2 {
		if err := l.Wait(context.Background(), host, 1); err == nil {
			t.Fatal("cancelled wait returned nil")
		}
	}
	if _, d := waits.snapshot(); len(d) != 2 || d[0] != d[1] || d[0] != 500*time.Millisecond {
		t.Fatalf("delays after cancel = %v", d)
	}
}

// probe.exclude has no next_hop exemption (#203): a provider next hop in an
// excluded origin ASN gets no packet, the target's own hosts are still
// probed, and no sample is stored as refused.
func TestExcludedNextHopNotProbed(t *testing.T) {
	gw := netip.MustParseAddr("192.0.2.1")
	p := provA
	p.NextHop = gw
	o := opts()
	o.Exclude = &Exclusion{ASNs: map[uint32]bool{64500: true}, Origin: originIn(map[string]uint32{"192.0.2.0/24": 64500})}
	pr := &recordingProber{}
	e, err := New([]Provider{p}, []NamedProber{{Name: "p", Prober: pr}}, src(plugin.Target{Prefix: pfx1}), o)
	if err != nil {
		t.Fatal(err)
	}
	e.RunOnce(context.Background())
	seen := pr.seen()
	if len(seen) == 0 || slices.Contains(seen, gw) {
		t.Fatalf("probed %v; want the prefix hosts and not the excluded next hop %s", seen, gw)
	}
	for _, r := range e.Results() {
		if r.Err != "" || !r.OK() {
			t.Fatalf("result %+v", r)
		}
	}
}

// A round where a source timed out still drops probe.exclude targets from
// the partial list (#203).
func TestIncompleteRoundStillDropsExcluded(t *testing.T) {
	o := opts()
	o.Exclude = &Exclusion{Prefixes: []netip.Prefix{pfx2}}
	static := &fakeSource{targets: []plugin.Target{{Prefix: pfx1}, {Prefix: pfx2}}}
	slow := &fakeSource{err: context.DeadlineExceeded}
	e, err := New([]Provider{provA}, []NamedProber{{Name: "p", Prober: &fakeProber{fn: ok(1)}}},
		[]NamedSource{{Name: "static", Source: static}, {Name: "slow", Source: slow}}, o)
	if err != nil {
		t.Fatal(err)
	}
	ts, incomplete := e.gatherTargets(context.Background())
	if !incomplete || len(ts) != 1 || ts[0].Prefix != pfx1 {
		t.Fatalf("incomplete=%v targets=%+v", incomplete, ts)
	}
}

func TestASNLimitsEvictLeastRecentlyUsed(t *testing.T) {
	l := NewASNLimits(5, 3, func(netip.Prefix) uint32 { return 0 })
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
	if err := l.Wait(context.Background(), netip.MustParseAddr("192.0.2.1"), 100); err != nil {
		t.Fatal(err)
	}
}
