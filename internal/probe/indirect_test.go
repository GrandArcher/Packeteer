package probe

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/source/traceroute"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// fakeHopper answers TTL-limited probes from a per-source path table.
// paths[src][ttl-1] is the hop that answers at that TTL; an invalid
// address is a silent TTL. Past the table every TTL is silent.
type fakeHopper struct {
	mu    sync.Mutex
	paths map[netip.Addr][]netip.Addr
	calls map[netip.Addr]int
	delay time.Duration
}

func (h *fakeHopper) hop(ctx context.Context, src, _ netip.Addr, ttl, _ int, timeout time.Duration) (netip.Addr, bool, error) {
	h.mu.Lock()
	if h.calls == nil {
		h.calls = map[netip.Addr]int{}
	}
	h.calls[src]++
	path := h.paths[src]
	delay := h.delay
	h.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return netip.Addr{}, false, ctx.Err()
		}
	}
	if ttl-1 < len(path) && path[ttl-1].IsValid() {
		return path[ttl-1], false, nil
	}
	return netip.Addr{}, false, nil
}

func (h *fakeHopper) total() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, c := range h.calls {
		n += c
	}
	return n
}

func (h *fakeHopper) from(src netip.Addr) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls[src]
}

var (
	hopA     = netip.MustParseAddr("203.0.113.50")
	hopB     = netip.MustParseAddr("203.0.113.61")
	silentIn = netip.MustParseAddr("198.51.100.1")
)

// twoPaths gives transit-a and transit-b different routes toward the
// silent prefix. a's last stable hop is at TTL 2, b's at TTL 3.
func twoPaths() *fakeHopper {
	return &fakeHopper{paths: map[netip.Addr][]netip.Addr{
		provA.Source: {netip.MustParseAddr("192.0.2.101"), hopA},
		provB.Source: {netip.MustParseAddr("192.0.2.102"), netip.MustParseAddr("203.0.113.60"), hopB},
	}}
}

// hopProber: every address inside 198.51.100.0/24 is silent unless
// answer is set; the two indirect hops answer with different RTTs.
type hopProber struct {
	mu     sync.Mutex
	answer bool
	hopA   bool // hopA answers
	seen   map[netip.Addr]int
}

func (p *hopProber) fn(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen == nil {
		p.seen = map[netip.Addr]int{}
	}
	p.seen[req.Target]++
	switch {
	case req.Target == hopA && p.hopA:
		return plugin.ProbeResult{Sent: req.Count, RTTs: ms(10, 10, 10)}, nil
	case req.Target == hopB:
		return plugin.ProbeResult{Sent: req.Count, RTTs: ms(40, 40, 40)}, nil
	case pfx1.Contains(req.Target) && p.answer:
		return plugin.ProbeResult{Sent: req.Count, RTTs: ms(5, 5, 5)}, nil
	}
	return plugin.ProbeResult{Sent: req.Count}, nil
}

func (p *hopProber) set(answer bool) {
	p.mu.Lock()
	p.answer = answer
	p.mu.Unlock()
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func indirectEngine(t *testing.T, hop *fakeHopper, pr *hopProber, lim Limiter, targets ...plugin.Target) (*Engine, *clock) {
	t.Helper()
	clk := &clock{t: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)}
	o := opts()
	o.Now = clk.now
	o.Limiter = lim
	o.Indirect = &Indirect{
		Tracer:   traceroute.Tracer{MaxHops: 8, Probes: 2, MinReplies: 2, Port: 33434, Timeout: 50 * time.Millisecond, Hop: hop.hop},
		Budget:   2 * time.Second,
		MinShare: 50 * time.Millisecond,
		CacheTTL: 10 * time.Minute,
	}
	if len(targets) == 0 {
		targets = []plugin.Target{{Prefix: pfx1}}
	}
	e, err := New([]Provider{provA, provB}, []NamedProber{{"fake", &fakeProber{fn: pr.fn}}}, src(targets...), o)
	if err != nil {
		t.Fatal(err)
	}
	return e, clk
}

func resultFor(t *testing.T, e *Engine, provider string) Result {
	t.Helper()
	for _, r := range e.Results() {
		if r.Provider == provider {
			return r
		}
	}
	t.Fatalf("no result for %s: %+v", provider, e.Results())
	return Result{}
}

// TestIndirectPerProviderHops: each provider is traced from its own
// source, the hops differ, and each provider is scored at its own hop.
func TestIndirectPerProviderHops(t *testing.T) {
	hop := twoPaths()
	pr := &hopProber{hopA: true}
	e, _ := indirectEngine(t, hop, pr, nil)
	ctx := context.Background()

	e.RunOnce(ctx)
	for _, r := range e.Results() {
		if r.Indirect || r.Stats.Received != 0 {
			t.Fatalf("first round before any trace: %+v", r)
		}
	}
	if got := len(e.pendingIndirect()); got != 2 {
		t.Fatalf("queued traces = %d, want one per provider", got)
	}
	if hop.total() != 0 {
		t.Fatal("the probe round traced; tracing belongs to the background pass")
	}
	if n := e.IndirectPass(ctx); n != 2 {
		t.Fatalf("pass finished %d traces, want 2", n)
	}
	if hop.from(provA.Source) == 0 || hop.from(provB.Source) == 0 {
		t.Fatalf("each provider must trace from its own source: %v", hop.calls)
	}

	e.RunOnce(ctx)
	a, b := resultFor(t, e, provA.Name), resultFor(t, e, provB.Name)
	if !a.Indirect || a.Target != hopA || a.Stats.RTTAvg != 10*time.Millisecond {
		t.Fatalf("transit-a not scored at its own hop: %+v", a)
	}
	if !b.Indirect || b.Target != hopB || b.Stats.RTTAvg != 40*time.Millisecond {
		t.Fatalf("transit-b not scored at its own hop: %+v", b)
	}
	if len(a.Hops) != 2 || a.Hops[0] != netip.MustParseAddr("192.0.2.101") || a.Hops[1] != hopA {
		t.Fatalf("transit-a hop path = %v", a.Hops)
	}
	if len(b.Hops) != 3 || b.Hops[2] != hopB {
		t.Fatalf("transit-b hop path = %v", b.Hops)
	}
	if a.Targets[len(a.Targets)-1] != hopA || a.Targets[0] != silentIn {
		t.Fatalf("targets should list the silent in-prefix addresses then the hop: %v", a.Targets)
	}
	pr.mu.Lock()
	crossA, crossB := pr.seen[hopA], pr.seen[hopB]
	pr.mu.Unlock()
	if crossA != 1 || crossB != 1 {
		t.Fatalf("each hop is probed once, by its own provider: a=%d b=%d", crossA, crossB)
	}
}

// TestIndirectCacheReuse: a found hop is reused until it ages out or an
// in-prefix address answers again.
func TestIndirectCacheReuse(t *testing.T) {
	hop := twoPaths()
	pr := &hopProber{hopA: true}
	e, clk := indirectEngine(t, hop, pr, nil)
	ctx := context.Background()
	e.RunOnce(ctx)
	e.IndirectPass(ctx)
	traced := hop.total()

	for i := 0; i < 3; i++ {
		clk.add(time.Minute)
		e.RunOnce(ctx)
		if !resultFor(t, e, provA.Name).Indirect {
			t.Fatalf("round %d: cached hop not used", i)
		}
		if n := e.IndirectPass(ctx); n != 0 {
			t.Fatalf("round %d: a cached prefix was traced again (%d)", i, n)
		}
	}
	if hop.total() != traced {
		t.Fatalf("hopper calls %d -> %d while the cache was fresh", traced, hop.total())
	}

	// Aged out: the round queues the trace again.
	clk.add(10 * time.Minute)
	e.RunOnce(ctx)
	if resultFor(t, e, provA.Name).Indirect {
		t.Fatal("an aged-out hop was still used")
	}
	if n := e.IndirectPass(ctx); n != 2 || hop.total() <= traced {
		t.Fatalf("aged-out prefix not traced again: n=%d calls=%d", n, hop.total())
	}

	// An in-prefix address answers: the direct score wins and the cache
	// is dropped.
	pr.set(true)
	e.RunOnce(ctx)
	for _, r := range e.Results() {
		if r.Indirect || r.Target != silentIn {
			t.Fatalf("answering prefix still indirect: %+v", r)
		}
	}
	if _, found := e.cachedIndirect(key{provA.Name, pfx1}); found {
		t.Fatal("cache kept after an in-prefix reply")
	}
	pr.set(false)
	e.RunOnce(ctx)
	if resultFor(t, e, provA.Name).Indirect || len(e.pendingIndirect()) != 2 {
		t.Fatalf("silent again: want a fresh trace queued, got %d", len(e.pendingIndirect()))
	}
}

// TestIndirectBudget: one pass stops at the budget, unfinished traces
// stay queued, and every trace packet waits on the rate limit.
func TestIndirectBudget(t *testing.T) {
	hop := twoPaths()
	hop.delay = 20 * time.Millisecond
	lim := &countingLimiter{}
	var targets []plugin.Target
	for i := 0; i < 6; i++ {
		targets = append(targets, plugin.Target{Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i * 32)}), 27)})
	}
	e, _ := indirectEngine(t, hop, &hopProber{}, lim, targets...)
	e.opt.Indirect.Budget = 150 * time.Millisecond
	e.opt.Indirect.MinShare = 60 * time.Millisecond
	ctx := context.Background()
	e.RunOnce(ctx)
	queued := len(e.pendingIndirect())
	if queued != 12 {
		t.Fatalf("queued = %d, want 12", queued)
	}
	before := lim.total
	start := time.Now()
	n := e.IndirectPass(ctx)
	took := time.Since(start)
	if took > 400*time.Millisecond {
		t.Fatalf("pass took %s with a 150ms budget", took)
	}
	left := len(e.pendingIndirect())
	if n >= queued || left == 0 || n+left != queued {
		t.Fatalf("finished=%d left=%d of %d: the budget must leave work queued", n, left, queued)
	}
	if got := lim.total - before; got != hop.total() || got == 0 {
		t.Fatalf("limiter tokens %d, hopper packets %d: every trace packet must wait", got, hop.total())
	}
}

// TestIndirectRejectsUnusableHop: a hop on an exchange LAN, or a trace
// that finds no stable hop, is cached as "none" and nothing is indirect.
func TestIndirectRejectsUnusableHop(t *testing.T) {
	lan := netip.MustParsePrefix("203.0.113.48/28")
	hop := twoPaths()
	pr := &hopProber{hopA: true}
	e, _ := indirectEngine(t, hop, pr, nil)
	e.opt.ExchangeLANs = []netip.Prefix{lan}
	hop.paths[provB.Source] = nil // b's path never answers
	ctx := context.Background()
	e.RunOnce(ctx)
	if n := e.IndirectPass(ctx); n != 2 {
		t.Fatalf("pass = %d", n)
	}
	calls := hop.total()
	e.RunOnce(ctx)
	for _, r := range e.Results() {
		if r.Indirect {
			t.Fatalf("unusable hop scored: %+v", r)
		}
	}
	if len(e.pendingIndirect()) != 0 || e.IndirectPass(ctx) != 0 || hop.total() != calls {
		t.Fatal("a trace that found no usable hop is retried before cache_ttl")
	}
}

// TestIndirectHopGoesSilent: a cached hop that stops answering is not
// scored as 100% loss; the cache entry is dropped and traced again.
func TestIndirectHopGoesSilent(t *testing.T) {
	hop := twoPaths()
	pr := &hopProber{hopA: true}
	e, _ := indirectEngine(t, hop, pr, nil)
	ctx := context.Background()
	e.RunOnce(ctx)
	e.IndirectPass(ctx)
	pr.mu.Lock()
	pr.hopA = false
	pr.mu.Unlock()
	e.RunOnce(ctx)
	a := resultFor(t, e, provA.Name)
	if a.Indirect || a.Target == hopA {
		t.Fatalf("silent hop defined the score: %+v", a)
	}
	if !resultFor(t, e, provB.Name).Indirect {
		t.Fatal("transit-b's own hop still answers and should stay indirect")
	}
	if _, found := e.cachedIndirect(key{provA.Name, pfx1}); found {
		t.Fatal("silent hop kept in the cache")
	}
}

// TestIndirectSkipsOutsidePin: a pin outside the prefix (a traceroute
// source hop) is not an in-prefix address, so nothing is traced.
func TestIndirectSkipsOutsidePin(t *testing.T) {
	hop := twoPaths()
	e, _ := indirectEngine(t, hop, &hopProber{}, nil,
		plugin.Target{Prefix: pfx1, Host: netip.MustParseAddr("192.0.2.200"), Pinned: true})
	e.RunOnce(context.Background())
	if len(e.pendingIndirect()) != 0 {
		t.Fatal("an out-of-prefix pin queued an indirect trace")
	}
}

// TestIndirectOffByDefault: without Options.Indirect nothing is queued
// and nothing is traced.
func TestIndirectOffByDefault(t *testing.T) {
	e, err := New([]Provider{provA}, []NamedProber{{"fake", &fakeProber{fn: (&hopProber{}).fn}}}, src(plugin.Target{Prefix: pfx1}), opts())
	if err != nil {
		t.Fatal(err)
	}
	e.RunOnce(context.Background())
	if len(e.pendingIndirect()) != 0 || e.IndirectPass(context.Background()) != 0 || e.Results()[0].Indirect {
		t.Fatal("indirect probing ran while disabled")
	}
	o := opts()
	o.Indirect = &Indirect{Budget: time.Second, CacheTTL: time.Minute}
	if _, err := New([]Provider{provA}, []NamedProber{{"fake", &fakeProber{fn: ok(1)}}}, nil, o); err == nil {
		t.Fatal("indirect without a tracer must be rejected")
	}
}

// TestIndirectPrunedWithTarget: a prefix that leaves every source drops
// its cached hop and queued trace.
func TestIndirectPrunedWithTarget(t *testing.T) {
	hop := twoPaths()
	pr := &hopProber{hopA: true}
	fs := &fakeSource{targets: []plugin.Target{{Prefix: pfx1}}}
	e, _ := indirectEngine(t, hop, pr, nil)
	e.sources = []NamedSource{{Name: "static", Source: fs}}
	ctx := context.Background()
	e.RunOnce(ctx)
	e.IndirectPass(ctx)
	fs.targets = []plugin.Target{{Prefix: pfx2, Host: netip.MustParseAddr("203.0.113.9")}}
	e.srcCache = nil
	e.RunOnce(ctx)
	if hs := e.indirectHosts(); len(hs) != 0 {
		t.Fatalf("hops kept for a dropped prefix: %v", hs)
	}
}

// TestIndirectRunBackground: Run traces in the background and a later
// round scores each provider at its own hop without a manual pass.
func TestIndirectRunBackground(t *testing.T) {
	hop := twoPaths()
	pr := &hopProber{hopA: true}
	e, _ := indirectEngine(t, hop, pr, nil)
	e.opt.Now = time.Now
	e.opt.Interval = 50 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		rs := e.Results()
		if len(rs) == 2 && rs[0].Indirect && rs[1].Indirect && rs[0].Target == hopA && rs[1].Target == hopB {
			cancel()
			<-done
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatalf("background trace never scored the hops: %+v", e.Results())
}
