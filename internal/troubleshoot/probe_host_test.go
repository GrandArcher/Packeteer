package troubleshoot

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakeResolver struct {
	names map[string][]netip.Addr
	err   error
	calls []string
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	f.calls = append(f.calls, host)
	if f.err != nil {
		return nil, f.err
	}
	return f.names[host], nil
}

// lossScorer ranks by loss first, then RTT in milliseconds.
type lossScorer struct{ plugin.Base }

func (lossScorer) Score(s plugin.PathStats) float64 {
	return s.LossPct*1000 + float64(s.RTTAvg/time.Millisecond)
}

type fakeQueue struct {
	got []netip.Prefix
	ttl time.Duration
	err error
}

func (f *fakeQueue) QueueManual(p netip.Prefix, ttl time.Duration) error {
	if f.err != nil {
		return f.err
	}
	f.got, f.ttl = append(f.got, p), ttl
	return nil
}

func hostTools(fp *fakeProber, res Resolver) *Tools {
	tl := New(Options{Enabled: true, Providers: provs, Probers: []probe.NamedProber{{Name: "fake", Prober: fp}},
		Packets: 4, Timeout: 10 * time.Millisecond, Resolver: res, Scorer: lossScorer{}})
	tl.SetRIB(testRIB())
	return tl
}

func TestProbeHostnameResolvesAndShowsAddressUsed(t *testing.T) {
	fp := &fakeProber{}
	res := &fakeResolver{names: map[string][]netip.Addr{"host.example.net": {
		addr("127.0.0.1"), addr("2001:db8::9"), addr("::ffff:203.0.113.9"), addr("203.0.113.9"),
	}}}
	ans, err := hostTools(fp, res).Probe(context.Background(), " Host.Example.Net. ")
	if err != nil {
		t.Fatal(err)
	}
	if ans.Host != "host.example.net" || ans.Target != addr("203.0.113.9") {
		t.Fatalf("host %q target %v", ans.Host, ans.Target)
	}
	if len(ans.Addresses) != 2 || ans.Addresses[0] != addr("2001:db8::9") || ans.Addresses[1] != addr("203.0.113.9") {
		t.Fatalf("addresses %v: loopback must be dropped and the mapped form de-duplicated", ans.Addresses)
	}
	if len(res.calls) != 1 || res.calls[0] != "host.example.net" {
		t.Fatalf("lookups %v", res.calls)
	}
	for _, r := range fp.reqs {
		if r.Target != addr("203.0.113.9") {
			t.Fatalf("probed %v, want the IPv4 address a provider source can reach", r.Target)
		}
	}
	if ans.Route == nil || ans.Route.Prefix != pfx("203.0.113.0/24") {
		t.Fatalf("covering route %+v", ans.Route)
	}
}

func TestProbeRejectsBadInputBeforeResolvingOrProbing(t *testing.T) {
	fp := &fakeProber{}
	res := &fakeResolver{names: map[string][]netip.Addr{}}
	tl := hostTools(fp, res)
	long := strings.Repeat("a", 64) + ".example"
	for _, in := range []string{"", "  ", "a b.example", "-x.example", "x-.example", "a..example", "http://host.example", "host.example/24",
		"127.1", "0x7f.1", "1.2.3", "host.example:80", long, strings.Repeat("a.", 130) + "example", "fe80::1%eth0", "127.0.0.1", "::1"} {
		if _, err := tl.Probe(context.Background(), in); err == nil {
			t.Errorf("%q accepted", in)
		}
		if _, err := tl.Optimize(context.Background(), in); err == nil {
			t.Errorf("optimize accepted %q", in)
		}
	}
	if len(res.calls) != 0 || len(fp.reqs) != 0 {
		t.Fatalf("bad input reached the resolver (%v) or sent %d probes", res.calls, len(fp.reqs))
	}
}

func TestProbeResolveFailures(t *testing.T) {
	fp := &fakeProber{}
	res := &fakeResolver{err: errors.New("no such host")}
	tl := hostTools(fp, res)
	if _, err := tl.Probe(context.Background(), "gone.example"); err == nil || !strings.Contains(err.Error(), "cannot resolve gone.example") {
		t.Fatalf("resolver error: %v", err)
	}
	res.err = nil
	res.names = map[string][]netip.Addr{"local.example": {addr("127.0.0.1"), addr("fe80::1")}}
	if _, err := tl.Probe(context.Background(), "local.example"); err == nil || !strings.Contains(err.Error(), "no routable address") {
		t.Fatalf("only unroutable addresses: %v", err)
	}
	if len(fp.reqs) != 0 {
		t.Fatalf("%d probes sent", len(fp.reqs))
	}
}

func TestProbeHostnameIsRateLimitedBeforeLookup(t *testing.T) {
	res := &fakeResolver{names: map[string][]netip.Addr{"host.example.net": {addr("203.0.113.9")}}}
	tl := New(Options{Enabled: true, Providers: provs, Probers: []probe.NamedProber{{Name: "fake", Prober: &fakeProber{}}}, Resolver: res, Limiter: &allow{n: 0}})
	if _, err := tl.Probe(context.Background(), "host.example.net"); !errors.Is(err, ErrBusy) {
		t.Fatalf("got %v", err)
	}
	if len(res.calls) != 0 {
		t.Fatalf("lookup ran while rate limited: %v", res.calls)
	}
}

func TestProbeCurrentVersusBest(t *testing.T) {
	// transit-b drops half its packets (fakeProber), so transit-a is best.
	tl := hostTools(&fakeProber{}, &fakeResolver{})
	ans, err := tl.Probe(context.Background(), "198.51.100.200")
	if err != nil {
		t.Fatal(err)
	}
	if ans.Route == nil || ans.Route.Prefix != pfx("198.51.100.128/25") || ans.Current != "transit-b" || ans.Best != "transit-a" {
		t.Fatalf("current %q best %q route %+v", ans.Current, ans.Best, ans.Route)
	}
	ans, _ = tl.Probe(context.Background(), "203.0.113.9")
	if ans.Current != "transit-a" || ans.Best != "transit-a" {
		t.Fatalf("current %q best %q", ans.Current, ans.Best)
	}

	// A provider that did not answer cannot be best, and no scorer means no
	// best at all.
	down := &fakeProber{fail: map[netip.Addr]error{addr("192.0.2.10"): errors.New("down")}}
	ans, _ = hostTools(down, &fakeResolver{}).Probe(context.Background(), "203.0.113.9")
	if ans.Best != "transit-b" {
		t.Fatalf("best %q with transit-a down", ans.Best)
	}
	bare := New(Options{Enabled: true, Providers: provs, Probers: []probe.NamedProber{{Name: "fake", Prober: &fakeProber{}}}})
	bare.SetRIB(testRIB())
	if ans, _ = bare.Probe(context.Background(), "203.0.113.9"); ans.Best != "" || ans.Current != "transit-a" {
		t.Fatalf("no scorer: current %q best %q", ans.Current, ans.Best)
	}
	ans, _ = tl.Probe(context.Background(), "192.0.2.200")
	if ans.Route != nil || ans.Current != "" {
		t.Fatalf("uncovered address: %+v", ans)
	}
}

// replyFrom answers probes only toward the addresses it lists.
type replyFrom struct {
	plugin.Base
	mu   sync.Mutex
	live map[netip.Addr]bool
	seen []netip.Addr
}

func (r *replyFrom) Probe(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	r.mu.Lock()
	r.seen = append(r.seen, req.Target)
	r.mu.Unlock()
	res := plugin.ProbeResult{Sent: req.Count}
	if r.live[req.Target] {
		for range req.Count {
			res.RTTs = append(res.RTTs, 8*time.Millisecond)
		}
	}
	return res, nil
}

type fakeTracer struct {
	hop   netip.Addr
	ok    bool
	err   error
	calls []netip.Addr
}

func (f *fakeTracer) Trace(_ context.Context, src, _ netip.Addr, _ func(context.Context) error) (netip.Addr, bool, error) {
	f.calls = append(f.calls, src)
	return f.hop, f.ok, f.err
}

func TestProbeIndirectFallbackForSilentTarget(t *testing.T) {
	target, hop := addr("203.0.113.9"), addr("192.0.2.77")
	// Nothing in the target answers, but the hop does.
	pr := &replyFrom{live: map[netip.Addr]bool{hop: true}}
	tr := &fakeTracer{hop: hop, ok: true}
	tl := New(Options{Enabled: true, Providers: provs, Probers: []probe.NamedProber{{Name: "fake", Prober: pr}}, Packets: 3, Timeout: 10 * time.Millisecond, Indirect: tr})
	tl.SetRIB(testRIB())
	a, err := tl.Probe(context.Background(), target.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.calls) != 2 {
		t.Fatalf("expected a trace from each silent provider, got %v", tr.calls)
	}
	for _, r := range a.Results {
		if !r.Indirect || r.Target != hop || r.Prefix != netip.PrefixFrom(target, 32) || r.Stats.Received != 3 {
			t.Fatalf("indirect result %+v", r)
		}
	}

	// An answering provider is never traced.
	pr.live = map[netip.Addr]bool{target: true}
	tr.calls = nil
	a, _ = tl.Probe(context.Background(), target.String())
	if len(tr.calls) != 0 || a.Results[0].Indirect || a.Results[1].Indirect {
		t.Fatalf("traced a reachable target: calls %v results %+v", tr.calls, a.Results)
	}
}

// pacer counts the packets the tools ask to pace.
type pacer struct{ n int }

func (p *pacer) WaitN(_ context.Context, n int) error {
	p.n += n
	return nil
}

// pacedTracer waits once per trace packet, as the traceroute source does.
type pacedTracer struct {
	packets int
	calls   int
}

func (f *pacedTracer) Trace(ctx context.Context, _, _ netip.Addr, wait func(context.Context) error) (netip.Addr, bool, error) {
	f.calls++
	for range f.packets {
		if err := wait(ctx); err != nil {
			return netip.Addr{}, false, err
		}
	}
	return netip.Addr{}, false, nil
}

func TestProbeIndirectTracePacketsWaitOnThePacketBudget(t *testing.T) {
	target := addr("203.0.113.9")
	pace := &pacer{}
	tr := &pacedTracer{packets: 3}
	tl := New(Options{Enabled: true, Providers: provs, Probers: []probe.NamedProber{{Name: "fake", Prober: &replyFrom{}}},
		Packets: 2, Timeout: 10 * time.Millisecond, Indirect: tr, PacketLimiter: pace})
	if _, err := tl.Probe(context.Background(), target.String()); err != nil {
		t.Fatal(err)
	}
	if tr.calls != len(provs) || pace.n != len(provs)*tr.packets {
		t.Fatalf("traces %d, paced packets %d: want one trace per silent provider and one wait per packet", tr.calls, pace.n)
	}
}

func TestProbeIndirectFallbackKeepsSilentResult(t *testing.T) {
	target, hop := addr("203.0.113.9"), addr("192.0.2.77")
	for name, tr := range map[string]*fakeTracer{
		"no stable hop":   {ok: false},
		"trace error":     {hop: hop, ok: true, err: plugin.ErrSourceUnavailable},
		"hop is silent":   {hop: addr("192.0.2.78"), ok: true},
		"no tracer wired": nil,
	} {
		pr := &replyFrom{live: map[netip.Addr]bool{hop: true}}
		opt := Options{Enabled: true, Providers: provs[:1], Probers: []probe.NamedProber{{Name: "fake", Prober: pr}}, Packets: 2, Timeout: 10 * time.Millisecond}
		if tr != nil {
			opt.Indirect = tr
		}
		a, err := New(opt).Probe(context.Background(), target.String())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		r := a.Results[0]
		if r.Indirect || r.Target != target || r.Stats.Received != 0 || r.Stats.LossPct != 100 {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// A source in the other family cannot trace toward the target.
	tr := &fakeTracer{hop: hop, ok: true}
	v6 := New(Options{Enabled: true, Providers: []probe.Provider{{Name: "transit-v6", Source: addr("2001:db8::10")}},
		Probers: []probe.NamedProber{{Name: "fake", Prober: &replyFrom{}}}, Indirect: tr})
	if _, err := v6.Probe(context.Background(), target.String()); err != nil || len(tr.calls) != 0 {
		t.Fatalf("family mismatch traced: %v %v", err, tr.calls)
	}
}

type notReady struct{ fakeRIB }

func (notReady) Ready() bool { return false }

func optimizeTools(q Queue, lim Limiter) (*Tools, *fakeResolver) {
	res := &fakeResolver{names: map[string][]netip.Addr{"host.example.net": {addr("198.51.100.200")}}}
	tl := New(Options{Enabled: true, Providers: provs, Probers: []probe.NamedProber{{Name: "fake", Prober: &fakeProber{}}},
		Resolver: res, Limiter: lim, Now: func() time.Time { return time.Unix(1_700_000_000, 0) }})
	tl.SetRIB(testRIB())
	tl.SetQueue(q)
	return tl, res
}

func TestOptimizeQueuesTheCoveringLearnedPrefix(t *testing.T) {
	q := &fakeQueue{}
	tl, _ := optimizeTools(q, nil)
	ans, err := tl.Optimize(context.Background(), "host.example.net")
	if err != nil {
		t.Fatal(err)
	}
	if len(q.got) != 1 || q.got[0] != pfx("198.51.100.128/25") || q.ttl != OptimizeTTL {
		t.Fatalf("queued %v ttl %v: want the longest learned prefix, not the /24", q.got, q.ttl)
	}
	if ans.Prefix != q.got[0] || ans.Target != addr("198.51.100.200") || ans.Host != "host.example.net" || !ans.Expires.Equal(time.Unix(1_700_000_000, 0).Add(OptimizeTTL)) {
		t.Fatalf("answer %+v", ans)
	}
	if !tl.Status().Optimize {
		t.Fatal("status does not offer optimize")
	}
}

func TestOptimizeRefusesWhatTheRIBDoesNotHold(t *testing.T) {
	q := &fakeQueue{}
	tl, _ := optimizeTools(q, nil)
	if _, err := tl.Optimize(context.Background(), "192.0.2.200"); err == nil || !strings.Contains(err.Error(), "no learned prefix") {
		t.Fatalf("uncovered address: %v", err)
	}
	tl.SetRIB(fakeRIB{routes: []rib.Route{{Prefix: pfx("0.0.0.0/0"), NextHop: addr("192.0.2.1"), Provider: "transit-a"}}})
	if _, err := tl.Optimize(context.Background(), "192.0.2.200"); err == nil {
		t.Fatal("a default route was queued")
	}
	if len(q.got) != 0 {
		t.Fatalf("queued %v", q.got)
	}
}

func TestOptimizeRefusalsSpendNoToken(t *testing.T) {
	q := &fakeQueue{}
	lim := &allow{n: 1}
	tl, res := optimizeTools(q, lim)

	tl.SetQueue(nil)
	if _, err := tl.Optimize(context.Background(), "198.51.100.200"); !errors.Is(err, ErrNoOptimize) {
		t.Fatalf("no queue: %v", err)
	}
	tl.SetQueue(q)
	tl.SetRIB(nil)
	if _, err := tl.Optimize(context.Background(), "198.51.100.200"); !errors.Is(err, ErrNoRIB) {
		t.Fatalf("no RIB: %v", err)
	}
	tl.SetRIB(notReady{testRIB()})
	if _, err := tl.Optimize(context.Background(), "host.example.net"); err == nil || !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("RIB not ready: %v", err)
	}
	if lim.n != 1 || len(res.calls) != 0 {
		t.Fatalf("refused requests spent a token (%d left) or looked up %v", lim.n, res.calls)
	}

	tl.SetRIB(testRIB())
	if _, err := tl.Optimize(context.Background(), "host.example.net"); err != nil || lim.n != 0 {
		t.Fatalf("admitted request: err %v, %d tokens left", err, lim.n)
	}
}

func TestOptimizeUnavailableCases(t *testing.T) {
	q := &fakeQueue{}
	tl, res := optimizeTools(q, nil)

	tl.SetQueue(nil)
	if _, err := tl.Optimize(context.Background(), "198.51.100.200"); !errors.Is(err, ErrNoOptimize) {
		t.Fatalf("no queue: %v", err)
	}
	if tl.Status().Optimize {
		t.Fatal("status offers optimize without a queue")
	}
	tl.SetQueue(q)
	tl.SetRIB(nil)
	if _, err := tl.Optimize(context.Background(), "198.51.100.200"); !errors.Is(err, ErrNoRIB) {
		t.Fatalf("no RIB: %v", err)
	}
	tl.SetRIB(notReady{testRIB()})
	if _, err := tl.Optimize(context.Background(), "198.51.100.200"); err == nil || !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("RIB not ready: %v", err)
	}

	off := New(Options{Resolver: res})
	off.SetQueue(q)
	off.SetRIB(testRIB())
	if _, err := off.Optimize(context.Background(), "198.51.100.200"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled: %v", err)
	}

	limited, res2 := optimizeTools(q, &allow{n: 0})
	if _, err := limited.Optimize(context.Background(), "host.example.net"); !errors.Is(err, ErrBusy) || len(res2.calls) != 0 {
		t.Fatalf("rate limit: %v lookups %v", err, res2.calls)
	}

	full := &fakeQueue{err: probe.ErrManualFull}
	tl.SetQueue(full)
	tl.SetRIB(testRIB())
	if _, err := tl.Optimize(context.Background(), "198.51.100.200"); !errors.Is(err, probe.ErrManualFull) {
		t.Fatalf("full queue: %v", err)
	}
	if len(q.got) != 0 {
		t.Fatalf("queued %v", q.got)
	}
}
