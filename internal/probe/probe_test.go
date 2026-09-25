package probe

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func ms(v ...float64) []time.Duration {
	out := make([]time.Duration, len(v))
	for i, x := range v {
		out[i] = time.Duration(x * float64(time.Millisecond))
	}
	return out
}

func TestCompute(t *testing.T) {
	tests := []struct {
		name string
		in   plugin.ProbeResult
		want Stats
	}{
		{"no packets", plugin.ProbeResult{}, Stats{}},
		{"all lost", plugin.ProbeResult{Sent: 4}, Stats{Sent: 4, LossPct: 100}},
		{"single reply", plugin.ProbeResult{Sent: 2, RTTs: ms(10)},
			Stats{Sent: 2, Received: 1, LossPct: 50, RTTMin: ms(10)[0], RTTAvg: ms(10)[0], RTTMax: ms(10)[0]}},
		// diffs: |12-10|=2, |11-12|=1, |15-11|=4 -> jitter 7/3 ms
		{"jitter", plugin.ProbeResult{Sent: 5, RTTs: ms(10, 12, 11, 15)},
			Stats{Sent: 5, Received: 4, LossPct: 20, RTTMin: ms(10)[0], RTTAvg: ms(12)[0], RTTMax: ms(15)[0],
				Jitter: 7 * time.Millisecond / 3}},
		{"more replies than sent is clamped", plugin.ProbeResult{Sent: 1, RTTs: ms(1, 1)},
			Stats{Sent: 1, Received: 2, LossPct: 0, RTTMin: ms(1)[0], RTTAvg: ms(1)[0], RTTMax: ms(1)[0]}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compute(tt.in)
			if math.Abs(float64(got.Jitter-tt.want.Jitter)) > 1 {
				t.Errorf("jitter %v want %v", got.Jitter, tt.want.Jitter)
			}
			got.Jitter = tt.want.Jitter
			if got != tt.want {
				t.Errorf("got %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestDefaultHost(t *testing.T) {
	for in, want := range map[string]string{
		"198.51.100.0/24":  "198.51.100.1",
		"198.51.100.77/24": "198.51.100.1",
		"192.0.2.5/32":     "192.0.2.5",
		"2001:db8::/32":    "2001:db8::1",
		"2001:db8::7/128":  "2001:db8::7",
	} {
		if got := DefaultHost(netip.MustParsePrefix(in)); got.String() != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
}

// ---- fakes ----

type fakeProber struct {
	plugin.Base
	fn    func(ctx context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error)
	calls atomic.Int32
}

func (f *fakeProber) Probe(ctx context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	f.calls.Add(1)
	return f.fn(ctx, req)
}

type fakeSource struct {
	plugin.Base
	targets []plugin.Target
	err     error
}

func (f *fakeSource) Targets(context.Context) ([]plugin.Target, error) { return f.targets, f.err }

func ok(rtts ...float64) func(context.Context, plugin.ProbeRequest) (plugin.ProbeResult, error) {
	return func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		return plugin.ProbeResult{Sent: req.Count, RTTs: ms(rtts...)}, nil
	}
}

var (
	provA = Provider{Name: "transit-a", Source: netip.MustParseAddr("192.0.2.11")}
	provB = Provider{Name: "transit-b", Source: netip.MustParseAddr("192.0.2.12")}
	prov6 = Provider{Name: "transit-v6", Source: netip.MustParseAddr("2001:db8::11")}
	pfx1  = netip.MustParsePrefix("198.51.100.0/24")
	pfx2  = netip.MustParsePrefix("203.0.113.0/24")
)

func opts() Options {
	return Options{Interval: time.Second, Timeout: 100 * time.Millisecond, Packets: 3, Workers: 4, PerTargetConcurrency: 2}
}

func src(ts ...plugin.Target) []NamedSource {
	return []NamedSource{{Name: "static", Source: &fakeSource{targets: ts}}}
}

func TestRunOnceBasic(t *testing.T) {
	p := &fakeProber{fn: func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		if req.Provider == "transit-a" {
			return plugin.ProbeResult{Sent: req.Count, RTTs: ms(10, 10, 10)}, nil
		}
		return plugin.ProbeResult{Sent: req.Count, RTTs: ms(30)}, nil
	}}
	var seen atomic.Int32
	o := opts()
	o.OnResult = func(Result) { seen.Add(1) }
	e, err := New([]Provider{provA, provB, prov6}, []NamedProber{{"fake", p}},
		src(plugin.Target{Prefix: pfx1}, plugin.Target{Prefix: pfx2, Host: netip.MustParseAddr("203.0.113.9")}), o)
	if err != nil {
		t.Fatal(err)
	}
	e.RunOnce(context.Background())
	rs := e.Results()
	if len(rs) != 4 { // v6 provider skipped for v4 targets
		t.Fatalf("results = %d: %+v", len(rs), rs)
	}
	if seen.Load() != 4 {
		t.Errorf("OnResult calls = %d", seen.Load())
	}
	r := rs[0]
	if r.Prefix != pfx1 || r.Provider != "transit-a" || r.Target.String() != "198.51.100.1" || r.Prober != "fake" {
		t.Errorf("first result = %+v", r)
	}
	if r.Stats.LossPct != 0 || rs[1].Stats.LossPct < 66 || rs[1].Stats.LossPct > 67 {
		t.Errorf("loss a=%v b=%v", r.Stats.LossPct, rs[1].Stats.LossPct)
	}
	if rs[2].Target.String() != "203.0.113.9" {
		t.Errorf("configured host not used: %+v", rs[2])
	}
}

func TestTargetsDedupAndSourceFailure(t *testing.T) {
	e, _ := New([]Provider{provA}, []NamedProber{{"fake", &fakeProber{fn: ok(1)}}}, []NamedSource{
		{Name: "broken", Source: &fakeSource{err: errors.New("boom")}},
		{Name: "a", Source: &fakeSource{targets: []plugin.Target{{Prefix: pfx1}}}},
		{Name: "b", Source: &fakeSource{targets: []plugin.Target{{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.50")}, {Prefix: pfx2}}}},
	}, opts())
	ts := e.Targets(context.Background())
	if len(ts) != 2 || ts[0].Host.String() != "198.51.100.1" {
		t.Fatalf("targets = %+v", ts)
	}
}

func TestFallbackChain(t *testing.T) {
	tests := []struct {
		name       string
		first      func(context.Context, plugin.ProbeRequest) (plugin.ProbeResult, error)
		second     func(context.Context, plugin.ProbeRequest) (plugin.ProbeResult, error)
		wantProber string
		wantErr    string
		wantLoss   float64
		wantDown   bool
		wantCalls2 int32
	}{
		{name: "first succeeds", first: ok(5, 5, 5), second: ok(1), wantProber: "icmp", wantCalls2: 0},
		{name: "first errors, fallback", first: func(context.Context, plugin.ProbeRequest) (plugin.ProbeResult, error) {
			return plugin.ProbeResult{}, errors.New("no raw socket")
		}, second: ok(7, 7, 7), wantProber: "tcp", wantCalls2: 1},
		{name: "first full loss, fallback answers", first: ok(), second: ok(9, 9, 9), wantProber: "tcp", wantCalls2: 1},
		{name: "both full loss keeps first", first: ok(), second: ok(), wantProber: "icmp", wantLoss: 100, wantCalls2: 1},
		{name: "all error", first: func(context.Context, plugin.ProbeRequest) (plugin.ProbeResult, error) {
			return plugin.ProbeResult{}, errors.New("e1")
		}, second: func(context.Context, plugin.ProbeRequest) (plugin.ProbeResult, error) {
			return plugin.ProbeResult{}, errors.New("e2")
		}, wantErr: "icmp: e1\ntcp: e2", wantCalls2: 1},
		{name: "source unavailable fails closed", first: func(context.Context, plugin.ProbeRequest) (plugin.ProbeResult, error) {
			return plugin.ProbeResult{}, fmt.Errorf("%w: 192.0.2.11", plugin.ErrSourceUnavailable)
		}, second: ok(1, 1, 1), wantErr: "probe source address unavailable", wantDown: true, wantCalls2: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p1, p2 := &fakeProber{fn: tt.first}, &fakeProber{fn: tt.second}
			e, _ := New([]Provider{provA}, []NamedProber{{"icmp", p1}, {"tcp", p2}}, src(plugin.Target{Prefix: pfx1}), opts())
			e.RunOnce(context.Background())
			rs := e.Results()
			if len(rs) != 1 {
				t.Fatalf("results %+v", rs)
			}
			r := rs[0]
			if tt.wantErr != "" {
				if r.OK() || !strings.Contains(r.Err, tt.wantErr) {
					t.Fatalf("err = %q want %q", r.Err, tt.wantErr)
				}
			} else if !r.OK() || r.Prober != tt.wantProber || r.Stats.LossPct != tt.wantLoss {
				t.Fatalf("result = %+v", r)
			}
			if p2.calls.Load() != tt.wantCalls2 {
				t.Errorf("second prober calls = %d want %d", p2.calls.Load(), tt.wantCalls2)
			}
			st := e.Providers()[0]
			if st.Up == tt.wantDown {
				t.Errorf("provider up = %v, want down=%v", st.Up, tt.wantDown)
			}
		})
	}
}

func TestProviderRecovers(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	p := &fakeProber{fn: func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		if fail.Load() {
			return plugin.ProbeResult{}, plugin.ErrSourceUnavailable
		}
		return plugin.ProbeResult{Sent: req.Count, RTTs: ms(1, 1, 1)}, nil
	}}
	e, _ := New([]Provider{provA, provB}, []NamedProber{{"p", p}}, src(plugin.Target{Prefix: pfx1}), opts())
	e.RunOnce(context.Background())
	if e.Providers()[0].Up || e.Providers()[1].Up {
		t.Fatal("providers should be down")
	}
	fail.Store(false)
	e.RunOnce(context.Background())
	if !e.Providers()[0].Up || e.Providers()[0].Reason != "" {
		t.Fatalf("provider should recover: %+v", e.Providers()[0])
	}
}

type countingLimiter struct {
	mu    sync.Mutex
	total int
	err   error
}

func (c *countingLimiter) WaitN(_ context.Context, n int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total += n
	return c.err
}

func TestRateLimiter(t *testing.T) {
	lim := &countingLimiter{}
	o := opts()
	o.Limiter = lim
	e, _ := New([]Provider{provA, provB}, []NamedProber{{"p", &fakeProber{fn: ok(1, 1, 1)}}},
		src(plugin.Target{Prefix: pfx1}, plugin.Target{Prefix: pfx2}), o)
	e.RunOnce(context.Background())
	if lim.total != 4*o.Packets {
		t.Errorf("limiter tokens = %d, want %d", lim.total, 4*o.Packets)
	}

	lim2 := &countingLimiter{err: errors.New("would exceed")}
	o.Limiter = lim2
	p := &fakeProber{fn: ok(1)}
	e, _ = New([]Provider{provA}, []NamedProber{{"p", p}}, src(plugin.Target{Prefix: pfx1}), o)
	e.RunOnce(context.Background())
	if p.calls.Load() != 0 || e.Results()[0].OK() {
		t.Errorf("prober must not run when the limiter refuses: calls=%d res=%+v", p.calls.Load(), e.Results())
	}
}

func TestRealLimiterTiming(t *testing.T) {
	// 20 packets/s with bursts of 3: 4 runs x 3 packets = 12 packets needs
	// at least (12-3)/20 = 450ms.
	o := opts()
	o.Limiter = newTokenLimiterForTest(20, 3)
	e, _ := New([]Provider{provA, provB}, []NamedProber{{"p", &fakeProber{fn: ok(1, 1, 1)}}},
		src(plugin.Target{Prefix: pfx1}, plugin.Target{Prefix: pfx2}), o)
	start := time.Now()
	e.RunOnce(context.Background())
	if el := time.Since(start); el < 400*time.Millisecond {
		t.Errorf("round took %s, rate limit not applied", el)
	}
}

func TestPerTargetConcurrency(t *testing.T) {
	var cur, peak atomic.Int32
	p := &fakeProber{fn: func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		n := cur.Add(1)
		for {
			old := peak.Load()
			if n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		cur.Add(-1)
		return plugin.ProbeResult{Sent: req.Count, RTTs: ms(1)}, nil
	}}
	var provs []Provider
	for i := 0; i < 6; i++ {
		provs = append(provs, Provider{Name: fmt.Sprintf("p%d", i), Source: netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", 20+i))})
	}
	o := opts()
	o.Workers, o.PerTargetConcurrency = 6, 2
	e, _ := New(provs, []NamedProber{{"p", p}}, src(plugin.Target{Prefix: pfx1}), o)
	e.RunOnce(context.Background())
	if peak.Load() != 2 {
		t.Errorf("peak concurrency toward one target = %d, want 2", peak.Load())
	}
	if len(e.Results()) != 6 {
		t.Errorf("results = %d", len(e.Results()))
	}
}

func TestProbeTimeout(t *testing.T) {
	p := &fakeProber{fn: func(ctx context.Context, _ plugin.ProbeRequest) (plugin.ProbeResult, error) {
		<-ctx.Done() // a stuck prober
		return plugin.ProbeResult{}, ctx.Err()
	}}
	o := opts()
	o.Packets, o.Timeout = 1, 10*time.Millisecond // job deadline = 1*10ms + 1s
	e, _ := New([]Provider{provA}, []NamedProber{{"stuck", p}}, src(plugin.Target{Prefix: pfx1}), o)
	start := time.Now()
	e.RunOnce(context.Background())
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("stuck prober not bounded: %s", el)
	}
	if r := e.Results()[0]; r.OK() || !strings.Contains(r.Err, "deadline exceeded") {
		t.Errorf("result = %+v", r)
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	p := &fakeProber{fn: ok(1)}
	o := opts()
	o.Interval = 20 * time.Millisecond
	e, _ := New([]Provider{provA}, []NamedProber{{"p", p}}, src(plugin.Target{Prefix: pfx1}), o)
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Millisecond)
	defer cancel()
	if err := e.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run = %v", err)
	}
	if c := p.calls.Load(); c < 3 {
		t.Errorf("expected several rounds, got %d probe calls", c)
	}
}

func TestNewValidation(t *testing.T) {
	p := []NamedProber{{"p", &fakeProber{fn: ok()}}}
	if _, err := New(nil, p, nil, opts()); err == nil {
		t.Error("want error for no providers")
	}
	if _, err := New([]Provider{provA}, nil, nil, opts()); err == nil {
		t.Error("want error for no probers")
	}
	o := opts()
	o.Packets = 0
	if _, err := New([]Provider{provA}, p, nil, o); err == nil {
		t.Error("want error for zero packets")
	}
}

// blockAfterProber answers the first allow calls, then blocks ignoring ctx.
type blockAfterProber struct {
	plugin.Base
	mu      sync.Mutex
	calls   int
	allow   int
	release chan struct{}
}

func (p *blockAfterProber) Probe(context.Context, plugin.ProbeRequest) (plugin.ProbeResult, error) {
	p.mu.Lock()
	p.calls++
	n := p.calls
	p.mu.Unlock()
	if n > p.allow {
		<-p.release
		return plugin.ProbeResult{}, errors.New("released")
	}
	return plugin.ProbeResult{Sent: 1, RTTs: ms(1)}, nil
}

// blockAfterSource returns one target once, then blocks ignoring ctx.
type blockAfterSource struct {
	plugin.Base
	mu      sync.Mutex
	calls   int
	release chan struct{}
}

func (s *blockAfterSource) Targets(context.Context) ([]plugin.Target, error) {
	s.mu.Lock()
	s.calls++
	n := s.calls
	s.mu.Unlock()
	if n > 1 {
		<-s.release
		return nil, errors.New("released")
	}
	return []plugin.Target{{Prefix: pfx1}}, nil
}

func waitRound(t *testing.T, e *Engine) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		e.RunOnce(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("round was not bounded by the overall timeout")
	}
}

func TestRunOnceHungProberKeepsResults(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	p := &blockAfterProber{allow: 1, release: release}
	o := opts()
	o.RoundTimeout = 80 * time.Millisecond
	o.Workers = 1
	var rounds atomic.Int32
	o.OnRound = func() { rounds.Add(1) }
	e, err := New([]Provider{provA}, []NamedProber{{"hung", p}}, src(plugin.Target{Prefix: pfx1}), o)
	if err != nil {
		t.Fatal(err)
	}
	waitRound(t, e)
	if rounds.Load() != 1 || len(e.Results()) != 1 || !e.Results()[0].OK() {
		t.Fatalf("first round rounds=%d results=%+v", rounds.Load(), e.Results())
	}
	waitRound(t, e) // prober ignores ctx; the round deadline must win
	if rounds.Load() != 1 || len(e.Results()) != 1 || !e.Results()[0].OK() {
		t.Fatalf("hung round replaced results: rounds=%d %+v", rounds.Load(), e.Results())
	}
	start := time.Now()
	waitRound(t, e) // previous probes still stuck: skip, do not start another
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("in-flight round was not skipped: %s", time.Since(start))
	}
	if rounds.Load() != 1 || len(e.Results()) != 1 {
		t.Fatalf("skipped round changed state: rounds=%d %+v", rounds.Load(), e.Results())
	}
}

func TestRunOnceHungTargetSourceKeepsResults(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	now := time.Unix(1_700_000_000, 0)
	o := opts()
	o.Now = func() time.Time { return now }
	o.RoundTimeout = 80 * time.Millisecond
	var rounds atomic.Int32
	o.OnRound = func() { rounds.Add(1) }
	e, err := New([]Provider{provA}, []NamedProber{{"p", &fakeProber{fn: ok(1, 1, 1)}}},
		[]NamedSource{{Name: "slow", Source: &blockAfterSource{release: release}}}, o)
	if err != nil {
		t.Fatal(err)
	}
	waitRound(t, e)
	if rounds.Load() != 1 || len(e.Results()) != 1 {
		t.Fatalf("first round rounds=%d results=%d", rounds.Load(), len(e.Results()))
	}
	now = now.Add(o.Interval) // the first success is cached for one interval
	waitRound(t, e)
	if rounds.Load() != 1 || len(e.Results()) != 1 || !e.Results()[0].OK() {
		t.Fatalf("hung target source replaced results: rounds=%d %+v", rounds.Load(), e.Results())
	}
}

func TestRetryReplacesHighLoss(t *testing.T) {
	var mu sync.Mutex
	var counts []int
	p := &fakeProber{fn: func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		mu.Lock()
		counts = append(counts, req.Count)
		n := len(counts)
		mu.Unlock()
		if n == 1 {
			return plugin.ProbeResult{Sent: req.Count}, nil // 100% loss
		}
		return plugin.ProbeResult{Sent: req.Count, RTTs: ms(5, 5, 5, 5)}, nil
	}}
	lim := &countingLimiter{}
	o := opts()
	o.Packets = 2
	o.RetryLossPct = 50
	o.RetryPackets = 4
	o.Limiter = lim
	e, err := New([]Provider{provA}, []NamedProber{{"udp", p}}, src(plugin.Target{Prefix: pfx1}), o)
	if err != nil {
		t.Fatal(err)
	}
	e.RunOnce(context.Background())
	if len(counts) != 2 || counts[0] != 2 || counts[1] != 4 {
		t.Fatalf("probe counts = %v", counts)
	}
	r := e.Results()[0]
	if !r.OK() || r.Stats.Sent != 4 || r.Stats.LossPct != 0 || r.Prober != "udp" {
		t.Fatalf("result = %+v", r)
	}
	if lim.total != 6 {
		t.Fatalf("limiter tokens = %d, want 6", lim.total)
	}
	if !e.Providers()[0].Up {
		t.Fatal("provider should stay up")
	}
}

func TestRetrySkippedBelowThreshold(t *testing.T) {
	p := &fakeProber{fn: func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		// 1 reply of 4 is 75% loss, under an 80% threshold.
		return plugin.ProbeResult{Sent: req.Count, RTTs: ms(5)}, nil
	}}
	o := opts()
	o.Packets = 4
	o.RetryLossPct = 80
	o.RetryPackets = 8
	e, _ := New([]Provider{provA}, []NamedProber{{"p", p}}, src(plugin.Target{Prefix: pfx1}), o)
	e.RunOnce(context.Background())
	if p.calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", p.calls.Load())
	}

	off := &fakeProber{fn: func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		return plugin.ProbeResult{Sent: req.Count}, nil
	}}
	o.RetryLossPct = 0
	e, _ = New([]Provider{provA}, []NamedProber{{"p", off}}, src(plugin.Target{Prefix: pfx1}), o)
	e.RunOnce(context.Background())
	if off.calls.Load() != 1 {
		t.Fatalf("disabled retry calls = %d", off.calls.Load())
	}
}

func TestRetrySourceDownFailsClosed(t *testing.T) {
	var n atomic.Int32
	p := &fakeProber{fn: func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		if n.Add(1) == 1 {
			return plugin.ProbeResult{Sent: req.Count}, nil
		}
		return plugin.ProbeResult{}, fmt.Errorf("%w: gone", plugin.ErrSourceUnavailable)
	}}
	o := opts()
	o.RetryLossPct = 1
	o.RetryPackets = 3
	e, _ := New([]Provider{provA}, []NamedProber{{"p", p}}, src(plugin.Target{Prefix: pfx1}), o)
	e.RunOnce(context.Background())
	r := e.Results()[0]
	if r.OK() || !strings.Contains(r.Err, "probe source address unavailable") {
		t.Fatalf("result = %+v", r)
	}
	if e.Providers()[0].Up {
		t.Fatal("provider should be down")
	}
}

func TestVIPIntervalAndRateLimit(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	o := opts()
	o.Packets = 2
	o.Interval = 100 * time.Millisecond
	o.Now = func() time.Time { return now }
	lim := &countingLimiter{}
	o.Limiter = lim
	var mu sync.Mutex
	hits := map[string]int{}
	p := &fakeProber{fn: func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		mu.Lock()
		hits[req.Target.String()]++
		mu.Unlock()
		rtt := 10.0
		if req.Target.String() == "198.51.100.10" {
			rtt = 1
		}
		return plugin.ProbeResult{Sent: req.Count, RTTs: ms(rtt, rtt)}, nil
	}}
	vipTarget := plugin.Target{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.10"), Interval: 20 * time.Millisecond}
	normal := plugin.Target{Prefix: pfx2, Host: netip.MustParseAddr("203.0.113.10")}
	e, err := New([]Provider{provA}, []NamedProber{{"p", p}}, src(vipTarget, normal), o)
	if err != nil {
		t.Fatal(err)
	}
	last := map[netip.Prefix]time.Time{}
	step := func() {
		t.Helper()
		probed, done := e.runRound(context.Background(), func(tg plugin.Target) bool {
			return e.targetDue(tg, last)
		}, true)
		if !done {
			t.Fatal("round did not complete")
		}
		for pref := range probed {
			last[pref] = now
		}
	}
	step()
	if hits["198.51.100.10"] != 1 || hits["203.0.113.10"] != 1 {
		t.Fatalf("first round %+v", hits)
	}
	now = now.Add(20 * time.Millisecond)
	step()
	if hits["198.51.100.10"] != 2 || hits["203.0.113.10"] != 1 {
		t.Fatalf("vip-only round %+v", hits)
	}
	var sawNorm bool
	for _, r := range e.Results() {
		if r.Prefix == pfx2 && r.Stats.RTTAvg == 10*time.Millisecond {
			sawNorm = true
		}
	}
	if !sawNorm {
		t.Fatalf("normal result dropped: %+v", e.Results())
	}
	if lim.total != 3*o.Packets {
		t.Fatalf("limiter tokens = %d, want %d", lim.total, 3*o.Packets)
	}
	e.RunOnce(context.Background())
	if hits["203.0.113.10"] != 2 || hits["198.51.100.10"] != 3 {
		t.Fatalf("RunOnce hits = %+v", hits)
	}
	if lim.total != 5*o.Packets {
		t.Fatalf("limiter after RunOnce = %d", lim.total)
	}
}

func TestShorterIntervalWins(t *testing.T) {
	o := opts()
	o.Interval = 30 * time.Second
	e, _ := New([]Provider{provA}, []NamedProber{{"p", &fakeProber{fn: ok(1)}}}, []NamedSource{
		{Name: "static", Source: &fakeSource{targets: []plugin.Target{{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.9")}}}},
		{Name: "vip", Source: &fakeSource{targets: []plugin.Target{{Prefix: pfx1, Interval: 5 * time.Second}, {Prefix: pfx2, Interval: 5 * time.Second}}}},
	}, o)
	ts := e.Targets(context.Background())
	if len(ts) != 2 {
		t.Fatalf("targets = %+v", ts)
	}
	if ts[0].Host.String() != "198.51.100.9" || ts[0].Interval != 5*time.Second {
		t.Fatalf("merged = %+v", ts[0])
	}
	if ts[1].Prefix != pfx2 || ts[1].Interval != 5*time.Second {
		t.Fatalf("vip-only = %+v", ts[1])
	}
}

func TestLongerVIPIntervalDoesNotSlowPrefix(t *testing.T) {
	o := opts()
	o.Interval = 30 * time.Second
	e, _ := New([]Provider{provA}, []NamedProber{{"p", &fakeProber{fn: ok(1)}}}, []NamedSource{
		{Name: "static", Source: &fakeSource{targets: []plugin.Target{{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.9")}}}},
		{Name: "vip", Source: &fakeSource{targets: []plugin.Target{{Prefix: pfx1, Interval: 5 * time.Minute}, {Prefix: pfx2, Interval: 5 * time.Minute}}}},
	}, o)
	ts := e.Targets(context.Background())
	if len(ts) != 2 {
		t.Fatalf("targets = %+v", ts)
	}
	if ts[0].Host.String() != "198.51.100.9" || ts[0].Interval != 0 {
		t.Fatalf("longer vip interval slowed the prefix: %+v", ts[0])
	}
	if ts[1].Prefix != pfx2 || ts[1].Interval != 5*time.Minute {
		t.Fatalf("vip-only = %+v", ts[1])
	}

	// VIP listed first still cannot keep a cadence slower than the engine
	// once a later source names the same prefix.
	e, _ = New([]Provider{provA}, []NamedProber{{"p", &fakeProber{fn: ok(1)}}}, []NamedSource{
		{Name: "vip", Source: &fakeSource{targets: []plugin.Target{{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.8"), Interval: 5 * time.Minute}}}},
		{Name: "static", Source: &fakeSource{targets: []plugin.Target{{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.9")}}}},
	}, o)
	ts = e.Targets(context.Background())
	if len(ts) != 1 || ts[0].Host.String() != "198.51.100.8" || ts[0].Interval != 0 {
		t.Fatalf("first host kept, interval not shortened to the engine: %+v", ts)
	}
}

type countingSource struct {
	plugin.Base
	mu      sync.Mutex
	n       int
	targets []plugin.Target
	err     error
	fresh   bool
}

func (s *countingSource) Fresh() bool { return s.fresh }

func (s *countingSource) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

func (s *countingSource) Targets(context.Context) ([]plugin.Target, error) {
	s.mu.Lock()
	s.n++
	s.mu.Unlock()
	return s.targets, s.err
}

func TestNonVIPSourceCachedAcrossShortWake(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	o := opts()
	o.Now = func() time.Time { return now }
	o.Interval = 30 * time.Second
	static := &countingSource{targets: []plugin.Target{{Prefix: pfx2, Host: netip.MustParseAddr("203.0.113.10")}}}
	vip := &countingSource{targets: []plugin.Target{{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.10"), Interval: time.Second}}}
	e, err := New([]Provider{provA}, []NamedProber{{"p", &fakeProber{fn: ok(1)}}}, []NamedSource{
		{Name: "static", Source: static},
		{Name: "vip", Source: vip},
	}, o)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, done := e.runRound(context.Background(), func(plugin.Target) bool { return true }, true); !done {
			t.Fatal("round did not complete")
		}
		now = now.Add(time.Second)
	}
	if static.Calls() != 1 {
		t.Fatalf("static source calls = %d, want 1 across VIP wakes", static.Calls())
	}
	if vip.Calls() != 3 {
		t.Fatalf("vip source calls = %d, want 3", vip.Calls())
	}
	now = now.Add(o.Interval)
	if _, done := e.runRound(context.Background(), func(plugin.Target) bool { return true }, true); !done {
		t.Fatal("round did not complete")
	}
	if static.Calls() != 2 {
		t.Fatalf("static source calls = %d after the engine interval, want 2", static.Calls())
	}
}

func TestRemovedPrefixDroppedWhenNothingDue(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	o := opts()
	o.Now = func() time.Time { return now }
	o.Interval = time.Minute
	var rounds atomic.Int32
	o.OnRound = func() { rounds.Add(1) }
	src := &fakeSource{targets: []plugin.Target{
		{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.1")},
		{Prefix: pfx2, Host: netip.MustParseAddr("203.0.113.1")},
	}}
	e, err := New([]Provider{provA}, []NamedProber{{"p", &fakeProber{fn: ok(1)}}},
		[]NamedSource{{Name: "static", Source: src}}, o)
	if err != nil {
		t.Fatal(err)
	}
	e.RunOnce(context.Background())
	if len(e.Results()) != 2 || rounds.Load() != 1 {
		t.Fatalf("first round results=%d rounds=%d", len(e.Results()), rounds.Load())
	}
	src.targets = []plugin.Target{{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.1")}}
	now = now.Add(o.Interval) // expire the cached target list
	probed, done := e.runRound(context.Background(), func(plugin.Target) bool { return false }, true)
	if !done || len(probed) != 0 {
		t.Fatalf("idle round probed=%v done=%v", probed, done)
	}
	rs := e.Results()
	if len(rs) != 1 || rs[0].Prefix != pfx1 {
		t.Fatalf("removed prefix kept: %+v", rs)
	}
	if rounds.Load() != 2 {
		t.Fatalf("drop did not commit a round: %d", rounds.Load())
	}
}

func TestRunSchedulesVIPAheadOfEngineInterval(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	o := opts()
	o.Now = func() time.Time { return now }
	o.Interval = 100 * time.Millisecond
	o.Packets = 1
	var mu sync.Mutex
	hits := map[string]int{}
	p := &fakeProber{fn: func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		mu.Lock()
		hits[req.Target.String()]++
		mu.Unlock()
		return plugin.ProbeResult{Sent: req.Count, RTTs: ms(1)}, nil
	}}
	e, err := New([]Provider{provA}, []NamedProber{{"p", p}}, []NamedSource{{Name: "s", Source: &fakeSource{targets: []plugin.Target{
		{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.10"), Interval: 20 * time.Millisecond},
		{Prefix: pfx2, Host: netip.MustParseAddr("203.0.113.10")},
	}}}}, o)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	steps := 0
	o.Sleep = func(ctx context.Context, d time.Duration) error {
		now = now.Add(d)
		steps++
		if steps >= 4 {
			cancel()
			return ctx.Err()
		}
		return nil
	}
	// Sleep is read from e.opt, which was copied at New. Set it on the engine.
	e.opt.Sleep = o.Sleep
	if err := e.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits["198.51.100.10"] < 3 {
		t.Fatalf("vip probes = %d, want at least 3", hits["198.51.100.10"])
	}
	if hits["203.0.113.10"] != 1 {
		t.Fatalf("normal probes = %d, want 1 in a 100ms interval", hits["203.0.113.10"])
	}
}

func TestFreshSourceReadOnShortWake(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	o := opts()
	o.Now = func() time.Time { return now }
	o.Interval = 30 * time.Second
	static := &countingSource{targets: []plugin.Target{{Prefix: pfx2, Host: netip.MustParseAddr("203.0.113.10")}}}
	fresh := &countingSource{fresh: true, targets: []plugin.Target{{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.10")}}}
	e, err := New([]Provider{provA}, []NamedProber{{"p", &fakeProber{fn: ok(1)}}}, []NamedSource{
		{Name: "static", Source: static},
		{Name: "outage", Source: fresh},
	}, o)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, done := e.runRound(context.Background(), func(plugin.Target) bool { return true }, true); !done {
			t.Fatal("round did not complete")
		}
		now = now.Add(time.Second)
	}
	if static.Calls() != 1 {
		t.Fatalf("static source calls = %d, want 1", static.Calls())
	}
	if fresh.Calls() != 3 {
		t.Fatalf("fresh source calls = %d, want 3", fresh.Calls())
	}
}

func TestUrgentProbesBeforeInterval(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	o := opts()
	o.Now = func() time.Time { return now }
	o.Interval = time.Minute
	var hits atomic.Int32
	p := &fakeProber{fn: func(context.Context, plugin.ProbeRequest) (plugin.ProbeResult, error) {
		hits.Add(1)
		return plugin.ProbeResult{Sent: 1, RTTs: ms(1)}, nil
	}}
	o.Packets = 1
	src := &countingSource{fresh: true, targets: []plugin.Target{{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.10"), Urgent: true, Interval: 5 * time.Second}}}
	e, err := New([]Provider{provA}, []NamedProber{{"p", p}}, []NamedSource{{Name: "outage", Source: src}}, o)
	if err != nil {
		t.Fatal(err)
	}
	last := map[netip.Prefix]time.Time{pfx1: now}
	probed, done := e.runRound(context.Background(), func(tg plugin.Target) bool {
		return e.targetDue(tg, last)
	}, true)
	if !done || len(probed) != 1 || hits.Load() != 1 {
		t.Fatalf("urgent probed=%v done=%v hits=%d", probed, done, hits.Load())
	}
	src.targets = []plugin.Target{{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.10"), Interval: 5 * time.Second}}
	probed, done = e.runRound(context.Background(), func(tg plugin.Target) bool {
		return e.targetDue(tg, last)
	}, true)
	if !done || len(probed) != 0 || hits.Load() != 1 {
		t.Fatalf("second pass probed=%v done=%v hits=%d", probed, done, hits.Load())
	}
}

func TestUrgentFromLaterSource(t *testing.T) {
	o := opts()
	o.Interval = 30 * time.Second
	e, err := New([]Provider{provA}, []NamedProber{{"p", &fakeProber{fn: ok(1)}}}, []NamedSource{
		{Name: "static", Source: &fakeSource{targets: []plugin.Target{{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.9")}}}},
		{Name: "outage", Source: &fakeSource{targets: []plugin.Target{{Prefix: pfx1, Urgent: true, Interval: 5 * time.Second}}}},
	}, o)
	if err != nil {
		t.Fatal(err)
	}
	ts := e.Targets(context.Background())
	if len(ts) != 1 || !ts[0].Urgent || ts[0].Interval != 5*time.Second || ts[0].Host.String() != "198.51.100.9" {
		t.Fatalf("merged = %+v", ts)
	}
}

func TestWakeSkipsRemainderOfInterval(t *testing.T) {
	e := &Engine{wake: make(chan struct{}, 1)}
	e.Wake()
	start := time.Now()
	if err := e.sleep(context.Background(), time.Hour); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("wake did not skip the wait: %s", time.Since(start))
	}

	now := time.Unix(1_700_000_000, 0)
	o := opts()
	o.Now = func() time.Time { return now }
	o.Interval = time.Hour
	o.Packets = 1
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := &countingSource{fresh: true, targets: []plugin.Target{{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.1")}}}
	var probes atomic.Int32
	eng, err := New([]Provider{provA}, []NamedProber{{"p", &fakeProber{fn: func(context.Context, plugin.ProbeRequest) (plugin.ProbeResult, error) {
		probes.Add(1)
		return plugin.ProbeResult{Sent: 1, RTTs: ms(1)}, nil
	}}}}, []NamedSource{{Name: "s", Source: src}}, o)
	if err != nil {
		t.Fatal(err)
	}
	rounds := 0
	eng.opt.OnRound = func() {
		rounds++
		if rounds == 1 {
			eng.Wake()
		}
	}
	slept := 0
	eng.opt.Sleep = func(context.Context, time.Duration) error {
		slept++
		cancel()
		return context.Canceled
	}
	if err := eng.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v", err)
	}
	// The waking round probes once. The next round starts before any sleep
	// and finds the prefix not due, so it does not probe again.
	if rounds != 1 || src.Calls() != 2 || probes.Load() != 1 || slept != 1 {
		t.Fatalf("rounds=%d sourceCalls=%d probes=%d sleeps=%d", rounds, src.Calls(), probes.Load(), slept)
	}
}

func TestOnRoundAfterCommit(t *testing.T) {
	o := opts()
	var e *Engine
	got := -1
	o.OnRound = func() { got = len(e.Results()) } // must not deadlock and must see fresh results
	e, _ = New([]Provider{provA}, []NamedProber{{"p", &fakeProber{fn: ok(1)}}}, src(plugin.Target{Prefix: pfx1}), o)
	e.RunOnce(context.Background())
	if got != 1 {
		t.Fatalf("OnRound saw %d results", got)
	}
}
