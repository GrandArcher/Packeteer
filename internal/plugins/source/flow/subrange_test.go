package flow

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// subrangeYAML splits learned prefixes into /26s so the tests stay in
// 198.51.100.0/24.
const subrangeYAML = "listen: 127.0.0.1:2055\nwindow: 1m\ntop_n: 10\nsubranges: {bits_v4: 26}\n"

// learnedCover maps 198.51.100.0/24 the way the RIB view would.
func learnedCover(s *Source) netip.Prefix {
	cover := netip.MustParsePrefix("198.51.100.0/24")
	s.SetPrefixLookup(func(a netip.Addr) (netip.Prefix, bool) {
		if cover.Contains(a) {
			return cover, true
		}
		return netip.Prefix{}, false
	})
	return cover
}

func TestSubrangesConfig(t *testing.T) {
	s := mustSource(t, "listen: 127.0.0.1:2055\nsubranges: {}\n")
	if s.sub == nil || s.sub.bits4 != 24 || s.sub.bits6 != 48 || s.sub.maxPer != 4 || s.sub.maxTotal != 1000 || s.win.subCap != 8 {
		t.Fatalf("defaults = %+v subCap %d", s.sub, s.win.subCap)
	}
	if off := mustSource(t, "listen: 127.0.0.1:2055\n"); off.sub != nil || off.win.subCap != 0 {
		t.Fatalf("subranges on without the block: %+v", off.sub)
	}
	bad := map[string]string{
		"subranges: {bits_v4: 33}":         "subranges.bits_v4",
		"subranges: {bits_v4: -1}":         "subranges.bits_v4",
		"subranges: {bits_v6: 129}":        "subranges.bits_v6",
		"subranges: {max_subranges: 1}":    "subranges.max_subranges",
		"subranges: {max_subranges: 17}":   "subranges.max_subranges",
		"subranges: {max_total: 1}":        "subranges.max_total",
		"subranges: {max_total: 10001}":    "subranges.max_total",
		"subranges: {announce: true}":      "field announce not found",
		"subranges: {more_specific: true}": "field more_specific not found",
	}
	for y, want := range bad {
		_, err := build("listen: 127.0.0.1:2055\n" + y + "\n")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", y, err, want)
		}
	}
}

func TestSubrangesBusiestPerPrefix(t *testing.T) {
	s := mustSource(t, "listen: 127.0.0.1:2055\nwindow: 1m\ntop_n: 10\nsubranges: {bits_v4: 26, max_subranges: 2}\n")
	now := time.Unix(1_700_000_000, 0)
	pin(s, now)
	cover := learnedCover(s)
	ingestRanks(s, now, []rankBytes{
		{"198.51.100.10", 500},
		{"198.51.100.11", 100},
		{"198.51.100.212", 400},
		{"198.51.100.65", 50},
		// Not inside the learned /24: aggregated to a /24 with a
		// single busy /26, so it has no sub-ranges.
		{"203.0.113.5", 30},
	})
	ts := targetsOf(t, s)
	if len(ts) != 2 || ts[0].Prefix != cover {
		t.Fatalf("targets = %+v", ts)
	}
	got := ts[0].Subranges
	if len(got) != 2 ||
		got[0].Prefix.String() != "198.51.100.0/26" || got[0].Host.String() != "198.51.100.10" || got[0].Weight != 600 ||
		got[1].Prefix.String() != "198.51.100.192/26" || got[1].Host.String() != "198.51.100.212" || got[1].Weight != 400 {
		t.Fatalf("sub-ranges = %+v", got)
	}
	if len(ts[1].Subranges) != 0 {
		t.Fatalf("a single sub-range was attached: %+v", ts[1])
	}
}

func TestSubrangesNeedTwoAndGlobalCap(t *testing.T) {
	s := mustSource(t, "listen: 127.0.0.1:2055\nwindow: 1m\ntop_n: 10\nsubranges: {bits_v4: 25, max_total: 3}\n")
	now := time.Unix(1_700_000_000, 0)
	pin(s, now)
	// Three /24s with traffic in two /25s each: 2 + 2 + 2 sub-ranges
	// wanted, max_total 3 leaves room for the busiest prefix only, and
	// a single remaining slot is not enough for the next one.
	ingestRanks(s, now, []rankBytes{
		{"198.51.100.10", 900}, {"198.51.100.200", 800},
		{"203.0.113.10", 700}, {"203.0.113.200", 600},
		{"192.0.2.10", 50},
	})
	ts := targetsOf(t, s)
	if len(ts) != 3 {
		t.Fatalf("targets = %+v", ts)
	}
	if len(ts[0].Subranges) != 2 || len(ts[1].Subranges) != 0 {
		t.Fatalf("global cap: %+v / %+v", ts[0].Subranges, ts[1].Subranges)
	}
	// One busy /25 alone is not split.
	if len(ts[2].Subranges) != 0 {
		t.Fatalf("single sub-range attached: %+v", ts[2])
	}
}

// subProber answers with an RTT per provider and target, and counts the
// packets it was asked to send.
type subProber struct {
	plugin.Base
	mu   sync.Mutex
	rtt  map[string]map[netip.Addr]time.Duration
	seen map[netip.Addr]int
}

func (p *subProber) Probe(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen == nil {
		p.seen = map[netip.Addr]int{}
	}
	p.seen[req.Target] += req.Count
	d := p.rtt[req.Provider][req.Target]
	rtts := make([]time.Duration, req.Count)
	for i := range rtts {
		rtts[i] = d
	}
	return plugin.ProbeResult{Sent: req.Count, RTTs: rtts}, nil
}

// countLimiter records every packet that waited on the global rate limit.
type countLimiter struct {
	mu sync.Mutex
	n  int
}

func (l *countLimiter) WaitN(_ context.Context, n int) error {
	l.mu.Lock()
	l.n += n
	l.mu.Unlock()
	return nil
}

// TestSubrangesSimulatedFlowDecision is the #121 acceptance check with
// simulated flow: two sub-ranges of a learned /24 with different best
// providers produce two scores, a traffic-weighted prefix decision, and
// the heterogeneous flag. Every packet waited on the rate limit. The
// decision runs in observe mode and changes nothing for a sub-range.
func TestSubrangesSimulatedFlowDecision(t *testing.T) {
	s := mustSource(t, subrangeYAML)
	now := time.Unix(1_700_000_000, 0)
	pin(s, now)
	cover := learnedCover(s)
	hostA := netip.MustParseAddr("198.51.100.10")
	hostB := netip.MustParseAddr("198.51.100.202")
	// 60% of the bytes go to 198.51.100.0/26, 40% to 198.51.100.192/26.
	ingestRanks(s, now, []rankBytes{{hostA.String(), 600}, {hostB.String(), 400}})

	// transit-a: 10ms to A, 40ms to B. Weighted 0.6*10 + 0.4*40 = 22ms.
	// transit-b: 30ms to A, 20ms to B. Weighted 0.6*30 + 0.4*20 = 26ms.
	pr := &subProber{rtt: map[string]map[netip.Addr]time.Duration{
		"transit-a": {hostA: 10 * time.Millisecond, hostB: 40 * time.Millisecond},
		"transit-b": {hostA: 30 * time.Millisecond, hostB: 20 * time.Millisecond},
	}}
	lim := &countLimiter{}
	e, err := probe.New(
		[]probe.Provider{
			{Name: "transit-a", Source: netip.MustParseAddr("192.0.2.11")},
			{Name: "transit-b", Source: netip.MustParseAddr("192.0.2.12")},
		},
		[]probe.NamedProber{{Name: "sim", Prober: pr}},
		[]probe.NamedSource{{Name: "flow", Source: s}},
		probe.Options{Interval: time.Second, Timeout: 10 * time.Millisecond, Packets: 3, Workers: 2,
			Limiter: lim, Now: func() time.Time { return now }},
	)
	if err != nil {
		t.Fatal(err)
	}
	e.RunOnce(context.Background())
	res := e.Results()
	if len(res) != 2 {
		t.Fatalf("results = %+v", res)
	}
	for _, r := range res {
		if r.Prefix != cover || len(r.Subranges) != 2 {
			t.Fatalf("result = %+v", r)
		}
		want := map[string]time.Duration{"transit-a": 22 * time.Millisecond, "transit-b": 26 * time.Millisecond}[r.Provider]
		if r.Stats.RTTAvg != want || r.Stats.Sent != 6 || r.Stats.LossPct != 0 {
			t.Fatalf("%s weighted stats = %+v, want rtt %s", r.Provider, r.Stats, want)
		}
	}
	// Only the two sub-range hosts were probed, three packets per
	// provider each, and each packet waited on the limiter.
	if len(pr.seen) != 2 || pr.seen[hostA] != 6 || pr.seen[hostB] != 6 || lim.n != 12 {
		t.Fatalf("probed %v, limiter %d", pr.seen, lim.n)
	}

	scorer, err := weighted.New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	_, out := policy.Decide(policy.NewState(), policy.Input{
		Results:    res,
		ProviderUp: map[string]bool{"transit-a": true, "transit-b": true},
		RIBEnabled: true, RIBReady: true,
		Native: map[netip.Prefix]string{cover: "transit-b"},
	}, policy.Config{Mode: "observe", MinLossDeltaPct: 1, MinRTTDelta: time.Millisecond, MaxImprovements: 50, MaxResultAge: time.Hour}, scorer, now)
	if len(out.Decisions) != 1 {
		t.Fatalf("decisions = %+v", out.Decisions)
	}
	d := out.Decisions[0]
	if d.Prefix != cover || d.Recommended != "transit-a" || !d.Heterogeneous {
		t.Fatalf("decision = %+v", d)
	}
	if len(d.Subranges) != 2 {
		t.Fatalf("sub-ranges = %+v", d.Subranges)
	}
	a, b := d.Subranges[0], d.Subranges[1]
	if a.Prefix.String() != "198.51.100.0/26" || a.Weight != 600 || a.Best != "transit-a" || len(a.Candidates) != 2 ||
		b.Prefix.String() != "198.51.100.192/26" || b.Weight != 400 || b.Best != "transit-b" || len(b.Candidates) != 2 {
		t.Fatalf("sub-ranges = %+v", d.Subranges)
	}
	if a.Candidates[0].Score >= a.Candidates[1].Score || b.Candidates[1].Score >= b.Candidates[0].Score {
		t.Fatalf("sub-range scores = %+v / %+v", a.Candidates, b.Candidates)
	}
	// Any change is for the learned prefix only.
	for _, c := range out.Changes {
		if c.New.Prefix != cover && c.Old.Prefix != cover {
			t.Fatalf("change for a prefix that is not the learned one: %+v", c)
		}
	}
}
