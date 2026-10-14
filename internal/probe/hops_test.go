package probe

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// #149: next hops are probed from each peer's own source address, through
// the prober chain, and never touch stored results or provider status.
func TestProbeHopsUsesPeerSourceAndLeavesEngineState(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]plugin.ProbeRequest{}
	p := &fakeProber{fn: func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		mu.Lock()
		seen[req.Provider] = req
		mu.Unlock()
		if req.Target == netip.MustParseAddr("203.0.113.12") {
			return plugin.ProbeResult{Sent: req.Count}, nil // silent next hop
		}
		return plugin.ProbeResult{Sent: req.Count, RTTs: ms(2, 4)}, nil
	}}
	e, err := New([]Provider{provA}, []NamedProber{{Name: "icmp", Prober: p}}, nil, opts())
	if err != nil {
		t.Fatal(err)
	}
	a, b := netip.MustParseAddr("203.0.113.11"), netip.MustParseAddr("203.0.113.12")
	got := e.ProbeHops(context.Background(), []HopTarget{
		{Provider: "ix-peer-a", Source: netip.MustParseAddr("192.0.2.31"), NextHop: a},
		{Provider: "ix-peer-b", Source: netip.MustParseAddr("192.0.2.32"), NextHop: b},
	})
	if len(got) != 2 || got[0].Provider != "ix-peer-a" || got[1].Provider != "ix-peer-b" {
		t.Fatalf("results = %+v", got)
	}
	if got[0].Err != "" || got[0].Stats.Received != 2 || got[0].Stats.RTTAvg != 3*time.Millisecond {
		t.Fatalf("answering hop = %+v", got[0])
	}
	// A silent next hop is a measurement with full loss, not an error.
	if got[1].Err != "" || got[1].Stats.LossPct != 100 || got[1].Stats.Received != 0 {
		t.Fatalf("silent hop = %+v", got[1])
	}
	if r := seen["ix-peer-a"]; r.Source != netip.MustParseAddr("192.0.2.31") || r.Target != a || r.Count != 3 {
		t.Fatalf("request for a = %+v", r)
	}
	if r := seen["ix-peer-b"]; r.Source != netip.MustParseAddr("192.0.2.32") || r.Target != b {
		t.Fatalf("request for b = %+v", r)
	}
	if len(e.Results()) != 0 || len(e.Providers()) != 1 || !e.Providers()[0].Up {
		t.Fatalf("engine state changed: results %v status %v", e.Results(), e.Providers())
	}
}

// A prober error is an error in the result, and an unusable source does
// not mark the provider down: a next hop is a health signal only.
func TestProbeHopsReportsErrors(t *testing.T) {
	p := &fakeProber{fn: func(context.Context, plugin.ProbeRequest) (plugin.ProbeResult, error) {
		return plugin.ProbeResult{}, plugin.ErrSourceUnavailable
	}}
	e, err := New([]Provider{provA}, []NamedProber{{Name: "icmp", Prober: p}}, nil, opts())
	if err != nil {
		t.Fatal(err)
	}
	got := e.ProbeHops(context.Background(), []HopTarget{{Provider: "transit-a", Source: provA.Source, NextHop: netip.MustParseAddr("203.0.113.11")}})
	if len(got) != 1 || got[0].Err == "" {
		t.Fatalf("results = %+v", got)
	}
	if st := e.Providers()[0]; !st.Up {
		t.Fatalf("hop probe changed provider status: %+v", st)
	}
}

// Every packet waits on the shared limiter (probe.rate_limit_pps), and a
// cancelled context stops the work.
func TestProbeHopsRespectsLimiterAndContext(t *testing.T) {
	p := &fakeProber{fn: ok(1)}
	o := opts()
	o.Limiter = newTokenLimiterForTest(1, 3) // one probe of 3 packets, then a long wait
	e, err := New([]Provider{provA}, []NamedProber{{Name: "icmp", Prober: p}}, nil, o)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	targets := []HopTarget{
		{Provider: "ix-peer-a", Source: provA.Source, NextHop: netip.MustParseAddr("203.0.113.11")},
		{Provider: "ix-peer-b", Source: provA.Source, NextHop: netip.MustParseAddr("203.0.113.12")},
	}
	got := e.ProbeHops(ctx, targets)
	// Workers race for the burst: exactly one probe gets the tokens.
	answered := 0
	for _, r := range got {
		if r.Err == "" && r.Stats.Received > 0 {
			answered++
		} else if r.Err == "" {
			t.Fatalf("a probe past the rate limit has no error: %+v", r)
		}
	}
	if answered != 1 {
		t.Fatalf("answered = %d, want 1: %+v", answered, got)
	}
	if n := p.calls.Load(); n != 1 {
		t.Fatalf("prober calls = %d, want 1", n)
	}
}
