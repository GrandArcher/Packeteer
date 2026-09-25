package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/announce"
	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// hungProber answers allow calls, then blocks until release. It does not
// watch ctx: the per-probe deadline must not be what unblocks it.
type hungProber struct {
	plugin.Base
	mu      sync.Mutex
	calls   int
	allow   int
	release chan struct{}
}

func (p *hungProber) Probe(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	p.mu.Lock()
	p.calls++
	n := p.calls
	p.mu.Unlock()
	if n > p.allow {
		<-p.release
		return plugin.ProbeResult{}, errors.New("released")
	}
	rtt := 50 * time.Millisecond
	if req.Provider == "transit-b" {
		rtt = 10 * time.Millisecond
	}
	rtts := make([]time.Duration, req.Count)
	for i := range rtts {
		rtts[i] = rtt
	}
	return plugin.ProbeResult{Sent: req.Count, RTTs: rtts}, nil
}

type staticSource struct{ plugin.Base }

func (staticSource) Targets(context.Context) ([]plugin.Target, error) {
	return []plugin.Target{{Prefix: netip.MustParsePrefix("198.51.100.0/24")}}, nil
}

type readyRIB struct{ p netip.Prefix }

func (r readyRIB) Ready() bool { return true }

func (r readyRIB) Contains(p netip.Prefix) bool { return p.Masked() == r.p.Masked() }

type memAnn struct {
	plugin.Base
	mu     sync.Mutex
	routes map[netip.Prefix]plugin.Route
}

func (a *memAnn) Announce(_ context.Context, r plugin.Route) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.routes == nil {
		a.routes = map[netip.Prefix]plugin.Route{}
	}
	a.routes[r.Prefix] = r
	return nil
}

func (a *memAnn) Withdraw(_ context.Context, p netip.Prefix) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.routes, p.Masked())
	return nil
}

func (a *memAnn) WithdrawAll(context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.routes = map[netip.Prefix]plugin.Route{}
	return nil
}

func (a *memAnn) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.routes)
}

func (a *memAnn) route(p netip.Prefix) (plugin.Route, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	r, ok := a.routes[p]
	return r, ok
}

// TestHungProberStalenessWithdraws is the regression for #46: a prober that
// ignores cancellation must not leave an announced route up. The round
// deadline abandons the stuck round, and the staleness ticker withdraws
// once MaxResultAge passes, with no further completed round and no RIB change.
func TestHungProberStalenessWithdraws(t *testing.T) {
	pfx := netip.MustParsePrefix("198.51.100.0/24")
	release := make(chan struct{})
	defer close(release)
	prober := &hungProber{allow: 2, release: release} // one target, two providers

	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	o := probe.Options{
		Interval:     time.Second,
		Timeout:      20 * time.Millisecond,
		Packets:      1,
		Workers:      2,
		RoundTimeout: 100 * time.Millisecond,
		Logger:       log,
	}
	kick := make(chan struct{}, 1)
	o.OnRound = func() {
		select {
		case kick <- struct{}{}:
		default:
		}
	}
	engine, err := probe.New(
		[]probe.Provider{
			{Name: "transit-a", Source: netip.MustParseAddr("192.0.2.11")},
			{Name: "transit-b", Source: netip.MustParseAddr("192.0.2.12")},
		},
		[]probe.NamedProber{{Name: "hung", Prober: prober}},
		[]probe.NamedSource{{Name: "static", Source: staticSource{}}},
		o,
	)
	if err != nil {
		t.Fatal(err)
	}
	scorer, err := weighted.New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	decider := policy.NewEngine(policy.Config{
		Mode:            "inject",
		MinLossDeltaPct: 1,
		MinRTTDelta:     15 * time.Millisecond,
		HoldTime:        time.Hour, // stale data withdraws without waiting this out
		MaxImprovements: 50,
		MaxResultAge:    time.Second,
		Allowlist:       []netip.Prefix{pfx},
	}, scorer)
	ann := &memAnn{}
	ctl, err := announce.New(announce.Config{
		Mode:            "inject",
		LocalPref:       250,
		Community:       "64512:666",
		MaxImprovements: 50,
		Allowlist:       []netip.Prefix{pfx},
		NextHops: map[string]netip.Addr{
			"transit-a": netip.MustParseAddr("192.0.2.1"),
			"transit-b": netip.MustParseAddr("192.0.2.2"),
		},
	}, ann, readyRIB{pfx}, log)
	if err != nil {
		t.Fatal(err)
	}

	eval := func(now time.Time) {
		in := policy.Input{
			Results:    engine.Results(),
			ProviderUp: map[string]bool{},
			RIBEnabled: true,
			RIBReady:   true,
			Native:     map[netip.Prefix]string{},
		}
		for _, p := range engine.Providers() {
			in.ProviderUp[p.Name] = p.Up
		}
		for _, r := range in.Results {
			if r.Prefix == pfx {
				in.Native[pfx] = "transit-a"
			}
		}
		runDecision(now, decider, in, ctl, log, "inject")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		decideLoop(ctx, 40*time.Millisecond, kick, eval)
	}()
	defer func() {
		cancel()
		wg.Wait()
	}()

	engine.RunOnce(context.Background())
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && ann.count() != 1 {
		time.Sleep(10 * time.Millisecond)
	}
	rt, ok := ann.route(pfx)
	if !ok || ann.count() != 1 {
		t.Fatalf("route not announced: %+v logs=%s", ann, logs.String())
	}
	if rt.Prefix != pfx || rt.Provider != "transit-b" || rt.NextHop.String() != "192.0.2.2" || len(rt.Communities) != 1 || rt.Communities[0] != "64512:666" {
		t.Fatalf("announced route = %+v", rt)
	}

	// The next round never finishes. The route must stay until MaxResultAge,
	// then leave without another completed round.
	done := make(chan struct{})
	go func() {
		engine.RunOnce(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("hung prober was not bounded by the round timeout")
	}
	if ann.count() != 1 {
		t.Fatalf("withdrew before measurements were stale:\n%s", logs.String())
	}
	if len(engine.Results()) != 2 {
		t.Fatalf("hung round dropped results: %+v", engine.Results())
	}

	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && ann.count() != 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if ann.count() != 0 {
		t.Fatalf("stale improvement still announced:\n%s", logs.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("stale")) {
		t.Fatalf("withdraw was not caused by staleness:\n%s", logs.String())
	}
	if len(engine.Results()) != 2 {
		t.Fatalf("results changed after withdraw: %+v", engine.Results())
	}
}
