package main

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/internal/troubleshoot"
)

// learnedRIB is a troubleshoot.RIB over fixed documentation routes.
type learnedRIB []rib.Route

func (l learnedRIB) Ready() bool { return true }
func (l learnedRIB) Exact(p netip.Prefix) (rib.Route, bool) {
	for _, r := range l {
		if r.Prefix == p.Masked() {
			return r, true
		}
	}
	return rib.Route{}, false
}
func (l learnedRIB) Covering(p netip.Prefix) (rib.Route, bool) {
	best, ok := rib.Route{}, false
	for _, r := range l {
		if r.Prefix.Bits() <= p.Bits() && r.Prefix.Contains(p.Addr()) && (!ok || r.Prefix.Bits() > best.Prefix.Bits()) {
			best, ok = r, true
		}
	}
	return best, ok
}
func (l learnedRIB) Routes() []rib.Route            { return l }
func (l learnedRIB) Paths(netip.Prefix) []rib.Route { return nil }

// manualRig is the #126 flow in inject mode: Probe and optimize queues a
// learned prefix that no target source lists, the engine probes it, and
// only Decide and the announcer can act on the measurement.
type manualRig struct {
	*retainRig
	tools *troubleshoot.Tools
}

func newManualRig(t *testing.T) *manualRig {
	t.Helper()
	r := newRetainRig(t, time.Hour, 2*time.Hour)
	r.src.targets = nil
	tools := troubleshoot.New(troubleshoot.Options{Enabled: true, Now: func() time.Time { return r.now }})
	tools.SetRIB(learnedRIB{
		{Prefix: r.pfx, NextHop: netip.MustParseAddr("192.0.2.1"), Provider: "transit-a"},
		{Prefix: netip.MustParsePrefix("203.0.113.0/24"), NextHop: netip.MustParseAddr("192.0.2.1"), Provider: "transit-a"},
	})
	tools.SetQueue(r.engine)
	return &manualRig{retainRig: r, tools: tools}
}

func (m *manualRig) optimize(target string) troubleshoot.OptimizeAnswer {
	m.t.Helper()
	ans, err := m.tools.Optimize(context.Background(), target)
	if err != nil {
		m.t.Fatalf("optimize %s: %v", target, err)
	}
	return ans
}

func (m *manualRig) measured() map[netip.Prefix]bool {
	got := map[netip.Prefix]bool{}
	for _, res := range m.engine.Results() {
		if res.OK() {
			got[res.Prefix] = true
		}
	}
	return got
}

// TestOptimizeQueuesPrefixThatDecideThenImproves: the queued prefix is
// probed on the next round with no source listing it, Decide moves it under
// its usual rules, and the route carries the configured community.
func TestOptimizeQueuesPrefixThatDecideThenImproves(t *testing.T) {
	m := newManualRig(t)
	m.probe()
	if len(m.measured()) != 0 || m.ann.count() != 0 {
		t.Fatalf("something was measured or announced before anything was queued")
	}
	ans := m.optimize("198.51.100.77")
	if ans.Prefix != m.pfx {
		t.Fatalf("queued %v, want the covering learned prefix %v", ans.Prefix, m.pfx)
	}
	if m.ann.count() != 0 {
		t.Fatal("queuing announced a route")
	}

	m.now = m.now.Add(time.Second)
	m.probe()
	if got := m.measured(); !got[m.pfx] || len(got) != 1 {
		t.Fatalf("measured %v on the next round", got)
	}
	changes := m.decide("transit-a")
	if len(changes) != 1 || changes[0].Action != policy.ActionImprove || changes[0].New.Provider != "transit-b" {
		t.Fatalf("decide = %+v\n%s", changes, m.logs.String())
	}
	m.requireRoute()

	// The improvement keeps the prefix measured past the queue's TTL.
	m.now = m.now.Add(troubleshoot.OptimizeTTL + time.Minute)
	m.probe()
	if !m.measured()[m.pfx] {
		t.Fatal("improved prefix dropped from the probe set when the queue entry expired")
	}
}

// TestOptimizeExpiresWithoutImprovement: a queued prefix that Decide does
// not move is dropped from the probe set and its results after the TTL.
func TestOptimizeExpiresWithoutImprovement(t *testing.T) {
	m := newManualRig(t)
	m.optimize("198.51.100.77")
	m.probe()
	if !m.measured()[m.pfx] {
		t.Fatal("queued prefix not probed")
	}
	// transit-a is already the best path, so Decide has nothing to do.
	m.prober.rtt["transit-a"] = 5 * time.Millisecond
	m.probe()
	if changes := m.decide("transit-a"); len(changes) != 0 || m.ann.count() != 0 {
		t.Fatalf("decide = %+v announced %d", changes, m.ann.count())
	}

	m.now = m.now.Add(troubleshoot.OptimizeTTL - time.Second)
	m.probe()
	if !m.measured()[m.pfx] {
		t.Fatal("dropped before the TTL")
	}
	m.now = m.now.Add(2 * time.Second)
	m.probe()
	if got := m.measured(); len(got) != 0 {
		t.Fatalf("still measured after the TTL: %v", got)
	}
	for _, tg := range m.engine.Targets(context.Background()) {
		t.Fatalf("target kept after the TTL: %+v", tg)
	}
}

// TestOptimizeNeverBypassesDecideRails: queuing measures, and nothing is
// announced for a prefix outside the allowlist or one the RIB view does not
// hold, even when its probes show a much better path.
func TestOptimizeNeverBypassesDecideRails(t *testing.T) {
	m := newManualRig(t)
	outside := netip.MustParsePrefix("203.0.113.0/24")
	m.optimize("198.51.100.77")
	m.optimize("203.0.113.5")
	m.probe()
	if got := m.measured(); !got[m.pfx] || !got[outside] {
		t.Fatalf("measured %v", got)
	}

	// Learned in the RIB view but not allowlisted: no move.
	in := policy.Input{
		Results: m.engine.Results(), ProviderUp: map[string]bool{"transit-a": true, "transit-b": true},
		RIBEnabled: true, RIBReady: true, Native: map[netip.Prefix]string{outside: "transit-a"},
	}
	if changes := m.dec.Evaluate(in, m.now); len(changes) != 0 {
		t.Fatalf("a prefix outside the allowlist moved: %+v", changes)
	}

	// Allowlisted but missing from the RIB view: no move.
	in.Native = map[netip.Prefix]string{}
	if changes := m.dec.Evaluate(in, m.now); len(changes) != 0 {
		t.Fatalf("a prefix missing from the RIB view moved: %+v", changes)
	}
	if m.ann.count() != 0 {
		t.Fatalf("announced %d routes", m.ann.count())
	}

	// Control: with the prefix learned and allowlisted, the same
	// measurements do move it, and only it.
	changes := m.decide("transit-a")
	if len(changes) != 1 || changes[0].New.Provider != "transit-b" || changes[0].New.Prefix != m.pfx {
		t.Fatalf("control decide = %+v", changes)
	}
	m.requireRoute()
}

// TestOptimizedImprovementWithdraws: a route that exists only because a
// queued prefix was measured goes away on the same triggers as any other
// improvement: the prefix leaving the RIB view, the RIB session dropping,
// and shutdown. Withdrawing also drops the probe target once the queue
// entry has expired.
func TestOptimizedImprovementWithdraws(t *testing.T) {
	improved := func(t *testing.T) *manualRig {
		t.Helper()
		m := newManualRig(t)
		m.optimize("198.51.100.77")
		m.now = m.now.Add(time.Second)
		m.probe()
		if changes := m.decide("transit-a"); len(changes) != 1 || changes[0].Action != policy.ActionImprove {
			t.Fatalf("decide = %+v\n%s", changes, m.logs.String())
		}
		m.requireRoute()
		return m
	}

	t.Run("rib leave", func(t *testing.T) {
		m := improved(t)
		m.now = m.now.Add(time.Second)
		m.probe()
		if changes := m.decide("transit-a"); len(changes) != 0 {
			t.Fatalf("withdrew while the prefix was still in the RIB: %+v", changes)
		}
		m.now = m.now.Add(5 * time.Second)
		m.probe()
		m.requireWithdrawn(m.decide(""), "prefix no longer in RIB")
	})

	t.Run("rib session lost", func(t *testing.T) {
		m := improved(t)
		in := policy.Input{
			Results:    m.engine.Results(),
			ProviderUp: map[string]bool{"transit-a": true, "transit-b": true},
			RIBEnabled: true, RIBReady: false,
		}
		changes, err := runDecision(m.now, m.dec, in, m.ctl, slog.New(slog.NewTextHandler(m.logs, nil)), "inject", m.engine)
		if err != nil {
			t.Fatal(err)
		}
		m.requireWithdrawn(changes, "bgp session down")
	})

	t.Run("shutdown", func(t *testing.T) {
		m := improved(t)
		if err := m.ctl.WithdrawAll(context.Background()); err != nil {
			t.Fatal(err)
		}
		if m.ann.count() != 0 {
			t.Fatalf("%d routes left after shutdown", m.ann.count())
		}
	})
}
