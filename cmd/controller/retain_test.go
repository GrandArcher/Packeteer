package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/announce"
	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// listSource stands in for the flow source. Fresh, so the next round sees
// an empty list instead of a cached one.
type listSource struct {
	plugin.Base
	targets []plugin.Target
}

func (listSource) Fresh() bool { return true }

func (s *listSource) Targets(context.Context) ([]plugin.Target, error) {
	return append([]plugin.Target(nil), s.targets...), nil
}

// rttProber answers every address. Tests change a provider's RTT to flip
// the native path back.
type rttProber struct {
	plugin.Base
	rtt map[string]time.Duration
}

func (p *rttProber) Probe(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	d := p.rtt[req.Provider]
	if d <= 0 {
		d = 50 * time.Millisecond
	}
	rtts := make([]time.Duration, req.Count)
	for i := range rtts {
		rtts[i] = d
	}
	return plugin.ProbeResult{Sent: req.Count, RTTs: rtts}, nil
}

// retainRig is inject mode with a fake flow source and an in-memory
// announcer. now is the clock for both probes and decisions.
type retainRig struct {
	t      *testing.T
	now    time.Time
	pfx    netip.Prefix
	host   netip.Addr
	every  time.Duration
	src    *listSource
	prober *rttProber
	engine *probe.Engine
	dec    *policy.Engine
	ctl    *announce.Controller
	ann    *memAnn
	logs   *bytes.Buffer
}

func newRetainRig(t *testing.T, hold, ttl time.Duration) *retainRig {
	t.Helper()
	pfx := netip.MustParsePrefix("198.51.100.0/24")
	host := netip.MustParseAddr("198.51.100.50")
	every := 5 * time.Second
	r := &retainRig{
		t: t, now: time.Unix(1_700_000_000, 0), pfx: pfx, host: host, every: every,
		src: &listSource{targets: []plugin.Target{{
			Prefix: pfx, Host: host, Candidate: true, Interval: every,
		}}},
		prober: &rttProber{rtt: map[string]time.Duration{
			"transit-a": 80 * time.Millisecond,
			"transit-b": 10 * time.Millisecond,
		}},
		ann:  &memAnn{},
		logs: &bytes.Buffer{},
	}
	log := slog.New(slog.NewTextHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	eng, err := probe.New(
		[]probe.Provider{
			{Name: "transit-a", Source: netip.MustParseAddr("192.0.2.11")},
			{Name: "transit-b", Source: netip.MustParseAddr("192.0.2.12")},
		},
		[]probe.NamedProber{{Name: "rtt", Prober: r.prober}},
		[]probe.NamedSource{{Name: "flow", Source: r.src}},
		probe.Options{
			Interval: 30 * time.Second,
			Timeout:  20 * time.Millisecond,
			Packets:  1,
			Workers:  2,
			Logger:   log,
			Now:      func() time.Time { return r.now },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	scorer, err := weighted.New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	r.engine = eng
	r.dec = policy.NewEngine(policy.Config{
		Mode:            "inject",
		MinLossDeltaPct: 1,
		MinRTTDelta:     15 * time.Millisecond,
		HoldTime:        hold,
		MaxImprovements: 50,
		ImprovementTTL:  ttl,
		MaxResultAge:    2 * time.Hour,
		Allowlist:       []netip.Prefix{pfx},
	}, scorer)
	r.ctl, err = announce.New(announce.Config{
		Mode:            "inject",
		LocalPref:       250,
		Community:       "64512:666",
		MaxImprovements: 50,
		Allowlist:       []netip.Prefix{pfx},
		NextHops: map[string]netip.Addr{
			"transit-a": netip.MustParseAddr("192.0.2.1"),
			"transit-b": netip.MustParseAddr("192.0.2.2"),
		},
	}, r.ann, readyRIB{pfx}, log)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// probe measures the current targets. decide runs one inject evaluation
// and feeds the active improvements back to the probe engine.
func (r *retainRig) probe() {
	r.t.Helper()
	r.engine.RunOnce(context.Background())
}

func (r *retainRig) decide(native string) []policy.Change {
	r.t.Helper()
	in := policy.Input{
		Results:    r.engine.Results(),
		ProviderUp: map[string]bool{},
		RIBEnabled: true,
		RIBReady:   true,
		Native:     map[netip.Prefix]string{},
	}
	for _, p := range r.engine.Providers() {
		in.ProviderUp[p.Name] = p.Up
	}
	if native != "" {
		in.Native[r.pfx] = native
	}
	changes, err := runDecision(r.now, r.dec, in, r.ctl, slog.New(slog.NewTextHandler(r.logs, nil)), "inject", r.engine)
	if err != nil {
		r.t.Fatalf("decide: %v\n%s", err, r.logs.String())
	}
	return changes
}

func (r *retainRig) improve() {
	r.t.Helper()
	r.probe()
	changes := r.decide("transit-a")
	if len(changes) != 1 || changes[0].Action != policy.ActionImprove || changes[0].New.Provider != "transit-b" {
		r.t.Fatalf("improve = %+v\n%s", changes, r.logs.String())
	}
	r.requireRoute()
	r.src.targets = nil
}

func (r *retainRig) requireRoute() {
	r.t.Helper()
	rt, ok := r.ann.route(r.pfx)
	if !ok || r.ann.count() != 1 {
		r.t.Fatalf("route count=%d ok=%v logs=%s", r.ann.count(), ok, r.logs.String())
	}
	if rt.Prefix != r.pfx || rt.Provider != "transit-b" || rt.NextHop.String() != "192.0.2.2" || rt.LocalPref != 250 ||
		len(rt.Communities) != 1 || rt.Communities[0] != "64512:666" {
		r.t.Fatalf("announced route = %+v", rt)
	}
}

// requireKept checks the route is still up and the prefix is still probed
// at its last host and interval after the flow source dropped it.
func (r *retainRig) requireKept() {
	r.t.Helper()
	r.requireRoute()
	var got *plugin.Target
	for _, tg := range r.engine.Targets(context.Background()) {
		if tg.Prefix == r.pfx {
			cp := tg
			got = &cp
		}
	}
	if got == nil || got.Host != r.host || got.Interval != r.every || !got.Candidate || got.Pinned {
		r.t.Fatalf("retained target = %+v", got)
	}
	measured := false
	for _, res := range r.engine.Results() {
		if res.Prefix != r.pfx || !res.OK() {
			continue
		}
		measured = true
		if len(res.Targets) == 0 || res.Targets[0] != r.host {
			r.t.Fatalf("probe hosts = %v", res.Targets)
		}
	}
	if !measured {
		r.t.Fatalf("no measurement for %s", r.pfx)
	}
}

func (r *retainRig) requireWithdrawn(changes []policy.Change, reason string) {
	r.t.Helper()
	if len(changes) != 1 || changes[0].Action != policy.ActionRetire || !strings.Contains(changes[0].Old.Reason, reason) {
		r.t.Fatalf("retire (%s) = %+v\n%s", reason, changes, r.logs.String())
	}
	if r.ann.count() != 0 {
		rt, _ := r.ann.route(r.pfx)
		r.t.Fatalf("route still announced: %+v", rt)
	}
}

func (r *retainRig) requireTargetDropped() {
	r.t.Helper()
	r.now = r.now.Add(time.Second)
	r.probe()
	for _, tg := range r.engine.Targets(context.Background()) {
		if tg.Prefix == r.pfx {
			r.t.Fatalf("target kept after retire: %+v", tg)
		}
	}
	for _, res := range r.engine.Results() {
		if res.Prefix == r.pfx {
			r.t.Fatalf("measurement kept after retire: %+v", res)
		}
	}
}

// TestImprovedPrefixStaysAfterFlowDrops is the inject-mode check for #116.
// A flow prefix is improved, then removed from the source. The route stays
// while measurements stay good, and withdraws on improvement_ttl, flip-back,
// and a confirmed RIB leave. The next round drops the probe target.
func TestImprovedPrefixStaysAfterFlowDrops(t *testing.T) {
	t.Run("improvement_ttl", func(t *testing.T) {
		r := newRetainRig(t, time.Hour, 30*time.Minute)
		r.improve()
		r.now = r.now.Add(time.Minute)
		r.probe()
		if changes := r.decide("transit-a"); len(changes) != 0 {
			t.Fatalf("withdrew while measurements were good: %+v", changes)
		}
		r.requireKept()

		r.now = r.now.Add(30 * time.Minute)
		r.probe()
		r.requireWithdrawn(r.decide("transit-a"), "ttl expired")
		r.requireTargetDropped()
	})

	t.Run("flip-back", func(t *testing.T) {
		r := newRetainRig(t, 15*time.Minute, 2*time.Hour)
		r.improve()
		r.now = r.now.Add(time.Minute)
		r.probe()
		if changes := r.decide("transit-a"); len(changes) != 0 {
			t.Fatalf("withdrew while measurements were good: %+v", changes)
		}
		r.requireKept()

		// Native is better, but hold_time has not elapsed.
		r.prober.rtt["transit-a"] = 10 * time.Millisecond
		r.prober.rtt["transit-b"] = 80 * time.Millisecond
		r.now = r.now.Add(time.Minute)
		r.probe()
		if changes := r.decide("transit-a"); len(changes) != 0 {
			t.Fatalf("flipped inside hold_time: %+v", changes)
		}
		r.requireRoute()

		r.now = r.now.Add(15 * time.Minute)
		r.probe()
		r.requireWithdrawn(r.decide("transit-a"), "native path better")
		r.requireTargetDropped()
	})

	t.Run("rib leave", func(t *testing.T) {
		r := newRetainRig(t, time.Hour, 2*time.Hour)
		r.improve()
		// The sighting that created the improvement does not arm the
		// leave check. One later round must still see the prefix.
		r.now = r.now.Add(time.Second)
		r.probe()
		if changes := r.decide("transit-a"); len(changes) != 0 {
			t.Fatalf("withdrew while the prefix was still in the RIB: %+v", changes)
		}
		r.requireKept()

		r.now = r.now.Add(5 * time.Second)
		r.probe()
		r.requireWithdrawn(r.decide(""), "prefix no longer in RIB")
		r.requireTargetDropped()
	})
}
