package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/announce"
	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// hostRTTProber answers with an RTT per provider and target address.
type hostRTTProber struct {
	plugin.Base
	rtt map[string]map[netip.Addr]time.Duration
}

func (p *hostRTTProber) Probe(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	d := p.rtt[req.Provider][req.Target]
	if d <= 0 {
		d = 50 * time.Millisecond
	}
	rtts := make([]time.Duration, req.Count)
	for i := range rtts {
		rtts[i] = d
	}
	return plugin.ProbeResult{Sent: req.Count, RTTs: rtts}, nil
}

// TestSubrangeMeasurementAnnouncesOnlyLearnedPrefix is the inject-mode
// check for #121. A learned /16 carries two measured /24 sub-ranges with
// different best providers. The decision is the traffic-weighted
// aggregate and flags the prefix heterogeneous. The only route announced
// is the learned /16 itself, with the community; no sub-range is ever
// announced. When the weighted aggregate keeps the native exit, nothing
// is announced at all. Crash cleanup withdraws everything.
func TestSubrangeMeasurementAnnouncesOnlyLearnedPrefix(t *testing.T) {
	learned := netip.MustParsePrefix("198.51.0.0/16")
	subA := netip.MustParsePrefix("198.51.100.0/24")
	subB := netip.MustParsePrefix("198.51.200.0/24")
	hostA := netip.MustParseAddr("198.51.100.10")
	hostB := netip.MustParseAddr("198.51.200.10")

	run := func(t *testing.T, weightA, weightB float64) (*memAnn, policy.Decision, []policy.Change, *announce.Controller) {
		t.Helper()
		now := time.Unix(1_700_000_000, 0)
		logs := &bytes.Buffer{}
		log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
		src := &listSource{targets: []plugin.Target{{
			Prefix: learned, Host: hostA, Candidate: true, Weight: weightA + weightB,
			Subranges: []plugin.Subrange{
				{Prefix: subA, Host: hostA, Weight: weightA},
				{Prefix: subB, Host: hostB, Weight: weightB},
			},
		}}}
		// subA is much faster via transit-b; subB is faster via
		// transit-a, the native exit.
		prober := &hostRTTProber{rtt: map[string]map[netip.Addr]time.Duration{
			"transit-a": {hostA: 90 * time.Millisecond, hostB: 10 * time.Millisecond},
			"transit-b": {hostA: 10 * time.Millisecond, hostB: 90 * time.Millisecond},
		}}
		eng, err := probe.New(
			[]probe.Provider{
				{Name: "transit-a", Source: netip.MustParseAddr("192.0.2.11")},
				{Name: "transit-b", Source: netip.MustParseAddr("192.0.2.12")},
			},
			[]probe.NamedProber{{Name: "rtt", Prober: prober}},
			[]probe.NamedSource{{Name: "flow", Source: src}},
			probe.Options{Interval: 30 * time.Second, Timeout: 20 * time.Millisecond, Packets: 1, Workers: 2,
				Logger: log, Now: func() time.Time { return now }},
		)
		if err != nil {
			t.Fatal(err)
		}
		scorer, err := weighted.New(plugin.Config{}, plugin.Env{})
		if err != nil {
			t.Fatal(err)
		}
		allow := []netip.Prefix{netip.MustParsePrefix("198.51.0.0/16")}
		dec := policy.NewEngine(policy.Config{
			Mode: "inject", MinLossDeltaPct: 1, MinRTTDelta: 15 * time.Millisecond,
			HoldTime: time.Minute, MaxImprovements: 50, MaxResultAge: time.Hour, Allowlist: allow,
		}, scorer)
		ann := &memAnn{}
		ctl, err := announce.New(announce.Config{
			Mode: "inject", LocalPref: 250, Community: "64512:666", MaxImprovements: 50, Allowlist: allow,
			NextHops: map[string]netip.Addr{
				"transit-a": netip.MustParseAddr("192.0.2.1"),
				"transit-b": netip.MustParseAddr("192.0.2.2"),
			},
		}, ann, readyRIB{learned}, log)
		if err != nil {
			t.Fatal(err)
		}
		eng.RunOnce(context.Background())
		in := policy.Input{
			Results: eng.Results(), ProviderUp: map[string]bool{"transit-a": true, "transit-b": true},
			RIBEnabled: true, RIBReady: true, Native: map[netip.Prefix]string{learned: "transit-a"},
		}
		changes, err := runDecision(now, dec, in, ctl, log, "inject", eng)
		if err != nil {
			t.Fatalf("decide: %v\n%s", err, logs.String())
		}
		ds, _ := dec.Decisions()
		if len(ds) != 1 {
			t.Fatalf("decisions = %+v", ds)
		}
		return ann, ds[0], changes, ctl
	}

	requireOnlyLearned := func(t *testing.T, ann *memAnn) {
		t.Helper()
		ann.mu.Lock()
		defer ann.mu.Unlock()
		for p := range ann.routes {
			if p != learned {
				t.Fatalf("announced %s, which is not the learned prefix", p)
			}
		}
	}

	t.Run("weighted move announces the learned prefix only", func(t *testing.T) {
		ann, d, changes, ctl := run(t, 900, 100)
		if !d.Heterogeneous || len(d.Subranges) != 2 {
			t.Fatalf("decision = %+v", d)
		}
		if d.Subranges[0].Prefix != subA || d.Subranges[0].Best != "transit-b" ||
			d.Subranges[1].Prefix != subB || d.Subranges[1].Best != "transit-a" {
			t.Fatalf("sub-ranges = %+v", d.Subranges)
		}
		if len(changes) != 1 || changes[0].Action != policy.ActionImprove || changes[0].New.Prefix != learned || changes[0].New.Provider != "transit-b" {
			t.Fatalf("changes = %+v", changes)
		}
		requireOnlyLearned(t, ann)
		rt, ok := ann.route(learned)
		if !ok || ann.count() != 1 || rt.Provider != "transit-b" || len(rt.Communities) != 1 || rt.Communities[0] != "64512:666" {
			t.Fatalf("route = %+v ok=%v count=%d", rt, ok, ann.count())
		}
		if _, ok := ann.route(subA); ok {
			t.Fatal("sub-range announced")
		}
		if err := ctl.WithdrawAll(context.Background()); err != nil {
			t.Fatal(err)
		}
		if ann.count() != 0 {
			t.Fatalf("routes left after withdraw-all: %d", ann.count())
		}
	})

	t.Run("weighted native keeps everything unannounced", func(t *testing.T) {
		ann, d, changes, _ := run(t, 100, 900)
		if !d.Heterogeneous || d.Recommended != "transit-a" {
			t.Fatalf("decision = %+v", d)
		}
		if len(changes) != 0 || ann.count() != 0 {
			t.Fatalf("announced %d routes, changes %+v", ann.count(), changes)
		}
	})
}
