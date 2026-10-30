package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/announce"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rpki"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// coverRIB has the covering prefix learned and nothing inside it.
type coverRIB struct{ readyRIB }

func (coverRIB) MoreSpecifics([]netip.Prefix) []netip.Prefix { return nil }

// TestSynthesizeEndToEnd is the controller path of #122: a learned /24
// measured as two /25s with different best providers. The aggregate keeps
// the /24 native. With synthesize the /25 that transit-b serves better is
// decided on its own; inject announces it, and only it, with the
// community and the marker. Observe lists it and announces nothing.
// Synthesize off announces nothing that is not learned. The synthesized
// /25 is not probed as a target of its own, and WithdrawAll removes it.
func TestSynthesizeEndToEnd(t *testing.T) {
	cover := netip.MustParsePrefix("198.51.100.0/24")
	lo := netip.MustParsePrefix("198.51.100.0/25")
	hi := netip.MustParsePrefix("198.51.100.128/25")
	hostLo := netip.MustParseAddr("198.51.100.10")
	hostHi := netip.MustParseAddr("198.51.100.200")

	type run struct {
		ann *memAnn
		ctl *announce.Controller
		dec *policy.Engine
		eng *probe.Engine
	}
	start := func(t *testing.T, mode string, synth bool) run {
		t.Helper()
		now := time.Unix(1_700_000_000, 0)
		log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
		src := &listSource{targets: []plugin.Target{{
			Prefix: cover, Host: hostLo, Candidate: true, Weight: 2,
			Subranges: []plugin.Subrange{{Prefix: lo, Host: hostLo, Weight: 1}, {Prefix: hi, Host: hostHi, Weight: 1}},
		}}}
		prober := &hostRTTProber{rtt: map[string]map[netip.Addr]time.Duration{
			"transit-a": {hostLo: 90 * time.Millisecond, hostHi: 10 * time.Millisecond},
			"transit-b": {hostLo: 10 * time.Millisecond, hostHi: 90 * time.Millisecond},
		}}
		eng, err := probe.New(
			[]probe.Provider{{Name: "transit-a", Source: netip.MustParseAddr("192.0.2.11")}, {Name: "transit-b", Source: netip.MustParseAddr("192.0.2.12")}},
			[]probe.NamedProber{{Name: "rtt", Prober: prober}},
			[]probe.NamedSource{{Name: "flow", Source: src}},
			probe.Options{Interval: 30 * time.Second, Timeout: 20 * time.Millisecond, Packets: 1, Workers: 2, Logger: log, Now: func() time.Time { return now }},
		)
		if err != nil {
			t.Fatal(err)
		}
		scorer, err := weighted.New(plugin.Config{}, plugin.Env{})
		if err != nil {
			t.Fatal(err)
		}
		allow := []netip.Prefix{cover}
		dec := policy.NewEngine(policy.Config{Mode: mode, MinLossDeltaPct: 1, MinRTTDelta: 15 * time.Millisecond,
			HoldTime: time.Minute, MaxImprovements: 50, MaxResultAge: time.Hour, Allowlist: allow}, scorer)
		ac := announce.Config{Mode: mode, LocalPref: 250, Community: "64512:666", MaxImprovements: 50, Allowlist: allow,
			NextHops: map[string]netip.Addr{"transit-a": netip.MustParseAddr("192.0.2.1"), "transit-b": netip.MustParseAddr("192.0.2.2")}}
		if synth {
			ac.MaxRoutes = 10
			ac.Synthesize = &announce.Synthesize{Covering: allow, MaxBits: 1, MaxLenV4: 25, MaxLenV6: 48, Marker: "64512:667"}
		}
		ann := &memAnn{}
		ctl, err := announce.New(ac, ann, coverRIB{readyRIB{cover}}, log)
		if err != nil {
			t.Fatal(err)
		}
		eng.RunOnce(context.Background())
		in := policy.Input{Results: eng.Results(), ProviderUp: map[string]bool{"transit-a": true, "transit-b": true},
			RIBEnabled: true, RIBReady: true, Native: map[netip.Prefix]string{cover: "transit-a"}}
		in.Synthesize = ctl.Synthesizable(in.Results)
		if _, err := runDecision(now, dec, in, ctl, log, mode, eng); err != nil {
			t.Fatalf("decide: %v", err)
		}
		return run{ann: ann, ctl: ctl, dec: dec, eng: eng}
	}
	decision := func(t *testing.T, dec *policy.Engine, p netip.Prefix) (policy.Decision, bool) {
		t.Helper()
		ds, _ := dec.Decisions()
		for _, d := range ds {
			if d.Prefix == p {
				return d, true
			}
		}
		return policy.Decision{}, false
	}

	t.Run("inject announces the synthesized sub-range only", func(t *testing.T) {
		r := start(t, config.ModeInject, true)
		rt, ok := r.ann.routes[lo]
		if !ok || r.ann.count() != 1 || rt.Provider != "transit-b" || !slices.Equal(rt.Communities, []string{"64512:666", "64512:667"}) {
			t.Fatalf("routes = %+v", r.ann.routes)
		}
		if d, _ := decision(t, r.dec, cover); d.Action != policy.ActionNone {
			t.Fatalf("covering prefix decision = %+v", d)
		}
		imps := r.dec.Improvements()
		if len(imps) != 1 || imps[0].Prefix != lo || imps[0].Covering != cover {
			t.Fatalf("improvements = %+v", imps)
		}
		// The next round probes the covering prefix, not the /25 itself.
		r.eng.RunOnce(context.Background())
		for _, res := range r.eng.Results() {
			if res.Prefix != cover {
				t.Fatalf("probed %s as a target of its own", res.Prefix)
			}
		}
		if err := r.ctl.WithdrawAll(context.Background()); err != nil || r.ann.count() != 0 {
			t.Fatalf("withdraw-all: %v, %d left", err, r.ann.count())
		}
	})

	t.Run("observe lists the would-be route and announces nothing", func(t *testing.T) {
		r := start(t, config.ModeObserve, true)
		if r.ann.count() != 0 {
			t.Fatalf("observe announced %+v", r.ann.routes)
		}
		d, ok := decision(t, r.dec, lo)
		if !ok || d.Covering != cover || d.Recommended != "transit-b" {
			t.Fatalf("would-be decision = %+v", d)
		}
	})

	t.Run("off announces nothing unlearned", func(t *testing.T) {
		r := start(t, config.ModeInject, false)
		if r.ann.count() != 0 {
			t.Fatalf("announced %+v", r.ann.routes)
		}
		if _, ok := decision(t, r.dec, lo); ok {
			t.Fatal("sub-range decided with synthesize off")
		}
	})
}

func TestSynthesizeSetupWarning(t *testing.T) {
	cfg := &config.Config{}
	if st := setupInfo(cfg, &pluginhost.Set{}); st.SynthesizeWarning != "" {
		t.Fatalf("warning without synthesize: %q", st.SynthesizeWarning)
	}
	cfg.Synthesize = &config.Synthesize{Enabled: true}
	if st := setupInfo(cfg, &pluginhost.Set{}); !strings.Contains(st.SynthesizeWarning, "NOT in the learned RIB") {
		t.Fatalf("warning = %q", st.SynthesizeWarning)
	}
}

func TestSimulatedProbesSetupNotice(t *testing.T) {
	cfg := &config.Config{Probers: []config.PluginSpec{{Type: "fixed"}}}
	if st := setupInfo(cfg, &pluginhost.Set{}); st.SimulatedProbes != "" {
		t.Fatalf("notice with only a fixed prober: %q", st.SimulatedProbes)
	}
	cfg.Probers = append(cfg.Probers, config.PluginSpec{Type: "sim"})
	if st := setupInfo(cfg, &pluginhost.Set{}); st.SimulatedProbes != config.SimulatedProbesNotice || !strings.Contains(st.SimulatedProbes, "simulated, not measured") {
		t.Fatalf("notice = %q", st.SimulatedProbes)
	}
}

// synthesize is restart-only: a reload that turns it on or changes it is
// refused by name (#122).
func TestSynthesizeIsRestartOnly(t *testing.T) {
	run := &config.Config{Mode: config.ModeInject}
	next := &config.Config{Mode: config.ModeInject, Synthesize: &config.Synthesize{Enabled: true}}
	restart, online := classify(run, next)
	if !slices.Contains(restart, "synthesize") || len(online) != 0 {
		t.Fatalf("restart %v online %v", restart, online)
	}
}

// vrpSource is an RPKI source backed by a real VRP table.
type vrpSource struct {
	plugin.Base
	*rpki.VRPs
}

func (vrpSource) Status() plugin.RPKIStatus {
	return plugin.RPKIStatus{Up: true, VRPs: 1, Source: "vrps"}
}

// synthInvalid refuses a sub-range past a ROA's max length for the origin
// it is announced with, and is nil with RPKI off (#122, #200).
func TestSynthInvalidUsesTheROAMaxLength(t *testing.T) {
	if synthInvalid(rpki.NewSet(nil)) != nil {
		t.Fatal("RPKI off still checks")
	}
	sub := netip.MustParsePrefix("198.51.100.0/25")
	for _, tc := range []struct {
		maxLen  uint8
		origin  uint32
		invalid bool
	}{
		{24, 64500, true},  // max length stops short of the /25
		{25, 64500, false}, // the ROA covers the /25
		{25, 64512, true},  // another origin, such as the local AS on an empty path
	} {
		vrps := rpki.NewVRPs()
		vrps.Apply([]rpki.Change{{Prefix: netip.MustParsePrefix("198.51.100.0/24"), MaxLen: tc.maxLen, ASN: 64500}})
		invalid := synthInvalid(rpki.NewSet([]plugin.RPKI{vrpSource{VRPs: vrps}}))
		if got := invalid(sub, tc.origin); got != tc.invalid {
			t.Errorf("max length /%d origin AS%d: invalid = %v, want %v", tc.maxLen, tc.origin, got, tc.invalid)
		}
	}
}
