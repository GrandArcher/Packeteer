package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/offload"
	"github.com/GrandArcher/Packeteer/internal/offload/mikrotik"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/plugins/routercheck/routeros"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// labL3HW is a CCR2216 on RouterOS 7.24.2 that passes every pre-check, with
// documentation addresses.
func labL3HW() routeros.L3HW {
	return routeros.L3HW{
		Version: "7.24.2", Applicable: true,
		Monitor:  routeros.Monitor{State: "ok", IPv4RoutesTotal: 90000, IPv4RoutesHW: 90000, NexthopCap: 8192, NexthopUsage: 93},
		Advanced: &routeros.AdvancedMonitor{ErrorCode: "0", HasLPM: true, LPMCap: 200000, LPMUsage: 60000},
		Settings: routeros.Settings{IPv6HW: true},
		Ports:    []routeros.Port{{Name: "sfp-sfpplus1", L3HW: true}},
		Bridges:  []routeros.Iface{{Name: "bridge1", L3HW: true}},
		DefaultRoutes: []routeros.DefaultRoute{
			{Family: "ipv4", Gateway: "192.0.2.1", Distance: 20, Protocol: "BGP", Active: true, SuppressHWOffload: true},
		},
	}
}

type offloadLab struct {
	oa     *offloadAware
	router *offloadRouter
	src    blastSource
	// route is Packeteer's route for the target on the simulated edge.
	route  func() (nh string, comms map[uint32]bool, ok bool)
	active func() int
	imps   func() int
}

// startOffloadLab runs a controller in mode against a simulated edge that
// learns 203.0.113.0/24 from transit-a, decides one round that prefers
// transit-b, and attaches a dry run with a fake RouterOS reading.
func startOffloadLab(t *testing.T, mode string, l3hw routeros.L3HW) offloadLab {
	t.Helper()
	edge, port := edgeRouter(t)
	ctx := context.Background()
	target := netip.MustParsePrefix("203.0.113.0/24")

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(blastConfig(port, mode, `"203.0.113.0/24"`)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	plugins, err := pluginhost.Build(cfg, pluginhost.Options{Logger: log, Getenv: noEnv})
	if err != nil {
		t.Fatal(err)
	}
	view, err := newRIB(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	ctl, err := newController(cfg, plugins, view, nil, nil, nil, nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	decider, err := newDecider(cfg, plugins)
	if err != nil {
		t.Fatal(err)
	}
	if err := view.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = view.Stop(context.Background()) })
	ctl.RememberSpeaker(view.Server())
	if mode == config.ModeInject {
		if err := ctl.Bind(view.Server()); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, target.String()+" learned", func() bool { _, ok := view.Exact(target); return ok })

	now := time.Now()
	var res []probe.Result
	for prov, rtt := range map[string]time.Duration{"transit-a": 80 * time.Millisecond, "transit-b": 20 * time.Millisecond} {
		res = append(res, probe.Result{Provider: prov, Prefix: target, Time: now, Stats: probe.Stats{Sent: 10, Received: 10, RTTAvg: rtt}})
	}
	in := policy.Input{Results: res, ProviderUp: map[string]bool{"transit-a": true, "transit-b": true},
		RIBEnabled: true, RIBReady: true, Native: map[netip.Prefix]string{target: "transit-a"}}
	if _, err := runDecision(now, decider, in, ctl, log, mode, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ctl.WithdrawAll(ctx) })

	src := blastSource{live: &liveConfig{cfg: cfg}, decider: decider, ctl: ctl, view: view, plugins: plugins, check: candidateChecker(noEnv, "")}
	oa := &offloadAware{recheck: time.Minute, now: time.Now, log: log, wanted: src.offloadWanted, learned: learnedByBGP(view, ctl.Injected),
		volumes: func(source string) map[netip.Prefix]float64 {
			if source == "" {
				return nil
			}
			return map[netip.Prefix]float64{target: 80, netip.MustParsePrefix("192.0.2.0/25"): 20}
		}}
	r, err := oa.addRouter("192.0.2.1", mikrotik.Options{Model: mikrotik.CCR2216, VolumeSource: "lab-sflow"},
		func(context.Context) (routeros.L3HW, error) { return l3hw, nil })
	if err != nil {
		t.Fatal(err)
	}
	oa.routers = []*offloadRouter{r}
	r.refresh(ctx, time.Minute, oa.now, log)

	if mode == config.ModeInject {
		waitFor(t, "route on the edge", func() bool { _, _, ok := packeteerPath(t, edge, target.String()); return ok })
	}
	return offloadLab{oa: oa, router: r, src: src,
		route:  func() (string, map[uint32]bool, bool) { return packeteerPath(t, edge, target.String()) },
		active: ctl.Active, imps: func() int { return len(decider.Improvements()) }}
}

// In every mode the dry run reports the fix and announces nothing: the
// routes on the simulated edge, the active improvements and the decider's
// state are the same before and after.
func TestOffloadDryRunAnnouncesNothingInAnyMode(t *testing.T) {
	for _, mode := range []string{config.ModeObserve, config.ModeSuggest, config.ModeInject} {
		t.Run(mode, func(t *testing.T) {
			lab := startOffloadLab(t, mode, labL3HW())
			oa := lab.oa
			nh0, comms0, ok0 := lab.route()
			active0, imps0 := lab.active(), lab.imps()
			if ok0 != (mode == config.ModeInject) || imps0 != 1 {
				t.Fatalf("setup: route on the edge %v, improvements %d", ok0, imps0)
			}

			rep := oa.Report()
			if len(rep.Routers) != 1 || rep.Run != "dry_run" {
				t.Fatalf("report = %+v", rep)
			}
			r := rep.Routers[0]
			if r.Verdict != offload.VerdictFits || len(r.Fixes) != 1 {
				t.Fatalf("verdict %q fixes %+v", r.Verdict, r.Fixes)
			}
			f := r.Fixes[0]
			if f.Prefix != "203.0.113.0/24" || f.Provider != "transit-b" || f.State != offload.FixOffload || f.VolumeMbps == nil || *f.VolumeMbps != 80 {
				t.Errorf("fix = %+v", f)
			}
			// 80 of 100 Mbps reach a learned route; the rest is connected or IGP.
			if r.Volume.Source != "lab-sflow" || r.Volume.IGPMbps != 20 || r.Volume.BGPMbps != 80 || r.Volume.HardwareShareMin == nil || *r.Volume.HardwareShareMin != 0.2 {
				t.Errorf("volume = %+v", r.Volume)
			}

			oa.at = time.Time{}
			_ = oa.Report()
			nh1, comms1, ok1 := lab.route()
			if ok1 != ok0 || nh1 != nh0 || len(comms1) != len(comms0) || lab.active() != active0 || lab.imps() != imps0 {
				t.Fatalf("the dry run changed the wire or the state: route %v->%v next hop %q->%q active %d->%d improvements %d->%d",
					ok0, ok1, nh0, nh1, active0, lab.active(), imps0, lab.imps())
			}
		})
	}
}

// The dry run wants the fixes the blast-radius preview adds: both decide the
// latest round again under inject.
func TestOffloadWantedMatchesTheBlastPreview(t *testing.T) {
	lab := startOffloadLab(t, config.ModeObserve, labL3HW())
	wanted := lab.oa.wanted()
	prev, err := lab.src.Preview(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(prev.Add) != 1 || len(wanted) != 1 || wanted[0].Prefix != prev.Add[0].Prefix || wanted[0].Provider != prev.Add[0].To || wanted[0].Gain <= 0 {
		t.Fatalf("wanted %+v, preview add %+v", wanted, prev.Add)
	}
}

// A router that cannot be read yields no installs: the report says why and
// every fix is blocked.
func TestOffloadReadFailureBlocksTheFixes(t *testing.T) {
	lab := startOffloadLab(t, config.ModeObserve, labL3HW())
	oa, r := lab.oa, lab.router
	r.read = func(context.Context) (routeros.L3HW, error) {
		return routeros.L3HW{}, errors.New("read /system/resource: connection refused")
	}
	r.mu.Lock()
	r.snap, r.at = nil, time.Time{}
	r.mu.Unlock()
	r.refresh(context.Background(), time.Minute, oa.now, oa.log)
	oa.at = time.Time{}
	got := oa.Report().Routers[0]
	if got.Verdict != offload.VerdictUnavailable || !strings.Contains(got.Error, "connection refused") || got.ReadAt != nil {
		t.Fatalf("report = %+v", got)
	}
	if len(got.Fixes) != 1 || got.Fixes[0].State != offload.FixBlocked {
		t.Errorf("fixes = %+v", got.Fixes)
	}
}

// A config without an offload_aware entry builds nothing, and a disabled
// block builds nothing either.
func TestNoOffloadAwareEntryBuildsNothing(t *testing.T) {
	for _, extra := range []string{"", "offload_aware: {enabled: false}\n"} {
		cfg := mustParse(t, offloadConfig+extra)
		oa, err := newOffloadAware(cfg, blastSource{}, nil, nil, noEnv, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
		if oa != nil || err != nil {
			t.Errorf("%q: %v, %v", extra, oa, err)
		}
	}
}

// An enabled block builds one poller per router, from the config's login;
// a login that is missing its environment variables refuses the start.
func TestNewOffloadAwareFromConfig(t *testing.T) {
	text := offloadConfig + `offload_aware:
  enabled: true
  routers:
    - neighbor: 192.0.2.254
      profile: mikrotik-l3hw-lpm
      reader: routeros
      model: ccr2216
      url: https://192.0.2.253
      username_env: PK_L3HW_USER
      password_env: PK_L3HW_PASSWORD
`
	cfg := mustParse(t, text)
	log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	env := func(k string) string {
		return map[string]string{"PK_L3HW_USER": "pk-reader", "PK_L3HW_PASSWORD": "lab-only"}[k]
	}
	oa, err := newOffloadAware(cfg, blastSource{}, nil, nil, env, log)
	if err != nil || oa == nil || len(oa.routers) != 1 || oa.routers[0].neighbor != "192.0.2.254" || oa.recheck != config.DefaultOffloadRecheck {
		t.Fatalf("oa = %+v, err %v", oa, err)
	}
	if _, err := newOffloadAware(cfg, blastSource{}, nil, nil, noEnv, log); err == nil || !strings.Contains(err.Error(), "PK_L3HW_USER") {
		t.Errorf("no login: %v", err)
	}
}

type plainSrc struct{ plugin.Base }

func (plainSrc) Targets(context.Context) ([]plugin.Target, error) { return nil, nil }

// The named volume source must be a running source that reports per-prefix
// traffic; a source that cannot would freeze the CPU dimension for good.
func TestCheckVolumeSource(t *testing.T) {
	set := &pluginhost.Set{Sources: []pluginhost.Instance[plugin.TargetSource]{
		{Name: "lab-sflow", Type: "sflow", Plugin: &volSrc{}},
		{Name: "lab-static", Type: "static", Plugin: plainSrc{}},
	}}
	if err := checkVolumeSource(set, ""); err != nil {
		t.Errorf("empty: %v", err)
	}
	if err := checkVolumeSource(set, "lab-sflow"); err != nil {
		t.Errorf("volume source: %v", err)
	}
	if err := checkVolumeSource(set, "lab-static"); err == nil || !strings.Contains(err.Error(), "does not report per-prefix traffic") {
		t.Errorf("plain source: %v", err)
	}
	if err := checkVolumeSource(set, "missing"); err == nil || !strings.Contains(err.Error(), "not a running source") {
		t.Errorf("missing: %v", err)
	}
}

// With no volume_source no source is read, so the report cannot show a
// hardware share from sources that never saw hardware traffic.
func TestOffloadWithoutVolumeSourceReadsNoSource(t *testing.T) {
	oa := &offloadAware{recheck: time.Minute, now: time.Now, learned: func(netip.Prefix) bool { return false },
		volumes: func(source string) map[netip.Prefix]float64 {
			t.Errorf("volumes read for source %q", source)
			return map[netip.Prefix]float64{netip.MustParsePrefix("198.51.100.0/24"): 50}
		}}
	r, err := oa.addRouter("192.0.2.1", mikrotik.Options{Model: mikrotik.CCR2216}, nil)
	if err != nil {
		t.Fatal(err)
	}
	vol := oa.evaluate(r, nil, time.Now()).Volume
	if vol.Prefixes != 0 || vol.HardwareShareMin != nil || len(vol.BlindSpots) != 1 || vol.BlindSpots[0].Code != offload.BlindTrafficFlow {
		t.Errorf("volume = %+v", vol)
	}
}
