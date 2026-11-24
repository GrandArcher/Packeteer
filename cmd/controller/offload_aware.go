package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/offload"
	"github.com/GrandArcher/Packeteer/internal/offload/mikrotik"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/plugins/routercheck/routeros"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// offloadReportTTL bounds how often a request or a scrape decides the latest
// round again for the dry run.
const offloadReportTTL = 5 * time.Second

// offloadAware is the offload_aware dry run (#738). It polls each watched
// router with GET requests and reports what the hardware routing budget
// would allow for the fixes inject wants. It announces nothing, installs
// nothing, and writes nothing to a router.
type offloadAware struct {
	routers []*offloadRouter
	recheck time.Duration
	// wanted are the fixes inject would hold under the running config.
	wanted func() []offload.Wanted
	// volumes is the traffic rate per prefix of the named source instance;
	// an empty name reads every source.
	volumes func(source string) map[netip.Prefix]float64
	learned func(netip.Prefix) bool
	now     func() time.Time
	log     *slog.Logger

	mu     sync.Mutex
	report offload.DryRunReport
	at     time.Time
}

// offloadRouter is one watched router and its latest reading.
type offloadRouter struct {
	neighbor string
	opts     mikrotik.Options
	eval     *mikrotik.Evaluator
	read     func(context.Context) (routeros.L3HW, error)

	mu   sync.Mutex
	snap *mikrotik.Snapshot
	at   time.Time
	err  string
}

// newOffloadAware builds the dry run from the config, or nil when
// offload_aware is off. An unusable router login refuses the start.
func newOffloadAware(cfg *config.Config, b blastSource, plugins *pluginhost.Set, view *rib.View, getenv func(string) string, log *slog.Logger) (*offloadAware, error) {
	o := cfg.OffloadAware
	if o == nil || !o.Enabled {
		return nil, nil
	}
	oa := &offloadAware{recheck: o.Recheck, now: time.Now, log: log,
		wanted:  b.offloadWanted,
		volumes: func(source string) map[netip.Prefix]float64 { return volumeRates(plugins, source) },
		learned: learnedByBGP(view, b.ctl.Injected),
	}
	for _, r := range o.Routers {
		rd, err := routeros.Open(mikrotik.RESTConfig(r), plugin.Env{Getenv: getenv})
		if err != nil {
			return nil, fmt.Errorf("offload_aware router %s: %w", r.Neighbor, err)
		}
		if err := checkVolumeSource(plugins, r.VolumeSource); err != nil {
			return nil, fmt.Errorf("offload_aware router %s: %w", r.Neighbor, err)
		}
		opts := mikrotik.OptionsOf(r)
		er, err := oa.addRouter(r.Neighbor, opts, rd.ReadL3HW)
		if err != nil {
			return nil, err
		}
		oa.routers = append(oa.routers, er)
	}
	return oa, nil
}

// checkVolumeSource refuses a volume_source that cannot report per-prefix
// traffic; the CPU dimension would otherwise freeze on every reading.
func checkVolumeSource(plugins *pluginhost.Set, name string) error {
	if name == "" {
		return nil
	}
	for _, src := range plugins.SourcesSnapshot() {
		if src.Name != name {
			continue
		}
		if _, ok := src.Plugin.(plugin.VolumeSource); !ok {
			return fmt.Errorf("volume_source %q (type %s) does not report per-prefix traffic", name, src.Type)
		}
		return nil
	}
	return fmt.Errorf("volume_source %q is not a running source", name)
}

func (oa *offloadAware) addRouter(neighbor string, opts mikrotik.Options, read func(context.Context) (routeros.L3HW, error)) (*offloadRouter, error) {
	ev, err := mikrotik.NewEvaluator(opts, oa.recheck)
	if err != nil {
		return nil, fmt.Errorf("offload_aware router %s: %w", neighbor, err)
	}
	return &offloadRouter{neighbor: neighbor, opts: opts, eval: ev, read: read}, nil
}

// learnedByBGP says whether a BGP route other than a default covers the
// prefix: a learned route, or one Packeteer holds on the wire (the router then
// stops sending the native path it replaced). Without a RIB view every
// destination counts as learned, which only raises the CPU-path upper bound.
func learnedByBGP(view *rib.View, onWire func(netip.Prefix) bool) func(netip.Prefix) bool {
	if view == nil {
		return func(netip.Prefix) bool { return true }
	}
	return func(p netip.Prefix) bool {
		if onWire != nil && onWire(p) {
			return true
		}
		r, ok := view.Covering(p)
		return ok && r.Prefix.Bits() > 0
	}
}

func volumeRates(plugins *pluginhost.Set, source string) map[netip.Prefix]float64 {
	out := map[netip.Prefix]float64{}
	for p, v := range collectVolumeRowsOf(context.Background(), plugins, source) {
		out[p] = v.Mbps()
	}
	return out
}

// Run polls every router now and then each recheck, until ctx ends.
func (oa *offloadAware) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, r := range oa.routers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.poll(ctx, oa.recheck, oa.now, oa.log)
		}()
	}
	wg.Wait()
}

func (r *offloadRouter) poll(ctx context.Context, every time.Duration, now func() time.Time, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		r.refresh(ctx, every, now, log)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// refresh reads the router once. A failed read keeps the last snapshot, which
// then ages until the budget calls it stale.
func (r *offloadRouter) refresh(ctx context.Context, limit time.Duration, now func() time.Time, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	l, err := r.read(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			log.Warn("offload_aware: read failed", "router", r.neighbor, "err", err)
		}
		r.err = err.Error()
		return
	}
	r.snap, r.at, r.err = &mikrotik.Snapshot{L3HW: l}, now(), ""
}

// Report is the dry run as of now, cached for offloadReportTTL.
func (oa *offloadAware) Report() offload.DryRunReport {
	oa.mu.Lock()
	defer oa.mu.Unlock()
	now := oa.now()
	if !oa.at.IsZero() && now.Sub(oa.at) < offloadReportTTL {
		return oa.report
	}
	wanted := oa.wanted()
	rep := offload.DryRunReport{At: now, Run: offload.DryRun.String(), Routers: []offload.RouterReport{}}
	for _, r := range oa.routers {
		rep.Routers = append(rep.Routers, oa.evaluate(r, wanted, now))
	}
	oa.report, oa.at = rep, now
	return rep
}

func (oa *offloadAware) evaluate(r *offloadRouter, wanted []offload.Wanted, now time.Time) offload.RouterReport {
	// Without a named source, summing every source would show traffic that
	// Traffic-Flow cannot see as a hardware share.
	var rates map[netip.Prefix]float64
	if r.opts.VolumeSource != "" {
		rates = oa.volumes(r.opts.VolumeSource)
	}
	vol := offload.BuildVolume(r.opts.VolumeSource, rates, oa.learned)
	r.mu.Lock()
	in := mikrotik.Input{Now: now, Neighbor: r.neighbor, At: r.at, Err: r.err, Volume: vol}
	if r.snap != nil {
		s := *r.snap
		// The CPU path is at most the traffic to learned BGP routes; the
		// bound is only a reading when a volume source reported something.
		s.CPUPathBps, s.CPUPathKnown = uint64(vol.BGPMbps*1e6), r.opts.VolumeSource != "" && vol.Prefixes > 0
		in.Snap = &s
	}
	r.mu.Unlock()
	for _, w := range wanted {
		if mbps, ok := rates[w.Prefix]; ok && r.opts.VolumeSource != "" {
			w.VolumeMbps = mbps
		}
		in.Wanted = append(in.Wanted, w)
	}
	return r.eval.Evaluate(in)
}

// offloadWanted are the fixes inject would hold under the running config:
// Decide on a copy of the live state, then the announcer's own refusals. The
// config is copied; the running mode, the wire and the state are untouched.
func (b blastSource) offloadWanted() []offload.Wanted {
	run := b.live.snapshot()
	if run == nil {
		return nil
	}
	inject := *run
	inject.Mode = config.ModeInject
	pc, err := policy.FromConfig(&inject)
	if err != nil {
		return nil
	}
	what, ok := b.decider.WhatIf(pc, time.Now())
	if !ok {
		return nil
	}
	cands := map[netip.Prefix][]policy.Candidate{}
	for _, d := range what.Output.Decisions {
		cands[d.Prefix] = d.Candidates
	}
	var out []offload.Wanted
	for _, im := range what.State.Improvements {
		if b.refusal(im) != "" {
			continue
		}
		out = append(out, offload.Wanted{
			Candidate: offload.Candidate{Prefix: im.Prefix, Cause: im.Cause, Gain: policy.ImprovementGain(cands[im.Prefix], im), Since: im.Since},
			Provider:  im.Provider,
		})
	}
	return out
}
