package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/inbound"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/verify"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var (
	verifyPrefix = netip.MustParsePrefix("198.51.100.0/24")
	verifyOwn    = netip.MustParsePrefix("203.0.113.0/24")
	verifyT0     = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
)

// rateTelemetry is a telemetry plugin whose rows the test sets.
type rateTelemetry struct {
	plugin.Base
	mu   sync.Mutex
	rows []plugin.Usage
}

func (r *rateTelemetry) set(at time.Time, in, out map[string]float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows = nil
	for _, name := range []string{"transit-a", "transit-b"} {
		r.rows = append(r.rows, plugin.Usage{Provider: name, CommitMbps: 100, Samples: 10, InMbps: in[name], InMbps95: in[name],
			OutMbps: out[name], Updated: at})
	}
}

func (r *rateTelemetry) Snapshot(context.Context) ([]plugin.Usage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]plugin.Usage(nil), r.rows...), nil
}

type steerAnnouncer struct {
	plugin.Base
	mu     sync.Mutex
	routes map[netip.Prefix]bool
	fail   bool
}

func (a *steerAnnouncer) Action(p string) (plugin.InboundAction, bool) {
	return plugin.InboundAction{Provider: p, Prepend: 2, Communities: []string{"64512:1102"}}, true
}

func (a *steerAnnouncer) Announce(_ context.Context, r plugin.InboundRoute) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return errors.New("announce refused")
	}
	a.routes[r.Prefix] = true
	return nil
}

func (a *steerAnnouncer) Withdraw(_ context.Context, p netip.Prefix) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.routes, p)
	return nil
}

func (a *steerAnnouncer) WithdrawAll(context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.routes = map[netip.Prefix]bool{}
	return nil
}

func (a *steerAnnouncer) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.routes)
}

type verifyRIB struct{ down bool }

func (r *verifyRIB) Ready() bool { return !r.down }
func (*verifyRIB) NextHop(netip.Prefix) (netip.Addr, bool) {
	return netip.MustParseAddr("192.0.2.1"), true
}

type verifyRig struct {
	v   *steerVerifier
	tel *rateTelemetry
	dec *policy.Engine
	inb *inbound.Controller
	ann *steerAnnouncer
	rib *verifyRIB
	inj map[netip.Prefix]bool
}

func newVerifyRig(t *testing.T, vc verify.Config) *verifyRig {
	t.Helper()
	sc, err := weighted.New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	dec := policy.NewEngine(policy.Config{Mode: config.ModeObserve, MinLossDeltaPct: 1, MinRTTDelta: 15 * time.Millisecond,
		HoldTime: 15 * time.Minute, MaxImprovements: 50, MaxResultAge: 2 * time.Minute}, sc)
	ann := &steerAnnouncer{routes: map[netip.Prefix]bool{}}
	rib := &verifyRIB{}
	inb, err := inbound.New(inbound.Config{
		Mode: config.ModeInject, Prefixes: []netip.Prefix{verifyOwn}, Allowlist: []netip.Prefix{verifyOwn},
		Community: "64512:666", LocalPref: 1, MaxImprovements: 50, SharedCap: 50, HoldTime: time.Minute, TTL: time.Hour,
		ReleasePct: 90, MaxAge: time.Hour, Providers: []string{"transit-a", "transit-b", "transit-c"},
	}, ann, rib, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	tel := &rateTelemetry{}
	vc.Enabled = true
	cfg := &config.Config{Verify: vc}
	set := &pluginhost.Set{Telemetry: []pluginhost.Instance[plugin.Telemetry]{{Name: "rates", Plugin: tel}}}
	return &verifyRig{v: newSteerVerifier(cfg, dec, inb, set, slog.New(slog.NewTextHandler(io.Discard, nil))),
		tel: tel, dec: dec, inb: inb, ann: ann, rib: rib, inj: map[netip.Prefix]bool{verifyPrefix: true}}
}

func (r *verifyRig) injected(p netip.Prefix) bool { return r.inj[p] }

func (r *verifyRig) improve(t *testing.T, now time.Time, mbps float64) []policy.Change {
	t.Helper()
	return r.improveWith(t, now, mbps, mbps)
}

// improveWith is improve with the volume the decision input carries
// (inputMbps) apart from the one the change must come out with (wantMbps):
// under the weighted scorer the input carries none.
func (r *verifyRig) improveWith(t *testing.T, now time.Time, inputMbps, wantMbps float64) []policy.Change {
	t.Helper()
	res := func(provider string, loss, rtt float64) probe.Result {
		return probe.Result{Provider: provider, Prefix: verifyPrefix, Time: now, Stats: probe.Stats{Sent: 10, Received: 10, LossPct: loss, RTTAvg: time.Duration(rtt * float64(time.Millisecond))}}
	}
	in := policy.Input{Results: []probe.Result{res("transit-a", 0, 90), res("transit-b", 0, 30)}, ProviderUp: map[string]bool{"transit-a": true, "transit-b": true},
		RIBEnabled: true, RIBReady: true, Native: map[netip.Prefix]string{verifyPrefix: "transit-a"}, VolumeMbps: map[netip.Prefix]float64{verifyPrefix: inputMbps}}
	ch := r.dec.Evaluate(in, now)
	if len(ch) != 1 || ch[0].Action != policy.ActionImprove || ch[0].New.VolumeMbps != wantMbps {
		t.Fatalf("improve: %+v", ch)
	}
	return ch
}

func (r *verifyRig) steerInbound(t *testing.T, now time.Time) []inbound.Change {
	t.Helper()
	ch := r.decideInbound(t, now)
	if err := r.inb.Sync(context.Background()); err != nil || r.ann.count() != 1 {
		t.Fatalf("announce: %v routes=%d", err, r.ann.count())
	}
	return ch
}

// decideInbound is steerInbound without the sync: the steer is decided but
// the route is not announced.
func (r *verifyRig) decideInbound(t *testing.T, now time.Time) []inbound.Change {
	t.Helper()
	ch := r.inb.Plan(now, inbound.Input{Usage: []plugin.Usage{
		{Provider: "transit-a", CommitMbps: 100, Samples: 10, InMbps95: 150, Updated: now},
		{Provider: "transit-b", CommitMbps: 100, Samples: 10, InMbps95: 30, Updated: now}}})
	if len(ch) != 1 || ch[0].Action != inbound.ActionSteer {
		t.Fatalf("steer: %+v", ch)
	}
	return ch
}

func TestVerifyOutboundVerifiedLeavesTheImprovement(t *testing.T) {
	r := newVerifyRig(t, verify.Config{Backout: []string{"outbound"}})
	r.tel.set(verifyT0, nil, map[string]float64{"transit-a": 100, "transit-b": 10})
	r.v.begin(context.Background(), verifyT0, r.injected, config.ModeInject, r.improve(t, verifyT0, 40), nil, nil)
	if l := r.v.results(); len(l) != 1 || l[0].Status != verify.Pending || l[0].From != "transit-a" || l[0].ExpectedMbps != 40 {
		t.Fatalf("pending = %+v", l)
	}
	at := verifyT0.Add(verify.DefaultOutboundWindow)
	r.tel.set(at, nil, map[string]float64{"transit-a": 62, "transit-b": 48})
	done, pol, in := r.v.check(context.Background(), at, r.injected, nil)
	if len(done) != 1 || done[0].Status != verify.Verified || len(pol) != 0 || len(in) != 0 || len(r.dec.Improvements()) != 1 {
		t.Fatalf("done %+v pol %+v in %+v improvements %+v", done, pol, in, r.dec.Improvements())
	}
}

func TestVerifyOutboundNotMovedBacksOutOnlyWhenConfigured(t *testing.T) {
	for _, tc := range []struct {
		name    string
		backout []string
		gone    bool
	}{{"default warns only", nil, false}, {"outbound listed", []string{"outbound"}, true}} {
		t.Run(tc.name, func(t *testing.T) {
			r := newVerifyRig(t, verify.Config{Backout: tc.backout})
			r.tel.set(verifyT0, nil, map[string]float64{"transit-a": 100, "transit-b": 10})
			r.v.begin(context.Background(), verifyT0, r.injected, config.ModeInject, r.improve(t, verifyT0, 40), nil, nil)
			at := verifyT0.Add(verify.DefaultOutboundWindow)
			r.tel.set(at, nil, map[string]float64{"transit-a": 100, "transit-b": 10})
			done, pol, _ := r.v.check(context.Background(), at, r.injected, nil)
			if len(done) != 1 || done[0].Status != verify.NotMoved || done[0].BackedOut != tc.gone {
				t.Fatalf("done %+v", done)
			}
			if tc.gone {
				if len(pol) != 1 || pol[0].Action != policy.ActionRetire || pol[0].Old.Prefix != verifyPrefix || len(r.dec.Improvements()) != 0 {
					t.Fatalf("pol %+v improvements %+v", pol, r.dec.Improvements())
				}
			} else if len(pol) != 0 || len(r.dec.Improvements()) != 1 {
				t.Fatalf("a warning-only steer was undone: pol %+v improvements %+v", pol, r.dec.Improvements())
			}
		})
	}
}

func TestVerifySkipsWhatWasNotAnnounced(t *testing.T) {
	r := newVerifyRig(t, verify.Config{})
	r.tel.set(verifyT0, map[string]float64{"transit-a": 150, "transit-b": 30}, map[string]float64{"transit-a": 100, "transit-b": 10})
	changes := r.improve(t, verifyT0, 40)
	r.inj[verifyPrefix] = false
	inCh := r.steerInbound(t, verifyT0)
	// Observe mode and a moderated steer announce nothing.
	r.v.begin(context.Background(), verifyT0, r.injected, config.ModeInject, changes, nil, nil)
	r.v.begin(context.Background(), verifyT0, r.injected, config.ModeSuggest, nil, inCh, nil)
	inCh[0].Steer.Moderated = true
	r.v.begin(context.Background(), verifyT0, r.injected, config.ModeInject, nil, inCh, nil)
	if l := r.v.results(); len(l) != 0 {
		t.Fatalf("verifying steers that announced nothing: %+v", l)
	}
	// A release ends an open check.
	inCh[0].Steer.Moderated = false
	r.v.begin(context.Background(), verifyT0, r.injected, config.ModeInject, nil, inCh, nil)
	if l := r.v.results(); len(l) != 1 {
		t.Fatalf("results = %+v", l)
	}
	inCh[0].Action = inbound.ActionRelease
	r.v.begin(context.Background(), verifyT0, r.injected, config.ModeInject, nil, inCh, nil)
	if l := r.v.results(); len(l) != 0 {
		t.Fatalf("a released steer is still being verified: %+v", l)
	}
}

func TestVerifyInboundVerifiedKeepsTheSteer(t *testing.T) {
	r := newVerifyRig(t, verify.Config{})
	r.tel.set(verifyT0, map[string]float64{"transit-a": 150, "transit-b": 30}, nil)
	r.v.begin(context.Background(), verifyT0, r.injected, config.ModeInject, nil, r.steerInbound(t, verifyT0), nil)
	at := verifyT0.Add(verify.DefaultInboundWindow)
	r.tel.set(at, map[string]float64{"transit-a": 40, "transit-b": 140}, nil)
	done, _, in := r.v.check(context.Background(), at, r.injected, nil)
	if len(done) != 1 || done[0].Status != verify.Verified || len(in) != 0 || r.ann.count() != 1 || len(r.inb.Status().Steers) != 1 {
		t.Fatalf("done %+v in %+v routes %d", done, in, r.ann.count())
	}
}

// The steer is decided while the RIB is not ready, so it is announced rounds
// later with no new change. The window must start when the route goes out:
// the traffic that moved after that is what is judged.
func TestVerifyInboundStartsWhenTheRouteGoesOut(t *testing.T) {
	r := newVerifyRig(t, verify.Config{})
	ctx := context.Background()
	r.rib.down = true
	r.tel.set(verifyT0, map[string]float64{"transit-a": 40, "transit-b": 140}, nil)
	inCh := r.decideInbound(t, verifyT0)
	_ = r.inb.Sync(ctx)
	r.v.begin(ctx, verifyT0, r.injected, config.ModeInject, nil, inCh, nil)
	if l := r.v.results(); len(l) != 0 {
		t.Fatalf("verifying a steer that is not on the wire: %+v", l)
	}
	if done, _, _ := r.v.check(ctx, verifyT0.Add(time.Second), r.injected, nil); len(done) != 0 {
		t.Fatalf("done = %+v", done)
	}

	out := verifyT0.Add(5 * time.Second)
	r.rib.down = false
	if err := r.inb.Sync(ctx); err != nil || r.ann.count() != 1 {
		t.Fatalf("announce: %v routes=%d", err, r.ann.count())
	}
	r.tel.set(out, map[string]float64{"transit-a": 150, "transit-b": 30}, nil)
	r.v.begin(ctx, out, r.injected, config.ModeInject, nil, nil, nil)
	l := r.v.results()
	if len(l) != 1 || l[0].Status != verify.Pending || !l[0].Started.Equal(out) {
		t.Fatalf("results = %+v", l)
	}

	at := out.Add(verify.DefaultInboundWindow)
	r.tel.set(at, map[string]float64{"transit-a": 40, "transit-b": 140}, nil)
	done, _, in := r.v.check(ctx, at, r.injected, nil)
	if len(done) != 1 || done[0].Status != verify.Verified || len(in) != 0 {
		t.Fatalf("done %+v in %+v", done, in)
	}
}

// A second steer whose announce failed leaves the first route on the wire:
// that route steers away from the first provider only, so the second one is
// not verified until a route that steers away from it goes out.
func TestVerifyInboundNeedsARouteAwayFromTheProvider(t *testing.T) {
	r := newVerifyRig(t, verify.Config{})
	ctx := context.Background()
	r.tel.set(verifyT0, map[string]float64{"transit-a": 150, "transit-b": 30}, nil)
	r.v.begin(ctx, verifyT0, r.injected, config.ModeInject, nil, r.steerInbound(t, verifyT0), nil)

	later := verifyT0.Add(time.Minute)
	r.ann.fail = true
	ch := r.inb.Plan(later, inbound.Input{Usage: []plugin.Usage{
		{Provider: "transit-a", CommitMbps: 100, Samples: 10, InMbps95: 150, Updated: later},
		{Provider: "transit-b", CommitMbps: 100, Samples: 10, InMbps95: 150, Updated: later},
		{Provider: "transit-c", CommitMbps: 100, Samples: 10, InMbps95: 30, Updated: later}}})
	if len(ch) != 1 || ch[0].Action != inbound.ActionSteer || ch[0].Steer.Provider != "transit-b" {
		t.Fatalf("second steer: %+v", ch)
	}
	if err := r.inb.Sync(ctx); err == nil {
		t.Fatal("the refused announce must fail the sync")
	}
	r.v.begin(ctx, later, r.injected, config.ModeInject, nil, ch, nil)
	if l := r.v.results(); len(l) != 1 || l[0].Provider != "transit-a" {
		t.Fatalf("verifying a steer that is not on the wire: %+v", l)
	}

	out := later.Add(2 * time.Second)
	r.ann.fail = false
	if err := r.inb.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	r.v.begin(ctx, out, r.injected, config.ModeInject, nil, nil, nil)
	l := r.v.results()
	if len(l) != 2 || l[0].Provider != "transit-a" || l[1].Provider != "transit-b" || !l[1].Started.Equal(out) {
		t.Fatalf("results = %+v", l)
	}
}

// A RIB flap withdraws the route and drops the open check; the route goes
// out again with no new change, and the window starts over from then.
func TestVerifyInboundRestartsAfterARIBFlap(t *testing.T) {
	r := newVerifyRig(t, verify.Config{})
	ctx := context.Background()
	r.tel.set(verifyT0, map[string]float64{"transit-a": 150, "transit-b": 30}, nil)
	r.v.begin(ctx, verifyT0, r.injected, config.ModeInject, nil, r.steerInbound(t, verifyT0), nil)

	r.rib.down = true
	_ = r.inb.Sync(ctx)
	down := verifyT0.Add(time.Minute)
	if done, _, _ := r.v.check(ctx, down, r.injected, nil); len(done) != 0 || len(r.v.results()) != 0 {
		t.Fatalf("a withdrawn steer is still verified: %+v", r.v.results())
	}

	up := down.Add(5 * time.Second)
	r.rib.down = false
	if err := r.inb.Sync(ctx); err != nil || r.ann.count() != 1 {
		t.Fatalf("announce: %v routes=%d", err, r.ann.count())
	}
	r.tel.set(up, map[string]float64{"transit-a": 150, "transit-b": 30}, nil)
	r.v.begin(ctx, up, r.injected, config.ModeInject, nil, nil, nil)
	if l := r.v.results(); len(l) != 1 || l[0].Status != verify.Pending || !l[0].Started.Equal(up) {
		t.Fatalf("results = %+v", l)
	}
}

// A steer that is released before its route went out is never verified.
func TestVerifyInboundAwaitingEndsWithTheSteer(t *testing.T) {
	r := newVerifyRig(t, verify.Config{})
	ctx := context.Background()
	r.rib.down = true
	r.tel.set(verifyT0, map[string]float64{"transit-a": 150, "transit-b": 30}, nil)
	inCh := r.decideInbound(t, verifyT0)
	r.v.begin(ctx, verifyT0, r.injected, config.ModeInject, nil, inCh, nil)
	inCh[0].Action = inbound.ActionRelease
	r.v.begin(ctx, verifyT0, r.injected, config.ModeInject, nil, inCh, nil)
	r.rib.down = false
	if err := r.inb.Sync(ctx); err != nil || r.ann.count() != 1 {
		t.Fatalf("announce: %v routes=%d", err, r.ann.count())
	}
	r.v.begin(ctx, verifyT0, r.injected, config.ModeInject, nil, nil, nil)
	if l := r.v.results(); len(l) != 0 || len(r.v.awaiting) != 0 {
		t.Fatalf("results %+v awaiting %v", l, r.v.awaiting)
	}
}

func TestVerifyInboundNotMovedRevertsAndWithdraws(t *testing.T) {
	r := newVerifyRig(t, verify.Config{})
	r.tel.set(verifyT0, map[string]float64{"transit-a": 150, "transit-b": 30}, nil)
	r.v.begin(context.Background(), verifyT0, r.injected, config.ModeInject, nil, r.steerInbound(t, verifyT0), nil)
	at := verifyT0.Add(verify.DefaultInboundWindow)
	r.tel.set(at, map[string]float64{"transit-a": 150, "transit-b": 30}, nil)
	done, _, in := r.v.check(context.Background(), at, r.injected, nil)
	if len(done) != 1 || done[0].Status != verify.NotMoved || !done[0].BackedOut || len(in) != 1 || in[0].Action != inbound.ActionRelease {
		t.Fatalf("done %+v in %+v", done, in)
	}
	if err := r.inb.Sync(context.Background()); err != nil || r.ann.count() != 0 {
		t.Fatalf("the reverted steer is still announced: %v routes=%d", err, r.ann.count())
	}
	// The trigger is still on; the steer waits out the back-off.
	next := at.Add(10 * time.Minute)
	if ch := r.inb.Plan(next, inbound.Input{Usage: []plugin.Usage{{Provider: "transit-a", CommitMbps: 100, Samples: 10, InMbps95: 150, Updated: next}}}); len(ch) != 0 {
		t.Fatalf("steered again inside the back-off: %+v", ch)
	}
	if l := r.v.results(); len(l) != 1 || l[0].Status != verify.NotMoved || !l[0].BackedOut {
		t.Fatalf("result must stay listed after the back-out: %+v", l)
	}
}

func TestVerifyOffIsNil(t *testing.T) {
	cfg := &config.Config{}
	if v := newSteerVerifier(cfg, nil, nil, nil, slog.Default()); v != nil {
		t.Fatalf("verify off built a verifier: %+v", v)
	}
	var v *steerVerifier
	v.begin(context.Background(), verifyT0, nil, "", nil, nil, nil)
	v.reset()
	if done, pol, in := v.check(context.Background(), verifyT0, nil, nil); done != nil || pol != nil || in != nil || v.results() != nil {
		t.Fatal("a nil verifier did something")
	}
}

func TestVerifyDegradedUsesThePerformanceThresholds(t *testing.T) {
	r := newVerifyRig(t, verify.Config{})
	if !r.v.degraded(verify.Path{LossPct: 0, RTTMs: 30}, verify.Path{LossPct: 5, RTTMs: 30}) {
		t.Fatal("5 points more loss is past min_loss_delta_pct 1")
	}
	if !r.v.degraded(verify.Path{LossPct: 0, RTTMs: 30}, verify.Path{LossPct: 0, RTTMs: 80}) {
		t.Fatal("50 ms more RTT is past min_rtt_delta_ms 15")
	}
	if r.v.degraded(verify.Path{LossPct: 0, RTTMs: 30}, verify.Path{LossPct: 0, RTTMs: 35}) {
		t.Fatal("5 ms more RTT is inside the threshold")
	}
}

// volumeSource reports a fixed volume, as the static source does with mbps.
type volumeSource struct {
	plugin.Base
	mbps float64
}

func (volumeSource) Targets(context.Context) ([]plugin.Target, error) { return nil, nil }

func (v volumeSource) Volumes(context.Context) ([]plugin.PrefixVolume, error) {
	return []plugin.PrefixVolume{{Prefix: verifyPrefix, Bytes: uint64(v.mbps * 1e6 / 8), Window: time.Second}}, nil
}

func TestVerifyReadsTheFlowVolumeWhenTheImprovementHasNone(t *testing.T) {
	r := newVerifyRig(t, verify.Config{})
	r.v.plugins.Sources = []pluginhost.Instance[plugin.TargetSource]{{Name: "volumes", Plugin: volumeSource{mbps: 40}}}
	r.tel.set(verifyT0, nil, map[string]float64{"transit-a": 100, "transit-b": 10})
	// The weighted scorer plans nothing by volume, so the change carries none.
	changes := r.improveWith(t, verifyT0, 0, 0)
	r.v.begin(context.Background(), verifyT0, r.injected, config.ModeInject, changes, nil, nil)
	if l := r.v.results(); len(l) != 1 || l[0].ExpectedMbps != 40 {
		t.Fatalf("results = %+v, want 40 Mbps expected from the volume source", l)
	}
	at := verifyT0.Add(verify.DefaultOutboundWindow)
	r.tel.set(at, nil, map[string]float64{"transit-a": 62, "transit-b": 48})
	if done, _, _ := r.v.check(context.Background(), at, r.injected, nil); len(done) != 1 || done[0].Status != verify.Verified {
		t.Fatalf("done = %+v", done)
	}
}

func TestVerifyDropsSteersThatLeftTheWire(t *testing.T) {
	r := newVerifyRig(t, verify.Config{Backout: []string{"inbound", "outbound"}})
	r.tel.set(verifyT0, map[string]float64{"transit-a": 150, "transit-b": 30}, map[string]float64{"transit-a": 100, "transit-b": 10})
	r.v.begin(context.Background(), verifyT0, r.injected, config.ModeInject, r.improve(t, verifyT0, 40), r.steerInbound(t, verifyT0), nil)
	if l := r.v.results(); len(l) != 2 {
		t.Fatalf("results = %+v", l)
	}
	// A mode change or a failed sync took both routes off the wire while the
	// controllers still hold the steers. Unchanged usage must not read as
	// a steer that moved nothing, and must not back anything out.
	r.inj[verifyPrefix] = false
	if err := r.inb.WithdrawAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	at := verifyT0.Add(verify.DefaultInboundWindow)
	r.tel.set(at, map[string]float64{"transit-a": 150, "transit-b": 30}, map[string]float64{"transit-a": 100, "transit-b": 10})
	done, pol, in := r.v.check(context.Background(), at, r.injected, nil)
	if len(done) != 0 || len(pol) != 0 || len(in) != 0 || len(r.v.results()) != 0 {
		t.Fatalf("judged steers that were not announced: done %+v pol %+v in %+v results %+v", done, pol, in, r.v.results())
	}
	if len(r.dec.Improvements()) != 1 || len(r.inb.Status().Steers) != 1 {
		t.Fatal("verification touched steers it did not judge")
	}
}
