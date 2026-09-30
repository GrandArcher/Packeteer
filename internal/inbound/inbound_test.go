package inbound

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var (
	own   = netip.MustParsePrefix("203.0.113.0/24")
	own2  = netip.MustParsePrefix("198.51.100.0/24")
	nh    = netip.MustParseAddr("192.0.2.1")
	start = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
)

type fakeAnn struct {
	plugin.Base
	actions map[string]plugin.InboundAction
	routes  map[netip.Prefix]plugin.InboundRoute
	calls   int
	fail    error
}

func newFakeAnn(providers ...string) *fakeAnn {
	a := &fakeAnn{actions: map[string]plugin.InboundAction{}, routes: map[netip.Prefix]plugin.InboundRoute{}}
	for _, p := range providers {
		a.actions[p] = plugin.InboundAction{Provider: p, Prepend: 2, Communities: []string{"64512:1102"}}
	}
	return a
}

func (a *fakeAnn) Action(p string) (plugin.InboundAction, bool) {
	act, ok := a.actions[p]
	return act, ok
}

func (a *fakeAnn) Announce(_ context.Context, r plugin.InboundRoute) error {
	a.calls++
	if a.fail != nil {
		return a.fail
	}
	a.routes[r.Prefix] = r
	return nil
}

func (a *fakeAnn) Withdraw(_ context.Context, p netip.Prefix) error {
	a.calls++
	delete(a.routes, p)
	return nil
}

func (a *fakeAnn) WithdrawAll(context.Context) error {
	a.calls++
	a.routes = map[netip.Prefix]plugin.InboundRoute{}
	return nil
}

type fakeRIB struct {
	ready  bool
	routes map[netip.Prefix]netip.Addr
}

func (r *fakeRIB) Ready() bool { return r.ready }

func (r *fakeRIB) NextHop(p netip.Prefix) (netip.Addr, bool) {
	a, ok := r.routes[p]
	return a, ok
}

func baseConfig(mode string) Config {
	return Config{
		Mode: mode, Prefixes: []netip.Prefix{own}, Allowlist: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), own2},
		Community: "64512:666", LocalPref: 1, MaxImprovements: 50, SharedCap: 50,
		HoldTime: 5 * time.Minute, TTL: time.Hour, ReleasePct: 90, MaxAge: 5 * time.Minute,
		Providers: []string{"transit-a", "transit-b"},
	}
}

func usage(now time.Time, rows map[string]float64) []plugin.Usage {
	var out []plugin.Usage
	for p, in := range rows {
		out = append(out, plugin.Usage{Provider: p, CommitMbps: 100, Samples: 10, InMbps95: in, OutMbps95: 10, Updated: now})
	}
	return out
}

func mustNew(t *testing.T, cfg Config, ann plugin.InboundAnnouncer, rib RIB) *Controller {
	t.Helper()
	c, err := New(cfg, ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func readyRIB() *fakeRIB {
	return &fakeRIB{ready: true, routes: map[netip.Prefix]netip.Addr{own: nh, own2: nh}}
}

func TestNewRequiresInjectSafety(t *testing.T) {
	rib := readyRIB()
	ann := newFakeAnn("transit-a")
	for name, mut := range map[string]func(*Config){
		"community":  func(c *Config) { c.Community = "" },
		"local_pref": func(c *Config) { c.LocalPref = 0 },
		"cap":        func(c *Config) { c.MaxImprovements = 0 },
		"allowlist":  func(c *Config) { c.Allowlist = nil },
	} {
		cfg := baseConfig(config.ModeInject)
		mut(&cfg)
		if _, err := New(cfg, ann, rib, nil); err == nil {
			t.Errorf("%s: inject accepted", name)
		}
	}
	if _, err := New(baseConfig(config.ModeInject), nil, rib, nil); err == nil {
		t.Error("inject without announcer accepted")
	}
	if _, err := New(baseConfig(config.ModeObserve), nil, nil, nil); err != nil {
		t.Errorf("observe without announcer: %v", err)
	}
}

func TestObserveAndSuggestNeverAnnounce(t *testing.T) {
	for _, mode := range []string{config.ModeObserve, config.ModeSuggest} {
		ann := newFakeAnn("transit-a", "transit-b")
		c := mustNew(t, baseConfig(mode), ann, readyRIB())
		ch := c.Evaluate(start, usage(start, map[string]float64{"transit-a": 150, "transit-b": 20}))
		if len(ch) != 1 || ch[0].Action != ActionSteer || ch[0].Steer.Provider != "transit-a" {
			t.Fatalf("%s: changes = %+v", mode, ch)
		}
		if err := c.Sync(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := c.WithdrawAll(context.Background()); err != nil {
			t.Fatal(err)
		}
		if ann.calls != 0 || c.Active() != 0 {
			t.Fatalf("%s: announcer called %d times", mode, ann.calls)
		}
		st := c.Status()
		if st.Mode != mode || len(st.Steers) != 1 || len(st.Announced) != 0 {
			t.Fatalf("%s: status = %+v", mode, st)
		}
	}
	// No announcer in observe: the plan still names the provider.
	c := mustNew(t, baseConfig(config.ModeObserve), nil, nil)
	if ch := c.Evaluate(start, usage(start, map[string]float64{"transit-a": 150})); len(ch) != 1 {
		t.Fatalf("observe without catalog: %+v", ch)
	}
}

func TestInjectSteerHoldReleaseCooldown(t *testing.T) {
	ctx := context.Background()
	ann := newFakeAnn("transit-a", "transit-b")
	c := mustNew(t, baseConfig(config.ModeInject), ann, readyRIB())

	// Under commit: nothing.
	if ch := c.Evaluate(start, usage(start, map[string]float64{"transit-a": 99, "transit-b": 20})); len(ch) != 0 {
		t.Fatalf("under commit: %+v", ch)
	}
	if err := c.Sync(ctx); err != nil || len(ann.routes) != 0 {
		t.Fatalf("sync: %v %v", err, ann.routes)
	}

	now := start.Add(time.Minute)
	ch := c.Evaluate(now, usage(now, map[string]float64{"transit-a": 150, "transit-b": 20}))
	if len(ch) != 1 || ch[0].Steer.Action.Prepend != 2 {
		t.Fatalf("steer: %+v", ch)
	}
	if err := c.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	r, ok := ann.routes[own]
	if !ok || r.NextHop != nh || r.LocalPref != 1 || r.Community != "64512:666" || !slices.Equal(r.Away, []string{"transit-a"}) {
		t.Fatalf("route = %+v %v", r, ok)
	}
	if c.Active() != 1 {
		t.Fatalf("active = %d", c.Active())
	}
	calls := ann.calls
	if err := c.Sync(ctx); err != nil || ann.calls != calls {
		t.Fatalf("idempotent sync re-announced (%v)", err)
	}

	// Under the release threshold but inside hold_time: kept.
	now = now.Add(time.Minute)
	if ch := c.Evaluate(now, usage(now, map[string]float64{"transit-a": 50, "transit-b": 20})); len(ch) != 0 {
		t.Fatalf("released inside hold_time: %+v", ch)
	}
	// Above release_pct (90) after hold: kept.
	now = start.Add(10 * time.Minute)
	if ch := c.Evaluate(now, usage(now, map[string]float64{"transit-a": 95, "transit-b": 20})); len(ch) != 0 {
		t.Fatalf("released above release_pct: %+v", ch)
	}
	// At or below 90% after hold: released and withdrawn.
	ch = c.Evaluate(now, usage(now, map[string]float64{"transit-a": 90, "transit-b": 20}))
	if len(ch) != 1 || ch[0].Action != ActionRelease {
		t.Fatalf("release: %+v", ch)
	}
	if err := c.Sync(ctx); err != nil || len(ann.routes) != 0 || c.Active() != 0 {
		t.Fatalf("withdraw after release: %v %v", err, ann.routes)
	}

	// Over again inside the cooldown: blocked, then steered after it.
	now = now.Add(time.Minute)
	if ch := c.Evaluate(now, usage(now, map[string]float64{"transit-a": 150, "transit-b": 20})); len(ch) != 0 {
		t.Fatalf("re-steered inside cooldown: %+v", ch)
	}
	if st := c.Status(); len(st.Blocked) != 1 || !strings.Contains(st.Blocked[0].Reason, "hold_time") {
		t.Fatalf("blocked = %+v", st.Blocked)
	}
	now = now.Add(5 * time.Minute)
	if ch := c.Evaluate(now, usage(now, map[string]float64{"transit-a": 150, "transit-b": 20})); len(ch) != 1 {
		t.Fatalf("not re-steered after cooldown: %+v", ch)
	}
}

func TestStaleTelemetryReleasesAtOnce(t *testing.T) {
	ctx := context.Background()
	for name, rows := range map[string]func(time.Time) []plugin.Usage{
		"missing": func(time.Time) []plugin.Usage { return nil },
		"old": func(now time.Time) []plugin.Usage {
			return usage(now.Add(-time.Hour), map[string]float64{"transit-a": 150})
		},
		"error": func(now time.Time) []plugin.Usage {
			u := usage(now, map[string]float64{"transit-a": 150})
			u[0].Error = "timeout"
			return u
		},
	} {
		ann := newFakeAnn("transit-a", "transit-b")
		c := mustNew(t, baseConfig(config.ModeInject), ann, readyRIB())
		c.Evaluate(start, usage(start, map[string]float64{"transit-a": 150}))
		if err := c.Sync(ctx); err != nil || len(ann.routes) != 1 {
			t.Fatalf("%s: steer: %v", name, err)
		}
		now := start.Add(time.Second) // inside hold_time
		ch := c.Evaluate(now, rows(now))
		if len(ch) != 1 || ch[0].Action != ActionRelease || !strings.Contains(ch[0].Reason, "stale") {
			t.Fatalf("%s: changes = %+v", name, ch)
		}
		if err := c.Sync(ctx); err != nil || len(ann.routes) != 0 {
			t.Fatalf("%s: not withdrawn: %v", name, err)
		}
	}
}

func TestNeverSteersAwayFromEveryProvider(t *testing.T) {
	ann := newFakeAnn("transit-a", "transit-b")
	c := mustNew(t, baseConfig(config.ModeInject), ann, readyRIB())
	ch := c.Evaluate(start, usage(start, map[string]float64{"transit-a": 150, "transit-b": 200}))
	if len(ch) != 1 || ch[0].Steer.Provider != "transit-b" {
		t.Fatalf("changes = %+v (want only the worst provider)", ch)
	}
	st := c.Status()
	if len(st.Blocked) != 1 || st.Blocked[0].Provider != "transit-a" || !strings.Contains(st.Blocked[0].Reason, "every provider") {
		t.Fatalf("blocked = %+v", st.Blocked)
	}
}

func TestProviderWithoutCatalogActionIsNotSteered(t *testing.T) {
	ann := newFakeAnn("transit-b")
	cfg := baseConfig(config.ModeInject)
	cfg.Providers = append(cfg.Providers, "transit-c")
	c := mustNew(t, cfg, ann, readyRIB())
	if ch := c.Evaluate(start, usage(start, map[string]float64{"transit-a": 150})); len(ch) != 0 {
		t.Fatalf("changes = %+v", ch)
	}
	// Unknown providers in telemetry are ignored.
	if ch := c.Evaluate(start, usage(start, map[string]float64{"transit-z": 500})); len(ch) != 0 {
		t.Fatalf("unknown provider: %+v", ch)
	}
}

func TestRIBAllowlistAndCaps(t *testing.T) {
	ctx := context.Background()
	ann := newFakeAnn("transit-a", "transit-b")
	rib := readyRIB()
	delete(rib.routes, own)
	cfg := baseConfig(config.ModeInject)
	cfg.Prefixes = []netip.Prefix{own, own2, netip.MustParsePrefix("192.0.2.0/24")}
	cfg.MaxImprovements = 1
	c := mustNew(t, cfg, ann, rib)
	c.Evaluate(start, usage(start, map[string]float64{"transit-a": 150}))
	err := c.Sync(ctx)
	if err == nil || !strings.Contains(err.Error(), "203.0.113.0/24 is not in the RIB") ||
		!strings.Contains(err.Error(), "192.0.2.0/24 is not allowlisted") {
		t.Fatalf("err = %v", err)
	}
	if _, ok := ann.routes[own]; ok {
		t.Fatal("announced a prefix that is not in the RIB")
	}
	if len(ann.routes) != 1 {
		t.Fatalf("routes = %v", ann.routes)
	}
	// The cap binds once the RIB has the prefix.
	rib.routes[own] = nh
	if err := c.Sync(ctx); err == nil || !strings.Contains(err.Error(), "max_improvements (1)") {
		t.Fatalf("cap err = %v", err)
	}

	// The shared cap counts outbound routes.
	ann = newFakeAnn("transit-a", "transit-b")
	cfg = baseConfig(config.ModeInject)
	cfg.SharedCap = 3
	cfg.Others = func() int { return 3 }
	c = mustNew(t, cfg, ann, readyRIB())
	c.Evaluate(start, usage(start, map[string]float64{"transit-a": 150}))
	if err := c.Sync(ctx); err == nil || !strings.Contains(err.Error(), "shared max_improvements") || len(ann.routes) != 0 {
		t.Fatalf("shared cap: %v %v", err, ann.routes)
	}
}

func TestRIBLossWithdrawsAndHiddenRouteIsKept(t *testing.T) {
	ctx := context.Background()
	ann := newFakeAnn("transit-a", "transit-b")
	rib := readyRIB()
	c := mustNew(t, baseConfig(config.ModeInject), ann, rib)
	c.Evaluate(start, usage(start, map[string]float64{"transit-a": 150}))
	if err := c.Sync(ctx); err != nil || len(ann.routes) != 1 {
		t.Fatal(err)
	}
	// The edge prefers the steer route and stops sending the prefix.
	delete(rib.routes, own)
	if err := c.Sync(ctx); err != nil || len(ann.routes) != 1 {
		t.Fatalf("hidden route flapped: %v", err)
	}
	// Session lost: everything goes.
	rib.ready = false
	if err := c.Sync(ctx); err != nil || len(ann.routes) != 0 || c.Active() != 0 {
		t.Fatalf("rib loss: %v %v", err, ann.routes)
	}
	// Back up, but the prefix is not in the RIB: not announced.
	rib.ready = true
	if err := c.Sync(ctx); err == nil || len(ann.routes) != 0 {
		t.Fatalf("announced without the RIB: %v", err)
	}
}

func TestSteerSetChangeMovesInPlaceAndTTL(t *testing.T) {
	ctx := context.Background()
	ann := newFakeAnn("transit-a", "transit-b")
	rib := readyRIB()
	cfg := baseConfig(config.ModeInject)
	cfg.Providers = []string{"transit-a", "transit-b", "transit-c"}
	c := mustNew(t, cfg, ann, rib)
	c.Evaluate(start, usage(start, map[string]float64{"transit-a": 150}))
	if err := c.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	delete(rib.routes, own) // hidden by the steer route
	now := start.Add(time.Minute)
	c.Evaluate(now, usage(now, map[string]float64{"transit-a": 150, "transit-b": 150}))
	if err := c.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	r := ann.routes[own]
	if !slices.Equal(r.Away, []string{"transit-a", "transit-b"}) || r.NextHop != nh {
		t.Fatalf("moved route = %+v", r)
	}
	// improvement_ttl: released and withdrawn for a round, no re-steer in
	// the same evaluation, and not re-announced until the RIB has it.
	now = start.Add(time.Hour)
	ch := c.Evaluate(now, usage(now, map[string]float64{"transit-a": 150, "transit-b": 150}))
	if len(ch) != 1 || ch[0].Steer.Provider != "transit-a" || !strings.Contains(ch[0].Reason, "ttl") {
		t.Fatalf("ttl changes = %+v", ch)
	}
	if err := c.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ann.routes[own].Away; !slices.Equal(got, []string{"transit-b"}) {
		t.Fatalf("after ttl away = %v", got)
	}
}

func TestAnnounceErrorIsReportedAndNotActive(t *testing.T) {
	ann := newFakeAnn("transit-a", "transit-b")
	ann.fail = errors.New("boom")
	c := mustNew(t, baseConfig(config.ModeInject), ann, readyRIB())
	c.Evaluate(start, usage(start, map[string]float64{"transit-a": 150}))
	if err := c.Sync(context.Background()); err == nil || c.Active() != 0 {
		t.Fatalf("err = %v active = %d", err, c.Active())
	}
	if !c.Reserved(own) || c.Reserved(own2) {
		t.Fatal("Reserved")
	}
}

// A prefix threat mitigation holds (#28) loses its steer route and gets
// none until mitigation lets go.
func TestMitigatedPrefixIsExcluded(t *testing.T) {
	ctx := context.Background()
	ann := newFakeAnn("transit-a", "transit-b")
	held := false
	cfg := baseConfig(config.ModeInject)
	cfg.Excluded = func(p netip.Prefix) bool { return held && p == own }
	c := mustNew(t, cfg, ann, readyRIB())
	c.Evaluate(start, usage(start, map[string]float64{"transit-a": 150}))
	if err := c.Sync(ctx); err != nil || len(ann.routes) != 1 {
		t.Fatalf("steer: %v %v", err, ann.routes)
	}
	held = true
	if err := c.Sync(ctx); err != nil || len(ann.routes) != 0 || c.Active() != 0 {
		t.Fatalf("mitigated prefix kept its steer route: %v %v", err, ann.routes)
	}
	calls := ann.calls
	if err := c.Sync(ctx); err != nil || ann.calls != calls {
		t.Fatalf("mitigated prefix touched again: %v", err)
	}
	held = false
	if err := c.Sync(ctx); err != nil || len(ann.routes) != 1 {
		t.Fatalf("steer after mitigation let go: %v %v", err, ann.routes)
	}
}

// TestStandbyWithdrawsSteers: an HA standby (#31) has no steer routes on
// the wire; the plan is kept, and it is announced once active.
func TestStandbyWithdrawsSteers(t *testing.T) {
	ctx := context.Background()
	ann := newFakeAnn("transit-a", "transit-b")
	rib := readyRIB()
	var leader atomic.Bool
	cfg := baseConfig(config.ModeInject)
	cfg.Leader = leader.Load
	c := mustNew(t, cfg, ann, rib)
	c.Evaluate(start, usage(start, map[string]float64{"transit-a": 150}))
	if err := c.Sync(ctx); err != nil || len(ann.routes) != 0 || c.Active() != 0 {
		t.Fatalf("standby steered: %v %v", err, ann.routes)
	}
	leader.Store(true)
	if err := c.Sync(ctx); err != nil || len(ann.routes) != 1 {
		t.Fatalf("active did not steer: %v %v", err, ann.routes)
	}
	leader.Store(false)
	if err := c.Sync(ctx); err != nil || len(ann.routes) != 0 || c.Active() != 0 {
		t.Fatalf("demoted instance kept steers: %v %v", err, ann.routes)
	}
}
