package mitigation

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakeAnn struct {
	plugin.Base
	mu       sync.Mutex
	wire     map[netip.Prefix]plugin.MitigationRoute
	calls    int
	fail     error
	withdraw int
}

func newFakeAnn() *fakeAnn { return &fakeAnn{wire: map[netip.Prefix]plugin.MitigationRoute{}} }

func (f *fakeAnn) Catalog() plugin.MitigationCatalog {
	return plugin.MitigationCatalog{
		Blackhole:         true,
		BlackholeNextHops: []netip.Addr{netip.MustParseAddr("192.0.2.66")},
		Targets:           []plugin.MitigationTarget{{Name: "scrubber", NextHop: netip.MustParseAddr("192.0.2.77")}},
	}
}

func (f *fakeAnn) Announce(_ context.Context, r plugin.MitigationRoute) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.fail != nil {
		return f.fail
	}
	f.wire[r.Prefix] = r
	return nil
}

func (f *fakeAnn) Withdraw(_ context.Context, p netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.withdraw++
	delete(f.wire, p)
	return nil
}

func (f *fakeAnn) WithdrawAll(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.withdraw++
	f.wire = map[netip.Prefix]plugin.MitigationRoute{}
	return nil
}

func (f *fakeAnn) on(p netip.Prefix) (plugin.MitigationRoute, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.wire[p]
	return r, ok
}

type fakeRIB struct {
	ready   bool
	learned map[netip.Prefix]bool
}

func (r *fakeRIB) Ready() bool                  { return r.ready }
func (r *fakeRIB) Contains(p netip.Prefix) bool { return r.learned[p] }

var (
	victim = netip.MustParsePrefix("198.51.100.0/24")
	other  = netip.MustParsePrefix("203.0.113.0/24")
	t0     = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
)

func testConfig(mode string) Config {
	return Config{
		Mode:       mode,
		Allowlist:  []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24")},
		MaxRules:   2,
		DefaultTTL: time.Hour,
		MaxTTL:     2 * time.Hour,
		LocalPref:  250,
		Community:  "64512:666",
	}
}

func newTest(t *testing.T, mode string) (*Controller, *fakeAnn, *fakeRIB) {
	t.Helper()
	ann := newFakeAnn()
	rib := &fakeRIB{ready: true, learned: map[netip.Prefix]bool{victim: true}}
	c, err := New(testConfig(mode), ann, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetRIB(rib); err != nil {
		t.Fatal(err)
	}
	return c, ann, rib
}

func TestNewValidation(t *testing.T) {
	cases := map[string]func(*Config){
		"empty allowlist":   func(c *Config) { c.Allowlist = nil },
		"zero cap":          func(c *Config) { c.MaxRules = 0 },
		"default over max":  func(c *Config) { c.DefaultTTL = 3 * time.Hour },
		"no local pref":     func(c *Config) { c.LocalPref = 0 },
		"no community":      func(c *Config) { c.Community = "" },
		"zero default ttl":  func(c *Config) { c.DefaultTTL = 0 },
		"negative max ttl":  func(c *Config) { c.MaxTTL = -1 },
		"no ttl at all":     func(c *Config) { c.DefaultTTL, c.MaxTTL = 0, 0 },
		"cap below one too": func(c *Config) { c.MaxRules = -3 },
	}
	for name, mut := range cases {
		cfg := testConfig(config.ModeInject)
		mut(&cfg)
		if _, err := New(cfg, newFakeAnn(), nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := New(testConfig(config.ModeInject), nil, nil); err == nil {
		t.Error("inject without an announcer accepted")
	}
	c, err := New(testConfig(config.ModeInject), newFakeAnn(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetRIB(nil); err == nil {
		t.Error("inject without a RIB accepted")
	}
	if _, err := New(testConfig(config.ModeObserve), nil, nil); err != nil {
		t.Errorf("observe without an announcer: %v", err)
	}
}

func TestAddValidation(t *testing.T) {
	c, _, _ := newTest(t, config.ModeInject)
	bad := map[string]Request{
		"no prefix":         {Action: plugin.MitigationBlackhole},
		"host bits":         {Prefix: netip.MustParsePrefix("198.51.100.1/24"), Action: plugin.MitigationBlackhole},
		"default route":     {Prefix: netip.MustParsePrefix("0.0.0.0/0"), Action: plugin.MitigationBlackhole},
		"outside allowlist": {Prefix: netip.MustParsePrefix("192.0.2.0/24"), Action: plugin.MitigationBlackhole},
		"covering":          {Prefix: netip.MustParsePrefix("198.51.0.0/16"), Action: plugin.MitigationBlackhole},
		"ttl too long":      {Prefix: victim, Action: plugin.MitigationBlackhole, TTL: 3 * time.Hour},
		"ttl too short":     {Prefix: victim, Action: plugin.MitigationBlackhole, TTL: time.Millisecond},
		"negative ttl":      {Prefix: victim, Action: plugin.MitigationBlackhole, TTL: -time.Minute},
		"unknown action":    {Prefix: victim, Action: "drop"},
		"blackhole target":  {Prefix: victim, Action: plugin.MitigationBlackhole, Target: "scrubber"},
		"unknown target":    {Prefix: victim, Action: plugin.MitigationRedirect, Target: "nowhere"},
		"no v6 blackhole":   {Prefix: netip.MustParsePrefix("2001:db8::/32"), Action: plugin.MitigationBlackhole},
		"long reason":       {Prefix: victim, Action: plugin.MitigationBlackhole, Reason: strings.Repeat("x", 257)},
	}
	for name, req := range bad {
		if _, err := c.Add(req, t0); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	r, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationRedirect, Target: "scrubber", Reason: "ddos"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID == "" || r.NextHop != netip.MustParseAddr("192.0.2.77") || !r.Expires.Equal(t0.Add(time.Hour)) || r.Announced {
		t.Fatalf("rule = %+v", r)
	}
}

func TestCapAndReplace(t *testing.T) {
	c, _, _ := newTest(t, config.ModeInject)
	if _, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationBlackhole}, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Add(Request{Prefix: other, Action: plugin.MitigationBlackhole}, t0); err != nil {
		t.Fatal(err)
	}
	third := netip.MustParsePrefix("203.0.113.0/25")
	if _, err := c.Add(Request{Prefix: third, Action: plugin.MitigationBlackhole}, t0); !errors.Is(err, ErrFull) {
		t.Fatalf("third rule past max_rules: %v", err)
	}
	// Replacing a held prefix does not count again.
	r, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationRedirect, Target: "scrubber"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	st := c.Status()
	if len(st.Rules) != 2 || st.Rules[0].Action != plugin.MitigationRedirect || st.Rules[0].ID != r.ID || st.MaxRules != 2 {
		t.Fatalf("status = %+v", st)
	}
}

func TestObserveNeverAnnounces(t *testing.T) {
	c, ann, _ := newTest(t, config.ModeObserve)
	if _, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationBlackhole}, t0); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(context.Background(), t0); err != nil {
		t.Fatal(err)
	}
	if ann.calls != 0 || c.Holds(victim) || c.Active() != 0 {
		t.Fatalf("observe touched the wire: calls=%d holds=%v", ann.calls, c.Holds(victim))
	}
	st := c.Status()
	if len(st.Rules) != 1 || st.Rules[0].Announced || !strings.Contains(st.Rules[0].Pending, "dry run") {
		t.Fatalf("status = %+v", st)
	}
	if err := c.WithdrawAll(context.Background()); err != nil || ann.withdraw != 0 {
		t.Fatalf("observe withdraw: %v %d", err, ann.withdraw)
	}
	// Rules still expire in observe.
	if err := c.Sync(context.Background(), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(c.Status().Rules) != 0 {
		t.Fatal("observe rule did not expire")
	}
}

func TestInjectAnnounceWithdrawExpire(t *testing.T) {
	ctx := context.Background()
	c, ann, rib := newTest(t, config.ModeInject)

	// Never announce a prefix that is not in the learned RIB.
	if _, err := c.Add(Request{Prefix: other, Action: plugin.MitigationBlackhole, TTL: 30 * time.Minute}, t0); err != nil {
		t.Fatal(err)
	}
	r, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationBlackhole, TTL: 10 * time.Minute}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Holds(victim) || !c.Holds(other) {
		t.Fatal("rules must hold their prefixes before they are announced")
	}
	if err := c.Sync(ctx, t0); err != nil {
		t.Fatal(err)
	}
	got, ok := ann.on(victim)
	if !ok || got.Action != plugin.MitigationBlackhole || got.LocalPref != 250 || got.Community != "64512:666" {
		t.Fatalf("wire = %+v %v", got, ok)
	}
	if _, ok := ann.on(other); ok {
		t.Fatal("announced a prefix that is not in the RIB")
	}
	st := c.Status()
	if !st.Rules[0].Announced || st.Rules[1].Announced || st.Rules[1].Pending != "not in the learned RIB" || c.Active() != 1 {
		t.Fatalf("status = %+v", st.Rules)
	}

	// The edge stops sending the prefix once the mitigation route wins.
	// The route stays, and a new action replaces it in place.
	delete(rib.learned, victim)
	if _, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationRedirect, Target: "scrubber", TTL: 10 * time.Minute}, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, _ := ann.on(victim); got.Action != plugin.MitigationRedirect || got.Target != "scrubber" {
		t.Fatalf("replace = %+v", got)
	}
	calls := ann.calls
	if err := c.Sync(ctx, t0.Add(2*time.Minute)); err != nil || ann.calls != calls {
		t.Fatalf("unchanged rule re-announced: %v calls %d -> %d", err, calls, ann.calls)
	}

	// Removing the rule withdraws on the next Sync. Holds stays true
	// until the route is gone, so no other route can take the prefix.
	for _, rl := range c.Status().Rules {
		if rl.Prefix == victim {
			r = rl
		}
	}
	if !c.Remove(r.ID) || c.Remove(r.ID) {
		t.Fatal("remove")
	}
	if !c.Holds(victim) {
		t.Fatal("a route on the wire must keep holding its prefix")
	}
	if err := c.Sync(ctx, t0.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, ok := ann.on(victim); ok || c.Holds(victim) {
		t.Fatal("removed rule still on the wire")
	}

	// TTL expiry withdraws.
	rib.learned[victim] = true
	if _, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationBlackhole, TTL: 5 * time.Minute}, t0.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx, t0.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, ok := ann.on(victim); !ok {
		t.Fatal("not announced")
	}
	if err := c.Sync(ctx, t0.Add(9*time.Minute-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, ok := ann.on(victim); !ok {
		t.Fatal("withdrawn before its TTL")
	}
	if err := c.Sync(ctx, t0.Add(9*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, ok := ann.on(victim); ok || c.Holds(victim) {
		t.Fatal("expired rule still on the wire")
	}
	if len(c.Status().Rules) != 1 { // other, still pending
		t.Fatalf("rules = %+v", c.Status().Rules)
	}
}

func TestRIBLossAndShutdownWithdraw(t *testing.T) {
	ctx := context.Background()
	c, ann, rib := newTest(t, config.ModeInject)
	if _, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationBlackhole}, t0); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx, t0); err != nil {
		t.Fatal(err)
	}
	if _, ok := ann.on(victim); !ok {
		t.Fatal("not announced")
	}

	// RIB session loss withdraws everything.
	rib.ready = false
	if err := c.Sync(ctx, t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, ok := ann.on(victim); ok || c.Active() != 0 {
		t.Fatal("route kept with the RIB down")
	}
	// Back, and the prefix is learned again: the rule still holds, so the
	// route returns.
	rib.ready = true
	if err := c.Sync(ctx, t0.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, ok := ann.on(victim); !ok {
		t.Fatal("not re-announced after the RIB came back")
	}

	// Shutdown.
	if err := c.WithdrawAll(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := ann.on(victim); ok || c.Active() != 0 {
		t.Fatal("WithdrawAll left the route")
	}
	if err := c.WithdrawAll(ctx); err != nil {
		t.Fatalf("second WithdrawAll: %v", err)
	}
}

func TestAnnounceErrorStaysOff(t *testing.T) {
	c, ann, _ := newTest(t, config.ModeInject)
	ann.fail = errors.New("speaker said no")
	if _, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationBlackhole}, t0); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(context.Background(), t0); err == nil {
		t.Fatal("announce error swallowed")
	}
	st := c.Status()
	if st.Rules[0].Announced || st.Rules[0].Pending != "speaker said no" || c.Active() != 0 {
		t.Fatalf("status = %+v", st.Rules)
	}
}

func TestNilController(t *testing.T) {
	var c *Controller
	if c.Holds(victim) || c.Active() != 0 || c.Sync(context.Background(), t0) != nil || c.WithdrawAll(context.Background()) != nil {
		t.Fatal("nil controller")
	}
	if st := c.Status(); st.Rules == nil || st.Allowlist == nil || st.Catalog.Targets == nil {
		t.Fatalf("nil status = %+v", st)
	}
}

// TestStandbyWithdrawsRules: an HA standby (#31) keeps its rules (they
// still expire) but has no mitigation route on the wire.
func TestStandbyWithdrawsRules(t *testing.T) {
	ctx := context.Background()
	ann := newFakeAnn()
	rib := &fakeRIB{ready: true, learned: map[netip.Prefix]bool{victim: true}}
	var leader atomic.Bool
	cfg := testConfig(config.ModeInject)
	cfg.Leader = leader.Load
	c, err := New(cfg, ann, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetRIB(rib); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationBlackhole}, t0); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx, t0); err != nil {
		t.Fatal(err)
	}
	if _, ok := ann.on(victim); ok || c.Active() != 0 {
		t.Fatal("standby announced a mitigation route")
	}
	leader.Store(true)
	if err := c.Sync(ctx, t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, ok := ann.on(victim); !ok {
		t.Fatal("active did not announce")
	}
	leader.Store(false)
	if err := c.Sync(ctx, t0.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, ok := ann.on(victim); ok || c.Active() != 0 {
		t.Fatal("demoted instance kept a mitigation route")
	}
}

// NoReplace (the anomaly detector, #33) never replaces a held rule, and
// Has follows the rule's life.
func TestNoReplaceAndHas(t *testing.T) {
	c, _, _ := newTest(t, config.ModeInject)
	op, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationRedirect, Target: "scrubber"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Has(op.ID) {
		t.Fatal("Has is false for a held rule")
	}
	if _, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationBlackhole, NoReplace: true}, t0); !errors.Is(err, ErrConflict) {
		t.Fatalf("NoReplace over an operator rule: %v, want ErrConflict", err)
	}
	if st := c.Status(); len(st.Rules) != 1 || st.Rules[0].ID != op.ID {
		t.Fatalf("operator rule replaced: %+v", st.Rules)
	}
	auto, err := c.Add(Request{Prefix: other, Action: plugin.MitigationBlackhole, NoReplace: true}, t0)
	if err != nil {
		t.Fatalf("NoReplace on a free key: %v", err)
	}
	if !c.Remove(auto.ID) || c.Has(auto.ID) {
		t.Fatal("Has is true after Remove")
	}
	var nilc *Controller
	if nilc.Has("x") {
		t.Fatal("nil controller has a rule")
	}
}
