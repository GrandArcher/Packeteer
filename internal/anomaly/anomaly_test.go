package anomaly

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/mitigation"
	"github.com/GrandArcher/Packeteer/internal/plugins/detector/baseline"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var (
	victim = netip.MustParsePrefix("198.51.100.0/24")
	other  = netip.MustParsePrefix("203.0.113.0/24")
	t0     = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	udp    = plugin.IPProtocol(17)
	tcp    = plugin.IPProtocol(6)
)

// flows is a synthetic flow source: cumulative bytes per key, advanced by
// a rate each round.
type flows struct {
	mu   sync.Mutex
	ctr  map[plugin.TrafficKey]uint64
	fail error
}

func (f *flows) FlowCounters(context.Context) ([]plugin.FlowCounter, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	var out []plugin.FlowCounter
	for k, b := range f.ctr {
		out = append(out, plugin.FlowCounter{Prefix: k.Prefix, Protocol: k.Protocol, Bytes: b})
	}
	return out, nil
}

// send adds mbps for one 10s round toward each key.
func (f *flows) send(rates map[plugin.TrafficKey]float64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, mbps := range rates {
		f.ctr[k] += uint64(mbps * 1e6 / 8 * 10)
	}
}

type rib struct {
	ready   bool
	learned map[netip.Prefix]bool
}

func (r *rib) Ready() bool                  { return r.ready }
func (r *rib) Contains(p netip.Prefix) bool { return r.learned[p] }

// ann is a mitigation announcer with FlowSpec that records the wire.
type ann struct {
	plugin.Base
	mu    sync.Mutex
	wire  map[netip.Prefix]plugin.MitigationRoute
	fwire map[string]plugin.FlowSpecRoute
}

func newAnn() *ann {
	return &ann{wire: map[netip.Prefix]plugin.MitigationRoute{}, fwire: map[string]plugin.FlowSpecRoute{}}
}

func (a *ann) Catalog() plugin.MitigationCatalog {
	return plugin.MitigationCatalog{Blackhole: true, BlackholeNextHops: []netip.Addr{netip.MustParseAddr("192.0.2.66")}, Targets: []plugin.MitigationTarget{}}
}
func (a *ann) FlowSpecCatalog() plugin.FlowSpecCatalog {
	return plugin.FlowSpecCatalog{Enabled: true, Targets: []plugin.FlowSpecTarget{}}
}
func (a *ann) Announce(_ context.Context, r plugin.MitigationRoute) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.wire[r.Prefix] = r
	return nil
}
func (a *ann) Withdraw(_ context.Context, p netip.Prefix) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.wire, p)
	return nil
}
func (a *ann) WithdrawAll(context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.wire, a.fwire = map[netip.Prefix]plugin.MitigationRoute{}, map[string]plugin.FlowSpecRoute{}
	return nil
}
func (a *ann) AnnounceFlowSpec(_ context.Context, r plugin.FlowSpecRoute) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fwire[r.Key()] = r
	return nil
}
func (a *ann) WithdrawFlowSpec(_ context.Context, key string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.fwire, key)
	return nil
}
func (a *ann) routes() (int, []plugin.FlowSpecRoute) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var fs []plugin.FlowSpecRoute
	for _, r := range a.fwire {
		fs = append(fs, r)
	}
	return len(a.wire), fs
}

type lab struct {
	t     *testing.T
	src   *flows
	ctl   *Controller
	mit   *mitigation.Controller
	ann   *ann
	rib   *rib
	now   time.Time
	pokes int
	lead  bool
}

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

// newLab wires a baseline detector (warmup 5, trigger 1, clear 2) to a
// mitigation controller in mode with the given anomaly rules.
func newLab(t *testing.T, mode string, rules []Rule, mut func(*Config)) *lab {
	t.Helper()
	l := &lab{t: t, src: &flows{ctr: map[plugin.TrafficKey]uint64{}}, ann: newAnn(), now: t0, lead: true,
		rib: &rib{ready: true, learned: map[netip.Prefix]bool{victim: true, other: true}}}
	mit, err := mitigation.New(mitigation.Config{Mode: mode, Allowlist: []netip.Prefix{victim, other}, MaxRules: 3,
		DefaultTTL: time.Hour, MaxTTL: 2 * time.Hour, LocalPref: 250, Community: "64512:666"}, l.ann, quiet())
	if err != nil {
		t.Fatal(err)
	}
	if err := mit.SetRIB(l.rib); err != nil {
		t.Fatal(err)
	}
	l.mit = mit
	dc, _ := plugin.ConfigFromYAML("warmup: 5\ntrigger_rounds: 1\nclear_rounds: 2\nmin_mbps: 5\nsensitivity: 3")
	det, err := baseline.New(dc, plugin.Env{Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Interval: 10 * time.Second, MaxActionsPerHour: 6, MaxActive: 2, Rules: rules, Detector: "baseline", Source: "flow",
		Leader: func() bool { return l.lead }, Poke: func() { l.pokes++ }}
	if mut != nil {
		mut(&cfg)
	}
	ctl, err := New(cfg, l.src, det, mit, quiet())
	if err != nil {
		t.Fatal(err)
	}
	ctl.SetRIB(l.rib)
	l.ctl = ctl
	return l
}

// round sends one round of traffic, runs detection, and syncs mitigation
// as the decision loop would.
func (l *lab) round(rates map[plugin.TrafficKey]float64) error {
	l.t.Helper()
	l.src.send(rates)
	l.now = l.now.Add(10 * time.Second)
	err := l.ctl.Round(context.Background(), l.now)
	if serr := l.mit.Sync(context.Background(), l.now); serr != nil {
		l.t.Fatal(serr)
	}
	return err
}

var normal = map[plugin.TrafficKey]float64{
	{Prefix: victim, Protocol: udp}: 2, {Prefix: victim, Protocol: tcp}: 40, {Prefix: other, Protocol: udp}: 1,
}

func (l *lab) warm() {
	for range 8 {
		if err := l.round(normal); err != nil {
			l.t.Fatal(err)
		}
	}
	if st := l.ctl.Status(); len(st.Anomalies) != 0 || st.Tracked != 3 {
		l.t.Fatalf("warm-up: %+v", st)
	}
}

func flood(k plugin.TrafficKey, mbps float64) map[plugin.TrafficKey]float64 {
	out := map[plugin.TrafficKey]float64{}
	for kk, v := range normal {
		out[kk] = v
	}
	out[k] = mbps
	return out
}

func kinds(ch []Change) string {
	var s []string
	for _, c := range ch {
		s = append(s, c.Kind)
	}
	return strings.Join(s, ",")
}

var udpDrop = Rule{Name: "udp-flood", Prefixes: []netip.Prefix{victim}, Protocols: []plugin.IPProtocol{udp}, MinMbps: 20,
	Action: plugin.MitigationFlowSpecDrop, TTL: 30 * time.Minute}

// Without an explicit rule an anomaly is only reported: no mitigation
// rule, nothing on the wire, even in inject.
func TestNoRuleNoMitigation(t *testing.T) {
	l := newLab(t, config.ModeInject, nil, nil)
	l.warm()
	l.ctl.Changes()
	k := plugin.TrafficKey{Prefix: victim, Protocol: udp}
	for range 3 {
		if err := l.round(flood(k, 400)); err != nil {
			t.Fatal(err)
		}
	}
	st := l.ctl.Status()
	if len(st.Anomalies) != 1 || st.Anomalies[0].Prefix != victim || st.Anomalies[0].Protocol != udp || st.Anomalies[0].State != StateNoRule ||
		st.Anomalies[0].Mitigation != "" || st.Anomalies[0].PeakMbps < 399 {
		t.Fatalf("anomalies = %+v", st.Anomalies)
	}
	if n, fs := l.ann.routes(); n != 0 || len(fs) != 0 || len(l.mit.Status().Rules) != 0 {
		t.Fatalf("mitigation without a rule: %d routes, %v flowspec, %v rules", n, fs, l.mit.Status().Rules)
	}
	if got := kinds(l.ctl.Changes()); got != ChangeDetected {
		t.Fatalf("changes = %s", got)
	}
}

// A matching rule adds a FlowSpec drop for the anomaly's exact prefix and
// protocol through the mitigation controller; it reaches the wire on the
// next sync and is removed and withdrawn when the anomaly clears.
func TestRuleMitigatesAndClears(t *testing.T) {
	other := Rule{Name: "tcp-only", Prefixes: []netip.Prefix{victim}, Protocols: []plugin.IPProtocol{tcp}, Action: plugin.MitigationBlackhole, TTL: time.Hour}
	l := newLab(t, config.ModeInject, []Rule{other, udpDrop}, nil)
	l.warm()
	l.ctl.Changes()
	k := plugin.TrafficKey{Prefix: victim, Protocol: udp}
	if err := l.round(flood(k, 400)); err != nil {
		t.Fatal(err)
	}
	st := l.ctl.Status()
	if len(st.Anomalies) != 1 || st.Anomalies[0].Rule != "udp-flood" || st.Anomalies[0].State != StateMitigating || st.Mitigating != 1 || st.ActionsLastHour != 1 {
		t.Fatalf("status = %+v", st)
	}
	if l.pokes == 0 {
		t.Fatal("no poke after adding a rule")
	}
	rules := l.mit.Status().Rules
	if len(rules) != 1 || rules[0].Action != plugin.MitigationFlowSpecDrop || rules[0].MatchText() != "proto=17" ||
		!strings.Contains(rules[0].Reason, "rule udp-flood") || rules[0].Expires != l.now.Add(30*time.Minute) {
		t.Fatalf("mitigation rules = %+v", rules)
	}
	// Mitigation synced in the same round: the drop is on the wire.
	if n, fs := l.ann.routes(); n != 0 || len(fs) != 1 || fs[0].Destination != victim || fs[0].Community != "64512:666" {
		t.Fatalf("wire = %d %+v", n, fs)
	}
	for range 3 {
		if err := l.round(flood(k, 400)); err != nil {
			t.Fatal(err)
		}
	}
	if len(l.mit.Status().Rules) != 1 {
		t.Fatal("a lasting anomaly added a second rule")
	}
	// clear_rounds 2: back to normal for two rounds.
	for range 2 {
		if err := l.round(normal); err != nil {
			t.Fatal(err)
		}
	}
	if st := l.ctl.Status(); len(st.Anomalies) != 0 || len(l.mit.Status().Rules) != 0 {
		t.Fatalf("after clear: %+v %+v", st.Anomalies, l.mit.Status().Rules)
	}
	if n, fs := l.ann.routes(); n != 0 || len(fs) != 0 {
		t.Fatalf("wire after clear = %d %+v", n, fs)
	}
	ch := l.ctl.Changes()
	if got := kinds(ch); got != "detected,mitigated,cleared" {
		t.Fatalf("changes = %s", got)
	}
	rec := Record(ch[2])
	if rec.End.IsZero() || rec.Mitigation == "" || rec.Action != plugin.MitigationFlowSpecDrop || rec.Protocol != "udp" || rec.Rule != "udp-flood" {
		t.Fatalf("record = %+v", rec)
	}
}

// Rules that do not match (prefix, protocol, min_mbps) act on nothing.
func TestRuleMatching(t *testing.T) {
	a := &Anomaly{Prefix: victim, Protocol: udp, Mbps: 30, PeakMbps: 30}
	cases := map[string]struct {
		r    Rule
		want bool
	}{
		"match":          {udpDrop, true},
		"any protocol":   {Rule{Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/23")}}, true},
		"other prefix":   {Rule{Prefixes: []netip.Prefix{other}}, false},
		"more specific":  {Rule{Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/25")}}, false},
		"other protocol": {Rule{Prefixes: []netip.Prefix{victim}, Protocols: []plugin.IPProtocol{tcp}}, false},
		"under min_mbps": {Rule{Prefixes: []netip.Prefix{victim}, MinMbps: 31}, false},
	}
	for name, c := range cases {
		if got := c.r.matches(a); got != c.want {
			t.Errorf("%s: matches = %v", name, got)
		}
	}
}

// Observe: the rule is added as a dry run and nothing reaches the wire.
func TestObserveIsDryRun(t *testing.T) {
	l := newLab(t, config.ModeObserve, []Rule{udpDrop}, nil)
	l.warm()
	if err := l.round(flood(plugin.TrafficKey{Prefix: victim, Protocol: udp}, 400)); err != nil {
		t.Fatal(err)
	}
	if rules := l.mit.Status().Rules; len(rules) != 1 || !strings.Contains(rules[0].Pending, "dry run") {
		t.Fatalf("rules = %+v", rules)
	}
	if n, fs := l.ann.routes(); n != 0 || len(fs) != 0 {
		t.Fatal("observe announced")
	}
}

// Held back: not an exact learned prefix, HA standby, max_active, and
// max_actions_per_hour. Each is a held change, not a mitigation.
func TestHeldBack(t *testing.T) {
	k := plugin.TrafficKey{Prefix: victim, Protocol: udp}
	t.Run("not in the RIB", func(t *testing.T) {
		l := newLab(t, config.ModeInject, []Rule{udpDrop}, nil)
		l.warm()
		delete(l.rib.learned, victim)
		l.round(flood(k, 400))
		l.round(flood(k, 400))
		st := l.ctl.Status()
		if len(l.mit.Status().Rules) != 0 || !strings.Contains(st.Anomalies[0].State, "not an exact prefix in the learned RIB") {
			t.Fatalf("status = %+v", st.Anomalies)
		}
		if got := kinds(l.ctl.Changes()); !strings.HasSuffix(got, "detected,held") {
			t.Fatalf("changes = %s (held is reported once)", got)
		}
		// Learned again: the rule is added.
		l.rib.learned[victim] = true
		l.round(flood(k, 400))
		if len(l.mit.Status().Rules) != 1 {
			t.Fatal("not added once the prefix is learned")
		}
	})
	t.Run("standby", func(t *testing.T) {
		l := newLab(t, config.ModeInject, []Rule{udpDrop}, nil)
		l.warm()
		l.lead = false
		l.round(flood(k, 400))
		if len(l.mit.Status().Rules) != 0 || !strings.Contains(l.ctl.Status().Anomalies[0].State, "standby") {
			t.Fatal("standby added a rule")
		}
	})
	t.Run("caps", func(t *testing.T) {
		any := Rule{Name: "any", Prefixes: []netip.Prefix{victim, other}, Action: plugin.MitigationFlowSpecDrop, TTL: time.Hour}
		l := newLab(t, config.ModeInject, []Rule{any}, func(c *Config) { c.MaxActive = 1; c.MaxActionsPerHour = 2 })
		l.warm()
		both := flood(k, 400)
		both[plugin.TrafficKey{Prefix: other, Protocol: udp}] = 400
		l.round(both)
		st := l.ctl.Status()
		if len(l.mit.Status().Rules) != 1 || st.Mitigating != 1 || !strings.Contains(st.Anomalies[1].State, "max_active") {
			t.Fatalf("max_active: %+v", st.Anomalies)
		}
		// Clear both, flood again: the second action of the hour is
		// allowed, the third is not.
		l.round(normal)
		l.round(normal)
		l.round(flood(k, 400))
		l.round(normal)
		l.round(normal)
		l.round(flood(k, 400))
		st = l.ctl.Status()
		if len(l.mit.Status().Rules) != 0 || !strings.Contains(st.Anomalies[0].State, "max_actions_per_hour") || st.ActionsLastHour != 2 {
			t.Fatalf("max_actions_per_hour: %+v %d", st.Anomalies, st.ActionsLastHour)
		}
		// An hour later it may act again.
		l.now = l.now.Add(time.Hour)
		l.round(flood(k, 400))
		if len(l.mit.Status().Rules) != 1 {
			t.Fatal("rate limit did not reopen after an hour")
		}
	})
}

// The detector never replaces an operator's rule, and a rule that ended
// (TTL or an operator's DELETE) is not added again for the same anomaly.
func TestOperatorRulesWin(t *testing.T) {
	bh := Rule{Name: "bh", Prefixes: []netip.Prefix{victim}, Action: plugin.MitigationBlackhole, TTL: time.Hour}
	l := newLab(t, config.ModeInject, []Rule{bh}, nil)
	l.warm()
	op, err := l.mit.Add(mitigation.Request{Prefix: victim, Action: plugin.MitigationBlackhole, Reason: "operator"}, l.now)
	if err != nil {
		t.Fatal(err)
	}
	k := plugin.TrafficKey{Prefix: victim, Protocol: udp}
	l.round(flood(k, 400))
	l.round(flood(k, 400))
	rules := l.mit.Status().Rules
	if len(rules) != 1 || rules[0].ID != op.ID || !strings.Contains(l.ctl.Status().Anomalies[0].State, "refused") {
		t.Fatalf("operator rule replaced: %+v %+v", rules, l.ctl.Status().Anomalies)
	}

	l = newLab(t, config.ModeInject, []Rule{udpDrop}, nil)
	l.warm()
	l.round(flood(k, 400))
	id := l.ctl.Status().Anomalies[0].Mitigation
	if !l.mit.Remove(id) {
		t.Fatal("no rule to remove")
	}
	l.round(flood(k, 400))
	l.round(flood(k, 400))
	if len(l.mit.Status().Rules) != 0 || l.ctl.Status().Anomalies[0].Mitigation != "" {
		t.Fatal("a removed rule came back for the same anomaly")
	}
	if got := kinds(l.ctl.Changes()); !strings.HasSuffix(got, "mitigated,mitigation_ended") {
		t.Fatalf("changes = %s", got)
	}
}

// Stale flow data: after three failed reads every anomaly clears and its
// mitigation rule is removed and withdrawn.
func TestFlowFailureClears(t *testing.T) {
	l := newLab(t, config.ModeInject, []Rule{udpDrop}, nil)
	l.warm()
	k := plugin.TrafficKey{Prefix: victim, Protocol: udp}
	l.round(flood(k, 400))
	if _, fs := l.ann.routes(); len(fs) != 1 {
		t.Fatal("not mitigated")
	}
	l.src.fail = errors.New("collector down")
	for i := range 3 {
		if err := l.round(nil); err == nil {
			t.Fatal("no error from a failed read")
		}
		if want := i < 2; (len(l.ctl.Status().Anomalies) == 1) != want {
			t.Fatalf("round %d: anomalies = %+v", i, l.ctl.Status().Anomalies)
		}
	}
	if _, fs := l.ann.routes(); len(fs) != 0 || len(l.mit.Status().Rules) != 0 {
		t.Fatal("mitigation kept on stale flow data")
	}
	if st := l.ctl.Status(); st.Error == "" || !strings.Contains(st.Feed[0].Detail, "flow data unavailable") {
		t.Fatalf("status = %+v", st)
	}
	// Recovery starts a new rate baseline: no spurious spike.
	l.src.fail = nil
	l.round(normal)
	l.round(normal)
	if len(l.ctl.Status().Anomalies) != 0 {
		t.Fatal("recovery raised an anomaly")
	}
}

// Shutdown and session loss: the mitigation controller withdraws the
// detector's routes like any other (WithdrawAll, RIB not ready).
func TestWithdrawOnShutdownAndRIBLoss(t *testing.T) {
	l := newLab(t, config.ModeInject, []Rule{udpDrop}, nil)
	l.warm()
	k := plugin.TrafficKey{Prefix: victim, Protocol: udp}
	l.round(flood(k, 400))
	l.rib.ready = false
	l.round(flood(k, 400))
	if _, fs := l.ann.routes(); len(fs) != 0 {
		t.Fatal("RIB loss kept the detector's route")
	}
	l.rib.ready = true
	l.round(flood(k, 400))
	if _, fs := l.ann.routes(); len(fs) != 1 {
		t.Fatal("not announced again once the RIB is back")
	}
	if err := l.mit.WithdrawAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, fs := l.ann.routes(); len(fs) != 0 {
		t.Fatal("WithdrawAll kept the detector's route")
	}
}

func TestNewValidation(t *testing.T) {
	det, _ := baseline.New(plugin.Config{}, plugin.Env{})
	src := &flows{ctr: map[plugin.TrafficKey]uint64{}}
	good := Config{Interval: time.Second, MaxActive: 1, MaxActionsPerHour: 1}
	if _, err := New(good, nil, det, nil, nil); err == nil {
		t.Error("no source accepted")
	}
	if _, err := New(good, src, nil, nil, nil); err == nil {
		t.Error("no detector accepted")
	}
	bad := good
	bad.Rules = []Rule{udpDrop}
	if _, err := New(bad, src, det, nil, nil); err == nil {
		t.Error("rules without mitigation accepted")
	}
	bad = good
	bad.MaxActive = 0
	if _, err := New(bad, src, det, nil, nil); err == nil {
		t.Error("max_active 0 accepted")
	}
	if _, err := New(good, src, det, nil, nil); err != nil {
		t.Errorf("alert-only: %v", err)
	}
	var nilc *Controller
	if nilc.Changes() != nil {
		t.Error("nil Changes")
	}
}

// Run ticks until its context ends.
func TestRun(t *testing.T) {
	det, _ := baseline.New(plugin.Config{}, plugin.Env{})
	src := &flows{ctr: map[plugin.TrafficKey]uint64{}}
	c, err := New(Config{Interval: 5 * time.Millisecond, MaxActive: 1, MaxActionsPerHour: 1}, src, det, nil, quiet())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	c.Run(ctx)
	if c.Status().LastRound.IsZero() {
		t.Fatal("no round ran")
	}
}
