package threatfeed

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/mitigation"
	"github.com/GrandArcher/Packeteer/internal/plugins/threatfeed/httpfeed"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var (
	t0      = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	victim  = netip.MustParsePrefix("198.51.100.0/24")
	victim2 = netip.MustParsePrefix("198.51.100.128/25")
	other   = netip.MustParsePrefix("203.0.113.0/24")
	outside = netip.MustParsePrefix("192.0.2.0/24")
)

// served is an httptest feed whose body and status the test changes.
type served struct {
	mu     sync.Mutex
	body   string
	status int
	auth   string
	srv    *httptest.Server
}

func newServed(t *testing.T, body string) *served {
	s := &served{body: body, status: http.StatusOK}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.auth = r.Header.Get("Authorization")
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte(s.body))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *served) set(status int, body string) {
	s.mu.Lock()
	s.status, s.body = status, body
	s.mu.Unlock()
}

type rib struct {
	mu      sync.Mutex
	ready   bool
	learned map[netip.Prefix]bool
}

func (r *rib) Ready() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ready
}

func (r *rib) Contains(p netip.Prefix) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.learned[p]
}

// ann is a mitigation announcer with FlowSpec that records the wire.
type ann struct {
	plugin.Base
	mu    sync.Mutex
	calls int
	wire  map[netip.Prefix]plugin.MitigationRoute
	fwire map[string]plugin.FlowSpecRoute
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
	a.calls++
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
	a.calls++
	a.fwire[r.Key()] = r
	return nil
}
func (a *ann) WithdrawFlowSpec(_ context.Context, key string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.fwire, key)
	return nil
}

// onWire is the unicast prefixes and the FlowSpec destination/source pairs
// on the wire.
func (a *ann) onWire() (map[netip.Prefix]bool, map[[2]netip.Prefix]bool, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	u, f := map[netip.Prefix]bool{}, map[[2]netip.Prefix]bool{}
	for p := range a.wire {
		u[p] = true
	}
	for _, r := range a.fwire {
		f[[2]netip.Prefix{r.Destination, r.Match.Source}] = true
	}
	return u, f, a.calls
}

type lab struct {
	t    *testing.T
	feed *served
	ctl  *Controller
	mit  *mitigation.Controller
	ann  *ann
	rib  *rib
	now  time.Time
	lead bool
}

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

// newLab wires an http feed serving body to a mitigation controller in
// mode (allowlist victim and other, max_rules 4, max_ttl 2h) and a feed
// controller with the given rules (all reading feed "drop").
func newLab(t *testing.T, mode, body string, rules []Rule, mut func(*Config)) *lab {
	t.Helper()
	l := &lab{t: t, feed: newServed(t, body), now: t0, lead: true,
		ann: &ann{wire: map[netip.Prefix]plugin.MitigationRoute{}, fwire: map[string]plugin.FlowSpecRoute{}},
		rib: &rib{ready: true, learned: map[netip.Prefix]bool{victim: true, victim2: true, other: true}}}
	mit, err := mitigation.New(mitigation.Config{Mode: mode, Allowlist: []netip.Prefix{victim, other}, MaxRules: 4,
		DefaultTTL: time.Hour, MaxTTL: 2 * time.Hour, LocalPref: 250, Community: "64512:666"}, l.ann, quiet())
	if err != nil {
		t.Fatal(err)
	}
	if err := mit.SetRIB(l.rib); err != nil {
		t.Fatal(err)
	}
	l.mit = mit
	pc, _ := plugin.ConfigFromYAML("url: " + l.feed.srv.URL + "/drop.txt\n")
	fp, err := httpfeed.New(pc, plugin.Env{Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Interval: 15 * time.Minute, MaxActive: 3, MaxActionsPerHour: 6, Rules: rules,
		Feeds:  []Feed{{Name: "drop", Type: httpfeed.TypeName, Plugin: fp}},
		Leader: func() bool { return l.lead }}
	if mut != nil {
		mut(&cfg)
	}
	ctl, err := New(cfg, mit, quiet())
	if err != nil {
		t.Fatal(err)
	}
	ctl.SetRIB(l.rib)
	l.ctl = ctl
	return l
}

// round advances the clock, runs a feed round, and syncs mitigation as
// the decision loop would.
func (l *lab) round(d time.Duration) Status {
	l.t.Helper()
	l.now = l.now.Add(d)
	l.ctl.Round(context.Background(), l.now)
	if err := l.mit.Sync(context.Background(), l.now); err != nil {
		l.t.Fatal(err)
	}
	return l.ctl.Status()
}

func dstRule(name string, prefixes ...netip.Prefix) Rule {
	return Rule{Name: name, Feed: "drop", Match: config.ThreatMatchDestination, Prefixes: prefixes, Action: plugin.MitigationBlackhole, TTL: 30 * time.Minute}
}

func srcRule(name string, prefixes ...netip.Prefix) Rule {
	return Rule{Name: name, Feed: "drop", Match: config.ThreatMatchSource, Prefixes: prefixes, Action: plugin.MitigationFlowSpecDrop, TTL: 30 * time.Minute}
}

// In observe, listed networks become mitigation rules (a dry run) and
// nothing reaches the announcer.
func TestObserveProposesAndAnnouncesNothing(t *testing.T) {
	l := newLab(t, config.ModeObserve, "198.51.100.0/24 ; SBL1\n192.0.2.7\n", []Rule{dstRule("own", victim)}, nil)
	st := l.round(0)
	if len(st.Proposals) != 1 || st.Proposals[0].State != StateMitigating || st.Proposals[0].Prefix != victim || st.Held != 1 {
		t.Fatalf("proposals = %+v", st.Proposals)
	}
	rules := l.mit.Status().Rules
	if len(rules) != 1 || rules[0].Prefix != victim || rules[0].Announced || !strings.Contains(rules[0].Reason, "threat feed drop (rule own): 198.51.100.0/24 listed: SBL1") {
		t.Fatalf("mitigation rules = %+v", rules)
	}
	l.round(Tick)
	if _, _, calls := l.ann.onWire(); calls != 0 {
		t.Fatalf("observe called the announcer %d times", calls)
	}
}

// In inject, a destination rule announces only listed networks that are
// inside its prefixes and exact in the learned RIB.
func TestInjectDestinationOnlyLearnedInsideAllowlist(t *testing.T) {
	body := strings.Join([]string{
		"198.51.100.0/24",    // learned, inside
		"198.51.100.7/32",    // inside, not learned: never announced
		"192.0.2.0/24",       // outside the rule and the allowlist
		"203.0.113.0/24 # x", // learned and allowlisted, but outside the rule
	}, "\n")
	l := newLab(t, config.ModeInject, body, []Rule{dstRule("own", victim)}, nil)
	l.rib.learned[outside] = true
	st := l.round(0)
	l.round(Tick)
	uni, _, _ := l.ann.onWire()
	if len(uni) != 1 || !uni[victim] {
		t.Fatalf("wire = %v", uni)
	}
	if len(st.Proposals) != 1 || st.Feeds[0].Entries != 4 || st.Feeds[0].Error != "" {
		t.Fatalf("status = %+v", st)
	}
	// The more-specific becomes learned: it is announced on the next tick.
	l.rib.mu.Lock()
	l.rib.learned[netip.MustParsePrefix("198.51.100.7/32")] = true
	l.rib.mu.Unlock()
	l.round(Tick)
	if uni, _, _ = l.ann.onWire(); len(uni) != 2 {
		t.Fatalf("wire after learning = %v", uni)
	}
}

// A source rule sends one FlowSpec drop per listed network toward each
// learned rule prefix of the same family, under max_active.
func TestInjectSourceFlowSpecUnderMaxActive(t *testing.T) {
	body := "192.0.2.1\n192.0.2.2\n2001:db8::/48\n192.0.2.3\n192.0.2.4\n"
	l := newLab(t, config.ModeInject, body, []Rule{srcRule("srcs", victim)}, nil)
	st := l.round(0)
	_, fs, _ := l.ann.onWire()
	if len(fs) != 3 || st.Held != 3 || !strings.Contains(st.Waiting, "max_active (3)") {
		t.Fatalf("flowspec = %v status = %+v", fs, st)
	}
	for _, s := range []string{"192.0.2.1/32", "192.0.2.2/32", "192.0.2.3/32"} {
		if !fs[[2]netip.Prefix{victim, netip.MustParsePrefix(s)}] {
			t.Errorf("missing source %s in %v", s, fs)
		}
	}
	// Delisting one frees a slot for the next listed network.
	l.feed.set(http.StatusOK, "192.0.2.2\n2001:db8::/48\n192.0.2.3\n192.0.2.4\n")
	st = l.round(15 * time.Minute)
	_, fs, _ = l.ann.onWire()
	if len(fs) != 3 || fs[[2]netip.Prefix{victim, netip.MustParsePrefix("192.0.2.1/32")}] || !fs[[2]netip.Prefix{victim, netip.MustParsePrefix("192.0.2.4/32")}] {
		t.Fatalf("after delisting: %v", fs)
	}
	if st.ActionsLastHour != 4 {
		t.Fatalf("actions = %d", st.ActionsLastHour)
	}
}

// max_actions_per_hour caps rules added in any rolling hour, and
// mitigation.max_rules still caps every mitigation route.
func TestRateLimitAndMitigationCap(t *testing.T) {
	l := newLab(t, config.ModeInject, "192.0.2.1\n192.0.2.2\n192.0.2.3\n", []Rule{srcRule("srcs", victim)},
		func(c *Config) { c.MaxActionsPerHour, c.MaxActive = 2, 4 })
	st := l.round(0)
	if st.Held != 2 || !strings.Contains(st.Waiting, "max_actions_per_hour (2)") {
		t.Fatalf("status = %+v", st)
	}
	st = l.round(61 * time.Minute)
	if st.Held != 3 || st.Waiting != "" {
		t.Fatalf("an hour later: %+v", st)
	}

	// An operator holds two routes: with max_rules 4 only two feed rules fit.
	l = newLab(t, config.ModeInject, "192.0.2.1\n192.0.2.2\n192.0.2.3\n", []Rule{srcRule("srcs", victim)}, func(c *Config) { c.MaxActive = 4 })
	for _, src := range []string{"203.0.113.0/24", "198.51.100.0/24"} {
		if _, err := l.mit.Add(mitigation.Request{Prefix: other, Action: plugin.MitigationFlowSpecDrop, Match: plugin.FlowSpecMatch{Source: netip.MustParsePrefix(src)}}, l.now); err != nil {
			t.Fatal(err)
		}
	}
	st = l.round(0)
	if st.Held != 2 || !strings.Contains(st.Waiting, "max_rules") {
		t.Fatalf("under max_rules: %+v", st)
	}
}

// A failed fetch removes nothing and adds nothing. The rules expire on
// their TTL while the feed stays down and are added again once it answers.
func TestFeedFailureClearsNothing(t *testing.T) {
	l := newLab(t, config.ModeInject, "192.0.2.1\n", []Rule{srcRule("srcs", victim)}, nil)
	l.round(0)
	l.feed.set(http.StatusInternalServerError, "oops")
	st := l.round(15 * time.Minute)
	if _, fs, _ := l.ann.onWire(); len(fs) != 1 || st.Held != 1 {
		t.Fatalf("a failed fetch withdrew: %v %+v", fs, st)
	}
	if f := st.Feeds[0]; !strings.Contains(f.Error, "500") || f.Entries != 1 || !f.LastSuccess.Equal(t0) {
		t.Fatalf("feed status = %+v", f)
	}
	// TTL 30m: expired (withdrawn by the mitigation sync) and not added
	// again while the feed is down.
	l.round(16 * time.Minute)
	st = l.round(Tick)
	if _, fs, _ := l.ann.onWire(); len(fs) != 0 || st.Held != 0 || len(st.Proposals) != 0 {
		t.Fatalf("after ttl with the feed down: %v %+v", fs, st)
	}
	l.feed.set(http.StatusOK, "192.0.2.1\n")
	st = l.round(15 * time.Minute)
	if _, fs, _ := l.ann.onWire(); len(fs) != 1 || st.Held != 1 || st.Feeds[0].Error != "" {
		t.Fatalf("after the feed answers: %v %+v", fs, st)
	}
	// A body that does not parse is a failure too, not an empty list.
	l.feed.set(http.StatusOK, "<html>maintenance</html>")
	st = l.round(15 * time.Minute)
	if _, fs, _ := l.ann.onWire(); len(fs) != 1 || !strings.Contains(st.Feeds[0].Error, "line 1") {
		t.Fatalf("junk body: %v %+v", fs, st.Feeds[0])
	}
	// A successful empty list delists everything.
	l.feed.set(http.StatusOK, "# nothing listed\n")
	st = l.round(15 * time.Minute)
	if _, fs, _ := l.ann.onWire(); len(fs) != 0 || st.Held != 0 {
		t.Fatalf("empty list: %v %+v", fs, st)
	}
}

// A rule that expired is added again while the feed lists the network;
// one an operator removed is not, until the network leaves the feed and
// comes back.
func TestExpiredReaddedOperatorRemovalWins(t *testing.T) {
	l := newLab(t, config.ModeInject, "192.0.2.1\n", []Rule{srcRule("srcs", victim)}, func(c *Config) { c.Interval = time.Hour })
	st := l.round(0)
	first := st.Proposals[0].Mitigation
	l.round(31 * time.Minute)
	if _, fs, _ := l.ann.onWire(); len(fs) != 0 {
		t.Fatalf("not expired: %v", fs)
	}
	st = l.round(Tick)
	if _, fs, _ := l.ann.onWire(); len(fs) != 1 {
		t.Fatalf("not announced again after expiry: %v", fs)
	}
	if len(st.Proposals) != 1 || st.Proposals[0].Mitigation == "" || st.Proposals[0].Mitigation == first {
		t.Fatalf("not re-added after expiry: %+v", st.Proposals)
	}
	if !l.mit.Remove(st.Proposals[0].Mitigation) {
		t.Fatal("remove")
	}
	st = l.round(Tick)
	if _, fs, _ := l.ann.onWire(); len(fs) != 0 || st.Proposals[0].State != StateEnded || st.Held != 0 {
		t.Fatalf("after operator removal: %v %+v", fs, st.Proposals)
	}
	st = l.round(Tick)
	if _, fs, _ := l.ann.onWire(); len(fs) != 0 {
		t.Fatalf("re-added after operator removal: %v", fs)
	}
	l.feed.set(http.StatusOK, "# gone\n")
	l.round(time.Hour)
	l.feed.set(http.StatusOK, "192.0.2.1\n")
	st = l.round(time.Hour)
	if _, fs, _ := l.ann.onWire(); len(fs) != 1 || st.Proposals[0].State != StateMitigating {
		t.Fatalf("relisted: %v %+v", fs, st.Proposals)
	}
}

// The feed never replaces a rule someone else holds for the same key, an
// HA standby adds nothing, and nothing is added while the RIB is not ready.
func TestOperatorRuleStandbyAndRIB(t *testing.T) {
	l := newLab(t, config.ModeInject, "198.51.100.0/24\n", []Rule{dstRule("own", victim)}, nil)
	op, err := l.mit.Add(mitigation.Request{Prefix: victim, Action: plugin.MitigationBlackhole, Reason: "ticket 1"}, l.now)
	if err != nil {
		t.Fatal(err)
	}
	st := l.round(0)
	if len(st.Proposals) != 1 || !strings.HasPrefix(st.Proposals[0].State, "refused:") || st.Held != 0 || !l.mit.Has(op.ID) {
		t.Fatalf("operator rule: %+v", st.Proposals)
	}

	l = newLab(t, config.ModeInject, "198.51.100.0/24\n", []Rule{dstRule("own", victim)}, nil)
	l.lead = false
	st = l.round(0)
	if st.Held != 0 || !strings.Contains(st.Waiting, "standby") {
		t.Fatalf("standby: %+v", st)
	}
	l.lead = true
	l.rib.mu.Lock()
	l.rib.ready = false
	l.rib.mu.Unlock()
	st = l.round(Tick)
	if st.Held != 0 || !strings.Contains(st.Waiting, "RIB is not ready") {
		t.Fatalf("rib not ready: %+v", st)
	}
	l.rib.mu.Lock()
	l.rib.ready = true
	l.rib.mu.Unlock()
	if st = l.round(Tick); st.Held != 1 || st.Waiting != "" {
		t.Fatalf("rib ready: %+v", st)
	}
}

// RIB session loss, shutdown, and delisting withdraw feed rules like any
// mitigation rule.
func TestWithdrawOnRIBLossAndShutdown(t *testing.T) {
	l := newLab(t, config.ModeInject, "198.51.100.0/24\n", []Rule{dstRule("own", victim)}, nil)
	l.round(0)
	l.round(Tick)
	if uni, _, _ := l.ann.onWire(); !uni[victim] {
		t.Fatalf("not announced: %v", uni)
	}
	l.rib.mu.Lock()
	l.rib.ready = false
	l.rib.mu.Unlock()
	l.round(Tick)
	if uni, _, _ := l.ann.onWire(); len(uni) != 0 {
		t.Fatalf("rib loss kept %v", uni)
	}
	l.rib.mu.Lock()
	l.rib.ready = true
	l.rib.mu.Unlock()
	l.round(Tick)
	if uni, _, _ := l.ann.onWire(); !uni[victim] {
		t.Fatalf("not back with the session: %v", uni)
	}
	if err := l.mit.WithdrawAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if uni, _, _ := l.ann.onWire(); len(uni) != 0 {
		t.Fatalf("shutdown kept %v", uni)
	}
}

func TestNewChecks(t *testing.T) {
	mit, err := mitigation.New(mitigation.Config{Mode: config.ModeObserve, Allowlist: []netip.Prefix{victim}, MaxRules: 4,
		DefaultTTL: time.Hour, MaxTTL: 2 * time.Hour}, nil, quiet())
	if err != nil {
		t.Fatal(err)
	}
	ok := Config{Interval: time.Minute, MaxActive: 1, MaxActionsPerHour: 1}
	if _, err := New(ok, nil, quiet()); err == nil {
		t.Fatal("nil mitigation accepted")
	}
	bad := ok
	bad.MaxActive = 0
	if _, err := New(bad, mit, quiet()); err == nil {
		t.Fatal("max_active 0 accepted")
	}
	bad = ok
	bad.Rules = []Rule{dstRule("r", victim)}
	if _, err := New(bad, mit, quiet()); err == nil || !strings.Contains(err.Error(), "unknown feed") {
		t.Fatalf("unknown feed: %v", err)
	}
}
