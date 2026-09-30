package mitigation

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// fakeFSAnn is fakeAnn with FlowSpec.
type fakeFSAnn struct {
	*fakeAnn
	fmu   sync.Mutex
	fwire map[string]plugin.FlowSpecRoute
}

func newFakeFSAnn() *fakeFSAnn {
	return &fakeFSAnn{fakeAnn: newFakeAnn(), fwire: map[string]plugin.FlowSpecRoute{}}
}

func (f *fakeFSAnn) FlowSpecCatalog() plugin.FlowSpecCatalog {
	return plugin.FlowSpecCatalog{Enabled: true, Targets: []plugin.FlowSpecTarget{{Name: "scrub-vrf", RouteTarget: "64512:777"}}}
}

func (f *fakeFSAnn) AnnounceFlowSpec(_ context.Context, r plugin.FlowSpecRoute) error {
	f.fmu.Lock()
	defer f.fmu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.fwire[r.Key()] = r
	return nil
}

func (f *fakeFSAnn) WithdrawFlowSpec(_ context.Context, key string) error {
	f.fmu.Lock()
	defer f.fmu.Unlock()
	delete(f.fwire, key)
	return nil
}

func (f *fakeFSAnn) WithdrawAll(ctx context.Context) error {
	f.fmu.Lock()
	f.fwire = map[string]plugin.FlowSpecRoute{}
	f.fmu.Unlock()
	return f.fakeAnn.WithdrawAll(ctx)
}

func (f *fakeFSAnn) flows() []plugin.FlowSpecRoute {
	f.fmu.Lock()
	defer f.fmu.Unlock()
	var out []plugin.FlowSpecRoute
	for _, r := range f.fwire {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b plugin.FlowSpecRoute) int { return strings.Compare(a.Key(), b.Key()) })
	return out
}

// fakeGeo maps countries to networks.
type fakeGeo map[string][]netip.Prefix

func (g fakeGeo) Networks(cc string, v4 bool) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, p := range g[cc] {
		if p.Addr().Is4() == v4 {
			out = append(out, p)
		}
	}
	return out, nil
}

var geo = fakeGeo{
	"XA": {netip.MustParsePrefix("192.0.2.0/26"), netip.MustParsePrefix("192.0.2.64/26"), netip.MustParsePrefix("2001:db8:a::/48")},
	"XB": {netip.MustParsePrefix("203.0.113.128/25")},
	"XC": {netip.MustParsePrefix("192.0.2.128/28"), netip.MustParsePrefix("192.0.2.160/28"), netip.MustParsePrefix("192.0.2.192/28"),
		netip.MustParsePrefix("192.0.2.224/28")},
}

func newFSTest(t *testing.T, mode string, maxRules int) (*Controller, *fakeFSAnn, *fakeRIB) {
	t.Helper()
	ann := newFakeFSAnn()
	rib := &fakeRIB{ready: true, learned: map[netip.Prefix]bool{victim: true}}
	cfg := testConfig(mode)
	cfg.MaxRules = maxRules
	cfg.Geo = geo
	c, err := New(cfg, ann, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetRIB(rib); err != nil {
		t.Fatal(err)
	}
	return c, ann, rib
}

func udp53() plugin.FlowSpecMatch {
	return plugin.FlowSpecMatch{Protocols: []plugin.IPProtocol{17}, DestinationPorts: []plugin.PortRange{{From: 53, To: 53}}}
}

func TestFlowSpecAddValidation(t *testing.T) {
	c, _, _ := newFSTest(t, config.ModeInject, 3)
	bad := map[string]Request{
		"drop with target":       {Prefix: victim, Action: plugin.MitigationFlowSpecDrop, Target: "scrub-vrf"},
		"drop with rate":         {Prefix: victim, Action: plugin.MitigationFlowSpecDrop, RateMbps: 5},
		"rate-limit without":     {Prefix: victim, Action: plugin.MitigationFlowSpecRateLimit},
		"rate-limit too high":    {Prefix: victim, Action: plugin.MitigationFlowSpecRateLimit, RateMbps: 1e7},
		"rate-limit with target": {Prefix: victim, Action: plugin.MitigationFlowSpecRateLimit, RateMbps: 5, Target: "scrub-vrf"},
		"redirect unknown":       {Prefix: victim, Action: plugin.MitigationFlowSpecRedirect, Target: "nowhere"},
		"redirect with rate":     {Prefix: victim, Action: plugin.MitigationFlowSpecRedirect, Target: "scrub-vrf", RateMbps: 1},
		"outside allowlist":      {Prefix: netip.MustParsePrefix("192.0.2.0/24"), Action: plugin.MitigationFlowSpecDrop},
		"v6 source on v4":        {Prefix: victim, Action: plugin.MitigationFlowSpecDrop, Match: plugin.FlowSpecMatch{Source: netip.MustParsePrefix("2001:db8::/32")}},
		"source host bits":       {Prefix: victim, Action: plugin.MitigationFlowSpecDrop, Match: plugin.FlowSpecMatch{Source: netip.MustParsePrefix("192.0.2.1/24")}},
		"source and countries":   {Prefix: victim, Action: plugin.MitigationFlowSpecDrop, Countries: []string{"XA"}, Match: plugin.FlowSpecMatch{Source: netip.MustParsePrefix("192.0.2.0/24")}},
		"lower-case country":     {Prefix: victim, Action: plugin.MitigationFlowSpecDrop, Countries: []string{"xa"}},
		"duplicate country":      {Prefix: victim, Action: plugin.MitigationFlowSpecDrop, Countries: []string{"XA", "XA"}},
		"country with no nets":   {Prefix: victim, Action: plugin.MitigationFlowSpecDrop, Countries: []string{"ZZ"}},
		"country past the cap":   {Prefix: victim, Action: plugin.MitigationFlowSpecDrop, Countries: []string{"XC"}},
		"too many ports": {Prefix: victim, Action: plugin.MitigationFlowSpecDrop, Match: plugin.FlowSpecMatch{
			DestinationPorts: []plugin.PortRange{{From: 1, To: 1}, {From: 2, To: 2}, {From: 3, To: 3}, {From: 4, To: 4}, {From: 5, To: 5}, {From: 6, To: 6}, {From: 7, To: 7}, {From: 8, To: 8}, {From: 9, To: 9}}}},
		"match on blackhole":     {Prefix: victim, Action: plugin.MitigationBlackhole, Match: udp53()},
		"countries on blackhole": {Prefix: victim, Action: plugin.MitigationBlackhole, Countries: []string{"XA"}},
		"rate on redirect":       {Prefix: victim, Action: plugin.MitigationRedirect, Target: "scrubber", RateMbps: 3},
	}
	for name, req := range bad {
		if _, err := c.Add(req, t0); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}

	// No FlowSpec on the announcer: refused. No GeoIP: countries refused.
	plain, err := New(testConfig(config.ModeInject), newFakeAnn(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.Add(Request{Prefix: victim, Action: plugin.MitigationFlowSpecDrop}, t0); err == nil || !strings.Contains(err.Error(), "flowspec is not configured") {
		t.Fatalf("flowspec without a flowspec announcer: %v", err)
	}
	cfg := testConfig(config.ModeInject)
	noGeo, _ := New(cfg, newFakeFSAnn(), nil)
	if _, err := noGeo.Add(Request{Prefix: victim, Action: plugin.MitigationFlowSpecDrop, Countries: []string{"XA"}}, t0); err == nil || !strings.Contains(err.Error(), "geoip_db") {
		t.Fatalf("countries without geoip: %v", err)
	}
	// Observe with no announcer: drop is a dry run; redirect needs a catalog.
	obs, _ := New(testConfig(config.ModeObserve), nil, nil)
	if _, err := obs.Add(Request{Prefix: victim, Action: plugin.MitigationFlowSpecDrop, Match: udp53()}, t0); err != nil {
		t.Fatalf("observe dry-run flowspec: %v", err)
	}
	if _, err := obs.Add(Request{Prefix: victim, Action: plugin.MitigationFlowSpecRedirect, Target: "scrub-vrf"}, t0); err == nil {
		t.Fatal("observe flowspec redirect without a catalog accepted")
	}
}

func TestFlowSpecInject(t *testing.T) {
	ctx := context.Background()
	c, ann, rib := newFSTest(t, config.ModeInject, 4)

	// A FlowSpec rule and an RTBH rule share a prefix; FlowSpec never
	// holds it against outbound improvements.
	drop, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationFlowSpecDrop, Match: udp53(), TTL: 10 * time.Minute, Reason: "dns flood"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if c.Holds(victim) {
		t.Fatal("a flowspec rule holds its prefix")
	}
	// Not in the learned RIB: held, never announced.
	if _, err := c.Add(Request{Prefix: other, Action: plugin.MitigationFlowSpecDrop, TTL: 10 * time.Minute}, t0); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx, t0); err != nil {
		t.Fatal(err)
	}
	fl := ann.flows()
	if len(fl) != 1 || fl[0].Destination != victim || fl[0].Action != plugin.MitigationFlowSpecDrop || fl[0].Community != "64512:666" ||
		fl[0].LocalPref != 250 || fl[0].Match.Key() != "proto=17 dport=53" {
		t.Fatalf("wire = %+v", fl)
	}
	st := c.Status()
	if st.Routes != 2 || st.OnWire != 1 || c.Active() != 1 {
		t.Fatalf("status counts = %d held, %d on wire", st.Routes, st.OnWire)
	}
	for _, r := range st.Rules {
		switch r.Prefix {
		case victim:
			if !r.Announced || r.FirstAnnounced != t0 {
				t.Fatalf("victim rule = %+v", r)
			}
		case other:
			if r.Announced || r.Pending != "not in the learned RIB" {
				t.Fatalf("other rule = %+v", r)
			}
		}
	}

	// Same match, new action: replaced in place, still one route.
	if _, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationFlowSpecRateLimit, RateMbps: 10, Match: udp53(), TTL: 10 * time.Minute}, t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx, t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if fl = ann.flows(); len(fl) != 1 || fl[0].Action != plugin.MitigationFlowSpecRateLimit || fl[0].RateMbps != 10 {
		t.Fatalf("after replace: %+v", fl)
	}

	// A country rule: two networks, two routes; the cap counts routes.
	cr, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationFlowSpecDrop, Countries: []string{"XB", "XA"},
		Match: plugin.FlowSpecMatch{Protocols: []plugin.IPProtocol{17}}, TTL: 5 * time.Minute}, t0.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if cr.Routes != 2 || !slices.Equal(cr.Countries, []string{"XA", "XB"}) ||
		!slices.Equal(cr.Sources, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/25"), netip.MustParsePrefix("203.0.113.128/25")}) {
		t.Fatalf("country rule = %+v", cr)
	}
	// The edge stops sending the prefix: routes on the wire stay, a new
	// one waits.
	delete(rib.learned, victim)
	if err := c.Sync(ctx, t0.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if fl = ann.flows(); len(fl) != 1 {
		t.Fatalf("country routes announced for a prefix not in the RIB: %+v", fl)
	}
	rib.learned[victim] = true
	if err := c.Sync(ctx, t0.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	fl = ann.flows()
	var srcs []string
	for _, r := range fl {
		if r.Match.Source.IsValid() {
			srcs = append(srcs, r.Match.Source.String())
		}
	}
	if len(fl) != 3 || !slices.Equal(srcs, []string{"192.0.2.0/25", "203.0.113.128/25"}) {
		t.Fatalf("country routes = %+v", fl)
	}

	// RTBH shares the cap: 4 routes held of 4, so it fits only once the
	// rule that waits is removed.
	if _, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationBlackhole, TTL: time.Minute}, t0.Add(3*time.Second)); !errors.Is(err, ErrFull) {
		t.Fatalf("fifth route: %v", err)
	}
	if !c.Remove(findID(c, other)) {
		t.Fatal("remove")
	}
	if _, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationBlackhole, TTL: time.Minute}, t0.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx, t0.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, ok := ann.on(victim); !ok || !c.Holds(victim) || c.Active() != 4 {
		t.Fatalf("rtbh next to flowspec: active %d", c.Active())
	}

	// Expiry: the country rule (5m) and RTBH (1m) go; the rate limit
	// (10m) stays.
	if err := c.Sync(ctx, t0.Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if fl = ann.flows(); len(fl) != 1 || fl[0].Action != plugin.MitigationFlowSpecRateLimit {
		t.Fatalf("after expiry: %+v", fl)
	}
	if _, ok := ann.on(victim); ok {
		t.Fatal("rtbh survived its ttl")
	}

	// RIB loss withdraws FlowSpec too.
	rib.ready = false
	if err := c.Sync(ctx, t0.Add(7*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(ann.flows()) != 0 || c.Active() != 0 {
		t.Fatal("rib loss left flowspec on the wire")
	}
	rib.ready = true
	if err := c.Sync(ctx, t0.Add(7*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(ann.flows()) != 1 {
		t.Fatal("flowspec not back after the rib recovered")
	}
	// Shutdown.
	if err := c.WithdrawAll(ctx); err != nil {
		t.Fatal(err)
	}
	if len(ann.flows()) != 0 || c.Active() != 0 {
		t.Fatal("WithdrawAll left flowspec on the wire")
	}

	// The feed tells the whole story, newest first.
	var kinds []string
	for _, ch := range c.Status().Feed {
		if ch.Rule.ID == drop.ID {
			kinds = append(kinds, ch.Kind)
		}
	}
	if !slices.Equal(kinds, []string{ChangeReplaced, ChangeAnnounced, ChangeAdded}) {
		t.Fatalf("feed for the first rule = %v", kinds)
	}
	changes := c.Changes()
	if len(changes) == 0 || len(c.Changes()) != 0 {
		t.Fatal("Changes must drain")
	}
	var last Change
	for _, ch := range changes {
		if ch.Kind == ChangeExpired && ch.Rule.Action == plugin.MitigationFlowSpecDrop {
			last = ch
		}
	}
	rec := Record(last)
	if rec.ID != cr.ID || rec.Routes != 2 || rec.Countries != "XA,XB" || rec.Match != "proto=17" || rec.End != t0.Add(6*time.Minute) ||
		rec.EndReason != ChangeExpired || rec.Announced != t0.Add(3*time.Second) || rec.Mode != config.ModeInject {
		t.Fatalf("record = %+v", rec)
	}
}

func TestFlowSpecObserveNeverAnnounces(t *testing.T) {
	c, ann, _ := newFSTest(t, config.ModeObserve, 4)
	if _, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationFlowSpecDrop, Countries: []string{"XA"}}, t0); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(context.Background(), t0); err != nil {
		t.Fatal(err)
	}
	if len(ann.flows()) != 0 || c.Active() != 0 {
		t.Fatal("observe announced flowspec")
	}
	st := c.Status()
	if st.Rules[0].Announced || !strings.Contains(st.Rules[0].Pending, "dry run") || !st.GeoIP || !st.FlowSpec.Enabled {
		t.Fatalf("observe status = %+v", st)
	}
}

func TestFlowSpecAnnounceError(t *testing.T) {
	c, ann, _ := newFSTest(t, config.ModeInject, 4)
	ann.fail = errors.New("speaker down")
	if _, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationFlowSpecDrop}, t0); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(context.Background(), t0); err == nil {
		t.Fatal("announce error not returned")
	}
	if st := c.Status(); st.Rules[0].Announced || st.Rules[0].Pending != "speaker down" || c.Active() != 0 {
		t.Fatalf("status = %+v", st.Rules)
	}
}

func findID(c *Controller, p netip.Prefix) string {
	for _, r := range c.Status().Rules {
		if r.Prefix == p {
			return r.ID
		}
	}
	return ""
}

// Different rules can expand to the same FlowSpec route. Add refuses the
// second, and should two ever share a route, the lowest rule key owns it
// every round, so the edge never sees it flap.
func TestFlowSpecOverlapRefused(t *testing.T) {
	ctx := context.Background()
	c, _, _ := newFSTest(t, config.ModeInject, 10)
	xa, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationFlowSpecDrop, Countries: []string{"XA"}, TTL: 10 * time.Minute}, t0)
	if err != nil {
		t.Fatal(err)
	}
	// XA is 192.0.2.0/25: a rule on that source is the same route.
	for name, req := range map[string]Request{
		"source is a country network": {Prefix: victim, Action: plugin.MitigationFlowSpecRateLimit, RateMbps: 8,
			Match: plugin.FlowSpecMatch{Source: netip.MustParsePrefix("192.0.2.0/25")}},
		"country superset": {Prefix: victim, Action: plugin.MitigationFlowSpecDrop, Countries: []string{"XA", "XB"}},
	} {
		req.TTL = 10 * time.Minute
		_, err := c.Add(req, t0)
		if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), xa.ID) {
			t.Fatalf("%s: err = %v, want ErrConflict naming %s", name, err, xa.ID)
		}
	}
	// Same key replaces; a different source or match does not collide.
	if _, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationFlowSpecRateLimit, RateMbps: 8, Countries: []string{"XA"}, TTL: 10 * time.Minute}, t0); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if _, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationFlowSpecDrop, TTL: 10 * time.Minute,
		Match: plugin.FlowSpecMatch{Source: netip.MustParsePrefix("192.0.2.0/26")}}, t0); err != nil {
		t.Fatalf("narrower source: %v", err)
	}
	if _, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationFlowSpecDrop, Countries: []string{"XB"}, Match: udp53(), TTL: 10 * time.Minute}, t0); err != nil {
		t.Fatalf("other country: %v", err)
	}
	if st := c.Status(); st.Routes != 3 {
		t.Fatalf("routes held = %d, want 3", st.Routes)
	}

	// Force a shared route past Add: the owner must never change.
	c2, ann2, _ := newFSTest(t, config.ModeInject, 10)
	a, err := c2.Add(Request{Prefix: victim, Action: plugin.MitigationFlowSpecDrop, Countries: []string{"XA"}, TTL: 10 * time.Minute}, t0)
	if err != nil {
		t.Fatal(err)
	}
	b := &Rule{ID: "b", Prefix: victim, Action: plugin.MitigationFlowSpecRateLimit, RateMbps: 8, Routes: 1, Created: t0, Expires: t0.Add(time.Hour),
		Match: &plugin.FlowSpecMatch{Source: netip.MustParsePrefix("192.0.2.0/25")}}
	b.key = "flowspec dst=" + victim.String() + " " + b.MatchText() + " countries="
	c2.mu.Lock()
	c2.rules[b.key] = b
	winner, loser := a.ID, "b"
	for k, r := range c2.rules {
		if r.ID == a.ID && b.key < k {
			winner, loser = "b", a.ID
		}
	}
	c2.mu.Unlock()
	for i := range 50 {
		if err := c2.Sync(ctx, t0.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	withdrawn := 0
	st := c2.Status()
	for _, ch := range st.Feed {
		if ch.Kind == ChangeWithdrawn {
			withdrawn++
		}
	}
	if withdrawn != 0 {
		t.Fatalf("%d withdrawals over 50 syncs", withdrawn)
	}
	for _, r := range st.Rules {
		switch r.ID {
		case winner:
			if !r.Announced {
				t.Fatalf("winner %+v not announced", r)
			}
		case loser:
			if r.Announced || !strings.Contains(r.Pending, "sent by rule "+winner) {
				t.Fatalf("loser %+v", r)
			}
		}
	}
	if fl := ann2.flows(); len(fl) != 1 {
		t.Fatalf("wire = %+v", fl)
	}
}

// A rule waiting for its prefix logs the warning once, not every round.
func TestFlowSpecWaitLogsOnce(t *testing.T) {
	var buf bytes.Buffer
	ann := newFakeFSAnn()
	cfg := testConfig(config.ModeInject)
	c, err := New(cfg, ann, slog.New(slog.NewTextHandler(&buf, nil)))
	if err != nil {
		t.Fatal(err)
	}
	rib := &fakeRIB{ready: true, learned: map[netip.Prefix]bool{}}
	if err := c.SetRIB(rib); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Add(Request{Prefix: victim, Action: plugin.MitigationFlowSpecDrop, TTL: 10 * time.Minute}, t0); err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if err := c.Sync(context.Background(), t0.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(buf.String(), "mitigation flowspec rule waits"); n != 1 {
		t.Fatalf("waits logged %d times, want 1", n)
	}
	if st := c.Status(); st.Rules[0].Pending != pendingRIB {
		t.Fatalf("pending = %q", st.Rules[0].Pending)
	}
}
