package extpolicy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/announce"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// fakeAnn is an embedded announcer; refuse fails Announce for a prefix and
// failWithdraw fails every withdraw.
type fakeAnn struct {
	plugin.Base
	on           map[netip.Prefix]plugin.Route
	refuse       netip.Prefix
	failWithdraw bool
	bound        bool
}

func newFakeAnn() *fakeAnn { return &fakeAnn{on: map[netip.Prefix]plugin.Route{}} }

func (a *fakeAnn) Announce(_ context.Context, r plugin.Route) error {
	if r.Prefix == a.refuse {
		return errors.New("refused")
	}
	a.on[r.Prefix] = r
	return nil
}

func (a *fakeAnn) Withdraw(_ context.Context, p netip.Prefix) error {
	if a.failWithdraw {
		return errors.New("withdraw failed")
	}
	delete(a.on, p)
	return nil
}

func (a *fakeAnn) WithdrawAll(context.Context) error {
	if a.failWithdraw {
		return errors.New("withdraw failed")
	}
	clear(a.on)
	return nil
}

func (a *fakeAnn) Bind(any, string) error { a.bound = true; return nil }

// fakeRIB has every prefix in learned.
type fakeRIB struct {
	ready   bool
	learned map[netip.Prefix]bool
}

func (r *fakeRIB) Ready() bool                                 { return r.ready }
func (r *fakeRIB) Contains(p netip.Prefix) bool                { return r.learned[p] }
func (r *fakeRIB) MoreSpecifics([]netip.Prefix) []netip.Prefix { return nil }

var (
	pA       = netip.MustParsePrefix("198.51.100.0/24")
	pB       = netip.MustParsePrefix("203.0.113.0/24")
	pNotRIB  = netip.MustParsePrefix("198.51.100.128/25")
	pNotList = netip.MustParsePrefix("192.0.2.0/24")
	nhB      = netip.MustParseAddr("198.51.100.2")
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func controller(t *testing.T, ann plugin.Announcer, rib *fakeRIB, max int) *announce.Controller {
	t.Helper()
	ctl, err := announce.New(announce.Config{
		Mode: config.ModeInject, LocalPref: 250, Community: "64512:666", MaxImprovements: max,
		CauseCommunities: map[string][]string{plugin.CauseCost: {"64512:700"}},
		Allowlist:        []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24")},
		NextHops:         map[string]netip.Addr{"transit-b": nhB},
	}, ann, rib, quiet())
	if err != nil {
		t.Fatal(err)
	}
	if err := ctl.Bind(struct{}{}); err != nil {
		t.Fatal(err)
	}
	return ctl
}

func imps() []policy.Improvement {
	return []policy.Improvement{
		{Prefix: pA, Provider: "transit-b", Reason: "loss 0% vs 5%"},
		{Prefix: pB, Provider: "transit-b", Cause: plugin.CauseCost, Reason: "cheaper"},
		{Prefix: pNotRIB, Provider: "transit-b", Reason: "not learned"},
		{Prefix: pNotList, Provider: "transit-b", Reason: "not allowlisted"},
	}
}

// The feed is fed by the announce controller, so it applies the same rails
// as inject: a prefix outside the allowlist or the learned RIB, or over the
// cap, never reaches it, and with an embedded announcer it lists exactly
// what that announcer holds. Feed only (no announcer) lists the same set.
func TestFeedCarriesWhatInjectAnnounces(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	rib := &fakeRIB{ready: true, learned: map[netip.Prefix]bool{pA: true, pB: true, pNotList: true}}
	inner := newFakeAnn()
	both := New(true, 30*time.Second, func() time.Time { return now })
	ctl := controller(t, NewMirror(inner, both), rib, 50)
	if !inner.bound {
		t.Fatal("the embedded announcer was not bound through the mirror")
	}
	if err := ctl.Sync(context.Background(), imps()); err == nil {
		t.Fatal("Sync accepted a prefix outside the allowlist or the RIB")
	}
	both.Touch(now, imps())

	only := New(true, 30*time.Second, func() time.Time { return now })
	ctlOnly := controller(t, NewMirror(nil, only), rib, 50)
	_ = ctlOnly.Sync(context.Background(), imps())
	only.Touch(now, imps())

	doc := both.Document()
	var got []netip.Prefix
	for _, r := range doc.Routes {
		got = append(got, r.Prefix)
		w, ok := inner.on[r.Prefix]
		if !ok || w.NextHop != r.NextHop || w.LocalPref != r.LocalPref || !slices.Equal(append(slices.Clone(w.Communities), NoExport), r.Communities) {
			t.Errorf("feed route %+v is not what the announcer holds (%+v)", r, w)
		}
	}
	if want := []netip.Prefix{pA, pB}; !slices.Equal(got, want) || len(inner.on) != 2 {
		t.Fatalf("feed prefixes %v, announcer %d routes; want %v", got, len(inner.on), want)
	}
	a, b := doc.Routes[0], doc.Routes[1]
	if a.Cause != plugin.CausePerformance || a.Reason != "loss 0% vs 5%" || !slices.Equal(a.Communities, []string{"64512:666", NoExport}) {
		t.Errorf("performance route %+v", a)
	}
	if b.Cause != plugin.CauseCost || !slices.Equal(b.Communities, []string{"64512:666", "64512:700", NoExport}) || b.Provider != "transit-b" || b.NextHop != nhB {
		t.Errorf("cost route %+v", b)
	}
	if !slices.EqualFunc(doc.Routes, only.Document().Routes, sameRoute) {
		t.Errorf("feed only %+v differs from feed beside the announcer %+v", only.Document().Routes, doc.Routes)
	}

	capped := New(true, 30*time.Second, func() time.Time { return now })
	_ = controller(t, NewMirror(nil, capped), rib, 1).Sync(context.Background(), imps())
	capped.Touch(now, imps())
	if n := len(capped.Document().Routes); n != 1 {
		t.Errorf("max_improvements 1: feed has %d routes", n)
	}
}

// A route the announcer refused is not in the feed; one it failed to
// withdraw stays, because it is still on the wire. RIB loss withdraws
// everything, in the feed too.
func TestMirrorFollowsTheWire(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	rib := &fakeRIB{ready: true, learned: map[netip.Prefix]bool{pA: true, pB: true}}
	inner := newFakeAnn()
	inner.refuse = pB
	feed := New(true, 30*time.Second, func() time.Time { return now })
	ctl := controller(t, NewMirror(inner, feed), rib, 50)
	_ = ctl.Sync(context.Background(), imps()[:2])
	feed.Touch(now, imps())
	if r := feed.Document().Routes; len(r) != 1 || r[0].Prefix != pA {
		t.Fatalf("after a refused announce the feed has %+v, want only %s", r, pA)
	}
	inner.failWithdraw = true
	if err := ctl.Sync(context.Background(), nil); err == nil {
		t.Fatal("withdraw error not returned")
	}
	feed.Touch(now, nil)
	if r := feed.Document().Routes; len(r) != 1 {
		t.Fatalf("a route the announcer still holds left the feed: %+v", r)
	}
	inner.failWithdraw = false
	rib.ready = false
	if err := ctl.Sync(context.Background(), imps()[:1]); err != nil {
		t.Fatal(err)
	}
	feed.Touch(now, imps())
	if r := feed.Document().Routes; len(r) != 0 || len(inner.on) != 0 {
		t.Fatalf("RIB loss: feed %+v, announcer %d routes", r, len(inner.on))
	}
}

// The expiry runs from the last round; past it the document has no routes
// and no time left, so a consumer drops everything.
func TestFeedExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	feed := New(true, 9*time.Second, func() time.Time { return now })
	if d := feed.Document(); len(d.Routes) != 0 || d.ExpiresInMS != 0 {
		t.Fatalf("before the first round: %+v", d)
	}
	feed.set(plugin.Route{Prefix: pA, Provider: "transit-b", NextHop: nhB, LocalPref: 250, Communities: []string{"64512:666"}})
	t0 := now
	feed.Touch(t0, nil)
	rev := feed.Document().Revision
	now = t0.Add(5 * time.Second)
	d := feed.Document()
	if len(d.Routes) != 1 || d.ExpiresInMS != 4000 || !d.ExpiresAt.Equal(t0.Add(9*time.Second)) || d.HeartbeatMS != 3000 {
		t.Fatalf("inside the TTL: %+v", d)
	}
	feed.Touch(now, nil)
	if feed.Document().Revision != rev {
		t.Error("a round with the same routes changed the revision")
	}
	if d := feed.Document(); d.ExpiresInMS != 9000 {
		t.Errorf("a round did not renew the expiry: %+v", d)
	}
	now = now.Add(9 * time.Second)
	if d := feed.Document(); len(d.Routes) != 0 || d.ExpiresInMS != 0 {
		t.Fatalf("past the TTL: %+v", d)
	}
}

// Turning the feed off publishes an empty, expired set at once and wakes
// streams; on again, the routes return. Close is final.
func TestFeedToggleAndClose(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	feed := New(true, 30*time.Second, func() time.Time { return now })
	feed.set(plugin.Route{Prefix: pA, Provider: "transit-b", NextHop: nhB, LocalPref: 250, Communities: []string{"64512:666"}})
	feed.Touch(now, nil)
	rev := feed.Document().Revision
	ch, _ := feed.Changed()
	feed.SetRuntime(false, 30*time.Second)
	select {
	case <-ch:
	default:
		t.Fatal("turning the feed off did not wake streams")
	}
	d := feed.Document()
	if len(d.Routes) != 0 || d.ExpiresInMS != 0 || d.Revision == rev || !d.ExpiresAt.Equal(now) {
		t.Fatalf("off: %+v", d)
	}
	if feed.Routes() != 0 {
		t.Error("Routes counts routes while off")
	}
	feed.SetRuntime(true, 30*time.Second)
	if feed.Routes() != 1 {
		t.Fatal("on again: the routes on the wire are not published")
	}
	before := feed.Document().Revision
	feed.SetRuntime(true, time.Minute)
	if d := feed.Document(); d.Revision == before || d.HeartbeatMS != 20_000 {
		t.Fatalf("a ttl change must answer long polls with the new heartbeat: %+v", d)
	}
	feed.Close()
	feed.Touch(now, nil)
	if _, done := feed.Changed(); !done || feed.Routes() != 0 {
		t.Fatal("closed feed still publishes")
	}
	var nilFeed *Feed
	nilFeed.Touch(now, nil)
	nilFeed.Close()
}

// A learned more-specific announced with an improvement carries that
// improvement's cause and reason.
func TestImprovementForMoreSpecific(t *testing.T) {
	sub := netip.MustParsePrefix("198.51.100.64/26")
	list := []policy.Improvement{
		{Prefix: netip.MustParsePrefix("198.51.0.0/16"), Reason: "wide"},
		{Prefix: pA, Reason: "narrow", Cause: plugin.CauseCommit},
	}
	by := map[netip.Prefix]policy.Improvement{}
	for _, im := range list {
		by[im.Prefix] = im
	}
	if im := improvementFor(sub, by, list); im.Reason != "narrow" {
		t.Errorf("more-specific got %+v, want the closest covering improvement", im)
	}
	if im := improvementFor(pB, by, list); im.Prefix.IsValid() {
		t.Errorf("unrelated prefix got %+v", im)
	}
}

// Without an embedded announcer the mirror makes the announcer's checks
// before a route reaches the feed.
func TestMirrorChecksWithoutAnnouncer(t *testing.T) {
	feed := New(true, 30*time.Second, nil)
	m := NewMirror(nil, feed)
	ok := plugin.Route{Prefix: pA, Provider: "transit-b", NextHop: nhB, LocalPref: 250, Communities: []string{"64512:666"}}
	if err := m.Announce(context.Background(), ok); err == nil {
		t.Fatal("announced before Bind")
	}
	if err := m.Bind(nil, "64512:666"); err != nil {
		t.Fatal(err)
	}
	bad := func(edit func(*plugin.Route)) plugin.Route { r := ok; edit(&r); return r }
	for name, r := range map[string]plugin.Route{
		"unmasked":     bad(func(r *plugin.Route) { r.Prefix = netip.MustParsePrefix("198.51.100.1/24") }),
		"family":       bad(func(r *plugin.Route) { r.NextHop = netip.MustParseAddr("2001:db8::1") }),
		"local_pref 0": bad(func(r *plugin.Route) { r.LocalPref = 0 }),
		"no community": bad(func(r *plugin.Route) { r.Communities = []string{"64512:700"} }),
		"no next hop":  bad(func(r *plugin.Route) { r.NextHop = netip.Addr{} }),
	} {
		if err := m.Announce(context.Background(), r); err == nil {
			t.Errorf("%s: accepted %+v", name, r)
		}
	}
	if err := m.Announce(context.Background(), ok); err != nil {
		t.Fatal(err)
	}
	feed.Touch(time.Now(), nil)
	if n := feed.Routes(); n != 1 {
		t.Fatalf("feed has %d routes, want only the valid one", n)
	}
}

// A withdraw outside a decision round (leak watch, HA step-down, a reload
// that leaves inject) reaches the published document at once, with a new
// revision and a change signal, without waiting for the next Touch.
func TestMirrorWithdrawPublishesAtOnce(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	rib := &fakeRIB{ready: true, learned: map[netip.Prefix]bool{pA: true, pB: true}}
	feed := New(true, 30*time.Second, func() time.Time { return now })
	m := NewMirror(newFakeAnn(), feed)
	_ = controller(t, m, rib, 50).Sync(context.Background(), imps()[:2])
	feed.Touch(now, imps())
	if n := len(feed.Document().Routes); n != 2 {
		t.Fatalf("feed has %d routes, want 2", n)
	}
	rev := feed.Document().Revision
	ch, _ := feed.Changed()
	if err := m.Withdraw(context.Background(), pA); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch:
	default:
		t.Fatal("Withdraw did not signal a change")
	}
	doc := feed.Document()
	if len(doc.Routes) != 1 || doc.Routes[0].Prefix != pB || doc.Revision == rev {
		t.Fatalf("after Withdraw: rev %d routes %+v, want only %s at a new revision", doc.Revision, doc.Routes, pB)
	}
	ch, _ = feed.Changed()
	if err := m.WithdrawAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch:
	default:
		t.Fatal("WithdrawAll did not signal a change")
	}
	if n := len(feed.Document().Routes); n != 0 {
		t.Fatalf("after WithdrawAll the feed has %d routes", n)
	}
}
