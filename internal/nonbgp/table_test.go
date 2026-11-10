package nonbgp

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fakeCovering struct {
	plugin.Base
	mu    sync.Mutex
	calls []netip.Addr
	ans   netip.Prefix
	asn   uint32
	err   error
}

func (f *fakeCovering) Covering(_ context.Context, a netip.Addr) (plugin.Announced, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, a)
	return plugin.Announced{Prefix: f.ans, Origin: f.asn}, f.err
}

func (f *fakeCovering) set(p netip.Prefix, err error) {
	f.mu.Lock()
	f.ans, f.err = p, err
	f.mu.Unlock()
}

func (f *fakeCovering) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func newTestTable(widen int, cov plugin.Covering) (*Table, *clock) {
	c := &clock{t: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	return NewTable(Options{WidenBits: widen, Idle: 30 * time.Minute, MaxBlocks: 100, Now: c.now}, cov), c
}

// announce is a lookup answer of upper for every tracked block inside it,
// unless the block already sits in a more specific announced prefix.
func announce(t *Table, upper netip.Prefix, origin uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.known[upper] = origin
	for blk, b := range t.blocks {
		if upper.Contains(blk.Addr()) && (!b.upper.IsValid() || b.upper.Bits() < upper.Bits()) {
			b.upper, b.origin, b.own = upper, origin, true
		}
	}
}

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func addr(s string) netip.Addr  { return netip.MustParseAddr(s) }

func routePrefixes(t *Table) []string {
	var out []string
	for _, r := range t.Routes() {
		out = append(out, r.Prefix.String())
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestLookupRoundsToFloor(t *testing.T) {
	tbl, _ := newTestTable(4, nil)
	for in, want := range map[string]string{
		"203.0.113.77":      "203.0.113.0/24",
		"::ffff:192.0.2.9":  "192.0.2.0/24",
		"2001:db8:1:2::5":   "2001:db8:1::/48",
		"2001:db8:1:ffff::": "2001:db8:1::/48",
	} {
		got, ok := tbl.Lookup(addr(in))
		if !ok || got != pfx(want) {
			t.Errorf("Lookup(%s) = %s %v, want %s", in, got, ok, want)
		}
	}
	if _, ok := tbl.Lookup(netip.Addr{}); ok {
		t.Error("an invalid address was tracked")
	}
	tbl.Refresh()
	if got, want := routePrefixes(tbl), []string{"192.0.2.0/24", "203.0.113.0/24", "2001:db8:1::/48"}; !equal(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
}

func TestWidenWithinAnnouncedPrefixThenNarrow(t *testing.T) {
	cov := &fakeCovering{ans: pfx("2001:db8::/32")}
	tbl, clk := newTestTable(4, cov)
	tbl.Lookup(addr("2001:db8:1::10"))
	tbl.Refresh()
	if got := routePrefixes(tbl); !equal(got, []string{"2001:db8:1::/48"}) {
		t.Fatalf("one block routes = %v", got)
	}
	if !tbl.lookupOne(context.Background()) {
		t.Fatal("no lookup was due")
	}
	tbl.Refresh()
	// One active block stays at its floor even though the announced prefix is wide.
	if got := routePrefixes(tbl); !equal(got, []string{"2001:db8:1::/48"}) {
		t.Fatalf("after lookup with one block, routes = %v", got)
	}

	clk.add(time.Minute)
	tbl.Lookup(addr("2001:db8:2::10"))
	tbl.Refresh()
	got := tbl.Routes()
	if len(got) != 1 || got[0].Prefix != pfx("2001:db8::/46") || got[0].Blocks != 2 || got[0].Upper != pfx("2001:db8::/32") {
		t.Fatalf("widened routes = %+v", got)
	}
	// The flow source now counts both blocks under the wide prefix.
	if p, _ := tbl.Lookup(addr("2001:db8:1::99")); p != pfx("2001:db8::/46") {
		t.Fatalf("Lookup after widening = %s", p)
	}
	if cov.count() != 1 {
		t.Fatalf("covering asked %d times; the second block sits in the known announced prefix", cov.count())
	}

	// Only the second block keeps getting flow: the first ages out and the route narrows.
	clk.add(20 * time.Minute)
	tbl.Lookup(addr("2001:db8:2::11"))
	clk.add(20 * time.Minute)
	tbl.Refresh()
	got = tbl.Routes()
	if len(got) != 1 || got[0].Prefix != pfx("2001:db8:2::/48") || got[0].Blocks != 1 {
		t.Fatalf("narrowed routes = %+v", got)
	}
	clk.add(time.Hour)
	tbl.Refresh()
	if len(tbl.Routes()) != 0 || tbl.Has(pfx("2001:db8:2::/48")) {
		t.Fatalf("idle blocks were kept: %v", routePrefixes(tbl))
	}
}

func TestWidenStopsAtAnnouncedPrefix(t *testing.T) {
	cov := &fakeCovering{ans: pfx("2001:db8:0:8000::/49")}
	tbl, _ := newTestTable(8, cov)
	// An announced prefix more specific than the floor bounds nothing.
	tbl.Lookup(addr("2001:db8:0:1::1"))
	tbl.lookupOne(context.Background())
	tbl.Refresh()
	if got := routePrefixes(tbl); !equal(got, []string{"2001:db8::/48"}) {
		t.Fatalf("routes = %v", got)
	}
	if r := tbl.Routes(); r[0].Upper.IsValid() {
		t.Fatalf("a block that is not inside an announced prefix has the bound %s", r[0].Upper)
	}
	if tbl.lookupOne(context.Background()) || cov.count() != 1 {
		t.Fatalf("a settled block was asked again (%d calls)", cov.count())
	}
	// Blocks outside the announced prefix never merge with it.
	tbl2, _ := newTestTable(8, &fakeCovering{ans: pfx("2001:db8:1::/48")})
	tbl2.Lookup(addr("2001:db8:1::1"))
	tbl2.Lookup(addr("2001:db8:2::1"))
	for tbl2.lookupOne(context.Background()) {
	}
	tbl2.Refresh()
	if got := routePrefixes(tbl2); !equal(got, []string{"2001:db8:1::/48", "2001:db8:2::/48"}) {
		t.Fatalf("blocks outside the announced prefix merged: %v", got)
	}
}

func TestWidenBitsBoundAndZero(t *testing.T) {
	// Announced /32, widen 2: the /48 blocks 0 and 3 share /46 only if inside the 2-bit limit, which is /46.
	cov := &fakeCovering{ans: pfx("2001:db8::/32")}
	tbl, _ := newTestTable(2, cov)
	tbl.Lookup(addr("2001:db8::1"))
	tbl.Lookup(addr("2001:db8:3::1"))
	tbl.Lookup(addr("2001:db8:4::1"))
	for tbl.lookupOne(context.Background()) {
	}
	tbl.Refresh()
	if got := routePrefixes(tbl); !equal(got, []string{"2001:db8::/46", "2001:db8:4::/48"}) {
		t.Fatalf("widen_bits 2 routes = %v", got)
	}

	// widen_bits 0 never widens, but the announced prefix is still looked up
	// and shown.
	asked := &fakeCovering{ans: pfx("2001:db8::/32"), asn: 64500}
	zero, _ := newTestTable(0, asked)
	zero.Lookup(addr("2001:db8:1::1"))
	zero.Lookup(addr("2001:db8:2::1"))
	for zero.lookupOne(context.Background()) {
	}
	zero.Refresh()
	if got := routePrefixes(zero); !equal(got, []string{"2001:db8:1::/48", "2001:db8:2::/48"}) {
		t.Fatalf("widen_bits 0 routes = %v", got)
	}
	if r := zero.Routes(); r[0].Upper != pfx("2001:db8::/32") || r[0].Origin != 64500 {
		t.Fatalf("widen_bits 0 bound = %+v", r[0])
	}
}

func TestNestedGroupsMergeIntoOneRoute(t *testing.T) {
	tbl, _ := newTestTable(4, nil)
	// Block 2 sits in a /46 announced prefix, blocks 4 to 11 in a /44 that
	// holds it: grouped apart they would make /48 inside /44.
	for _, a := range []string{"2001:db8:2::1", "2001:db8:4::1", "2001:db8:5::1", "2001:db8:6::1", "2001:db8:7::1", "2001:db8:8::1", "2001:db8:9::1", "2001:db8:a::1", "2001:db8:b::1"} {
		tbl.Lookup(addr(a))
	}
	announce(tbl, pfx("2001:db8::/46"), 64501)
	announce(tbl, pfx("2001:db8::/44"), 64500)
	tbl.Refresh()
	got := tbl.Routes()
	if len(got) != 1 || got[0].Prefix != pfx("2001:db8::/44") || got[0].Blocks != 9 || got[0].Upper != pfx("2001:db8::/44") || got[0].Origin != 64500 {
		t.Fatalf("routes = %+v", got)
	}
	if p, _ := tbl.Lookup(addr("2001:db8:2::99")); p != pfx("2001:db8::/44") {
		t.Fatalf("Lookup = %s, want the merged prefix", p)
	}
}

// A widened prefix holds at least as many blocks with flow as idle ones, so
// two /48s far apart in an announced /44 are never one /44 route (#300).
func TestWidenedPrefixIsAtLeastHalfActive(t *testing.T) {
	table := func(addrs ...string) *Table {
		tbl, _ := newTestTable(4, nil)
		for _, a := range addrs {
			tbl.Lookup(addr(a))
		}
		announce(tbl, pfx("2001:db8::/44"), 64500)
		tbl.Refresh()
		return tbl
	}
	if got := routePrefixes(table("2001:db8::1", "2001:db8:f::1")); !equal(got, []string{"2001:db8::/48", "2001:db8:f::/48"}) {
		t.Fatalf("two /48s in a /44 widened over idle space: %v", got)
	}
	// Three of the four /48s of a /46 have flow: one /46 with one idle /48.
	if got := routePrefixes(table("2001:db8:4::1", "2001:db8:5::1", "2001:db8:7::1")); !equal(got, []string{"2001:db8:4::/46"}) {
		t.Fatalf("routes = %v", got)
	}
	// Two of the four, at the ends of a /46: half idle is allowed. A third
	// block in the next /46 does not make a /45 that is five-eighths idle.
	if got := routePrefixes(table("2001:db8:4::1", "2001:db8:7::1", "2001:db8:9::1")); !equal(got, []string{"2001:db8:4::/46", "2001:db8:9::/48"}) {
		t.Fatalf("routes = %v", got)
	}
}

func TestCoveringFailureKeepsFloorAndRetries(t *testing.T) {
	cov := &fakeCovering{err: errors.New("lookup service down")}
	tbl, clk := newTestTable(4, cov)
	tbl.Lookup(addr("2001:db8:1::1"))
	tbl.Lookup(addr("2001:db8:2::1"))
	for tbl.lookupOne(context.Background()) {
	}
	tbl.Refresh()
	if got := routePrefixes(tbl); !equal(got, []string{"2001:db8:1::/48", "2001:db8:2::/48"}) {
		t.Fatalf("a failed lookup widened the routes: %v", got)
	}
	st := tbl.Stats()
	if st.LookupErrors != 2 || st.LastError != "lookup service down" || st.Pending != 0 {
		t.Fatalf("stats = %+v", st)
	}
	if tbl.lookupOne(context.Background()) {
		t.Fatal("a failed block was asked again before the retry delay")
	}
	clk.add(lookupRetry)
	cov.set(pfx("2001:db8::/32"), nil)
	if st := tbl.Stats(); st.Pending != 2 {
		t.Fatalf("pending after the delay = %d, want 2", st.Pending)
	}
	for tbl.lookupOne(context.Background()) {
	}
	tbl.Refresh()
	if got := routePrefixes(tbl); !equal(got, []string{"2001:db8::/46"}) {
		t.Fatalf("routes after retry = %v", got)
	}
}

func TestCoveringAnswersAreChecked(t *testing.T) {
	for name, ans := range map[string]netip.Prefix{
		"default":       pfx("::/0"),
		"wrong family":  pfx("192.0.2.0/24"),
		"does not hold": pfx("2001:db8:9::/48"),
		"zero":          {},
		"v4 default":    pfx("0.0.0.0/0"),
	} {
		cov := &fakeCovering{ans: ans}
		tbl, _ := newTestTable(4, cov)
		tbl.Lookup(addr("2001:db8:1::1"))
		tbl.Lookup(addr("2001:db8:2::1"))
		for tbl.lookupOne(context.Background()) {
		}
		tbl.Refresh()
		if got := routePrefixes(tbl); !equal(got, []string{"2001:db8:1::/48", "2001:db8:2::/48"}) {
			t.Errorf("%s: answer %s changed the routes: %v", name, ans, got)
		}
		if tbl.Stats().LookupErrors != 2 {
			t.Errorf("%s: errors = %d, want 2", name, tbl.Stats().LookupErrors)
		}
	}
}

func TestBlockCap(t *testing.T) {
	tbl, _ := newTestTable(4, nil)
	tbl.opt.MaxBlocks = 2
	tbl.Lookup(addr("192.0.2.1"))
	tbl.Lookup(addr("198.51.100.1"))
	if p, ok := tbl.Lookup(addr("203.0.113.1")); ok || p.IsValid() {
		t.Fatalf("a block past the cap was tracked: %s", p)
	}
	if _, ok := tbl.Lookup(addr("192.0.2.200")); !ok {
		t.Fatal("a tracked block was refused at the cap")
	}
	if st := tbl.Stats(); st.Blocks != 2 || st.Dropped != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestUpperAndFill(t *testing.T) {
	cov := &fakeCovering{ans: pfx("2001:db8::/32"), asn: 64496}
	tbl, _ := newTestTable(4, cov)
	tbl.Lookup(addr("2001:db8:1::1"))
	tbl.Lookup(addr("203.0.113.1"))
	for tbl.lookupOne(context.Background()) {
	}
	tbl.Refresh()
	got := tbl.Routes()
	if len(got) != 2 || got[0].Prefix != pfx("203.0.113.0/24") || got[0].Upper.IsValid() || got[1].Upper != pfx("2001:db8::/32") || got[1].Origin != 64496 {
		t.Fatalf("routes = %+v, want the v6 block bounded by its announced prefix and origin, the v4 one unbounded", got)
	}

	in := policy.Input{Results: []probe.Result{
		{Prefix: pfx("2001:db8:1::/48"), Provider: "isp-a"},
		{Prefix: pfx("2001:db8:1::/48"), Provider: "isp-b"},
		{Prefix: pfx("192.0.2.0/24"), Provider: "isp-a"},
	}}
	tbl.Fill(&in, "isp-a")
	if !in.RIBEnabled || !in.RIBReady {
		t.Fatal("Fill left the RIB flags off")
	}
	if in.Native[pfx("2001:db8:1::/48")] != "isp-a" {
		t.Fatalf("Native = %v", in.Native)
	}
	if _, ok := in.Native[pfx("192.0.2.0/24")]; ok {
		t.Fatal("a prefix outside the table got a native provider")
	}
}

func TestLookupIsSafeConcurrently(t *testing.T) {
	tbl, _ := newTestTable(4, &fakeCovering{ans: pfx("2001:db8::/32")})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				tbl.Lookup(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, byte(i % 16), 0, 1}))
				if i%50 == 0 {
					tbl.Refresh()
					tbl.lookupOne(context.Background())
				}
			}
		}()
	}
	wg.Wait()
	tbl.Refresh()
	if st := tbl.Stats(); st.Blocks != 16 {
		t.Fatalf("blocks = %d, want 16", st.Blocks)
	}
}

func TestRunStopsWithContext(t *testing.T) {
	cov := &fakeCovering{ans: pfx("2001:db8::/32")}
	tbl, _ := newTestTable(4, cov)
	tbl.Lookup(addr("2001:db8:1::1"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { tbl.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for cov.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if cov.count() == 0 {
		t.Fatal("Run asked for no covering prefix")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop with its context")
	}
}

func TestReportJoinsRoutesWithSteeredOnes(t *testing.T) {
	tbl, _ := newTestTable(4, nil)
	tbl.Lookup(addr("198.51.100.5"))
	tbl.Lookup(addr("203.0.113.5"))
	tbl.Refresh()
	rig := newRig(t, true, 5)
	rig.live = map[netip.Prefix]bool{pfx("198.51.100.0/24"): true}
	if err := rig.s.Sync(context.Background(), []policy.Improvement{imp("198.51.100.0/24", "isp-b")}); err != nil {
		t.Fatal(err)
	}
	st := Report(Meta{Mode: "inject", DefaultProvider: "isp-a"}, tbl, rig.s)
	if st.Mode != "inject" || st.Blocks != 2 || len(st.Routes) != 2 {
		t.Fatalf("status = %+v", st)
	}
	a, b := st.Routes[0], st.Routes[1]
	if a.Prefix != pfx("198.51.100.0/24") || a.SteeredTo != "isp-b" || a.NextHop != addr("198.51.100.1") || a.SteeredSince.IsZero() {
		t.Fatalf("steered row = %+v", a)
	}
	if b.Prefix != pfx("203.0.113.0/24") || b.SteeredTo != "" || b.NextHop.IsValid() {
		t.Fatalf("unsteered row = %+v", b)
	}
	if a.Source != SourceSynthetic || b.Source != SourceSynthetic {
		t.Fatal("a synthetic route is not labeled synthetic")
	}
	// No steer controller (observe): the routes still list, none steered.
	obs := Report(Meta{Mode: "observe"}, tbl, nil)
	if len(obs.Routes) != 2 || obs.Routes[0].SteeredTo != "" {
		t.Fatalf("observe status = %+v", obs)
	}
}

// A block is asked again a day after its answer, so a prefix announced
// differently since is picked up, and an announced prefix no block holds
// any more is forgotten.
func TestAnswerIsAskedAgainAndForgotten(t *testing.T) {
	cov := &fakeCovering{ans: pfx("2001:db8::/32")}
	tbl, clk := newTestTable(4, cov)
	keep := func() {
		tbl.Lookup(addr("2001:db8::1"))
		tbl.Lookup(addr("2001:db8:1::1"))
	}
	keep()
	for tbl.lookupOne(context.Background()) {
	}
	tbl.Refresh()
	if got := routePrefixes(tbl); !equal(got, []string{"2001:db8::/47"}) {
		t.Fatalf("routes = %v", got)
	}
	if tbl.lookupOne(context.Background()) {
		t.Fatal("an answered block was asked again within a day")
	}

	// The /32 is now announced as more specifics: nothing bounds the blocks.
	cov.set(pfx("2001:db8:0:8000::/49"), nil)
	clk.add(relookup)
	keep()
	for tbl.lookupOne(context.Background()) {
	}
	tbl.Refresh()
	if got := routePrefixes(tbl); !equal(got, []string{"2001:db8::/48", "2001:db8:1::/48"}) {
		t.Fatalf("routes after the announcement changed = %v", got)
	}
	if cov.count() != 4 || len(tbl.known) != 0 {
		t.Fatalf("covering calls %d, known %v", cov.count(), tbl.known)
	}

	clk.add(relookup)
	cov.set(pfx("2001:db8::/32"), nil)
	keep()
	for tbl.lookupOne(context.Background()) {
	}
	tbl.Refresh()
	if len(tbl.known) != 1 {
		t.Fatalf("known = %v", tbl.known)
	}
	// Every block ages out: the cache of announced prefixes empties with them.
	clk.add(time.Hour)
	tbl.Refresh()
	if len(tbl.known) != 0 || len(tbl.Routes()) != 0 {
		t.Fatalf("known %v and routes %v outlived their blocks", tbl.known, tbl.Routes())
	}
}

// Blocks under one announced prefix are asked again one at a time, with
// rounds between: once each has seen the prefix withdrawn, none keeps it
// alive for the others.
func TestWithdrawnPrefixIsNotKeptAliveBySiblings(t *testing.T) {
	cov := &fakeCovering{ans: pfx("2001:db8::/32")}
	tbl, clk := newTestTable(4, cov)
	blocks := []string{"2001:db8::1", "2001:db8:1::1", "2001:db8:2::1", "2001:db8:3::1"}
	keep := func() {
		for _, a := range blocks {
			tbl.Lookup(addr(a))
		}
	}
	keep()
	tbl.lookupOne(context.Background())
	tbl.Refresh()
	if got := routePrefixes(tbl); !equal(got, []string{"2001:db8::/46"}) || cov.count() != 1 {
		t.Fatalf("routes = %v after %d lookups", got, cov.count())
	}

	cov.set(pfx("2001:db8:0:8000::/49"), nil)
	for day := 1; day <= 2; day++ {
		clk.add(relookup)
		for range blocks {
			keep()
			tbl.lookupOne(context.Background())
			tbl.Refresh()
		}
	}
	if got := routePrefixes(tbl); !equal(got, []string{"2001:db8::/48", "2001:db8:1::/48", "2001:db8:2::/48", "2001:db8:3::/48"}) {
		t.Fatalf("routes after the /32 was withdrawn = %v", got)
	}
	if len(tbl.known) != 0 {
		t.Fatalf("known = %v", tbl.known)
	}
}
