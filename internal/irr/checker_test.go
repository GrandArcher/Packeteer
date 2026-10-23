package irr

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakeIRR struct {
	plugin.Base
	routes map[netip.Prefix][]plugin.IRRRoute
	sets   map[string][]uint32
	names  map[uint32]string
	at     time.Time
	err    error
	noSets bool
	asked  int
}

func (f *fakeIRR) Routes(_ context.Context, p netip.Prefix) ([]plugin.IRRRoute, time.Time, error) {
	f.asked++
	if f.err != nil {
		return nil, time.Time{}, f.err
	}
	return f.routes[p], f.at, nil
}

func (f *fakeIRR) ASSetMembers(_ context.Context, name string) ([]uint32, time.Time, error) {
	if f.noSets {
		return nil, time.Time{}, plugin.ErrIRRUnsupported
	}
	if f.err != nil {
		return nil, time.Time{}, f.err
	}
	return f.sets[name], f.at, nil
}

func (f *fakeIRR) ASName(_ context.Context, asn uint32) (string, time.Time, error) {
	if f.noSets {
		return "", time.Time{}, plugin.ErrIRRUnsupported
	}
	if f.err != nil {
		return "", time.Time{}, f.err
	}
	return f.names[asn], f.at, nil
}

var (
	pfx = netip.MustParsePrefix("198.51.100.0/24")
	t0  = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
)

// drain runs every queued lookup, as Run would.
func drain(c *Checker) {
	for {
		select {
		case j := <-c.queue:
			c.fetch(context.Background(), j)
		default:
			return
		}
	}
}

func newTestChecker(opt Options, srcs ...*fakeIRR) (*Checker, *time.Time) {
	var list []Source
	for i, s := range srcs {
		list = append(list, Source{Name: []string{"local", "radb", "ripe"}[i], Type: "fake", IRR: s})
	}
	if opt.Refresh == 0 {
		opt.Refresh = DefaultRefresh
	}
	if opt.Staleness == 0 {
		opt.Staleness = DefaultStaleness
	}
	c := NewChecker(list, opt)
	now := t0
	c.now = func() time.Time { return now }
	return c, &now
}

// #214: a lookup never waits; the first answer is unknown and queues the
// lookup. Registered names the first source in order with a matching
// object; origins are the union; the as-set and the origin's as-name come
// along.
func TestCheckerRegistered(t *testing.T) {
	local := &fakeIRR{at: t0.Add(-time.Hour), routes: map[netip.Prefix][]plugin.IRRRoute{pfx: {{Prefix: pfx, Origin: 64497}}}, noSets: true}
	radb := &fakeIRR{at: t0, routes: map[netip.Prefix][]plugin.IRRRoute{pfx: {{Prefix: pfx, Origin: 64496, Database: "RADB"}}},
		sets: map[string][]uint32{"AS-EXAMPLE": {64496}}, names: map[uint32]string{64496: "EXAMPLE-NET-AS"}}
	c, _ := newTestChecker(Options{ASSets: map[string]string{"transit-a": "AS-EXAMPLE"}}, local, radb)
	if a := c.Lookup(pfx, 64496, "transit-a"); a.State != plugin.IRRUnknown || a.ASSetState != plugin.IRRUnknown || a.ASSet != "AS-EXAMPLE" {
		t.Fatalf("first lookup = %+v, want unknown", a)
	}
	drain(c)
	a := c.Lookup(pfx, 64496, "transit-a")
	if a.State != plugin.IRRRegistered || a.Source != "radb" || a.Database != "RADB" || !a.Updated.Equal(t0) ||
		!slices.Equal(a.Origins, []uint32{64496, 64497}) || a.ASSetState != plugin.IRRRegistered || a.OriginName != "EXAMPLE-NET-AS" {
		t.Fatalf("lookup = %+v", a)
	}
	if a := c.Lookup(pfx, 64497, "transit-b"); a.State != plugin.IRRRegistered || a.Source != "local" || a.ASSet != "" {
		t.Fatalf("local origin = %+v", a)
	}
	// A second origin for the same prefix is answered from the cache.
	if local.asked != 1 || radb.asked != 1 {
		t.Fatalf("asked local %d radb %d, want 1 each", local.asked, radb.asked)
	}
}

// Not registered only when every source answered freshly; a source that
// failed or aged out makes it unknown, so prefer_registered fails open.
func TestCheckerNotRegisteredNeedsEverySource(t *testing.T) {
	local := &fakeIRR{at: t0.Add(-2 * time.Hour), routes: map[netip.Prefix][]plugin.IRRRoute{pfx: {{Prefix: pfx, Origin: 64497}}}}
	radb := &fakeIRR{at: t0}
	c, now := newTestChecker(Options{ASSets: map[string]string{"transit-a": "AS-EXAMPLE"}}, local, radb)
	c.Lookup(pfx, 64496, "transit-a")
	drain(c)
	a := c.Lookup(pfx, 64496, "transit-a")
	if a.State != plugin.IRRNotRegistered || a.Source != "local" || !a.Updated.Equal(t0.Add(-2*time.Hour)) || !slices.Equal(a.Origins, []uint32{64497}) || a.ASSetState != plugin.IRRNotRegistered {
		t.Fatalf("lookup = %+v, want not registered from the oldest data", a)
	}

	// radb fails on the next refresh: its last answer is kept until
	// staleness, then the state is unknown, not not_registered.
	radb.err = errors.New("dial tcp: connection refused")
	*now = t0.Add(DefaultRefresh)
	c.Lookup(pfx, 64496, "transit-a")
	drain(c)
	if a := c.Lookup(pfx, 64496, "transit-a"); a.State != plugin.IRRNotRegistered {
		t.Fatalf("within staleness = %+v", a)
	}
	st := c.Statuses()
	if st[1].Up || st[1].Error != "dial tcp: connection refused" || !st[0].Up {
		t.Fatalf("statuses = %+v", st)
	}
	*now = t0.Add(DefaultStaleness + time.Second)
	if a := c.Lookup(pfx, 64496, "transit-a"); a.State != plugin.IRRUnknown || a.ASSetState != plugin.IRRUnknown {
		t.Fatalf("past staleness = %+v, want unknown", a)
	}
}

// A failed lookup is asked again after retryAfter, not every round, and a
// healthy one only after Refresh.
func TestCheckerRefreshAndRetry(t *testing.T) {
	src := &fakeIRR{at: t0, err: errors.New("timeout")}
	c, now := newTestChecker(Options{Refresh: time.Hour, Staleness: 2 * time.Hour}, src)
	c.Lookup(pfx, 64496, "")
	drain(c)
	c.Lookup(pfx, 64496, "")
	drain(c)
	if src.asked != 1 {
		t.Fatalf("asked %d times before retryAfter", src.asked)
	}
	*now = t0.Add(retryAfter)
	src.err = nil
	c.Lookup(pfx, 64496, "")
	drain(c)
	if src.asked != 2 {
		t.Fatalf("asked %d times after retryAfter, want 2", src.asked)
	}
	*now = t0.Add(retryAfter + 59*time.Minute)
	c.Lookup(pfx, 64496, "")
	drain(c)
	if src.asked != 2 {
		t.Fatalf("asked %d times before refresh", src.asked)
	}
	*now = t0.Add(retryAfter + time.Hour)
	c.Lookup(pfx, 64496, "")
	drain(c)
	if src.asked != 3 {
		t.Fatalf("asked %d times after refresh, want 3", src.asked)
	}
}

// A source that does not serve as-sets is left out of the as-set answer;
// with no source serving it, it is unknown.
func TestCheckerUnsupported(t *testing.T) {
	file := &fakeIRR{at: t0, noSets: true}
	c, _ := newTestChecker(Options{ASSets: map[string]string{"peer-a": "AS-EXAMPLE"}}, file)
	c.Lookup(pfx, 64496, "peer-a")
	drain(c)
	if a := c.Lookup(pfx, 64496, "peer-a"); a.State != plugin.IRRNotRegistered || a.ASSetState != plugin.IRRUnknown || a.OriginName != "" {
		t.Fatalf("lookup = %+v", a)
	}
	whois := &fakeIRR{at: t0, sets: map[string][]uint32{"AS-EXAMPLE": {64500}}}
	c, _ = newTestChecker(Options{ASSets: map[string]string{"peer-a": "AS-EXAMPLE"}}, file, whois)
	c.Lookup(pfx, 64496, "peer-a")
	drain(c)
	if a := c.Lookup(pfx, 64496, "peer-a"); a.ASSetState != plugin.IRRNotRegistered {
		t.Fatalf("as-set = %+v, want not a member", a)
	}
}

// With no sources every lookup is unknown and nothing is queued.
func TestCheckerOff(t *testing.T) {
	c := NewChecker(nil, Options{})
	if c.Enabled() {
		t.Fatal("enabled without sources")
	}
	if a := c.Lookup(pfx, 64496, "x"); a.State != plugin.IRRUnknown || len(c.queue) != 0 {
		t.Fatalf("off lookup = %+v queued %d", a, len(c.queue))
	}
	var nilChecker *Checker
	if nilChecker.Enabled() || nilChecker.Lookup(pfx, 1, "").State != plugin.IRRUnknown || nilChecker.Statuses() != nil {
		t.Fatal("nil checker is not off")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.Run(ctx)
}

// The cache is bounded: a new key in a full cache evicts first.
func TestCheckerBounded(t *testing.T) {
	src := &fakeIRR{at: t0}
	c, now := newTestChecker(Options{}, src)
	for i := range maxKeys {
		c.routes[netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 32)] = &entry[[]plugin.IRRRoute]{next: t0.Add(time.Duration(i%2) * 2 * DefaultRefresh)}
	}
	*now = t0.Add(time.Second)
	c.Lookup(pfx, 64496, "")
	drain(c)
	if len(c.routes) > maxKeys {
		t.Fatalf("cache grew to %d", len(c.routes))
	}
	if _, ok := c.routes[pfx]; !ok {
		t.Fatal("new key not stored")
	}
	if len(c.routes) > maxKeys/2+1 {
		t.Fatalf("due entries kept: %d", len(c.routes))
	}
}

// Run answers queued lookups until its context ends.
func TestCheckerRun(t *testing.T) {
	src := &fakeIRR{at: time.Now(), routes: map[netip.Prefix][]plugin.IRRRoute{pfx: {{Prefix: pfx, Origin: 64496}}}}
	c := NewChecker([]Source{{Name: "radb", IRR: src}}, Options{Refresh: time.Hour, Staleness: 2 * time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	c.Lookup(pfx, 64496, "")
	deadline := time.Now().Add(5 * time.Second)
	for c.Lookup(pfx, 64496, "").State != plugin.IRRRegistered {
		if time.Now().After(deadline) {
			t.Fatal("Run did not answer the lookup")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
}
