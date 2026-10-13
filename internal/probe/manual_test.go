package probe

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestQueueManualProbesNextRoundThenExpires(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	o := opts()
	o.Now = func() time.Time { return now }
	o.Interval = time.Hour
	pin := netip.MustParseAddr("203.0.113.9")
	e, err := New([]Provider{provA}, []NamedProber{{"p", &fakeProber{fn: ok(1)}}},
		src(plugin.Target{Prefix: pfx2, Host: pin}), o)
	if err != nil {
		t.Fatal(err)
	}
	last := map[netip.Prefix]time.Time{}
	round := func() map[netip.Prefix]struct{} {
		t.Helper()
		probed, done := e.runRound(context.Background(), func(tg plugin.Target) bool { return e.targetDue(tg, last) }, true)
		if !done {
			t.Fatal("round did not complete")
		}
		for p := range probed {
			last[p] = now
		}
		return probed
	}
	if got := round(); len(got) != 1 {
		t.Fatalf("first round probed %v", got)
	}

	now = now.Add(time.Minute)
	if got := round(); len(got) != 0 {
		t.Fatalf("idle round probed %v", got)
	}
	if err := e.QueueManual(pfx1, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	if !e.consumeWake() {
		t.Fatal("queueing did not wake the scheduler")
	}
	now = now.Add(time.Second)
	got := round()
	if _, ok := got[pfx1]; !ok || len(got) != 1 {
		t.Fatalf("next round probed %v, want only the queued prefix", got)
	}
	if rs := e.Results(); len(rs) != 2 {
		t.Fatalf("results = %+v", rs)
	}

	now = now.Add(time.Minute)
	if got := round(); len(got) != 0 {
		t.Fatalf("queued prefix was probed again before its interval: %v", got)
	}
	if rs := e.Results(); len(rs) != 2 {
		t.Fatalf("queued prefix dropped inside its TTL: %+v", rs)
	}

	now = now.Add(10 * time.Minute)
	round()
	rs := e.Results()
	if len(rs) != 1 || rs[0].Prefix != pfx2 {
		t.Fatalf("results after TTL = %+v", rs)
	}
	if ts := targetsByPrefix(t, e); len(ts) != 1 {
		t.Fatalf("targets after TTL = %+v", ts)
	}
}

func TestQueueManualKeepsSourceHost(t *testing.T) {
	pin := netip.MustParseAddr("203.0.113.9")
	e, err := New([]Provider{provA}, []NamedProber{{"p", &fakeProber{fn: ok(1)}}},
		src(plugin.Target{Prefix: pfx2, Host: pin}), opts())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.QueueManual(pfx2, time.Minute); err != nil {
		t.Fatal(err)
	}
	got := targetsByPrefix(t, e)
	if len(got) != 1 || got[pfx2].Host != pin || !got[pfx2].Pinned || !got[pfx2].Urgent {
		t.Fatalf("targets = %+v", got)
	}
}

func TestQueueManualUnlistedPrefixUsesDefaultHost(t *testing.T) {
	e, err := New([]Provider{provA}, []NamedProber{{"p", &fakeProber{fn: ok(1)}}}, nil, opts())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.QueueManual(netip.MustParsePrefix("198.51.100.77/24"), time.Minute); err != nil {
		t.Fatal(err)
	}
	got := targetsByPrefix(t, e)
	tg, ok := got[pfx1]
	if len(got) != 1 || !ok || tg.Pinned || tg.Candidate || tg.Host != DefaultHost(pfx1) || !tg.Urgent {
		t.Fatalf("targets = %+v", got)
	}
}

func TestQueueManualBounds(t *testing.T) {
	e, err := New([]Provider{provA}, []NamedProber{{"p", &fakeProber{fn: ok(1)}}}, nil, opts())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.QueueManual(netip.Prefix{}, time.Minute); err == nil {
		t.Fatal("invalid prefix accepted")
	}
	if err := e.QueueManual(pfx1, 0); err == nil {
		t.Fatal("zero ttl accepted")
	}
	for i := range MaxManual {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i * 4)}), 30)
		if err := e.QueueManual(p, time.Minute); err != nil {
			t.Fatalf("queue %d: %v", i, err)
		}
	}
	if err := e.QueueManual(pfx1, time.Minute); !errors.Is(err, ErrManualFull) {
		t.Fatalf("over the cap = %v", err)
	}
	renew := netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, 0}), 30)
	if err := e.QueueManual(renew, time.Minute); err != nil {
		t.Fatalf("renewing a queued prefix = %v", err)
	}
	if n := len(e.Targets(context.Background())); n != MaxManual {
		t.Fatalf("targets = %d", n)
	}
}

func TestQueueManualInsideExchangeLANIsDropped(t *testing.T) {
	o := opts()
	o.ExchangeLANs = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	e, err := New([]Provider{provA}, []NamedProber{{"p", &fakeProber{fn: ok(1)}}}, nil, o)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.QueueManual(pfx1, time.Minute); err != nil {
		t.Fatal(err)
	}
	if ts := e.Targets(context.Background()); len(ts) != 0 {
		t.Fatalf("queued exchange LAN prefix kept: %+v", ts)
	}
}
