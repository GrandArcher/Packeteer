package probe

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestRetainedPrefixKeepsHostAndInterval(t *testing.T) {
	auto := netip.MustParsePrefix("192.0.2.0/24")
	candHost := netip.MustParseAddr("198.51.100.50")
	laterHost := netip.MustParseAddr("198.51.100.60")
	pinHost := netip.MustParseAddr("203.0.113.9")
	every := 5 * time.Second
	src := &countingSource{fresh: true, targets: []plugin.Target{
		{Prefix: pfx1, Host: candHost, Candidate: true, Interval: every},
		{Prefix: pfx2, Host: pinHost},
		{Prefix: auto},
	}}
	e, err := New([]Provider{provA}, []NamedProber{{"p", &fakeProber{fn: ok(1)}}},
		[]NamedSource{{Name: "flow", Source: src}}, opts())
	if err != nil {
		t.Fatal(err)
	}
	e.RunOnce(context.Background())
	e.SetRetained([]netip.Prefix{pfx1, pfx2, auto})

	// A source that still lists the prefix keeps its current host. The
	// retained copy must not freeze the previous one.
	src.targets = []plugin.Target{
		{Prefix: pfx1, Host: laterHost, Candidate: true, Interval: every},
		{Prefix: pfx2, Host: pinHost},
		{Prefix: auto},
	}
	got := targetsByPrefix(t, e)
	if got[pfx1].Host != laterHost || !got[pfx1].Candidate || got[pfx1].Pinned || got[pfx1].Interval != every {
		t.Fatalf("live source host = %+v", got[pfx1])
	}

	src.targets = nil
	e.RunOnce(context.Background())
	got = targetsByPrefix(t, e)
	if len(got) != 3 {
		t.Fatalf("targets = %+v", got)
	}
	if got[pfx1].Host != laterHost || !got[pfx1].Candidate || got[pfx1].Pinned || got[pfx1].Interval != every {
		t.Fatalf("retained candidate = %+v", got[pfx1])
	}
	if got[pfx2].Host != pinHost || !got[pfx2].Pinned || got[pfx2].Candidate || got[pfx2].Interval != 0 {
		t.Fatalf("retained pin = %+v", got[pfx2])
	}
	if got[auto].Host != DefaultHost(auto) || got[auto].Pinned || got[auto].Candidate {
		t.Fatalf("retained automatic host became a pin: %+v", got[auto])
	}
	for _, r := range e.Results() {
		switch r.Prefix {
		case pfx1:
			if len(r.Targets) < 2 || r.Targets[0] != laterHost {
				t.Fatalf("candidate not probed first: %v", r.Targets)
			}
		case pfx2:
			if len(r.Targets) != 1 || r.Targets[0] != pinHost {
				t.Fatalf("pin was not the only host: %v", r.Targets)
			}
		case auto:
			if len(r.Targets) < 2 {
				t.Fatalf("automatic prefix probed as a pin: %v", r.Targets)
			}
		}
	}

	e.SetRetained(nil)
	e.RunOnce(context.Background())
	if ts := e.Targets(context.Background()); len(ts) != 0 {
		t.Fatalf("targets after retire = %+v", ts)
	}
	if rs := e.Results(); len(rs) != 0 {
		t.Fatalf("results after the next round = %+v", rs)
	}
}

func TestRetainedIntervalStaysDue(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	o := opts()
	o.Now = func() time.Time { return now }
	o.Interval = 30 * time.Second
	o.Packets = 1
	every := 5 * time.Second
	src := &countingSource{fresh: true, targets: []plugin.Target{
		{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.50"), Candidate: true, Interval: every},
		{Prefix: pfx2, Host: netip.MustParseAddr("203.0.113.9")},
	}}
	e, err := New([]Provider{provA}, []NamedProber{{"p", &fakeProber{fn: ok(1)}}},
		[]NamedSource{{Name: "flow", Source: src}}, o)
	if err != nil {
		t.Fatal(err)
	}
	if _, done := e.runRound(context.Background(), func(plugin.Target) bool { return true }, true); !done {
		t.Fatal("first round")
	}
	e.SetRetained([]netip.Prefix{pfx1})
	src.targets = nil
	last := map[netip.Prefix]time.Time{pfx1: now, pfx2: now}

	now = now.Add(time.Second)
	probed, done := e.runRound(context.Background(), func(tg plugin.Target) bool {
		return e.targetDue(tg, last)
	}, true)
	if !done || len(probed) != 0 {
		t.Fatalf("idle round probed=%v done=%v", probed, done)
	}
	rs := e.Results()
	if len(rs) != 1 || rs[0].Prefix != pfx1 {
		t.Fatalf("unimproved prefix kept or improved prefix dropped: %+v", rs)
	}

	now = now.Add(every)
	probed, done = e.runRound(context.Background(), func(tg plugin.Target) bool {
		return e.targetDue(tg, last)
	}, true)
	if _, ok := probed[pfx1]; !done || len(probed) != 1 || !ok {
		t.Fatalf("retained cadence probed=%v done=%v", probed, done)
	}
	rs = e.Results()
	if len(rs) != 1 || rs[0].Prefix != pfx1 || len(rs[0].Targets) == 0 || rs[0].Targets[0].String() != "198.51.100.50" {
		t.Fatalf("re-probe = %+v", rs)
	}
}

func targetsByPrefix(t *testing.T, e *Engine) map[netip.Prefix]plugin.Target {
	t.Helper()
	out := map[netip.Prefix]plugin.Target{}
	for _, tg := range e.Targets(context.Background()) {
		out[tg.Prefix] = tg
	}
	return out
}
