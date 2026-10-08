//go:build linux

package probe

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/source/traceroute"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TestIndirectLoopback runs a real background pass with the built-in
// Linux traceroute from two provider sources on loopback. Each trace
// binds its own provider's source, every packet goes through the rate
// limit, and the destination answering itself is not adopted as an
// indirect hop. A provider whose source is not local fails the trace
// without caching it, so it is asked for again.
func TestIndirectLoopback(t *testing.T) {
	a := Provider{Name: "lo-a", Source: netip.MustParseAddr("127.0.0.1")}
	b := Provider{Name: "lo-b", Source: netip.MustParseAddr("127.0.0.2")}
	gone := Provider{Name: "gone", Source: netip.MustParseAddr("192.0.2.99")}
	lim := &countingLimiter{}
	o := opts()
	o.Limiter = lim
	o.Indirect = &Indirect{
		Tracer:   traceroute.Tracer{MaxHops: 3, Probes: 1, MinReplies: 1, Port: 33434, Timeout: 300 * time.Millisecond, Hop: traceroute.Hop},
		Budget:   3 * time.Second,
		MinShare: 300 * time.Millisecond,
		CacheTTL: time.Minute,
	}
	silent := func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		return plugin.ProbeResult{Sent: req.Count}, nil
	}
	pfx := netip.MustParsePrefix("127.0.0.3/32")
	e, err := New([]Provider{a, b, gone}, []NamedProber{{"silent", &fakeProber{fn: silent}}}, src(plugin.Target{Prefix: pfx}), o)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	e.RunOnce(ctx)
	if got := len(e.pendingIndirect()); got != 3 {
		t.Fatalf("queued = %d, want one per provider", got)
	}
	before := lim.total
	if n := e.IndirectPass(ctx); n != 2 {
		t.Fatalf("finished traces = %d, want the two loopback providers", n)
	}
	if lim.total-before < 2 {
		t.Fatalf("trace packets did not wait on the rate limit: %d", lim.total-before)
	}
	for _, p := range []Provider{a, b} {
		hop, found := e.cachedIndirect(key{p.Name, pfx})
		if !found || hop.IsValid() {
			t.Fatalf("%s: destination answered itself; want a cached no-hop, got %v found=%v", p.Name, hop, found)
		}
	}
	if _, found := e.cachedIndirect(key{gone.Name, pfx}); found {
		t.Fatal("an unbindable source cached an outcome")
	}
	e.RunOnce(ctx)
	for _, r := range e.Results() {
		if r.Indirect {
			t.Fatalf("loopback scored indirect: %+v", r)
		}
	}
	if got := e.pendingIndirect(); len(got) != 1 || got[0].provider.Name != gone.Name {
		t.Fatalf("only the unbindable provider should be queued again: %+v", got)
	}
}
