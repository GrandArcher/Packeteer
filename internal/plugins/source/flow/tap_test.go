package flow

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// The tap sees each simulated NetFlow v5 record that is counted under a
// prefix, with the prefix the RIB lookup gave, and stops when removed.
func TestFlowTapGetsCountedObservations(t *testing.T) {
	s := mustSource(t, "listen: 127.0.0.1:2055\n")
	now := time.Unix(1_700_000_000, 0)
	pin(s, now)
	learned := netip.MustParsePrefix("198.51.100.0/24")
	s.SetPrefixLookup(func(a netip.Addr) (netip.Prefix, bool) { return learned, learned.Contains(a) })
	var mu sync.Mutex
	var got []plugin.FlowObservation
	s.SetFlowTap(func(o plugin.FlowObservation) {
		mu.Lock()
		got = append(got, o)
		mu.Unlock()
	})
	src := netip.MustParseAddr("203.0.113.9")
	dst := netip.MustParseAddr("198.51.100.10")
	private := netip.MustParseAddr("10.0.0.5")
	exporter := netip.MustParseAddr("192.0.2.8")
	s.ingest(now, exporter, buildV5TCP(0, []v5tcp{
		{src: src, dst: dst, proto: 6},
		{src: src, dst: private, proto: 6}, // dropped by keep(): not a probe target
	}))
	if len(got) != 1 {
		t.Fatalf("tap saw %d observations, want only the counted one: %+v", len(got), got)
	}
	o := got[0]
	if o.Src != src || o.Dst != dst || o.Proto != 6 || o.Prefix != learned || o.Bytes == 0 || !o.At.Equal(now) {
		t.Fatalf("observation = %+v", o)
	}

	s.SetFlowTap(nil)
	s.ingest(now, exporter, buildV5TCP(0, []v5tcp{{src: src, dst: dst, proto: 6}}))
	if len(got) != 1 {
		t.Fatalf("a removed tap still got %d observations", len(got))
	}
}
