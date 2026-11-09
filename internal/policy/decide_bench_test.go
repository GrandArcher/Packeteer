package policy

import (
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/probe"
)

const (
	benchTargets   = 100_000
	benchProviders = 4
)

var benchNames = [benchProviders]string{"transit-a", "transit-b", "transit-c", "transit-d"}

// benchPrefix is the i-th /64 inside 2001:db8::/32.
func benchPrefix(i int) netip.Prefix {
	var b [16]byte
	b[0], b[1], b[2], b[3] = 0x20, 0x01, 0x0d, 0xb8
	b[4], b[5], b[6], b[7] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
	return netip.PrefixFrom(netip.AddrFrom16(b), 64)
}

// benchInput is one result per target and provider. Every tenth target has
// a lossy native path, so the evaluation also compares and ranks.
func benchInput(at time.Time) Input {
	res := make([]probe.Result, 0, benchTargets*benchProviders)
	native := make(map[netip.Prefix]string, benchTargets)
	for i := range benchTargets {
		p := benchPrefix(i)
		native[p] = benchNames[0]
		for j, name := range benchNames {
			loss := 0.0
			if j == 0 && i%10 == 0 {
				loss = 20
			}
			res = append(res, probe.Result{Provider: name, Prefix: p, Time: at,
				Stats: probe.Stats{Sent: 10, Received: 10 - int(loss/10), LossPct: loss,
					RTTAvg: time.Duration(20+5*j) * time.Millisecond}})
		}
	}
	up := make(map[string]bool, benchProviders)
	for _, n := range benchNames {
		up[n] = true
	}
	return Input{Results: res, ProviderUp: up, RIBEnabled: true, RIBReady: true, Native: native}
}

// BenchmarkDecide100kTargets4Providers times one evaluation over 400,000
// results (100,000 targets, 4 providers) from a clean state.
func BenchmarkDecide100kTargets4Providers(b *testing.B) {
	in := benchInput(t0)
	c := cfg()
	s := scorer(b)
	b.ReportAllocs()
	b.ResetTimer()
	var out Output
	for range b.N {
		_, out = Decide(NewState(), in, c, s, t0)
	}
	b.StopTimer()
	if len(out.Decisions) != benchTargets {
		b.Fatalf("decisions %d, want %d", len(out.Decisions), benchTargets)
	}
	// The lossy native paths want a move; the cap is what stops them.
	if len(out.Changes) != c.MaxImprovements {
		b.Fatalf("changes %d, want the cap %d", len(out.Changes), c.MaxImprovements)
	}
}
