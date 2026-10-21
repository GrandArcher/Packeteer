package probe

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const (
	benchTargets   = 100_000
	benchProviders = 4
)

// benchAddr is the i-th /64 inside 2001:db8::/32, or its ::1 host.
func benchAddr(i int, host bool) netip.Prefix {
	var b [16]byte
	b[0], b[1], b[2], b[3] = 0x20, 0x01, 0x0d, 0xb8
	b[4], b[5], b[6], b[7] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
	if host {
		b[15] = 1
		return netip.PrefixFrom(netip.AddrFrom16(b), 128)
	}
	return netip.PrefixFrom(netip.AddrFrom16(b), 64)
}

// BenchmarkProbeRound100kTargets4Providers times one full round over
// 100,000 pinned targets and 4 providers (400,000 probe runs) against a
// prober that answers at once, so it measures the engine's scheduling,
// result storage, and commit, not the network.
func BenchmarkProbeRound100kTargets4Providers(b *testing.B) {
	targets := make([]plugin.Target, benchTargets)
	for i := range targets {
		targets[i] = plugin.Target{Prefix: benchAddr(i, false), Host: benchAddr(i, true).Addr(), Weight: 1}
	}
	var provs []Provider
	for i := range benchProviders {
		provs = append(provs, Provider{Name: fmt.Sprintf("transit-%c", 'a'+i), Source: netip.MustParseAddr(fmt.Sprintf("2001:db8:ffff::%d", 11+i))})
	}
	pr := &fakeProber{fn: ok(10, 11, 12)}
	o := opts()
	o.Workers = 64
	o.RoundTimeout = 10 * time.Minute
	e, err := New(provs, []NamedProber{{Name: "fake", Prober: pr}}, src(targets...), o)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		e.RunOnce(context.Background())
	}
	b.StopTimer()
	if n := len(e.Results()); n != benchTargets*benchProviders {
		b.Fatalf("results %d, want %d", n, benchTargets*benchProviders)
	}
	if n := int(pr.calls.Load()); n != b.N*benchTargets*benchProviders {
		b.Fatalf("probe runs %d, want %d", n, b.N*benchTargets*benchProviders)
	}
}
