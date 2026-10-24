package probe

import (
	"context"
	"net/netip"
	"sync"

	"golang.org/x/time/rate"

	"github.com/GrandArcher/Packeteer/internal/exchange"
)

// Exclusion is probe.exclude (#203): destinations no target source may
// probe. Prefixes are masked. Origin, when set, is the origin ASN of the
// longest learned route covering a prefix (a host is its own /32 or /128),
// or 0 when the RIB has none; the ASN rules need it, so until the RIB view
// is ready only the prefix list applies.
type Exclusion struct {
	Prefixes []netip.Prefix
	ASNs     map[uint32]bool
	Origin   func(netip.Prefix) uint32
}

// Empty reports whether nothing can match. A nil Exclusion is empty.
func (x *Exclusion) Empty() bool {
	return x == nil || len(x.Prefixes) == 0 && len(x.ASNs) == 0
}

// Prefix reports whether p may not be probed: equal to or inside an
// excluded prefix, or originated by an excluded ASN.
func (x *Exclusion) Prefix(p netip.Prefix) bool {
	if x.Empty() || !p.IsValid() {
		return false
	}
	return exchange.PrefixInside(x.Prefixes, p) || x.asnOut(p)
}

// Addr reports whether a may not be probed: inside an excluded prefix, or
// originated by an excluded ASN.
func (x *Exclusion) Addr(a netip.Addr) bool {
	if x.Empty() || !a.IsValid() {
		return false
	}
	a = a.Unmap()
	return exchange.ContainsAddr(x.Prefixes, a) || x.asnOut(netip.PrefixFrom(a, a.BitLen()))
}

func (x *Exclusion) asnOut(p netip.Prefix) bool {
	if len(x.ASNs) == 0 || x.Origin == nil {
		return false
	}
	asn := x.Origin(p)
	return asn != 0 && x.ASNs[asn]
}

// maxASNLimiters bounds the per-ASN limiter set (#203). Past it the least
// recently used ASN is dropped and starts again with a full burst when it
// is probed next.
const maxASNLimiters = 4096

// asnLimits is probe.per_asn_pps: one token bucket per destination origin
// ASN, waited on before the global limiter so a capped ASN never holds a
// global token while it waits. A destination with no learned origin is
// not capped here; the global limit still applies to it.
type asnLimits struct {
	pps, burst int
	origin     func(netip.Prefix) uint32

	mu   sync.Mutex
	tick uint64
	m    map[uint32]*asnLimiter
}

type asnLimiter struct {
	lim  *rate.Limiter
	used uint64
}

func newASNLimits(pps, burst int, origin func(netip.Prefix) uint32) *asnLimits {
	return &asnLimits{pps: pps, burst: max(burst, pps), origin: origin, m: map[uint32]*asnLimiter{}}
}

// wait blocks until count packets toward host fit that ASN's cap.
func (l *asnLimits) wait(ctx context.Context, host netip.Addr, count int) error {
	if l == nil || !host.IsValid() {
		return nil
	}
	host = host.Unmap()
	asn := l.origin(netip.PrefixFrom(host, host.BitLen()))
	if asn == 0 {
		return nil
	}
	return l.limiter(asn).WaitN(ctx, count)
}

func (l *asnLimits) limiter(asn uint32) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tick++
	if e, ok := l.m[asn]; ok {
		e.used = l.tick
		return e.lim
	}
	if len(l.m) >= maxASNLimiters {
		var oldest uint32
		first := true
		for k, e := range l.m {
			if first || e.used < l.m[oldest].used {
				oldest, first = k, false
			}
		}
		delete(l.m, oldest)
	}
	e := &asnLimiter{lim: rate.NewLimiter(rate.Limit(l.pps), l.burst), used: l.tick}
	l.m[asn] = e
	return e.lim
}
