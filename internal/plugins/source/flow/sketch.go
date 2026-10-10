package flow

import (
	"math"
	"math/bits"
	"net/netip"
)

// hll is a HyperLogLog with 4096 registers. Each flow bucket keeps one.
// It counts distinct prefixes the exact map did not have room for, in a
// fixed 4 KiB, so a full table does not grow the window (#125). It is not
// a volume: probe targets and the commit scorer still read the exact cells.
const (
	hllP = 12
	hllM = 1 << hllP
)

type hll struct {
	reg [hllM]uint8
}

func (h *hll) add(p netip.Prefix) {
	// FNV-1a of nearby prefixes shares low bits. SplitMix64 spreads the
	// register index; the estimate is otherwise high by about half.
	x := mix64(hashPrefix(p))
	idx := x & (hllM - 1)
	// The low hllP bits are the register. Rho is one plus the leading
	// zeros of the remaining bits, not of the zeros the shift introduced.
	w := x >> hllP
	rho := bits.LeadingZeros64(w) - hllP + 1
	if rho < 1 {
		rho = 1
	}
	if rho > 64-hllP+1 {
		rho = 64 - hllP + 1
	}
	if uint8(rho) > h.reg[idx] {
		h.reg[idx] = uint8(rho)
	}
}

func (h *hll) merge(o hll) {
	for i := range h.reg {
		if o.reg[i] > h.reg[i] {
			h.reg[i] = o.reg[i]
		}
	}
}

// estimate is the distinct-prefix count. An empty sketch is zero.
func (h hll) estimate() uint64 {
	var sum float64
	zeros := 0
	for _, r := range h.reg {
		sum += math.Ldexp(1, -int(r))
		if r == 0 {
			zeros++
		}
	}
	if sum == 0 {
		return 0
	}
	// alpha for m >= 128.
	alpha := 0.7213 / (1 + 1.079/hllM)
	est := alpha * hllM * hllM / sum
	if est <= 2.5*hllM && zeros > 0 {
		est = hllM * math.Log(float64(hllM)/float64(zeros))
	}
	if est < 0 {
		return 0
	}
	return uint64(est + 0.5)
}

// mix64 is SplitMix64. It is deterministic, unlike maphash.
func mix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

func hashPrefix(p netip.Prefix) uint64 {
	const (
		offset = 14695981039346656037
		prime  = 1099511628211
	)
	h := uint64(offset)
	b := p.Addr().As16()
	for _, c := range b {
		h ^= uint64(c)
		h *= prime
	}
	h ^= uint64(p.Bits())
	h *= prime
	return h
}
