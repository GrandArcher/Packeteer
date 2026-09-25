package traceroute

import "net/netip"

// sample is one probe at one TTL. from is invalid when nothing answered.
// reached is true when the reply is destination-unreachable (or a UDP
// payload from the destination): packets will not go further.
type sample struct {
	from    netip.Addr
	reached bool
}

// stableHop returns the address that answered at least min times, with
// no tie. A tie or too few replies is not a stable hop.
func stableHop(samples []sample, min int) (netip.Addr, int) {
	counts := map[netip.Addr]int{}
	var order []netip.Addr
	for _, s := range samples {
		if !s.from.IsValid() {
			continue
		}
		if counts[s.from] == 0 {
			order = append(order, s.from)
		}
		counts[s.from]++
	}
	var best netip.Addr
	bestN := 0
	tie := false
	for _, a := range order {
		n := counts[a]
		switch {
		case n > bestN:
			best, bestN, tie = a, n, false
		case n == bestN:
			tie = true
		}
	}
	if tie || bestN < min {
		return netip.Addr{}, 0
	}
	return best, bestN
}

// usableHop rejects answers that are not a real forward hop. The
// destination itself is always usable. Loopback, link-local, multicast,
// and unspecified addresses are not a "hop close to the destination"
// unless they are the destination (loopback tests).
func usableHop(addr, dest netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	if addr.Unmap() == dest.Unmap() {
		return true
	}
	if addr.IsLoopback() || addr.IsMulticast() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return false
	}
	return true
}

// selectHost picks the probe host from per-TTL samples (index 0 is TTL 1).
// The configured destination wins when it is a stable hop. Otherwise the
// stable hop with the highest TTL is the one closest to the destination.
func selectHost(hops [][]sample, dest netip.Addr, minReplies int) (netip.Addr, bool) {
	var best netip.Addr
	bestTTL := -1
	destOK := false
	for ttl, samples := range hops {
		addr, n := stableHop(samples, minReplies)
		if n < minReplies || !usableHop(addr, dest) {
			continue
		}
		if addr.Unmap() == dest.Unmap() {
			destOK = true
		}
		if ttl >= bestTTL {
			bestTTL = ttl
			best = addr
		}
	}
	if destOK {
		return dest, true
	}
	if bestTTL >= 0 {
		return best, true
	}
	return netip.Addr{}, false
}
