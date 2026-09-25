// Package probe runs the probe engine: for every target and provider it
// asks the configured prober chain to measure the path from that
// provider's source address, and keeps the latest statistics.
package probe

import (
	"net/netip"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Stats summarizes one probe run.
type Stats struct {
	Sent     int           `json:"sent"`
	Received int           `json:"received"`
	LossPct  float64       `json:"loss_pct"`
	RTTMin   time.Duration `json:"rtt_min"`
	RTTAvg   time.Duration `json:"rtt_avg"`
	RTTMax   time.Duration `json:"rtt_max"`
	// Jitter is the mean absolute difference between consecutive RTTs
	// (RFC 3550 style, without the exponential smoothing).
	Jitter time.Duration `json:"jitter"`
}

// Compute derives Stats from a raw probe result.
func Compute(r plugin.ProbeResult) Stats {
	s := Stats{Sent: r.Sent, Received: len(r.RTTs)}
	if s.Sent > 0 {
		lost := s.Sent - s.Received
		if lost < 0 {
			lost = 0
		}
		s.LossPct = 100 * float64(lost) / float64(s.Sent)
	}
	if s.Received == 0 {
		return s
	}
	var sum time.Duration
	s.RTTMin, s.RTTMax = r.RTTs[0], r.RTTs[0]
	for _, d := range r.RTTs {
		sum += d
		if d < s.RTTMin {
			s.RTTMin = d
		}
		if d > s.RTTMax {
			s.RTTMax = d
		}
	}
	s.RTTAvg = sum / time.Duration(s.Received)
	if s.Received > 1 {
		var diff time.Duration
		for i := 1; i < len(r.RTTs); i++ {
			d := r.RTTs[i] - r.RTTs[i-1]
			if d < 0 {
				d = -d
			}
			diff += d
		}
		s.Jitter = diff / time.Duration(s.Received-1)
	}
	return s
}

// DefaultHost picks the address to probe inside a prefix when none is
// configured: the first address after the network address (".1"), or the
// address itself for host routes.
func DefaultHost(p netip.Prefix) netip.Addr {
	p = p.Masked()
	a := p.Addr()
	if p.Bits() == a.BitLen() {
		return a
	}
	next := a.Next()
	if next.IsValid() && p.Contains(next) {
		return next
	}
	return a
}
