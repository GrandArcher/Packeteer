package exchange

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// History bounds (#156). Counts are kept in memory: a restart empties them.
// 288 samples at 15 minutes is three days per peer.
const (
	SampleEvery = 15 * time.Minute
	maxSamples  = 288
)

// Sample is one peer's availability counts at one time.
type Sample struct {
	At              time.Time `json:"at"`
	RouteServerOnly int       `json:"route_server_only"`
	BilateralOnly   int       `json:"bilateral_only"`
	Both            int       `json:"both"`
}

type seriesKey struct {
	exchange string
	nextHop  netip.Addr
}

// History keeps recent availability counts per configured peer (#156), so
// its size is bounded by the config.
type History struct {
	mu     sync.Mutex
	series map[seriesKey][]Sample
}

// NewHistory returns an empty history.
func NewHistory() *History {
	return &History{series: map[seriesKey][]Sample{}}
}

// Record appends one sample per peer in stats, drops the oldest beyond
// the bound, and forgets peers not seen for the whole window.
func (h *History) Record(at time.Time, stats []Stats) {
	h.mu.Lock()
	defer h.mu.Unlock()
	add := func(ex string, nextHop string, a Availability) {
		nh, err := netip.ParseAddr(nextHop)
		if err != nil {
			return
		}
		k := seriesKey{ex, nh}
		s := h.series[k]
		s = append(s, Sample{At: at, RouteServerOnly: a.RouteServerOnly, BilateralOnly: a.BilateralOnly, Both: a.Both})
		if len(s) > maxSamples {
			s = append(s[:0], s[len(s)-maxSamples:]...)
		}
		h.series[k] = s
	}
	for _, st := range stats {
		for _, p := range st.Peers {
			add(st.Name, p.NextHop, p.Availability)
		}
	}
	for k, s := range h.series {
		if at.Sub(s[len(s)-1].At) >= maxSamples*SampleEvery {
			delete(h.series, k)
		}
	}
}

// Series returns a copy of one peer's samples, oldest first.
func (h *History) Series(ex string, nh netip.Addr) []Sample {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Sample{}, h.series[seriesKey{ex, nh.Unmap()}]...)
}

// Run records sample() now and then every period until ctx ends.
func (h *History) Run(ctx context.Context, period time.Duration, sample func() []Stats) {
	h.Record(time.Now().UTC(), sample())
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			h.Record(now.UTC(), sample())
		}
	}
}
