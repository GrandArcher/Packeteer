package probe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Responder types (#224). A twamp responder is a TWAMP-Light reflector the
// operator runs, so its replies come back in the order the forward path
// delivered them. An icmp responder is any host that answers echo: the
// far end and ICMP rate limiting can reorder replies, so its reading is
// an estimate and never an input to Decide.
const (
	ResponderTWAMP = "twamp"
	ResponderICMP  = "icmp"
)

// Responder is one host the reordering trains are sent to from every
// provider's source address.
type Responder struct {
	Address netip.Addr
	// Port is the reflector's UDP port. Zero for icmp.
	Port   uint16
	Type   string
	Prober plugin.Prober
}

// Estimate reports whether this responder's reading is only an estimate.
func (r Responder) Estimate() bool { return r.Type != ResponderTWAMP }

// ReorderOptions tune the reordering monitor.
type ReorderOptions struct {
	Providers  []Provider
	Responders []Responder
	// Packets is the train length and Spacing the gap between its packets.
	// Timeout is how long the last packet's reply is waited for.
	Packets int
	Spacing time.Duration
	Timeout time.Duration
	// Interval is the time between measurements of the whole set.
	Interval time.Duration
	// Flows is how many trains, each from a new source port, are sent per
	// provider and twamp responder, so a bundle's members are sampled. An
	// icmp responder gets one train: echo has no port to rotate.
	Flows int
	// Limiter, PerASN, and Exclude are the probe engine's (#203): every
	// train waits on the same budgets, and an excluded responder gets no
	// packet.
	Limiter Limiter
	PerASN  *ASNLimits
	Exclude *Exclusion
	Logger  *slog.Logger
	Now     func() time.Time
	Sleep   func(context.Context, time.Duration) error
}

// ReorderStats are the RFC 4737 metrics of one train. Reordered is the
// count of packets that arrived after a packet sent later (section 3.3).
// RatioPct is Reordered over Received (section 4.1), in percent. Extent is
// the largest reordering extent (section 4.2): how many arrivals a
// reordered packet came after the first later-sent packet. NReordering is
// the largest n for which a packet is n-reordered (section 5.3): it
// arrived after n later-sent packets in a row.
type ReorderStats struct {
	Sent        int     `json:"sent"`
	Received    int     `json:"received"`
	Reordered   int     `json:"reordered"`
	RatioPct    float64 `json:"ratio_pct"`
	Extent      int     `json:"extent"`
	NReordering int     `json:"n_reordering"`
}

// ComputeReorder derives the RFC 4737 metrics from a train's arrival
// order: order holds the send index of each reply as it arrived. A
// prober that could not tell the order leaves it empty, and the result
// is then all zero but Sent.
func ComputeReorder(sent int, order []int) ReorderStats {
	st := ReorderStats{Sent: sent, Received: len(order)}
	if len(order) == 0 {
		return st
	}
	nextExp := 0
	for i, s := range order {
		if s >= nextExp {
			nextExp = s + 1
			continue
		}
		st.Reordered++
		// Extent: distance to the earliest arrival with a higher index.
		for j := 0; j < i; j++ {
			if order[j] > s {
				if e := i - j; e > st.Extent {
					st.Extent = e
				}
				break
			}
		}
		// n-reordering: later-sent packets immediately before this one.
		n := 0
		for j := i - 1; j >= 0 && order[j] > s; j-- {
			n++
		}
		if n > st.NReordering {
			st.NReordering = n
		}
	}
	st.RatioPct = 100 * float64(st.Reordered) / float64(st.Received)
	return st
}

// FlowReorder is one train: a fixed 5-tuple, so one ECMP member.
type FlowReorder struct {
	Flow int `json:"flow"`
	ReorderStats
	Err string `json:"error,omitempty"`
}

// ReorderResult is the latest reordering measurement of one provider path
// toward one responder (#224). Measurement only.
type ReorderResult struct {
	Provider  string     `json:"provider"`
	Responder netip.Addr `json:"responder"`
	Port      uint16     `json:"port,omitempty"`
	Type      string     `json:"type"`
	// Estimate is set for an icmp responder. Estimates are shown, and
	// never scored.
	Estimate bool          `json:"estimate"`
	Flows    []FlowReorder `json:"flows"`
	// Worst is the flow with the highest reordered ratio, the bundle
	// member that reorders most; WorstFlow is its number. Zero when no
	// train got a reply.
	Worst     ReorderStats `json:"worst"`
	WorstFlow int          `json:"worst_flow,omitempty"`
	// Err is set when no train got a reply, the responder is excluded, or
	// the source address cannot be used.
	Err  string    `json:"error,omitempty"`
	Time time.Time `json:"time"`
}

// OK reports whether the result holds a measurement.
func (r ReorderResult) OK() bool { return r.Err == "" }

type reorderKey struct {
	provider  string
	responder netip.AddrPort
	typ       string
}

// ReorderMonitor sends the reordering trains and keeps the latest result
// per provider and responder. It never announces.
type ReorderMonitor struct {
	opt     ReorderOptions
	mu      sync.RWMutex
	results map[reorderKey]ReorderResult
}

// NewReorderMonitor builds a monitor. Packets, Spacing, Timeout, Interval,
// and Flows must be positive; config validation guarantees that.
func NewReorderMonitor(opt ReorderOptions) (*ReorderMonitor, error) {
	if opt.Packets < 2 || opt.Spacing <= 0 || opt.Timeout <= 0 || opt.Interval <= 0 || opt.Flows < 1 {
		return nil, fmt.Errorf("reorder: packets %d, spacing %s, timeout %s, interval %s, flows %d must all be set",
			opt.Packets, opt.Spacing, opt.Timeout, opt.Interval, opt.Flows)
	}
	for _, r := range opt.Responders {
		if r.Prober == nil || !r.Address.IsValid() {
			return nil, fmt.Errorf("reorder: responder %s has no prober", r.Address)
		}
		if r.Type != ResponderTWAMP && r.Type != ResponderICMP {
			return nil, fmt.Errorf("reorder: responder %s has type %q (want twamp or icmp)", r.Address, r.Type)
		}
	}
	if opt.Logger == nil {
		opt.Logger = slog.New(slog.DiscardHandler)
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Sleep == nil {
		opt.Sleep = sleepCtx
	}
	return &ReorderMonitor{opt: opt, results: map[reorderKey]ReorderResult{}}, nil
}

// Run measures every provider and responder, then again every Interval,
// until ctx ends.
func (m *ReorderMonitor) Run(ctx context.Context) error {
	for {
		started := m.opt.Now()
		m.RunOnce(ctx)
		if err := ctx.Err(); err != nil {
			return err
		}
		wait := m.opt.Interval - m.opt.Now().Sub(started)
		if wait < 0 {
			wait = 0
		}
		if err := m.opt.Sleep(ctx, wait); err != nil {
			return err
		}
	}
}

// RunOnce measures every provider and responder once, one train at a
// time, and stores each result as it finishes.
func (m *ReorderMonitor) RunOnce(ctx context.Context) {
	for _, p := range m.opt.Providers {
		for _, r := range m.opt.Responders {
			if ctx.Err() != nil {
				return
			}
			res := m.measure(ctx, p, r)
			if ctx.Err() != nil {
				return
			}
			m.mu.Lock()
			m.results[reorderKey{p.Name, netip.AddrPortFrom(r.Address, r.Port), r.Type}] = res
			m.mu.Unlock()
			if res.OK() {
				m.opt.Logger.Info("reorder", "provider", p.Name, "responder", r.Address, "type", r.Type,
					"ratio_pct", res.Worst.RatioPct, "extent", res.Worst.Extent, "n_reordering", res.Worst.NReordering,
					"worst_flow", res.WorstFlow, "flows", len(res.Flows))
			} else {
				m.opt.Logger.Warn("reorder failed", "provider", p.Name, "responder", r.Address, "type", r.Type, "err", res.Err)
			}
		}
	}
}

func (m *ReorderMonitor) measure(ctx context.Context, p Provider, r Responder) ReorderResult {
	res := ReorderResult{Provider: p.Name, Responder: r.Address, Port: r.Port, Type: r.Type, Estimate: r.Estimate()}
	flows := m.opt.Flows
	if r.Estimate() {
		flows = 1
	}
	// Re-checked per measurement: an origin ASN exclusion follows the RIB.
	if m.opt.Exclude.Addr(r.Address) {
		res.Err, res.Time = "excluded by probe.exclude", m.opt.Now()
		return res
	}
	replied := false
	for f := 1; f <= flows; f++ {
		fl := FlowReorder{Flow: f}
		raw, err := m.train(ctx, p, r)
		switch {
		case err != nil && errors.Is(err, plugin.ErrSourceUnavailable):
			res.Err, res.Time = err.Error(), m.opt.Now()
			return res
		case err != nil:
			fl.Err = err.Error()
			if ctx.Err() != nil {
				return res
			}
		case len(raw.RTTs) > 0 && len(raw.Order) != len(raw.RTTs):
			fl.Err = "prober reports no arrival order"
			fl.Sent = raw.Sent
		default:
			fl.ReorderStats = ComputeReorder(raw.Sent, raw.Order)
			if fl.Received > 0 {
				replied = true
			}
		}
		res.Flows = append(res.Flows, fl)
	}
	res.Time = m.opt.Now()
	if !replied {
		res.Err = "no reply"
		for _, fl := range res.Flows {
			if fl.Err != "" {
				res.Err = fl.Err
				break
			}
		}
		return res
	}
	for _, fl := range res.Flows {
		if fl.Err != "" || fl.Received == 0 {
			continue
		}
		if res.WorstFlow == 0 || fl.RatioPct > res.Worst.RatioPct ||
			(fl.RatioPct == res.Worst.RatioPct && fl.Extent > res.Worst.Extent) {
			res.Worst, res.WorstFlow = fl.ReorderStats, fl.Flow
		}
	}
	return res
}

// train sends one train after waiting on the per-ASN and global budgets.
func (m *ReorderMonitor) train(ctx context.Context, p Provider, r Responder) (plugin.ProbeResult, error) {
	n := m.opt.Packets
	if err := m.opt.PerASN.Wait(ctx, r.Address, n); err != nil {
		return plugin.ProbeResult{}, fmt.Errorf("rate limit: %w", err)
	}
	if m.opt.Limiter != nil {
		if err := m.opt.Limiter.WaitN(ctx, n); err != nil {
			return plugin.ProbeResult{}, fmt.Errorf("rate limit: %w", err)
		}
	}
	req := p.Request(r.Address, n, m.opt.Timeout)
	req.Spacing, req.Port = m.opt.Spacing, r.Port
	pctx, cancel := context.WithTimeout(ctx, time.Duration(n)*m.opt.Spacing+m.opt.Timeout+time.Second)
	defer cancel()
	return r.Prober.Probe(pctx, req)
}

// Results is every stored result, by provider, responder, and type.
func (m *ReorderMonitor) Results() []ReorderResult {
	m.mu.RLock()
	out := make([]ReorderResult, 0, len(m.results))
	for _, r := range m.results {
		out = append(out, r)
	}
	m.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Provider != b.Provider {
			return a.Provider < b.Provider
		}
		if a.Responder != b.Responder {
			return a.Responder.Less(b.Responder)
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Type < b.Type
	})
	return out
}

// Scored is the reordered ratio Decide uses per provider: the worst flow
// of its freshest controlled (twamp) readings no older than maxAge. A
// provider with only estimates, failed trains, or stale readings is
// absent. Estimates never steer.
func (m *ReorderMonitor) Scored(now time.Time, maxAge time.Duration) map[string]float64 {
	out := map[string]float64{}
	for _, r := range m.Results() {
		if r.Estimate || !r.OK() || (maxAge > 0 && now.Sub(r.Time) > maxAge) {
			continue
		}
		if v, ok := out[r.Provider]; !ok || r.Worst.RatioPct > v {
			out[r.Provider] = r.Worst.RatioPct
		}
	}
	return out
}
