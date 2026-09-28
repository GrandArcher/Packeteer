// Package passive scores destination prefixes from passively observed TCP
// problems: retransmissions, resets, handshake timeouts, and handshake RTT.
//
// The span and flow target sources feed it. It keeps per-prefix counters in
// time buckets over a sliding window (no packets, no flow records) and
// returns the prefixes whose problem ratio crosses a threshold, so they are
// probed first. It does not announce.
package passive

import (
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Counts are problem counters for one prefix. A source adds deltas.
type Counts struct {
	// Flows is the number of TCP connections (span) or outbound TCP flow
	// records (flow) seen toward the prefix.
	Flows uint64
	// Timeouts are handshakes the remote side never answered.
	Timeouts uint64
	// Resets are RSTs sent by the remote side.
	Resets uint64
	// Segments are outbound data segments, retransmissions included.
	Segments uint64
	// Retrans are outbound data segments that repeat bytes already sent.
	Retrans uint64
	// RTTSamples and RTTSum are handshake round trips measured at the
	// capture point.
	RTTSamples uint64
	RTTSum     time.Duration
}

func (c *Counts) add(d Counts) {
	c.Flows += d.Flows
	c.Timeouts += d.Timeouts
	c.Resets += d.Resets
	c.Segments += d.Segments
	c.Retrans += d.Retrans
	c.RTTSamples += d.RTTSamples
	c.RTTSum += d.RTTSum
}

// events is the number of problem events in c. It ranks representative hosts.
func (c Counts) events() uint64 { return c.Timeouts + c.Resets + c.Retrans }

// RetransPct is retransmitted segments as a percentage of data segments.
func (c Counts) RetransPct() float64 {
	if c.Segments == 0 {
		return 0
	}
	return pct(c.Retrans, c.Segments)
}

// FailurePct is timeouts plus resets as a percentage of flows, capped at 100.
func (c Counts) FailurePct() float64 {
	if c.Flows == 0 {
		return 0
	}
	return pct(c.Timeouts+c.Resets, c.Flows)
}

// RTTAvg is the mean handshake RTT, or zero without samples.
func (c Counts) RTTAvg() time.Duration {
	if c.RTTSamples == 0 {
		return 0
	}
	return c.RTTSum / time.Duration(c.RTTSamples)
}

func pct(n, d uint64) float64 {
	v := float64(n) / float64(d) * 100
	if v > 100 {
		return 100
	}
	return v
}

// Thresholds decide when a prefix is a problem. A zero percentage or RTT
// disables that check. MinSegments guards the retransmission ratio;
// MinFlows guards the failure ratio and the RTT average.
type Thresholds struct {
	RetransPct  float64
	FailurePct  float64
	RTT         time.Duration
	MinSegments uint64
	MinFlows    uint64
}

// Validate rejects out-of-range values and a set with every check off.
func (t Thresholds) Validate() error {
	if t.RetransPct < 0 || t.RetransPct > 100 {
		return fmt.Errorf("retrans_pct %v must be between 0 and 100", t.RetransPct)
	}
	if t.FailurePct < 0 || t.FailurePct > 100 {
		return fmt.Errorf("failure_pct %v must be between 0 and 100", t.FailurePct)
	}
	if t.RTT < 0 {
		return fmt.Errorf("rtt threshold %s must not be negative", t.RTT)
	}
	if t.RetransPct == 0 && t.FailurePct == 0 && t.RTT == 0 {
		return fmt.Errorf("at least one of retrans_pct, failure_pct, or rtt_ms must be positive")
	}
	return nil
}

// Reasons a prefix is a problem.
const (
	ReasonRetrans = "retrans"
	ReasonFailure = "failure"
	ReasonRTT     = "rtt"
)

// Score is the largest ratio of an observed value to its threshold. A prefix
// is a problem when Score is at least 1. Checks without enough samples, or
// that are disabled, do not contribute.
func (t Thresholds) Score(c Counts) (float64, []string) {
	var score float64
	var reasons []string
	check := func(v, limit float64, reason string) {
		if limit <= 0 {
			return
		}
		r := v / limit
		if r > score {
			score = r
		}
		if r >= 1 {
			reasons = append(reasons, reason)
		}
	}
	minFlows := t.MinFlows
	if minFlows == 0 {
		minFlows = 1
	}
	minSegs := t.MinSegments
	if minSegs == 0 {
		minSegs = 1
	}
	if c.Segments >= minSegs {
		check(c.RetransPct(), t.RetransPct, ReasonRetrans)
	}
	if c.Flows >= minFlows {
		check(c.FailurePct(), t.FailurePct, ReasonFailure)
	}
	if c.RTTSamples >= minFlows && t.RTT > 0 {
		check(float64(c.RTTAvg()), float64(t.RTT), ReasonRTT)
	}
	return score, reasons
}

// Problem is one prefix over a threshold.
type Problem struct {
	Prefix  netip.Prefix
	Host    netip.Addr
	Counts  Counts
	Score   float64
	Reasons []string
}

// Window sums Counts per prefix over a sliding window of fixed buckets.
// Each bucket keeps at most maxPrefixes prefixes; a new prefix in a full
// bucket is dropped, so a scan cannot grow memory without bound.
type Window struct {
	mu     sync.Mutex
	window time.Duration
	bucket time.Duration
	max    int
	slots  map[int64]map[netip.Prefix]*cell
}

type cell struct {
	c          Counts
	host       netip.Addr
	hostEvents uint64
}

// NewWindow returns an empty window. maxPrefixes below 1 is treated as 1.
func NewWindow(window time.Duration, maxPrefixes int) *Window {
	b := window / 30
	if b < time.Second {
		b = time.Second
	}
	if maxPrefixes < 1 {
		maxPrefixes = 1
	}
	return &Window{window: window, bucket: b, max: maxPrefixes, slots: map[int64]map[netip.Prefix]*cell{}}
}

// Window is the configured length.
func (w *Window) Window() time.Duration { return w.window }

// Add records a delta for prefix p, observed toward host at time at.
func (w *Window) Add(at time.Time, p netip.Prefix, host netip.Addr, d Counts) {
	if !p.IsValid() {
		return
	}
	p = p.Masked()
	w.mu.Lock()
	defer w.mu.Unlock()
	slot := at.UnixNano() / int64(w.bucket)
	b := w.slots[slot]
	if b == nil {
		b = map[netip.Prefix]*cell{}
		w.slots[slot] = b
		w.prune(at)
	}
	c := b[p]
	if c == nil {
		if len(b) >= w.max {
			return
		}
		c = &cell{}
		b[p] = c
	}
	c.c.add(d)
	if host.IsValid() && p.Contains(host) {
		ev := d.events()
		switch {
		case !c.host.IsValid():
			c.host, c.hostEvents = host, ev
		case c.host == host:
			c.hostEvents += ev
		case ev > c.hostEvents:
			c.host, c.hostEvents = host, ev
		}
	}
}

func (w *Window) prune(now time.Time) {
	cutoff := now.Add(-w.window)
	for slot := range w.slots {
		start := time.Unix(0, slot*int64(w.bucket))
		if !start.Add(w.bucket).After(cutoff) {
			delete(w.slots, slot)
		}
	}
}

// Totals returns the summed counters per prefix inside the window.
func (w *Window) Totals(now time.Time) map[netip.Prefix]Problem {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.prune(now)
	out := map[netip.Prefix]Problem{}
	hostEv := map[netip.Prefix]uint64{}
	for _, b := range w.slots {
		for p, c := range b {
			pr := out[p]
			pr.Prefix = p
			pr.Counts.add(c.c)
			if c.host.IsValid() && (!pr.Host.IsValid() || c.hostEvents > hostEv[p]) {
				pr.Host = c.host
				hostEv[p] = c.hostEvents
			}
			out[p] = pr
		}
	}
	return out
}

// Problems returns the prefixes whose score is at least 1, worst first,
// capped at max (0 means no cap). Ties break by prefix.
func (w *Window) Problems(now time.Time, t Thresholds, max int) []Problem {
	var out []Problem
	for _, pr := range w.Totals(now) {
		s, reasons := t.Score(pr.Counts)
		if s < 1 {
			continue
		}
		pr.Score, pr.Reasons = s, reasons
		out = append(out, pr)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Prefix.String() < out[j].Prefix.String()
	})
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

// Fresh reports which problems are new since the previous call. A prefix
// that leaves the problem list and returns later is new again. The span
// source marks new problems urgent for one probe round.
type Fresh struct {
	mu   sync.Mutex
	prev map[netip.Prefix]bool
}

// Mark returns, for each problem, whether it was absent from the last call.
func (f *Fresh) Mark(ps []Problem) []bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	next := make(map[netip.Prefix]bool, len(ps))
	out := make([]bool, len(ps))
	for i, p := range ps {
		out[i] = !f.prev[p.Prefix]
		next[p.Prefix] = true
	}
	f.prev = next
	return out
}

// ParseNets parses a list of CIDR prefixes for config field name. Host bits
// and duplicates are errors.
func ParseNets(name string, in []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for i, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %q is not a valid CIDR", name, i, s)
		}
		if p != p.Masked() {
			return nil, fmt.Errorf("%s[%d]: %q has host bits set (did you mean %s?)", name, i, s, p.Masked())
		}
		if seen[p] {
			return nil, fmt.Errorf("%s[%d]: duplicate prefix %s", name, i, p)
		}
		seen[p] = true
		out = append(out, p)
	}
	return out, nil
}

// Contains reports whether any prefix in nets contains a.
func Contains(nets []netip.Prefix, a netip.Addr) bool {
	for _, p := range nets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
