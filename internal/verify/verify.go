// Package verify checks that a steer moved traffic (#305). After Packeteer
// announces an outbound improvement or an inbound steer, the interface
// counters of the providers involved, and for an outbound move the flow
// volume of the prefix, say whether the traffic went where it was meant
// to. The result is verified, partial, or not moved. The Tracker only
// judges and reports; undoing a steer is the job of the controller that
// made it.
package verify

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"
)

// Kind is the direction of the steer.
type Kind string

// Steer directions.
const (
	Outbound Kind = "outbound"
	Inbound  Kind = "inbound"
)

// Status is where a verification stands.
type Status string

// Verification statuses. Partial and NotMoved are the unverified ones.
const (
	Pending  Status = "pending"
	Verified Status = "verified"
	Partial  Status = "partial"
	NotMoved Status = "not_moved"
	// Unknown means the data to judge was missing or the traffic too
	// small. It is neither a pass nor a failure and undoes nothing.
	Unknown Status = "unknown"
)

// Unverified reports a status that is a routing anomaly.
func (s Status) Unverified() bool { return s == Partial || s == NotMoved }

// maxDone bounds the finished results kept for display.
const maxDone = 200

// Rate is a provider's latest interface rate in Mbps and when it was read.
type Rate struct {
	InMbps  float64
	OutMbps float64
	Updated time.Time
}

// Path is the probe result of one provider toward one prefix.
type Path struct {
	LossPct float64
	RTTMs   float64
}

// Claim is a steer to verify, with the readings from just before it took
// effect. Provider is where outbound traffic was steered to, or the
// provider inbound traffic is steered away from.
type Claim struct {
	Kind     Kind
	Prefix   netip.Prefix // outbound only
	Provider string
	// From is the provider the prefix used before (outbound), when known.
	From string
	// Expected is the prefix's flow volume in Mbps (outbound). An inbound
	// claim expects the provider's whole inbound rate.
	Expected float64
	Rates    map[string]Rate
	// Path is the new provider's result for the prefix (outbound).
	Path *Path
}

func (c Claim) key() string { return target(c.Kind, c.Prefix, c.Provider) }

// target is what a steer is keyed by: the prefix (outbound) or the provider
// inbound traffic is steered away from.
func target(k Kind, p netip.Prefix, provider string) string {
	if k == Outbound {
		return p.String()
	}
	return provider
}

// Observation is what the host reads each round.
type Observation struct {
	Rates map[string]Rate
	// Path returns a provider's latest result toward a prefix.
	Path func(netip.Prefix, string) (Path, bool)
}

// Result is one verification. Fields after Detail are set when it is judged.
type Result struct {
	Kind     Kind         `json:"kind"`
	Prefix   netip.Prefix `json:"prefix,omitzero"`
	Provider string       `json:"provider"`
	From     string       `json:"from,omitempty"`
	Status   Status       `json:"status"`
	Started  time.Time    `json:"started"`
	Due      time.Time    `json:"due"`
	Checked  time.Time    `json:"checked,omitzero"`
	// ExpectedMbps is the traffic that should have moved and MovedMbps
	// what did. MovedPct is their ratio.
	ExpectedMbps float64 `json:"expected_mbps"`
	MovedMbps    float64 `json:"moved_mbps"`
	MovedPct     float64 `json:"moved_pct"`
	// PathDegraded is set when the new provider's loss or RTT for the
	// prefix got worse under the new load (outbound).
	PathDegraded bool   `json:"path_degraded,omitempty"`
	Detail       string `json:"detail"`
	// BackedOut is set when the steer did not move traffic and Backout
	// names its direction: the host undoes it and holds it off for
	// Backoff.
	BackedOut bool          `json:"backed_out,omitempty"`
	Backoff   time.Duration `json:"-"`
}

// Target names what was steered: the prefix (outbound) or the provider
// inbound traffic is steered away from.
func (r Result) Target() string { return target(r.Kind, r.Prefix, r.Provider) }

type open struct {
	claim   Claim
	started time.Time
	due     time.Time
}

type strike struct {
	n    int
	last time.Time
}

// Tracker is safe for concurrent use.
type Tracker struct {
	cfg      Config
	degraded func(before, after Path) bool

	mu      sync.Mutex
	open    map[string]*open
	done    map[string]Result
	strikes map[string]strike
}

// New returns a tracker. degraded says whether after is a worse path than
// before by the decision thresholds; nil never reports a degraded path.
func New(cfg Config, degraded func(before, after Path) bool) *Tracker {
	return &Tracker{cfg: cfg.WithDefaults(), degraded: degraded,
		open: map[string]*open{}, done: map[string]Result{}, strikes: map[string]strike{}}
}

func mapKey(k Kind, key string) string { return string(k) + " " + key }

func (t *Tracker) window(k Kind) time.Duration {
	if k == Inbound {
		return t.cfg.InboundWindow
	}
	return t.cfg.OutboundWindow
}

// Begin starts verifying a steer. A claim for the same target replaces the
// open one, as a switch does.
func (t *Tracker) Begin(now time.Time, c Claim) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c.Kind == Inbound {
		c.Expected = c.Rates[c.Provider].InMbps
	}
	k := mapKey(c.Kind, c.key())
	t.open[k] = &open{claim: c, started: now, due: now.Add(t.window(c.Kind))}
	delete(t.done, k)
}

// Cancel drops an open verification because its steer ended first.
func (t *Tracker) Cancel(kind Kind, key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.open, mapKey(kind, key))
}

// Keep drops every open verification whose steer is no longer on the wire,
// as keep reports. A route that went away for another reason (a mode
// change, an allowlist change, a failed sync) must not be judged on traffic
// that has gone back to the native path.
func (t *Tracker) Keep(keep func(kind Kind, key string) bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, o := range t.open {
		if !keep(o.claim.Kind, o.claim.key()) {
			delete(t.open, k)
		}
	}
}

// Reset drops every open verification, as a step-down from active does:
// the next term starts with no steer to judge.
func (t *Tracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.open = map[string]*open{}
}

// Observe judges every claim whose window has passed and returns the
// results. A claim with no counter newer than half its window waits one
// more window, then is unknown.
func (t *Tracker) Observe(now time.Time, obs Observation) []Result {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, s := range t.strikes {
		if now.Sub(s.last) > 2*t.cfg.MaxBackoff {
			delete(t.strikes, k)
		}
	}
	var out []Result
	for _, k := range slices.Sorted(maps.Keys(t.open)) {
		o := t.open[k]
		if now.Before(o.due) {
			continue
		}
		r, waiting := t.judge(now, o, obs)
		if waiting && now.Before(o.due.Add(t.window(o.claim.Kind))) {
			continue
		}
		delete(t.open, k)
		t.finish(k, &r)
		out = append(out, r)
	}
	return out
}

// List is every open verification as pending, then the finished ones,
// newest first.
func (t *Tracker) List() []Result {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Result
	for _, k := range slices.Sorted(maps.Keys(t.open)) {
		o := t.open[k]
		out = append(out, Result{Kind: o.claim.Kind, Prefix: o.claim.Prefix, Provider: o.claim.Provider, From: o.claim.From,
			Status: Pending, Started: o.started, Due: o.due, ExpectedMbps: o.claim.Expected,
			Detail: "waiting for the window to pass"})
	}
	done := make([]Result, 0, len(t.done))
	for _, r := range t.done {
		done = append(done, r)
	}
	sort.Slice(done, func(i, j int) bool { return done[i].Checked.After(done[j].Checked) })
	return append(out, done...)
}

// finish records a result. A target that did not move traffic and is
// backed out gets a hold-off that doubles on each consecutive failure; a
// verified steer clears the count.
func (t *Tracker) finish(k string, r *Result) {
	switch {
	case r.Status == Verified:
		delete(t.strikes, k)
	case r.Status == NotMoved && t.cfg.backsOut(r.Kind):
		s := t.strikes[k]
		s.n++
		s.last = r.Checked
		t.strikes[k] = s
		r.BackedOut = true
		r.Backoff = t.cfg.Backoff
		for i := 1; i < s.n && r.Backoff < t.cfg.MaxBackoff; i++ {
			r.Backoff *= 2
		}
		r.Backoff = min(r.Backoff, t.cfg.MaxBackoff)
		r.Detail += fmt.Sprintf("; backed out, held off %s", r.Backoff)
	}
	t.done[k] = *r
	for len(t.done) > maxDone {
		var oldest string
		for dk, d := range t.done {
			if oldest == "" || d.Checked.Before(t.done[oldest].Checked) {
				oldest = dk
			}
		}
		delete(t.done, oldest)
	}
}

// moved is the traffic that left the old side and arrived on the new one:
// the smaller of the two when both have counters, so demand falling or an
// unrelated flow rising does not pass for a move. ok is false when no side
// has a counter newer than half the window.
func (t *Tracker) moved(o *open, obs Observation) (moved float64, note string, ok bool) {
	c := o.claim
	settle := o.started.Add(t.window(c.Kind) / 2)
	delta := func(name string, rate func(Rate) float64) (float64, bool) {
		b, bok := c.Rates[name]
		a, aok := obs.Rates[name]
		if !bok || !aok || a.Updated.Before(settle) {
			return 0, false
		}
		return rate(a) - rate(b), true
	}
	var left, arrived float64
	var haveLeft, haveArrived bool
	if c.Kind == Inbound {
		d, ok := delta(c.Provider, func(r Rate) float64 { return r.InMbps })
		left, haveLeft = -d, ok
		for name := range obs.Rates {
			if d, ok := delta(name, func(r Rate) float64 { return r.InMbps }); ok && name != c.Provider {
				arrived += d
				haveArrived = true
			}
		}
	} else {
		out := func(r Rate) float64 { return r.OutMbps }
		if c.From != "" {
			d, ok := delta(c.From, out)
			left, haveLeft = -d, ok
		}
		arrived, haveArrived = delta(c.Provider, out)
	}
	switch {
	case haveLeft && haveArrived:
		return max(0, min(left, arrived)), "", true
	case haveLeft:
		return max(0, left), "no counters for the receiving side", true
	case haveArrived:
		return max(0, arrived), "no counters for the sending side", true
	}
	return 0, "", false
}

// judge returns the result for o and whether it lacks counters, in which
// case Observe may wait for fresher ones.
func (t *Tracker) judge(now time.Time, o *open, obs Observation) (Result, bool) {
	c := o.claim
	r := Result{Kind: c.Kind, Prefix: c.Prefix, Provider: c.Provider, From: c.From, Started: o.started, Due: o.due,
		Checked: now, ExpectedMbps: c.Expected}
	if c.Expected < t.cfg.MinMbps {
		r.Status = Unknown
		r.Detail = fmt.Sprintf("expected %.2f Mbps is below min_mbps %.2f: no flow volume or too little traffic to judge", c.Expected, t.cfg.MinMbps)
		return r, false
	}
	moved, note, ok := t.moved(o, obs)
	if !ok {
		r.Status = Unknown
		r.Detail = "no interface counters newer than half the window"
		return r, true
	}
	r.MovedMbps = moved
	r.MovedPct = moved / c.Expected * 100
	switch {
	case r.MovedPct >= t.cfg.VerifiedPct:
		r.Status = Verified
	case r.MovedPct >= t.cfg.MovedPct:
		r.Status = Partial
	default:
		r.Status = NotMoved
	}
	r.Detail = fmt.Sprintf("%.1f of %.1f Mbps moved (%.0f%%)", moved, c.Expected, r.MovedPct)
	if note != "" {
		r.Detail += "; " + note
	}
	if c.Kind == Outbound && c.Path != nil && obs.Path != nil && t.degraded != nil {
		if after, ok := obs.Path(c.Prefix, c.Provider); ok && t.degraded(*c.Path, after) {
			r.PathDegraded = true
			r.Detail += fmt.Sprintf("; the new path got worse under load (loss %.1f%% to %.1f%%, RTT %.1f to %.1f ms)",
				c.Path.LossPct, after.LossPct, c.Path.RTTMs, after.RTTMs)
		}
	}
	return r, false
}
