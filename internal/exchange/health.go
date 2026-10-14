package exchange

import (
	"slices"
	"sync"
	"time"
)

// Reach states of a peer's next hop.
const (
	ReachReachable   = "reachable"
	ReachUnreachable = "unreachable"
	ReachUnknown     = "unknown"
)

// HealthOptions decide when a peer, and then the exchange, is degraded
// (#149).
type HealthOptions struct {
	// LossPct is the loss at or above which a peer is degraded.
	LossPct float64
	// RTT, when positive, degrades a peer whose mean RTT is above it.
	RTT time.Duration
	// MinPeers and MinPercent: the exchange is degraded when at least
	// MinPeers peers are, or, when MinPercent is positive, that share of
	// the exchange's peers. Never fewer than two peers.
	MinPeers   int
	MinPercent int
	// Window is how long a peer stays degraded after its last degraded
	// probe, so peers that fail in turn still add up and one good probe
	// does not end the alert.
	Window time.Duration
}

// HealthSpec is one exchange the tracker watches.
type HealthSpec struct {
	Exchange string
	Peers    []string
	HealthOptions
}

// HopSample is one probe of a peer's next hop. Measured is false when no
// measurement was possible (a prober error): it says nothing about the
// peer and is not counted.
type HopSample struct {
	Peer     string
	Measured bool
	LossPct  float64
	RTT      time.Duration
}

// PeerReach is the latest next-hop measurement of one peer.
type PeerReach struct {
	State    string    `json:"state"`
	LossPct  float64   `json:"loss_pct"`
	RTTMs    float64   `json:"rtt_ms"`
	Degraded bool      `json:"degraded"`
	Checked  time.Time `json:"checked,omitzero"`
}

// ExchangeHealth is the tracker's view of one exchange.
type ExchangeHealth struct {
	Degraded      bool
	DegradedPeers []string
	Since         time.Time
	Peers         map[string]PeerReach
}

// Change is an exchange entering or leaving the degraded state.
type Change struct {
	Exchange      string
	Degraded      bool
	DegradedPeers []string
	Peers         int
}

type peerState struct {
	last    HopSample
	checked time.Time
	lastBad time.Time
}

type exchangeState struct {
	spec     HealthSpec
	peers    map[string]*peerState
	degraded bool
	since    time.Time
}

// Health tracks next-hop reachability per peer and raises the
// exchange-wide state. It only reads probe results.
type Health struct {
	mu     sync.Mutex
	byPeer map[string]*exchangeState
	ex     []*exchangeState
}

// NewHealth watches the given exchanges. A peer listed twice or on two
// exchanges belongs to the first.
func NewHealth(specs []HealthSpec) *Health {
	h := &Health{byPeer: map[string]*exchangeState{}}
	for _, sp := range specs {
		st := &exchangeState{spec: sp, peers: map[string]*peerState{}}
		for _, p := range sp.Peers {
			if _, taken := h.byPeer[p]; taken {
				continue
			}
			st.peers[p] = &peerState{}
			h.byPeer[p] = st
		}
		h.ex = append(h.ex, st)
	}
	return h
}

func (o HealthOptions) bad(s HopSample) bool {
	return s.Measured && (s.LossPct >= o.LossPct || (o.RTT > 0 && s.RTT > o.RTT))
}

// Update records a round of samples and returns the exchanges whose state
// changed. A sample for a peer the tracker does not watch is ignored.
func (h *Health) Update(now time.Time, samples []HopSample) []Change {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range samples {
		ex := h.byPeer[s.Peer]
		if ex == nil {
			continue
		}
		p := ex.peers[s.Peer]
		p.last, p.checked = s, now.UTC()
		if ex.spec.bad(s) {
			p.lastBad = now
		}
	}
	var out []Change
	for _, ex := range h.ex {
		bad := ex.degradedPeers(now)
		n := len(ex.peers)
		deg := len(bad) >= 2 && (len(bad) >= min(ex.spec.MinPeers, n) ||
			(ex.spec.MinPercent > 0 && len(bad)*100 >= ex.spec.MinPercent*n))
		if deg == ex.degraded {
			continue
		}
		ex.degraded = deg
		ex.since = time.Time{}
		if deg {
			ex.since = now.UTC()
		}
		out = append(out, Change{Exchange: ex.spec.Exchange, Degraded: deg, DegradedPeers: bad, Peers: n})
	}
	return out
}

// degradedPeers lists the peers with a degraded probe inside the window,
// sorted.
func (ex *exchangeState) degradedPeers(now time.Time) []string {
	var out []string
	for name, p := range ex.peers {
		if !p.lastBad.IsZero() && now.Sub(p.lastBad) <= ex.spec.Window {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// Snapshot is the latest health per exchange name. A nil Health has none.
func (h *Health) Snapshot(now time.Time) map[string]ExchangeHealth {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]ExchangeHealth, len(h.ex))
	for _, ex := range h.ex {
		eh := ExchangeHealth{Degraded: ex.degraded, DegradedPeers: ex.degradedPeers(now), Since: ex.since, Peers: map[string]PeerReach{}}
		for name, p := range ex.peers {
			eh.Peers[name] = ex.reach(p, now)
		}
		out[ex.spec.Exchange] = eh
	}
	return out
}

func (ex *exchangeState) reach(p *peerState, now time.Time) PeerReach {
	r := PeerReach{State: ReachUnknown, Checked: p.checked}
	if p.last.Measured {
		r.LossPct, r.RTTMs = p.last.LossPct, float64(p.last.RTT)/float64(time.Millisecond)
		r.State = ReachReachable
		if p.last.LossPct >= 100 {
			r.State = ReachUnreachable
		}
	}
	r.Degraded = !p.lastBad.IsZero() && now.Sub(p.lastBad) <= ex.spec.Window
	return r
}
