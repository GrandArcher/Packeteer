// Package policy is the decision engine. Decide is a pure function: given
// the previous state, the current inputs (probe results, provider health,
// RIB view) and the time, it returns the new state and per-prefix
// decisions. It never touches the network; the announcer acts on the
// resulting improvements only in inject mode.
package policy

import (
	"net/netip"
	"slices"
	"time"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Actions recorded on a decision.
const (
	ActionNone    = "none"    // keep native routing
	ActionImprove = "improve" // new improvement
	ActionKeep    = "keep"    // existing improvement stays
	ActionSwitch  = "switch"  // existing improvement moves to another provider
	ActionRetire  = "retire"  // existing improvement removed
	ActionCapped  = "capped"  // would improve, but max_improvements reached
)

// NativePathConfirm is how long a neighbor must keep advertising a prefix
// after an improvement is already active before a later withdraw is treated
// as the prefix leaving. A shorter gap is the router suppressing the native
// path because Packeteer's route became best: iBGP does not send that route
// back to Packeteer, and it does not send a non-best path either. Retiring
// on that gap withdraws the improvement, the native path returns, and the
// next round injects it again. The announcer applies the same rule to the
// learned more-specifics it announces with an improvement (#56).
const NativePathConfirm = 5 * time.Second

const nativePathConfirm = NativePathConfirm

// Config tunes decisions.
type Config struct {
	Mode            string        // observe, suggest, inject
	MinLossDeltaPct float64       // loss improvement that justifies a move
	MinRTTDelta     time.Duration // latency improvement that justifies a move
	// MinRTTDeltaPct, when greater than 0, is the other half of an RTT
	// win: the improvement must also be at least this percent of the
	// current path's RTT. 0 leaves the absolute MinRTTDelta as the only
	// latency check. A loss win does not use it.
	MinRTTDeltaPct float64
	// ConfirmRounds is how many consecutive fresh probe rounds a new
	// performance move, or a switch onto a better provider, must win
	// before it is created. 0 and 1 are today's behavior (the first fresh
	// win). A stale round does not count. A fresh miss resets the streak.
	// Flip-back does not wait.
	ConfirmRounds   int
	HoldTime        time.Duration // minimum life of an improvement, and cooldown after flip-back
	MaxImprovements int
	ImprovementTTL  time.Duration // retire (and re-evaluate) after this long; 0 = never
	MaxResultAge    time.Duration // probe results older than this are stale
	Excluded        map[string]bool
	// RPKIAvoidInvalid refuses a new improvement onto a provider whose
	// learned path for the prefix is RPKI-invalid (#158). It is off by
	// default and never changes the learned RIB.
	RPKIAvoidInvalid bool
	Allowlist        []netip.Prefix // inject mode: only these (or more-specifics of them)
	// Providers carries group, precedence, and cc_disable. Empty means
	// commit control has no provider policy (the weighted scorer ignores it).
	Providers []ProviderPolicy
	// Ports are the exchange ports (#151) the commit and cost planners
	// share between a peer's providers.
	Ports []PortPolicy
	// Flap parks prefixes whose chosen provider keeps changing (#228).
	Flap FlapConfig
}

// ProviderPolicy is the commit-control and cost configuration of one
// provider. Precedence 0 means the default (100); lower is preferred.
// HasCost is false when the provider has no cost configured.
type ProviderPolicy struct {
	Name       string
	Group      string
	Precedence int
	CCDisable  bool
	Cost       float64
	HasCost    bool
	// Port names the exchange port this provider's peer shares (#151).
	Port string
}

// PortPolicy is one exchange port. Its telemetry row is the one whose
// provider name equals Name.
type PortPolicy struct {
	Name         string
	CapacityMbps float64
	CommitMbps   float64
}

// Input is everything Decide looks at.
type Input struct {
	Results    []probe.Result
	ProviderUp map[string]bool
	// RIBEnabled is false when no BGP neighbors are configured; decisions
	// then only rank providers (no native exit is known).
	RIBEnabled bool
	// RIBReady false while enabled means the view is stale: every
	// improvement is retired and nothing new is decided.
	RIBReady bool
	// Native maps a probed prefix to the provider of the path a neighbor is
	// still advertising. A prefix missing here is not in the learned RIB.
	// An active improvement whose prefix was still advertised for
	// nativePathConfirm, and is then missing, is retired. An improvement
	// whose prefix disappears sooner is kept: that is the router hiding the
	// native path because Packeteer's route won, not the prefix leaving.
	Native map[netip.Prefix]string
	// Held reports prefixes the leak watch holds off the wire (#199). The
	// neighbor advertising the native path then is expected, so it does not
	// arm the withdraw check above; otherwise clearing the hold would read
	// the router hiding the native path as the prefix leaving. Nil is none.
	Held func(netip.Prefix) bool
	// Usage is the latest telemetry snapshot. Commit control reads it only
	// when the scorer implements plugin.Planner.
	Usage []plugin.Usage
	// VolumeMbps is observed traffic per prefix, decimal megabits per second.
	// A missing or zero entry is not moved for commit or balance.
	VolumeMbps map[netip.Prefix]float64
	// WeightVolumeMbps is per-prefix volume read only for improvement
	// weights (#34) when the scorer is not a planner. It feeds nothing
	// else: not commit control, not cost annotations. Nil means use
	// VolumeMbps.
	WeightVolumeMbps map[netip.Prefix]float64
	// Policies is the routing-policy verdict per probed prefix, from the
	// configured policy chain. A missing entry means no policy matched.
	Policies map[netip.Prefix]plugin.PolicyVerdict
	// Maintenance lists providers inside an open maintenance window. They
	// are excluded for this evaluation.
	Maintenance []string
	// NoRoute lists, per prefix, providers the route check (bmp prefer or
	// only, or add_path, #26) found without a path for that exact prefix.
	// They are not usable for it: no new improvement goes there, and an
	// active one is retired. The native provider is never marked.
	NoRoute map[netip.Prefix]map[string]bool
	// EgressDown lists providers whose every egress router (bgp.neighbors
	// providers, #27) has lost its iBGP session. They are not usable: no
	// new improvement goes there, and an active one is retired. The native
	// provider is never marked.
	EgressDown map[string]bool
	// RPKI maps a prefix and provider to the RFC 6811 origin-validation
	// state of that provider's learned path (#158). It is shown on the
	// decision's candidates and, when RPKIAvoidInvalid is set, refuses a
	// new improvement onto an invalid path. A missing entry is unknown.
	RPKI map[netip.Prefix]map[string]plugin.RPKIValidity
	// Remote lists providers whose results a federation peer measured
	// (#30). Their times follow that peer's probe schedule, so they do not
	// show whether this instance's own probe round finished. Nil is none.
	Remote map[string]bool
}

// Improvement is an active (or, outside inject mode, recommended) steer.
type Improvement struct {
	Prefix   netip.Prefix `json:"prefix"`
	Provider string       `json:"provider"` // provider traffic is steered to
	Native   string       `json:"native"`   // provider the RIB used before
	Since    time.Time    `json:"since"`
	Reason   string       `json:"reason"`
	// Cause is performance, commit, or cost. Empty means performance
	// (state from before commit control, or a test that did not set it).
	Cause string `json:"cause,omitempty"`
	// CostDelta is the native provider's cost per Mbps minus the steered
	// provider's. Positive is a saving. EstSavings is CostDelta times the
	// prefix volume when a source reports one. Both are set only when both
	// providers have a cost, and are estimates for reports: they do not
	// change a decision.
	CostDelta  float64 `json:"cost_delta,omitempty"`
	EstSavings float64 `json:"est_savings,omitempty"`
	// VolumeMbps is the prefix's observed rate at the last decision, the
	// traffic this improvement moves. Zero when no source reports volume.
	// Display only: it does not change a decision.
	VolumeMbps float64 `json:"volume_mbps,omitempty"`

	// nativeSeen is the first decision, after this improvement already
	// existed, that still saw the prefix in the RIB. nativeHeld is that
	// previous decision's observation. Both stay zero until then so the
	// sighting that created the improvement does not count.
	nativeSeen time.Time
	nativeHeld bool
}

// confirm is a performance move that has won on fresh rounds but has not
// yet reached ConfirmRounds. It is not an announcement.
type confirm struct {
	Provider string
	Streak   int
	// Round is the newest measurement time that counted. The same
	// measurements seen again (a RIB change, or the staleness ticker)
	// do not count twice.
	Round time.Time
	// Local is the newest time among this instance's own results when the
	// round counted. A remote result is not compared with it.
	Local time.Time
	// Probe is set only for the evaluation that compared the paths and
	// left the streak short. The next evaluation clears it first, so a
	// round that cannot compare does not keep the prober awake.
	Probe bool
}

// State is carried between Decide calls.
type State struct {
	Improvements map[netip.Prefix]Improvement
	// Cooldown blocks re-improving a prefix until the given time after a
	// performance flip-back (flap prevention).
	Cooldown map[netip.Prefix]time.Time
	// confirm is the in-progress performance confirmation, per prefix.
	confirm map[netip.Prefix]confirm
	// flips are the recent provider changes per prefix, oldest first.
	flips map[netip.Prefix][]time.Time
	// quarantine holds the prefixes parked on their native path (#228).
	quarantine map[netip.Prefix]Quarantine
	offenses   map[netip.Prefix]offense
}

// NewState returns an empty state.
func NewState() State {
	return State{
		Improvements: map[netip.Prefix]Improvement{},
		Cooldown:     map[netip.Prefix]time.Time{},
		confirm:      map[netip.Prefix]confirm{},
		flips:        map[netip.Prefix][]time.Time{},
		quarantine:   map[netip.Prefix]Quarantine{},
		offenses:     map[netip.Prefix]offense{},
	}
}

func (s State) clone() State {
	n := NewState()
	for k, v := range s.Improvements {
		n.Improvements[k] = v
	}
	for k, v := range s.Cooldown {
		n.Cooldown[k] = v
	}
	for k, v := range s.confirm {
		n.confirm[k] = v
	}
	for k, v := range s.flips {
		n.flips[k] = slices.Clone(v)
	}
	for k, v := range s.quarantine {
		n.quarantine[k] = v
	}
	for k, v := range s.offenses {
		n.offenses[k] = v
	}
	return n
}

// Candidate is one provider's measurement toward a prefix.
type Candidate struct {
	Provider string        `json:"provider"`
	Score    float64       `json:"score"`
	LossPct  float64       `json:"loss_pct"`
	RTTAvg   time.Duration `json:"rtt_avg"`
	Jitter   time.Duration `json:"jitter"`
	Usable   bool          `json:"usable"`
	Why      string        `json:"why,omitempty"` // why not usable
	// RPKI is the RFC 6811 origin-validation state of this provider's
	// learned path for the prefix (#158). Display only unless
	// Config.RPKIAvoidInvalid makes an invalid path unusable.
	RPKI plugin.RPKIValidity `json:"rpki,omitempty"`
}

// Decision explains what happened to one prefix in one evaluation.
type Decision struct {
	Prefix      netip.Prefix `json:"prefix"`
	Native      string       `json:"native,omitempty"`
	Current     string       `json:"current,omitempty"` // native, or the improvement's provider
	Recommended string       `json:"recommended,omitempty"`
	Action      string       `json:"action"`
	Cause       string       `json:"cause,omitempty"`
	Reason      string       `json:"reason"`
	// Policy describes the routing policy that matched, if any.
	Policy string `json:"policy,omitempty"`
	// Weight is the move's improvement weight when the scorer's
	// improvement_weights are on (#34). It orders new moves for the cap.
	Weight     float64     `json:"weight,omitempty"`
	Candidates []Candidate `json:"candidates"`
	// Subranges are the measured parts of the prefix (#121), busiest
	// first. The candidates above are their traffic-weighted aggregate.
	// Heterogeneous is set when two of them have a different best
	// provider. Both are information only: nothing is announced for a
	// sub-range, and the decision steers only Prefix.
	Subranges     []SubrangeDecision `json:"subranges,omitempty"`
	Heterogeneous bool               `json:"heterogeneous,omitempty"`
}

// SubrangeDecision is one measured sub-range of a decided prefix (#121):
// its traffic weight, each provider's score toward it, and the best of
// them. Best is empty when no provider was usable.
type SubrangeDecision struct {
	Prefix     netip.Prefix `json:"prefix"`
	Weight     float64      `json:"weight"`
	Best       string       `json:"best,omitempty"`
	Candidates []Candidate  `json:"candidates"`
}

// Change is an improvement transition for the announcer and notifiers.
type Change struct {
	Action string      `json:"action"` // improve, switch, retire
	Old    Improvement `json:"old,omitempty"`
	New    Improvement `json:"new,omitempty"`
}

// pending is a new improvement waiting on the max_improvements cap.
// Entries are admitted by rank: static policy pins, then VIP performance
// moves, then other performance moves, then commit and cost moves.
type pending struct {
	d      *Decision
	imp    Improvement
	gain   float64
	commit bool
	rank   int
	// weight is set when the scorer's improvement weights are on (#34).
	weight  float64
	weighed bool
}

// Admission ranks for pending moves. Lower is admitted first.
const (
	rankStatic = iota
	rankVIP
	rankPerformance
	rankPlanned
)

// Output of one evaluation.
type Output struct {
	Decisions []Decision
	Changes   []Change
	// Urgent are prefixes whose performance move compared this evaluation
	// and is still short of confirm_rounds. The probe engine measures
	// them after a quarter of their interval. A round that cannot
	// compare leaves this empty. The global rate limit still applies.
	Urgent []netip.Prefix
	// Quarantines are the flap quarantines that started or ended in this
	// evaluation (#228).
	Quarantines []QuarantineChange
}

func sortedKeys(m map[netip.Prefix]Improvement) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	netpfx.Sort(out)
	return out
}
