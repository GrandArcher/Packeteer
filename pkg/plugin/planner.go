package plugin

import (
	"net/netip"
	"time"
)

// PlanPath is one provider's measurement toward a prefix.
type PlanPath struct {
	Provider string
	LossPct  float64
	RTT      time.Duration
	Usable   bool
}

// PlanPrefix is a prefix the planner may steer. VolumeMbps is observed
// traffic. Locked is a performance steer (active, or chosen this round and
// waiting on the cap): the planner moves its volume from Native to Current
// and does not emit a commit move for it. Reversible is an active commit
// improvement: the planner puts its volume back on Native before choosing,
// and the result is the full set of commit steers that should exist.
type PlanPrefix struct {
	Prefix     netip.Prefix
	Native     string
	Current    string
	VolumeMbps float64
	Locked     bool
	Reversible bool
	Paths      []PlanPath
}

// PlanProvider is one transit and its latest telemetry row. HaveRow is
// false when no telemetry plugin reported this provider. The planner
// decides whether the row is fresh enough to use.
type PlanProvider struct {
	Name       string
	Group      string
	Precedence int
	CCDisable  bool
	Excluded   bool
	Up         bool
	Usage      Usage
	HaveRow    bool
	// Cost is the provider's price per Mbps. HasCost is false when the
	// provider has no cost configured; such a provider is not a cost
	// destination and a prefix native to it is not cost-steered.
	Cost    float64
	HasCost bool
}

// PlanInput is a snapshot. Plan must not announce or touch the network.
type PlanInput struct {
	Now       time.Time
	Providers []PlanProvider
	Prefixes  []PlanPrefix
}

// PlanMove is a commit steer that should exist after this evaluation.
// Provider is the provider that should carry the prefix, which may already
// be the current one. ReliefMbps is the volume taken off the provider the
// move relieves, used when the improvement cap binds. Cause is CauseCommit
// (the default when empty) or CauseCost. A cost move ranks by Savings
// instead of ReliefMbps when the cap binds.
type PlanMove struct {
	Prefix     netip.Prefix
	Provider   string
	Reason     string
	ReliefMbps float64
	Cause      string
	// Savings is the estimated saving of a cost move: price difference
	// per Mbps times the prefix volume, or the price difference alone
	// when the volume is unknown.
	Savings float64
}

// Planner is optional. A scorer that also steers for commit and provider
// groups implements it. Decide calls Plan only when the scorer implements
// Planner; the weighted scorer does not, and commit control stays off.
type Planner interface {
	Plan(in PlanInput) []PlanMove
}

// LossOverride is optional on a Planner. AllowLoss reports whether a
// commit move may land on a path with higher loss than the one it leaves.
// A scorer that does not implement it is treated as refusing that move.
// Decide enforces the same rule when it accepts a PlanMove, including a
// move whose destination is the native provider (that is not a steer).
type LossOverride interface {
	AllowLoss() bool
}

// CostPolicy is required on a Planner that emits CauseCost moves. Decide
// refuses a cost move from a scorer that does not implement it.
//
// A path is inside the floor when its loss is at most MaxLossPct above
// the lowest loss, and its RTT is at most MaxRTT above the lowest RTT,
// among usable providers that are not excluded. Decide accepts a cost
// move only onto a path inside the floor that is cheaper than the native
// provider, and withdraws an active cost steer at once when its path
// leaves the floor.
type CostPolicy interface {
	Floor() (maxLossPct float64, maxRTT time.Duration)
	// CostFirst is true for cost precedence: a prefix with a performance
	// move is offered to the planner too, and a valid cost move replaces
	// that performance move. With performance precedence (false) a
	// performance move is locked and wins.
	CostFirst() bool
}
