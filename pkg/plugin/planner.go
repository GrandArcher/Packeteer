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
// traffic. Locked prefixes (an active performance improvement) are context
// only. Reversible is an active commit improvement: the planner puts its
// volume back on Native before choosing, and the result is the full set of
// commit steers that should exist.
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
// move relieves, used when the improvement cap binds.
type PlanMove struct {
	Prefix     netip.Prefix
	Provider   string
	Reason     string
	ReliefMbps float64
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
type LossOverride interface {
	AllowLoss() bool
}
