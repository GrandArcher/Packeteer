package plugin

import "net/netip"

// WeightInput is one new improvement competing for a max_improvements
// slot (#34).
type WeightInput struct {
	Prefix   netip.Prefix
	Provider string
	// Gain is the native path's score minus the chosen path's: how much
	// the move improves, in scorer units. Zero for a static policy pin.
	Gain float64
	// VolumeMbps is the prefix's observed traffic. Zero when no target
	// source reports a volume for it.
	VolumeMbps float64
}

// ImprovementWeigher is optional on a Scorer. When its weights are on,
// new improvements of the same admission lane (static pins, then VIP,
// then performance) are admitted to max_improvements by descending
// weight instead of by score gain alone. Weights only order moves Decide
// has already accepted: they never admit a prefix that is not in the
// learned RIB or not allowlisted, never exceed the cap, and never
// displace an active improvement. Commit and cost moves keep their own
// order (relief, savings).
type ImprovementWeigher interface {
	// ImprovementWeights reports whether weights are configured, and
	// whether they read VolumeMbps (the core reads target-source volumes
	// every decision only then).
	ImprovementWeights() (on, volume bool)
	// ImprovementWeight is the weight of one move. Higher is admitted
	// first.
	ImprovementWeight(in WeightInput) float64
}
