// Package mikrotik is the mikrotik-l3hw-lpm offload profile: RouterOS L3HW
// on the indexed-LPM switch chips (CCR2216, CCR2116 and the CRS models that
// share them). It describes the platform, reads its budget dimensions from
// an L3HW reading and assesses the pre-checks. It reads and decides; it
// writes nothing to the router and never touches a default route.
// Only the dry-run report calls it (#738), never the decision path.
package mikrotik

import (
	"fmt"
	"slices"
	"time"

	"github.com/GrandArcher/Packeteer/internal/offload"
)

// ID is the profile's registry ID.
const ID = "mikrotik-l3hw-lpm"

// Model is a switch-chip router whose lane bandwidth is known. The lanes
// carry what the CPU path must take when a route is not in hardware.
type Model string

const (
	CCR2116 Model = "ccr2116"
	CCR2216 Model = "ccr2216"
)

// laneBps is the CPU-path ceiling per model: CCR2116 has 4x10G lanes and
// CCR2216 4x25G.
var laneBps = map[Model]uint64{
	CCR2116: 4 * 10_000_000_000,
	CCR2216: 4 * 25_000_000_000,
}

// lpmTarget is the most hardware routes to aim for, below the chip's
// lpm-cap. Only the CCR2216 has one.
var lpmTarget = map[Model]uint64{CCR2216: 100_000}

// Thresholds and reserves from the issue. A reserve is the part of a
// dimension never handed out.
const (
	reservePct    = 0.20
	nexthopWarn   = 0.90
	nexthopFull   = 1.0
	routeIndexSec = 10 // route-index-delay-max
	queueDrainSec = 5  // allowance for the route queue to drain
	// ipv6Entries is what an IPv6 route is assumed to cost in the shared LPM
	// pool. It is not measured: a larger value only makes the budget
	// stricter until the v1.15 bench sets it.
	ipv6Entries = 2
	// maxChangesPerBatch is where RouterOS re-indexes the whole table: a
	// round stays under it, counting a swap as two changes.
	maxChangesPerBatch = 128
	swapsPerRound      = 16
	shedsPerRound      = 16
	installsPerRound   = 64
)

// A full round of installs, swaps (two changes each) and sheds must stay
// under the re-index limit; this fails to compile otherwise.
const _ = uint(maxChangesPerBatch - 1 - (installsPerRound + 2*swapsPerRound + shedsPerRound))

// Options is what the operator supplies per router.
type Options struct {
	// Model names the router, for its lane bandwidth and LPM target. Empty
	// means unknown: there is no LPM target, and with a VolumeSource named the
	// CPU dimension has no lane bandwidth to measure against, so the budget
	// freezes.
	Model Model
	// VolumeSource names the external per-prefix volume source (sFlow or
	// IPFIX from another device). RouterOS Traffic-Flow does not see
	// hardware-forwarded traffic, so without a source ranking falls back to
	// path gain and the CPU-path ceiling is not budgeted: nothing measures it.
	VolumeSource string
}

func (o Options) validate() error {
	if o.Model == "" {
		return nil
	}
	if _, ok := laneBps[o.Model]; !ok {
		return fmt.Errorf("mikrotik: unknown model %q", o.Model)
	}
	return nil
}

// Profile returns the profile reading from src, which returns the latest
// snapshot or false when there is none. MaxRun is DryRun: enforcing waits
// for the bench-gated v1.15 issue.
func Profile(opts Options, src func() (Snapshot, bool)) (offload.Profile, error) {
	if err := opts.validate(); err != nil {
		return offload.Profile{}, err
	}
	p := offload.Profile{
		ID:     ID,
		Status: offload.Partial,
		MaxRun: offload.DryRun,
		DefaultPolicy: offload.DefaultPolicy{
			Kind:   offload.OutOfHW,
			Reason: "defaults carry suppress-hw-offload=yes: misses go to the CPU and the full RIB",
		},
		Miss:       offload.CPUPunt,
		Dimensions: dimensions(opts),
		Cost:       offload.Cost{EntriesV4: 1, EntriesV6: ipv6Entries},
		Reader:     newReader(opts, src),
		Selection:  offload.CommunitySnippet,
		Thresholds: offload.Thresholds{Warn: nexthopWarn, Full: nexthopFull},
		PreChecks:  slices.Clone(preChecks),
		Flow:       offload.Flow{NeedsFlow: true},
		Timing:     offload.Timing{InstallSeconds: routeIndexSec + queueDrainSec, AgeOutSeconds: routeIndexSec + queueDrainSec},
		KnownBad:   knownBad(),
	}
	return p, p.Validate()
}

// dimensions are the budgeted dimensions: the CPU path only with a volume
// source to measure it.
func dimensions(opts Options) []offload.Dimension {
	dims := []offload.Dimension{offload.FIBv4, offload.NextHops}
	if opts.VolumeSource != "" {
		dims = append(dims, offload.CPU)
	}
	return dims
}

// BudgetConfig is the budget for the profile. ipv6HW is the router's
// ipv6-hw setting: IPv6 routes share the LPM pool when it is on, and with it
// off none are budgeted, so the IPv6 headroom is 0.
func BudgetConfig(opts Options, recheck time.Duration, ipv6HW bool) offload.Config {
	cfg := offload.Config{
		Recheck:    recheck,
		Dimensions: dimensions(opts),
		Reserve: map[offload.Dimension]offload.Reserve{
			offload.FIBv4:    {Pct: reservePct},
			offload.NextHops: {Pct: 1 - nexthopWarn},
		},
	}
	if opts.VolumeSource != "" {
		cfg.Reserve[offload.CPU] = offload.Reserve{Pct: reservePct}
	}
	if ipv6HW {
		cfg.IPv6 = offload.IPv6Pool{Shared: true, Weight: ipv6Entries}
	}
	return cfg
}

// PlannerConfig is the planner knobs for the profile. A round stays under
// the 128-change re-index, and ranking falls back to gain without a volume
// source.
func PlannerConfig(opts Options, ipv6HW bool) offload.PlannerConfig {
	cfg := offload.PlannerConfig{
		MaxSwapsPerRound:    swapsPerRound,
		MaxShedPerRound:     shedsPerRound,
		MaxInstallsPerRound: installsPerRound,
		GainOnly:            opts.VolumeSource == "",
	}
	if ipv6HW {
		cfg.IPv6 = offload.IPv6Pool{Shared: true, Weight: ipv6Entries}
	}
	return cfg
}
