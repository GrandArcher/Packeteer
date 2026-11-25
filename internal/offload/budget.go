package offload

import (
	"context"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// FreezeReason is why the budget stops all installs. A frozen budget never
// installs and never sheds: an unknown or untrusted reading is not evidence
// that the table is full or empty.
type FreezeReason string

const (
	// FreezeMissing: a dimension has no reading (dead reader, read error,
	// unsupported dimension).
	FreezeMissing FreezeReason = "missing"
	// FreezeStale: the reading is older than 3 x recheck.
	FreezeStale FreezeReason = "stale"
	// FreezeInsane: used above cap, a zero or wrapped-negative value, or a cap
	// that changed with no version or profile change.
	FreezeInsane FreezeReason = "insane"

	// The reasons below are set by the caller; the budget math does not
	// compute them.
	FreezePreCheck      FreezeReason = "pre_check_failed"
	FreezeSettling      FreezeReason = "settling"
	FreezeKnownBad      FreezeReason = "known_bad_version"
	FreezeDefaultPolicy FreezeReason = "default_policy_violated"
	FreezeStatus        FreezeReason = "status_below_run_level"
)

// Two more dimensions beyond the ones in profile.go: next-hop/FEC/adjacency
// and ECMP group exhaustion can come before route space runs out.
const (
	NextHops   Dimension = "next_hops"
	ECMPGroups Dimension = "ecmp_groups"
)

func (d Dimension) valid() bool {
	switch d {
	case FIBv4, FIBv6, FlowTable, CPU, NextHops, ECMPGroups:
		return true
	}
	return false
}

// Sample is a reading and when it was taken.
type Sample struct {
	Reading
	At time.Time
}

// Reserve is the part of a dimension that is never handed out:
// max(Pct x cap, Abs).
type Reserve struct {
	Pct float64
	Abs uint64
}

// IPv6Pool says how IPv6 routes are budgeted. With Shared false the profile
// lists FIBv6 as its own dimension. With Shared true IPv6 draws from the FIBv4
// pool and each IPv6 route costs Weight entries (2 on platforms where IPv6
// takes double); FIBv6 must not be listed.
type IPv6Pool struct {
	Shared bool
	Weight uint64
}

// Config is the budget for one profile.
type Config struct {
	// Recheck is the poll interval; a reading older than 3 x Recheck is stale.
	Recheck    time.Duration
	Dimensions []Dimension
	Reserve    map[Dimension]Reserve
	IPv6       IPv6Pool
}

func (c Config) validate() error {
	if c.Recheck <= 0 {
		return fmt.Errorf("offload: budget recheck must be positive")
	}
	if len(c.Dimensions) == 0 {
		return fmt.Errorf("offload: budget has no dimensions")
	}
	listed := map[Dimension]bool{}
	for _, d := range c.Dimensions {
		if !d.valid() {
			return fmt.Errorf("offload: budget: unknown dimension %q", d)
		}
		if listed[d] {
			return fmt.Errorf("offload: budget: dimension %q listed twice", d)
		}
		listed[d] = true
	}
	for d, r := range c.Reserve {
		if !listed[d] {
			return fmt.Errorf("offload: budget: reserve for unlisted dimension %q", d)
		}
		if !(r.Pct >= 0 && r.Pct <= 1) {
			return fmt.Errorf("offload: budget: reserve pct for %q must be in [0, 1]", d)
		}
	}
	if c.IPv6.Shared {
		if listed[FIBv6] {
			return fmt.Errorf("offload: budget: shared IPv6 pool and a separate %q dimension are exclusive", FIBv6)
		}
		if !listed[FIBv4] {
			return fmt.Errorf("offload: budget: shared IPv6 pool needs the %q dimension", FIBv4)
		}
		if c.IPv6.Weight < 1 {
			return fmt.Errorf("offload: budget: shared IPv6 weight must be at least 1")
		}
	} else if c.IPv6.Weight != 0 {
		return fmt.Errorf("offload: budget: IPv6 weight applies only to a shared pool")
	}
	return nil
}

// Identity names the platform build a cap belongs to. A cap may change only
// when it does.
type Identity struct {
	Profile string
	Version string
}

// Freeze is one reason for a freeze and the dimension it came from. Dimension
// is empty for a reason that is not about one dimension.
type Freeze struct {
	Reason    FreezeReason `json:"reason"`
	Dimension Dimension    `json:"dimension,omitempty"`
}

// Result is one budget evaluation. When Freezes is not empty nothing may be
// installed or shed: Free is nil, both headrooms are 0 and ShedOK is false.
type Result struct {
	Freezes []Freeze
	// Free is cap - used - reserve per dimension, never below 0.
	Free map[Dimension]uint64
	// HeadroomV4 and HeadroomV6 are how many more routes of each family may be
	// installed: the smallest free across the dimensions that family uses.
	HeadroomV4, HeadroomV6 uint64
	// HeadroomHost is how many more host entries may be installed: the
	// smallest free across the dimensions other than the FIB ones, because a
	// host entry takes no FIB entry.
	HeadroomHost uint64
	// ShedOK is true only when every reading is trusted and some dimension has
	// no free entries left.
	ShedOK bool
}

// Frozen reports whether installs are stopped.
func (r Result) Frozen() bool { return len(r.Freezes) > 0 }

type baseline struct {
	id    Identity
	total uint64
}

// Budget turns readings into install headroom. It remembers the first cap it
// saw per dimension for an identity so that an unexplained cap change is
// caught; the baseline moves only when the identity changes, so build a new
// Budget to accept a cap the operator changed on purpose. It is safe for
// concurrent use.
type Budget struct {
	cfg Config

	mu   sync.Mutex
	caps map[Dimension]baseline
}

// NewBudget returns a Budget for cfg, or the first defect in it.
func NewBudget(cfg Config) (*Budget, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Budget{cfg: cfg, caps: map[Dimension]baseline{}}, nil
}

// Collect reads dims from r at now. A nil reader, a read error, a panic, or an
// unknown reading all give a sample with Known false, which Evaluate freezes
// on: a dead reader never looks like an empty or a full table.
func Collect(ctx context.Context, r Reader, dims []Dimension, now time.Time) map[Dimension]Sample {
	out := make(map[Dimension]Sample, len(dims))
	for _, d := range dims {
		out[d] = Sample{Reading: readOne(ctx, r, d), At: now}
	}
	return out
}

func readOne(ctx context.Context, r Reader, d Dimension) (rd Reading) {
	if r == nil {
		return Reading{}
	}
	defer func() {
		if recover() != nil {
			rd = Reading{}
		}
	}()
	got, err := r.Read(ctx, d)
	if err != nil {
		return Reading{}
	}
	return got
}

// Evaluate computes the headroom from samples at now. Every configured
// dimension must have a known, sane, fresh sample, or the result is frozen.
func (b *Budget) Evaluate(now time.Time, id Identity, samples map[Dimension]Sample) Result {
	b.mu.Lock()
	defer b.mu.Unlock()

	var freezes []Freeze
	free := make(map[Dimension]uint64, len(b.cfg.Dimensions))
	for _, d := range b.cfg.Dimensions {
		s, ok := samples[d]
		reason, bad := b.check(now, id, d, s, ok)
		if bad {
			freezes = append(freezes, Freeze{Reason: reason, Dimension: d})
			continue
		}
		free[d] = freeOf(s.Reading, b.cfg.Reserve[d])
	}
	if len(freezes) > 0 {
		sort.Slice(freezes, func(i, j int) bool { return freezes[i].Dimension < freezes[j].Dimension })
		return Result{Freezes: freezes}
	}

	res := Result{Free: free}
	res.HeadroomV4 = b.headroom(free, false)
	res.HeadroomV6 = b.headroom(free, true)
	res.HeadroomHost = b.hostHeadroom(free)
	for _, f := range free {
		if f == 0 {
			res.ShedOK = true
		}
	}
	return res
}

// check validates one sample and, when it is good, records its cap.
func (b *Budget) check(now time.Time, id Identity, d Dimension, s Sample, present bool) (FreezeReason, bool) {
	switch {
	case !present || !s.Known:
		return FreezeMissing, true
	case s.Total == 0 || s.Used > s.Total || s.Total > math.MaxInt64:
		// A wrapped negative shows up as a value above MaxInt64.
		return FreezeInsane, true
	}
	if age := now.Sub(s.At); s.At.IsZero() || age < 0 || age > 3*b.cfg.Recheck {
		return FreezeStale, true
	}
	base, seen := b.caps[d]
	if seen && base.id == id && base.total != s.Total {
		return FreezeInsane, true
	}
	b.caps[d] = baseline{id: id, total: s.Total}
	return "", false
}

func reserveOf(res Reserve, total uint64) uint64 {
	return max(uint64(math.Ceil(res.Pct*float64(total))), res.Abs)
}

func freeOf(r Reading, res Reserve) uint64 {
	reserve := reserveOf(res, r.Total)
	if left := r.Total - r.Used; reserve < left {
		return left - reserve
	}
	return 0
}

// Reserved is the part of a dimension with this total that is never handed out.
func (b *Budget) Reserved(d Dimension, total uint64) uint64 {
	return reserveOf(b.cfg.Reserve[d], total)
}

// Free is cap - used - reserve of a sane reading, never below 0.
func (b *Budget) Free(d Dimension, r Reading) uint64 {
	return freeOf(r, b.cfg.Reserve[d])
}

// hostHeadroom is the room left once the FIB dimensions are set aside. With
// none left to count it is 0, as the FIB headroom is without its dimension.
func (b *Budget) hostHeadroom(free map[Dimension]uint64) uint64 {
	lowest, counted := uint64(math.MaxUint64), false
	for _, d := range b.cfg.Dimensions {
		switch f := free[d]; {
		case d == CPU:
			if f == 0 {
				return 0
			}
		case d == FIBv4 || d == FIBv6:
		default:
			lowest, counted = min(lowest, f), true
		}
	}
	if !counted {
		return 0
	}
	return lowest
}

// headroom is the smallest per-route room over the dimensions a family uses.
// A family with no FIB dimension of its own to draw on gets 0. CPU has no
// per-route unit, so it only gates: no free CPU means no installs.
func (b *Budget) headroom(free map[Dimension]uint64, v6 bool) uint64 {
	fib := FIBv4
	if v6 && !b.cfg.IPv6.Shared {
		fib = FIBv6
	}
	if _, ok := free[fib]; !ok {
		return 0
	}
	lowest := uint64(math.MaxUint64)
	for _, d := range b.cfg.Dimensions {
		f := free[d]
		switch {
		case d == CPU:
			if f == 0 {
				return 0
			}
			continue
		case d == FIBv6 && !v6, d == FIBv4 && v6 && !b.cfg.IPv6.Shared:
			continue
		case d == FIBv4 && v6:
			f /= b.cfg.IPv6.Weight
		}
		if f < lowest {
			lowest = f
		}
	}
	return lowest
}
