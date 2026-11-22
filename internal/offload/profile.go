// Package offload is the shared core of the opt-in offload_aware mode: the
// per-platform Profile, the registry of profiles, and the pure check of how
// far a profile may be run. Nothing calls it from the decision path yet.
package offload

import (
	"context"
	"errors"
	"fmt"
)

// Status is how far a platform's behavior has been verified in the lab.
type Status string

const (
	Verified   Status = "verified"
	Partial    Status = "partial"
	Unverified Status = "unverified"
)

func (s Status) valid() bool {
	return s == Verified || s == Partial || s == Unverified
}

// RunLevel is how far a profile may act. The levels are ordered: a profile
// that allows a level allows every lower one.
type RunLevel int

const (
	// Refuse evaluates nothing.
	Refuse RunLevel = iota
	// Report reads and reports; it never suggests or selects.
	Report
	// DryRun computes what Enforce would do and applies nothing.
	DryRun
	Enforce
)

func (l RunLevel) String() string {
	switch l {
	case Refuse:
		return "refuse"
	case Report:
		return "report"
	case DryRun:
		return "dry_run"
	case Enforce:
		return "enforce"
	}
	return fmt.Sprintf("run_level(%d)", int(l))
}

func (l RunLevel) valid() bool { return l >= Refuse && l <= Enforce }

// PolicyKind is where a platform puts a prefix that no rule covers.
type PolicyKind string

const (
	OutOfHW       PolicyKind = "out_of_hw"
	InHW          PolicyKind = "in_hw"
	NotApplicable PolicyKind = "not_applicable"
)

func (k PolicyKind) valid() bool {
	return k == OutOfHW || k == InHW || k == NotApplicable
}

// DefaultPolicy is the platform's default placement and the words a report
// uses for it.
type DefaultPolicy struct {
	Kind   PolicyKind
	Reason string
}

// Miss is what a platform does with a packet whose route is not in hardware.
// Unknown is a valid answer: a platform that cannot say is never guessed.
type Miss string

const (
	CPUPunt        Miss = "cpu_punt"
	Drop           Miss = "drop"
	ParentDrop     Miss = "parent_drop"
	FollowCovering Miss = "follow_covering"
	FlowCache      Miss = "flow_cache"
	Unknown        Miss = "unknown"
)

func (m Miss) valid() bool {
	switch m {
	case CPUPunt, Drop, ParentDrop, FollowCovering, FlowCache, Unknown:
		return true
	}
	return false
}

// Dimension is one hardware resource a reader can measure.
type Dimension string

const (
	FIBv4     Dimension = "fib_v4"
	FIBv6     Dimension = "fib_v6"
	FlowTable Dimension = "flow_table"
	CPU       Dimension = "cpu"
)

// Reading is one measurement. Known is false when the reader is unavailable
// or the platform does not report the dimension: that is unknown, never zero.
type Reading struct {
	Used  uint64
	Total uint64
	Known bool
}

// Reader measures a profile's dimensions. An unreachable device or an
// unsupported dimension yields Reading{Known: false}, not an error;
// the error is for a failed read the caller should log.
type Reader interface {
	Read(ctx context.Context, d Dimension) (Reading, error)
}

// Cost is the hardware entries one route uses.
type Cost struct {
	EntriesV4 uint32
	EntriesV6 uint32
}

// Selection is how a profile's advice reaches the operator.
type Selection string

const (
	CommunitySnippet Selection = "community_snippet"
	WithholdOnly     Selection = "withhold_only"
	ObserveFlags     Selection = "observe_flags"
)

func (s Selection) valid() bool {
	return s == CommunitySnippet || s == WithholdOnly || s == ObserveFlags
}

// Thresholds are fractions of a dimension's total at which a platform is
// reported as filling up and as full. Both zero means none are set; otherwise
// 0 < Warn <= Full <= 1.
type Thresholds struct {
	Warn float64
	Full float64
}

// Flow says whether the profile needs per-prefix flow data to judge a route.
type Flow struct {
	NeedsFlow bool
}

// Timing is how long, in seconds, a platform needs to install or age out
// hardware entries before a reading is trusted.
type Timing struct {
	InstallSeconds int
	AgeOutSeconds  int
}

// KnownBad is a platform software version with a documented defect.
type KnownBad struct {
	Version string
	Reason  string
}

// Profile describes one platform's hardware-offload behavior. Reader is nil
// for a profile that measures nothing.
type Profile struct {
	ID            string
	Status        Status
	MaxRun        RunLevel
	DefaultPolicy DefaultPolicy
	Miss          Miss
	Dimensions    []Dimension
	Cost          Cost
	Reader        Reader
	Selection     Selection
	Thresholds    Thresholds
	PreChecks     []string
	Flow          Flow
	Timing        Timing
	KnownBad      []KnownBad
}

// ErrRefused is returned when a profile does not allow the requested level.
var ErrRefused = errors.New("offload: run level refused")

// CheckRun returns the requested level when the profile allows it. A level
// above the profile's MaxRun is refused, so a Refuse profile accepts only
// Refuse. The error carries the profile's reason.
func CheckRun(p Profile, requested RunLevel) (RunLevel, error) {
	if !requested.valid() {
		return Refuse, fmt.Errorf("%w: profile %q: unknown level %s", ErrRefused, p.ID, requested)
	}
	if requested > p.MaxRun {
		return Refuse, fmt.Errorf("%w: profile %q allows at most %s, requested %s: %s",
			ErrRefused, p.ID, p.MaxRun, requested, p.DefaultPolicy.Reason)
	}
	return requested, nil
}

// Validate reports the first defect in p. An unverified platform must be a
// Refuse profile: it ships as refuse, never as a guess.
func (p Profile) Validate() error {
	switch {
	case p.ID == "":
		return errors.New("offload: profile has no id")
	case !p.Status.valid():
		return fmt.Errorf("offload: profile %q: unknown status %q", p.ID, p.Status)
	case !p.MaxRun.valid():
		return fmt.Errorf("offload: profile %q: unknown max run level %d", p.ID, int(p.MaxRun))
	case !p.DefaultPolicy.Kind.valid():
		return fmt.Errorf("offload: profile %q: unknown default policy %q", p.ID, p.DefaultPolicy.Kind)
	case p.DefaultPolicy.Reason == "":
		return fmt.Errorf("offload: profile %q: default policy has no reason", p.ID)
	case !p.Miss.valid():
		return fmt.Errorf("offload: profile %q: unknown miss behavior %q", p.ID, p.Miss)
	case !p.Selection.valid():
		return fmt.Errorf("offload: profile %q: unknown selection %q", p.ID, p.Selection)
	case p.Status == Unverified && p.MaxRun != Refuse:
		return fmt.Errorf("offload: profile %q: an unverified platform must be refuse, not %s", p.ID, p.MaxRun)
	case p.Thresholds != (Thresholds{}) &&
		!(p.Thresholds.Warn > 0 && p.Thresholds.Warn <= p.Thresholds.Full && p.Thresholds.Full <= 1):
		return fmt.Errorf("offload: profile %q: thresholds must satisfy 0 < warn <= full <= 1", p.ID)
	case p.MaxRun > Report && p.Reader == nil:
		return fmt.Errorf("offload: profile %q: %s needs a reader", p.ID, p.MaxRun)
	}
	return nil
}
