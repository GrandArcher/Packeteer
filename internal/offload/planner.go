package offload

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Defaults for the planner knobs.
const (
	DefaultDisplaceMargin  = 0.25
	DefaultMaxShedPerRound = 5
)

// Action is what the planner decides for one prefix.
type Action string

const (
	// Install puts a new fix into hardware.
	Install Action = "install"
	// Keep leaves an installed fix or a mitigation route alone.
	Keep Action = "keep"
	// Swap installs a challenger and removes the installed fix it displaces.
	Swap Action = "swap"
	// Shed removes an installed fix to relieve pressure.
	Shed Action = "shed"
	// Withhold leaves a wanted fix out of hardware.
	Withhold Action = "withhold"
)

// Emphasis is which signal leads the rank key.
type Emphasis int

const (
	// GainEmphasis ranks by the improvement weight first. It is for platforms
	// that drop what is not in hardware: the cost of a miss is the lost gain.
	GainEmphasis Emphasis = iota
	// VolumeEmphasis ranks by traffic first. It is for platforms that punt a
	// miss to the CPU: the cost of a miss is the traffic the CPU must carry.
	VolumeEmphasis
)

func emphasisFor(m Miss) Emphasis {
	if m == CPUPunt {
		return VolumeEmphasis
	}
	return GainEmphasis
}

// PlannerConfig holds the planner knobs.
type PlannerConfig struct {
	// Weigher is the improvement_weights block (#34). Nil, or one that is
	// off, ranks by Gain alone.
	Weigher plugin.ImprovementWeigher
	// DisplaceMargin: a challenger displaces an installed fix only when its
	// weight is at least the fix's x (1 + DisplaceMargin).
	DisplaceMargin float64
	// HoldTime is how long an installed fix stays before it may be displaced.
	HoldTime time.Duration
	// MaxSwapsPerRound caps swaps in one round.
	MaxSwapsPerRound int
	// MaxSwapsPerMinute caps swaps over a minute, counting those the caller
	// reports in Input.SwapsLastMinute. 0 means no cap. A profile whose
	// platform re-indexes or flushes a cache on every table change sets it.
	MaxSwapsPerMinute int
	// MaxShedPerRound caps sheds in one round.
	MaxShedPerRound int
	// IPv6 is how the budget pools IPv6 routes; it must match the Budget.
	IPv6 IPv6Pool
}

func (c PlannerConfig) validate() error {
	switch {
	case math.IsNaN(c.DisplaceMargin) || math.IsInf(c.DisplaceMargin, 0) || c.DisplaceMargin < 0:
		return errors.New("offload: displace margin must be a finite number, 0 or more")
	case c.HoldTime < 0:
		return errors.New("offload: hold time must not be negative")
	case c.MaxSwapsPerRound < 1:
		return errors.New("offload: max swaps per round must be at least 1")
	case c.MaxSwapsPerMinute < 0:
		return errors.New("offload: max swaps per minute must not be negative")
	case c.MaxShedPerRound < 1:
		return errors.New("offload: max shed per round must be at least 1")
	case c.IPv6.Shared && c.IPv6.Weight < 1:
		return errors.New("offload: shared IPv6 weight must be at least 1")
	}
	return nil
}

// Candidate is a fix Decide wants in hardware, installed or not.
type Candidate struct {
	Prefix     netip.Prefix
	Cause      string
	Gain       float64
	VolumeMbps float64
	// Since is when the fix was installed, or for one not installed when it
	// was first wanted. Older ranks higher on a tie.
	Since     time.Time
	Installed bool
}

// Input is one planning round.
type Input struct {
	Now        time.Time
	Candidates []Candidate
	// Mitigation are installed RTBH or redirect routes. They hold hardware
	// entries but are an operator's decision: never swapped, never shed.
	Mitigation []netip.Prefix
	Budget     Result
	// LastInstall and LastShed are when the caller last changed hardware. A
	// failover or reprogram is reported as both. Zero means never.
	LastInstall, LastShed time.Time
	// SwapsLastMinute is how many swaps the caller applied in the last
	// minute.
	SwapsLastMinute int
}

// Decision is the plan for one prefix. A Swap names the installed fix it
// replaces in Out, and Out has no decision of its own. The caller feeds each
// Swap to flap quarantine as a change of both prefixes.
type Decision struct {
	Prefix netip.Prefix
	Action Action
	Out    netip.Prefix
	Reason string
}

// Plan is the result of a round, ordered by prefix. When Freezes is not empty
// nothing is installed, swapped or shed.
type Plan struct {
	Decisions []Decision
	Freezes   []Freeze
}

// Planner turns improvements, a budget and a profile's timing into decisions.
// It keeps no state: the caller owns what is installed and when.
type Planner struct {
	cfg      PlannerConfig
	timing   Timing
	emphasis Emphasis
}

// NewPlanner returns a Planner for profile p, or the first defect in cfg.
func NewPlanner(p Profile, cfg PlannerConfig) (*Planner, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if p.Timing.InstallSeconds < 0 || p.Timing.AgeOutSeconds < 0 {
		return nil, fmt.Errorf("offload: profile %q: timing must not be negative", p.ID)
	}
	return &Planner{cfg: cfg, timing: p.Timing, emphasis: emphasisFor(p.Miss)}, nil
}

type ranked struct {
	Candidate
	weight float64
	v6     bool
}

// causeOrder is the precedence between causes: a static pin first, then the
// causes in the order Decide admits them.
func causeOrder(cause string) int {
	switch cause {
	case plugin.CauseStatic:
		return 0
	case plugin.CausePerformance:
		return 1
	case plugin.CauseCommit:
		return 2
	case plugin.CauseCost:
		return 3
	}
	return 4
}

func (p *Planner) weight(c Candidate) float64 {
	w := c.Gain
	if p.cfg.Weigher != nil {
		if on, _ := p.cfg.Weigher.ImprovementWeights(); on {
			w = p.cfg.Weigher.ImprovementWeight(plugin.WeightInput{
				Prefix: c.Prefix, Gain: c.Gain, VolumeMbps: c.VolumeMbps,
			})
		}
	}
	if math.IsNaN(w) || w < 0 {
		return 0
	}
	return w
}

func clean(v float64) float64 {
	if math.IsNaN(v) || v < 0 {
		return 0
	}
	return v
}

// better reports whether a ranks above b. The key is total, so equal weights
// come out the same whatever order the input arrives in.
func (p *Planner) better(a, b ranked) bool {
	av, bv := clean(a.VolumeMbps), clean(b.VolumeMbps)
	if p.emphasis == VolumeEmphasis && av != bv {
		return av > bv
	}
	if a.weight != b.weight {
		return a.weight > b.weight
	}
	if ca, cb := causeOrder(a.Cause), causeOrder(b.Cause); ca != cb {
		return ca < cb
	}
	if av != bv {
		return av > bv
	}
	if !a.Since.Equal(b.Since) {
		return a.Since.Before(b.Since)
	}
	if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
		return c < 0
	}
	return a.Prefix.Bits() < b.Prefix.Bits()
}

// room is the routes of each family that may still be installed. With a
// shared IPv6 pool both families draw on the IPv4 entries.
type room struct {
	v4, v6 uint64
	pool   IPv6Pool
}

func (r *room) take(v6 bool) bool {
	if v6 {
		if r.v6 == 0 {
			return false
		}
		r.v6--
		if r.pool.Shared {
			r.v4 -= min(r.v4, r.pool.Weight)
		}
	} else {
		if r.v4 == 0 {
			return false
		}
		r.v4--
	}
	if r.pool.Shared {
		r.v6 = min(r.v6, r.v4/r.pool.Weight)
	}
	return true
}

// settling reports whether a change is still taking effect in hardware: an
// install is not trusted until InstallSeconds pass, a shed until AgeOutSeconds.
func (p *Planner) settling(in Input) bool {
	window := func(last time.Time, secs int) bool {
		return !last.IsZero() && in.Now.Sub(last) < time.Duration(secs)*time.Second
	}
	return window(in.LastInstall, p.timing.InstallSeconds) || window(in.LastShed, p.timing.AgeOutSeconds)
}

// Plan decides what to install, keep, swap, shed and withhold. It never
// plans a default route and never touches a mitigation route. Under a budget
// freeze or a settling window it installs and sheds nothing.
func (p *Planner) Plan(in Input) (Plan, error) {
	seen := map[netip.Prefix]bool{}
	for _, m := range in.Mitigation {
		if seen[m] {
			return Plan{}, fmt.Errorf("offload: prefix %s listed twice", m)
		}
		seen[m] = true
	}
	var installed, wanted []ranked
	var out Plan
	for _, c := range in.Candidates {
		if seen[c.Prefix] {
			return Plan{}, fmt.Errorf("offload: prefix %s listed twice", c.Prefix)
		}
		seen[c.Prefix] = true
		r := ranked{Candidate: c, weight: p.weight(c), v6: c.Prefix.Addr().Is6()}
		switch {
		case c.Installed:
			installed = append(installed, r)
		case !c.Prefix.IsValid() || c.Prefix.Bits() == 0:
			out.Decisions = append(out.Decisions, Decision{c.Prefix, Withhold, netip.Prefix{}, "invalid or default route is never planned"})
		default:
			wanted = append(wanted, r)
		}
	}
	for _, m := range in.Mitigation {
		out.Decisions = append(out.Decisions, Decision{m, Keep, netip.Prefix{}, "mitigation route"})
	}
	sort.Slice(installed, func(i, j int) bool { return p.better(installed[j], installed[i]) })
	sort.Slice(wanted, func(i, j int) bool { return p.better(wanted[i], wanted[j]) })

	out.Freezes = append(out.Freezes, in.Budget.Freezes...)
	if p.settling(in) {
		out.Freezes = append(out.Freezes, Freeze{Reason: FreezeSettling})
	}
	if len(out.Freezes) > 0 {
		out.Decisions = append(out.Decisions, hold(installed, Keep, "frozen")...)
		out.Decisions = append(out.Decisions, hold(wanted, Withhold, "frozen")...)
		finish(&out)
		return out, nil
	}

	// installed is lowest-ranked first.
	shed := map[netip.Prefix]bool{}
	if in.Budget.ShedOK {
		for _, r := range installed {
			if len(shed) == p.cfg.MaxShedPerRound {
				break
			}
			shed[r.Prefix] = true
			out.Decisions = append(out.Decisions, Decision{r.Prefix, Shed, netip.Prefix{}, "table under pressure, lowest ranked"})
		}
	}

	rm := room{v4: in.Budget.HeadroomV4, v6: in.Budget.HeadroomV6, pool: p.cfg.IPv6}
	swaps := p.cfg.MaxSwapsPerRound
	if p.cfg.MaxSwapsPerMinute > 0 {
		swaps = min(swaps, max(0, p.cfg.MaxSwapsPerMinute-in.SwapsLastMinute))
	}
	swapped := map[netip.Prefix]bool{}
	for _, c := range wanted {
		if rm.take(c.v6) {
			out.Decisions = append(out.Decisions, Decision{c.Prefix, Install, netip.Prefix{}, "headroom"})
			continue
		}
		d := Decision{c.Prefix, Withhold, netip.Prefix{}, "no headroom"}
		if swaps > 0 {
			if v, why, ok := p.victim(in.Now, c, installed, shed, swapped); ok {
				swaps--
				swapped[v.Prefix] = true
				d = Decision{c.Prefix, Swap, v.Prefix, why}
			} else {
				d.Reason = why
			}
		} else {
			d.Reason = "swap cap reached"
		}
		out.Decisions = append(out.Decisions, d)
	}
	for _, r := range installed {
		if !shed[r.Prefix] && !swapped[r.Prefix] {
			out.Decisions = append(out.Decisions, Decision{r.Prefix, Keep, netip.Prefix{}, "installed"})
		}
	}
	finish(&out)
	return out, nil
}

// victim is the lowest-ranked installed fix of the challenger's family that
// the challenger may displace. The lowest candidate is the one whose weight
// the margin is tested against: any higher-ranked one needs more.
func (p *Planner) victim(now time.Time, c ranked, installed []ranked, shed, taken map[netip.Prefix]bool) (ranked, string, bool) {
	why := "no installed fix of this family to displace"
	for _, v := range installed {
		if v.v6 != c.v6 || shed[v.Prefix] || taken[v.Prefix] {
			continue
		}
		if v.Since.IsZero() || now.Sub(v.Since) < p.cfg.HoldTime {
			why = "lowest installed fix is inside hold time"
			continue
		}
		if c.weight > v.weight && c.weight >= v.weight*(1+p.cfg.DisplaceMargin) {
			return v, "outweighs " + v.Prefix.String() + " by the displace margin", true
		}
		return ranked{}, "weight is inside the displace margin of the lowest installed fix", false
	}
	return ranked{}, why, false
}

func hold(rs []ranked, a Action, reason string) []Decision {
	ds := make([]Decision, 0, len(rs))
	for _, r := range rs {
		ds = append(ds, Decision{r.Prefix, a, netip.Prefix{}, reason})
	}
	return ds
}

func finish(pl *Plan) {
	sort.Slice(pl.Decisions, func(i, j int) bool {
		a, b := pl.Decisions[i].Prefix, pl.Decisions[j].Prefix
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
}
