// Package policy is the decision engine. Decide is a pure function: given
// the previous state, the current inputs (probe results, provider health,
// RIB view) and the time, it returns the new state and per-prefix
// decisions. It never touches the network; the announcer acts on the
// resulting improvements only in inject mode.
package policy

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"

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
	Allowlist       []netip.Prefix // inject mode: only these (or more-specifics of them)
	// Providers carries group, precedence, and cc_disable. Empty means
	// commit control has no provider policy (the weighted scorer ignores it).
	Providers []ProviderPolicy
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
}

// NewState returns an empty state.
func NewState() State {
	return State{
		Improvements: map[netip.Prefix]Improvement{},
		Cooldown:     map[netip.Prefix]time.Time{},
		confirm:      map[netip.Prefix]confirm{},
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
}

// nativeOf is the native provider of p: the one recorded on an active
// improvement, else the RIB's.
func nativeOf(st State, in Input, p netip.Prefix) string {
	if imp, ok := st.Improvements[p]; ok {
		return imp.Native
	}
	return in.Native[p]
}

// Decide runs one evaluation.
func Decide(prev State, in Input, cfg Config, scorer plugin.Scorer, now time.Time) (State, Output) {
	st := prev.clone()
	var out Output
	maint := map[string]bool{}
	if len(in.Maintenance) > 0 {
		// A provider in maintenance is excluded for this evaluation only.
		excl := make(map[string]bool, len(cfg.Excluded)+len(in.Maintenance))
		for k, v := range cfg.Excluded {
			excl[k] = v
		}
		for _, name := range in.Maintenance {
			maint[name] = true
			excl[name] = true
		}
		cfg.Excluded = excl
	}
	for p, until := range st.Cooldown {
		if !now.Before(until) {
			delete(st.Cooldown, p)
		}
	}

	retire := func(p netip.Prefix, reason string, cooldown bool) {
		old := st.Improvements[p]
		delete(st.Improvements, p)
		delete(st.confirm, p)
		if cooldown && cfg.HoldTime > 0 {
			st.Cooldown[p] = now.Add(cfg.HoldTime)
		}
		old.Reason = reason
		out.Changes = append(out.Changes, Change{Action: ActionRetire, Old: old})
	}

	// Stale RIB: withdraw everything, decide nothing. A half-confirmed
	// move does not survive the session loss either.
	if in.RIBEnabled && !in.RIBReady {
		st.confirm = map[netip.Prefix]confirm{}
		for _, p := range sortedKeys(st.Improvements) {
			retire(p, "rib not ready (bgp session down)", false)
		}
		return st, out
	}

	// Group usable measurements by prefix.
	byPrefix := map[netip.Prefix][]Candidate{}
	subs := map[netip.Prefix]map[netip.Prefix]*SubrangeDecision{}
	for _, r := range in.Results {
		c := Candidate{Provider: r.Provider, LossPct: r.Stats.LossPct, RTTAvg: r.Stats.RTTAvg, Jitter: r.Stats.Jitter, Usable: true}
		switch {
		case !r.OK():
			c.Usable, c.Why = false, "probe error"
		case !in.ProviderUp[r.Provider]:
			c.Usable, c.Why = false, "provider down"
		case cfg.MaxResultAge > 0 && now.Sub(r.Time) > cfg.MaxResultAge:
			c.Usable, c.Why = false, "stale"
		case r.Stats.Sent == 0:
			c.Usable, c.Why = false, "no packets sent"
		case in.NoRoute[r.Prefix][r.Provider] && r.Provider != nativeOf(st, in, r.Prefix):
			c.Usable, c.Why = false, "no route via provider (route check)"
		case in.EgressDown[r.Provider] && r.Provider != nativeOf(st, in, r.Prefix):
			c.Usable, c.Why = false, "egress router down"
		}
		if c.Usable {
			c.Score = scorer.Score(plugin.PathStats{Provider: r.Provider, LossPct: c.LossPct, RTTAvg: c.RTTAvg, Jitter: c.Jitter})
		}
		byPrefix[r.Prefix] = append(byPrefix[r.Prefix], c)
		noteSubranges(subs, r, c, scorer)
	}

	// An improvement with no measurement in this evaluation is retired.
	// A configured source dropping the prefix does not cause that: the
	// probe engine keeps an active improvement's prefix in the target
	// set, so its results stay until the improvement retires. This is
	// the backstop when that prefix produced no result at all.
	for _, p := range sortedKeys(st.Improvements) {
		if _, ok := byPrefix[p]; !ok {
			retire(p, "prefix no longer probed", false)
		}
	}

	var wants []pending
	commitOK := map[netip.Prefix]bool{}
	decIdx := map[netip.Prefix]*Decision{}
	var holds []commitHold
	prefixes := make([]netip.Prefix, 0, len(byPrefix))
	for p := range byPrefix {
		prefixes = append(prefixes, p)
	}
	sortPrefixes(prefixes)
	decisions := make([]Decision, len(prefixes))

	for i, p := range prefixes {
		// A streak only asks for an early probe when this evaluation
		// compares the paths. Anything else (provider down, no RIB
		// provider, a static pin, a cooldown, the cost floor) leaves
		// the streak and does not wake the prober.
		clearConfirmProbe(&st, p)
		cands := byPrefix[p]
		sort.Slice(cands, func(a, b int) bool { return cands[a].Provider < cands[b].Provider })
		d := &decisions[i]
		*d = Decision{Prefix: p, Candidates: cands, Action: ActionNone}
		decIdx[p] = d
		imp, active := st.Improvements[p]
		verdict, hasPolicy := in.Policies[p]
		if hasPolicy {
			d.Policy = policyText(verdict)
			native := in.Native[p]
			if active {
				native = imp.Native
			}
			applyPolicy(cands, verdict, native)
		}
		static := ""
		if hasPolicy && verdict.Action == plugin.PolicyStatic && len(verdict.Providers) == 1 {
			static = verdict.Providers[0]
		}
		ignore := hasPolicy && verdict.Action == plugin.PolicyIgnore
		get := func(name string) (Candidate, bool) {
			for _, c := range cands {
				if c.Provider == name && c.Usable {
					return c, true
				}
			}
			return Candidate{}, false
		}
		best, haveBest := bestCandidate(cands, cfg.Excluded, "")
		if haveBest {
			d.Recommended = best.Provider
		}

		if active {
			d.Native, d.Current = imp.Native, imp.Provider
			if ignore {
				reason := "policy ignore (" + verdict.Rule + ")"
				retire(p, reason, false)
				setDecision(d, ActionRetire, reason, imp.Native, "", imp.Cause)
				continue
			}
			if in.RIBEnabled {
				_, inRIB := in.Native[p]
				switch {
				case inRIB:
					if imp.nativeSeen.IsZero() {
						imp.nativeSeen = now
					}
					imp.nativeHeld = true
					st.Improvements[p] = imp
				case imp.nativeHeld && !imp.nativeSeen.IsZero() && now.Sub(imp.nativeSeen) >= nativePathConfirm:
					// The neighbor kept sending this prefix after the
					// improvement was active, then stopped. That is a real
					// withdraw. Cooldown stops a mis-read from being
					// re-injected on the next round.
					retire(p, "prefix no longer in RIB", true)
					d.Action, d.Reason, d.Current = ActionRetire, "prefix no longer in RIB", imp.Native
					continue
				default:
					// Gone before it was confirmed, or never seen while
					// active. The router stopped advertising the native path
					// because our route is best. Keep the improvement.
					imp.nativeSeen = time.Time{}
					imp.nativeHeld = false
					st.Improvements[p] = imp
				}
			}
			cur, ok := get(imp.Provider)
			switch {
			case !ok:
				// A static pin has no performance threshold to stop it from
				// returning on the next good sample, so it waits out hold_time.
				retire(p, "improvement provider unusable ("+whyUnusable(cands, imp.Provider)+")", imp.Cause == plugin.CauseStatic)
				d.Action, d.Reason, d.Current = ActionRetire, "improvement provider unusable", imp.Native
				continue
			case maint[imp.Provider]:
				retire(p, "provider in maintenance", false)
				d.Action, d.Reason, d.Current = ActionRetire, "provider in maintenance", imp.Native
				continue
			case cfg.Excluded[imp.Provider]:
				retire(p, "provider excluded", false)
				d.Action, d.Reason, d.Current = ActionRetire, "provider excluded", imp.Native
				continue
			case cfg.Mode == "inject" && !allowed(cfg.Allowlist, p):
				retire(p, "not allowlisted", false)
				d.Action, d.Reason, d.Current = ActionRetire, "not allowlisted", imp.Native
				continue
			case cfg.ImprovementTTL > 0 && now.Sub(imp.Since) >= cfg.ImprovementTTL:
				// Static pins expire too: while a pin is active the router
				// may hide the native path, so the TTL is what notices an
				// upstream withdraw. No cooldown, so a pin whose prefix is
				// still in the RIB returns on the next round.
				retire(p, "ttl expired; re-evaluating native path", false)
				d.Action, d.Reason, d.Current = ActionRetire, "ttl expired", imp.Native
				continue
			}
			if static != "" {
				if static == imp.Native {
					reason := "policy static: native is the pinned provider"
					retire(p, reason, false)
					setDecision(d, ActionRetire, reason, imp.Native, imp.Native, plugin.CauseStatic)
					continue
				}
				pin, ok := get(static)
				if !ok || cfg.Excluded[static] {
					reason := "policy static: " + static + " not usable (" + staticWhy(cands, cfg, static) + ")"
					retire(p, reason, true)
					setDecision(d, ActionRetire, reason, imp.Native, "", plugin.CauseStatic)
					continue
				}
				if fault := pinFault(pin, cands, imp.Native, verdict, cfg); fault != "" {
					// The pinned path is lossy or slow: withdraw now and wait
					// out hold_time so a flapping path does not re-pin.
					reason := "policy static: " + static + " " + fault
					retire(p, reason, true)
					setDecision(d, ActionRetire, reason, imp.Native, "", plugin.CauseStatic)
					continue
				}
				if imp.Provider == static {
					// Already on the pinned provider: relabel, do not re-announce.
					imp.Cause, imp.Reason = plugin.CauseStatic, "policy static ("+verdict.Rule+")"
					st.Improvements[p] = imp
					setDecision(d, ActionKeep, imp.Reason, imp.Provider, imp.Provider, plugin.CauseStatic)
					continue
				}
				if now.Sub(imp.Since) < cfg.HoldTime {
					d.Recommended, d.Cause = static, plugin.CauseStatic
					d.Action, d.Reason = ActionKeep, "policy static: hold_time not elapsed before switching to "+static
					continue
				}
				n := Improvement{Prefix: p, Provider: static, Native: imp.Native, Since: now,
					Reason: "policy static (" + verdict.Rule + ")", Cause: plugin.CauseStatic,
					nativeSeen: imp.nativeSeen, nativeHeld: imp.nativeHeld}
				st.Improvements[p] = n
				out.Changes = append(out.Changes, Change{Action: ActionSwitch, Old: imp, New: n})
				setDecision(d, ActionSwitch, n.Reason, n.Provider, n.Provider, plugin.CauseStatic)
				continue
			}
			if imp.Cause == plugin.CauseStatic {
				retire(p, "static policy removed", false)
				setDecision(d, ActionRetire, "static policy removed", imp.Native, "", plugin.CauseStatic)
				continue
			}
			if planned(imp.Cause) {
				if imp.Cause == plugin.CauseCommit && ccDisabled(cfg, imp.Provider) {
					retire(p, "provider excluded from commit control", false)
					d.Action, d.Reason, d.Current, d.Cause = ActionRetire, "provider excluded from commit control", imp.Native, plugin.CauseCommit
					continue
				}
				holds = append(holds, commitHold{imp: imp, d: d, held: now.Sub(imp.Since) < cfg.HoldTime})
				continue
			}
			held := now.Sub(imp.Since) < cfg.HoldTime
			// Flip back when the native path is now clearly better.
			// Confirmation does not apply: flip-back keeps today's rule.
			if nat, ok := get(imp.Native); ok && better(nat, cur, cfg) {
				delete(st.confirm, p)
				if held {
					d.Action, d.Reason = ActionKeep, "native better but hold_time not elapsed"
					continue
				}
				retire(p, "native path better again", true)
				d.Action, d.Reason, d.Current = ActionRetire, "native path better again", imp.Native
				continue
			}
			// Move to a clearly better alternative. A performance switch
			// waits for confirm_rounds consecutive fresh wins. Hold time
			// still has to elapse before the switch is created.
			if alt, ok := bestCandidate(cands, cfg.Excluded, imp.Native); ok && alt.Provider != imp.Provider && better(alt, cur, cfg) {
				ready, n := notePerformance(&st, in, cfg, p, alt.Provider, now)
				if !ready {
					d.Recommended = alt.Provider
					d.Action, d.Reason = ActionKeep, fmt.Sprintf("confirming switch to %s (%d/%d)", alt.Provider, n, cfg.confirmRounds())
					continue
				}
				if !held {
					delete(st.confirm, p)
					sw := Improvement{Prefix: p, Provider: alt.Provider, Native: imp.Native, Since: now,
						Reason: reasonText(alt, cur), Cause: plugin.CausePerformance, nativeSeen: imp.nativeSeen, nativeHeld: imp.nativeHeld}
					st.Improvements[p] = sw
					out.Changes = append(out.Changes, Change{Action: ActionSwitch, Old: imp, New: sw})
					d.Action, d.Reason, d.Current, d.Cause = ActionSwitch, sw.Reason, sw.Provider, plugin.CausePerformance
					continue
				}
			} else if lost, _ := freshLoss(st.confirm[p], in, cfg, p, now); lost {
				delete(st.confirm, p)
			}
			d.Action, d.Reason = ActionKeep, "improvement still valid"
			continue
		}

		// No active improvement.
		if in.RIBEnabled {
			nat, inRIB := in.Native[p]
			if !inRIB {
				delete(st.confirm, p)
				d.Reason = "prefix not in RIB"
				continue
			}
			d.Native, d.Current = nat, nat
			if nat == "" {
				d.Reason = "RIB next-hop matches no provider"
				continue
			}
		} else {
			d.Reason = "no RIB configured: ranking only"
			continue
		}
		if ignore {
			delete(st.confirm, p)
			d.Reason = "policy ignore (" + verdict.Rule + ")"
			continue
		}
		if static != "" {
			d.Cause = plugin.CauseStatic
			pin, usable := get(static)
			switch {
			case static == d.Native:
				d.Recommended, d.Reason = static, "policy static: native is the pinned provider"
				continue
			case !usable || cfg.Excluded[static]:
				d.Reason = "policy static: " + static + " not usable (" + staticWhy(cands, cfg, static) + ")"
				continue
			}
			if fault := pinFault(pin, cands, d.Native, verdict, cfg); fault != "" {
				d.Reason = "policy static: " + static + " " + fault
				continue
			}
			d.Recommended = static
			if until, cool := st.Cooldown[p]; cool {
				d.Reason = "cooldown until " + until.Format(time.RFC3339)
				continue
			}
			if cfg.Mode == "inject" && !allowed(cfg.Allowlist, p) {
				d.Reason = "policy static but prefix not allowlisted"
				continue
			}
			wants = append(wants, pending{d: d, rank: rankStatic,
				imp: Improvement{Prefix: p, Provider: static, Native: d.Native, Since: now, Reason: "policy static (" + verdict.Rule + ")", Cause: plugin.CauseStatic}})
			continue
		}
		natC, ok := get(d.Native)
		if !ok {
			d.Reason = "no usable measurement for native provider (" + whyUnusable(cands, d.Native) + ")"
			continue
		}
		alt, ok := bestCandidate(cands, cfg.Excluded, d.Native)
		if !ok || !better(alt, natC, cfg) {
			if lost, _ := freshLoss(st.confirm[p], in, cfg, p, now); lost {
				delete(st.confirm, p)
			}
			d.Reason = "native path is best (within thresholds)"
			commitOK[p] = true
			continue
		}
		if until, cool := st.Cooldown[p]; cool {
			d.Reason = "cooldown after flip-back until " + until.Format(time.RFC3339)
			continue
		}
		if cfg.Mode == "inject" && !allowed(cfg.Allowlist, p) {
			d.Recommended, d.Reason = alt.Provider, "better path exists but prefix not allowlisted"
			continue
		}
		if cp, ok := costFirst(scorer); ok {
			// Cost precedence: the planner may replace this move with a
			// cheaper path inside the floor. A native path already inside
			// the floor is kept.
			commitOK[p] = true
			if maxLoss, maxRTT := cp.Floor(); inFloor(cands, cfg.Excluded, d.Native, maxLoss, maxRTT) {
				d.Recommended, d.Reason, d.Cause = d.Native, "native path inside performance floor (cost precedence)", plugin.CauseCost
				continue
			}
		}
		ready, n := notePerformance(&st, in, cfg, p, alt.Provider, now)
		if !ready {
			d.Recommended = alt.Provider
			d.Reason = fmt.Sprintf("confirming %s (%d/%d)", alt.Provider, n, cfg.confirmRounds())
			continue
		}
		rank := rankPerformance
		if hasPolicy && verdict.Action == plugin.PolicyVIP {
			rank = rankVIP
		}
		wants = append(wants, pending{d: d, gain: natC.Score - alt.Score, rank: rank,
			imp: Improvement{Prefix: p, Provider: alt.Provider, Native: d.Native, Since: now, Reason: reasonText(alt, natC), Cause: plugin.CausePerformance}})
	}

	integrateCommit(st, &out, decIdx, holds, commitOK, byPrefix, &wants, cfg, scorer, in, now, retire)

	weightVolume := in.VolumeMbps
	if in.WeightVolumeMbps != nil {
		weightVolume = in.WeightVolumeMbps
	}
	weighWants(wants, scorer, weightVolume)

	// Static pins take the cap first, then VIP and other performance
	// moves. A commit steer already in the
	// table gives up its slot to a new performance move. Commit moves then
	// take what is left, largest relief first. Inside a lane, improvement
	// weights (#34), when on, go first. Equal relief breaks by
	// prefix so the same inputs always pick the same prefix.
	sort.Slice(wants, func(a, b int) bool {
		if wants[a].rank != wants[b].rank {
			return wants[a].rank < wants[b].rank
		}
		if wants[a].weighed && wants[b].weighed && wants[a].weight != wants[b].weight {
			return wants[a].weight > wants[b].weight
		}
		if wants[a].gain != wants[b].gain {
			return wants[a].gain > wants[b].gain
		}
		return lessPrefix(wants[a].imp.Prefix, wants[b].imp.Prefix)
	})
	for _, w := range wants {
		w.d.Cause = w.imp.Cause
		for len(st.Improvements) >= cfg.MaxImprovements {
			if w.commit || cfg.MaxImprovements <= 0 || !displaceCommit(st, decIdx, in.VolumeMbps, retire) {
				w.d.Action, w.d.Reason, w.d.Recommended = ActionCapped, fmt.Sprintf("max_improvements (%d) reached", cfg.MaxImprovements), w.imp.Provider
				break
			}
		}
		if w.d.Action == ActionCapped {
			continue
		}
		delete(st.confirm, w.imp.Prefix)
		st.Improvements[w.imp.Prefix] = w.imp
		out.Changes = append(out.Changes, Change{Action: ActionImprove, New: w.imp})
		w.d.Action, w.d.Reason, w.d.Current, w.d.Recommended = ActionImprove, w.imp.Reason, w.imp.Provider, w.imp.Provider
	}
	for p := range st.confirm {
		if _, ok := byPrefix[p]; !ok {
			delete(st.confirm, p)
		}
	}
	markPendingUrgent(st, &out, cfg.confirmRounds())
	annotateCost(st, &out, cfg, in.VolumeMbps)
	for i := range decisions {
		attachSubranges(&decisions[i], subs[decisions[i].Prefix], cfg.Excluded)
	}
	out.Decisions = decisions
	return st, out
}

// noteSubranges adds one provider's sub-range measurements (#121) to the
// prefix's sub-range table. A sub-range is usable for that provider only
// when the provider's prefix candidate is usable and the sub-range itself
// was measured.
func noteSubranges(subs map[netip.Prefix]map[netip.Prefix]*SubrangeDecision, r probe.Result, pc Candidate, scorer plugin.Scorer) {
	if len(r.Subranges) == 0 {
		return
	}
	m := subs[r.Prefix]
	if m == nil {
		m = map[netip.Prefix]*SubrangeDecision{}
		subs[r.Prefix] = m
	}
	for _, sr := range r.Subranges {
		d := m[sr.Prefix]
		if d == nil {
			d = &SubrangeDecision{Prefix: sr.Prefix}
			m[sr.Prefix] = d
		}
		if sr.Weight > d.Weight {
			d.Weight = sr.Weight
		}
		c := Candidate{Provider: r.Provider, LossPct: sr.Stats.LossPct, RTTAvg: sr.Stats.RTTAvg, Jitter: sr.Stats.Jitter, Usable: pc.Usable, Why: pc.Why}
		switch {
		case !c.Usable:
		case !sr.OK():
			c.Usable, c.Why = false, "probe error"
		case sr.Stats.Sent == 0:
			c.Usable, c.Why = false, "no packets sent"
		}
		if c.Usable {
			c.Score = scorer.Score(plugin.PathStats{Provider: r.Provider, LossPct: c.LossPct, RTTAvg: c.RTTAvg, Jitter: c.Jitter})
		}
		d.Candidates = append(d.Candidates, c)
	}
}

// attachSubranges records the prefix's sub-ranges on its decision, busiest
// first, with the best provider of each, and flags the prefix
// heterogeneous when two sub-ranges have different best providers. It
// changes no action, recommendation, or improvement.
func attachSubranges(d *Decision, m map[netip.Prefix]*SubrangeDecision, excluded map[string]bool) {
	if len(m) == 0 {
		return
	}
	list := make([]SubrangeDecision, 0, len(m))
	for _, s := range m {
		sort.Slice(s.Candidates, func(a, b int) bool { return s.Candidates[a].Provider < s.Candidates[b].Provider })
		if best, ok := bestCandidate(s.Candidates, excluded, ""); ok {
			s.Best = best.Provider
		}
		list = append(list, *s)
	}
	sort.Slice(list, func(a, b int) bool {
		if list[a].Weight != list[b].Weight {
			return list[a].Weight > list[b].Weight
		}
		return lessPrefix(list[a].Prefix, list[b].Prefix)
	})
	best := ""
	for _, s := range list {
		if s.Best == "" {
			continue
		}
		if best == "" {
			best = s.Best
		} else if s.Best != best {
			d.Heterogeneous = true
		}
	}
	d.Subranges = list
}

// weighWants sets the improvement weight (#34) of every new static, VIP,
// and performance move when the scorer's weights are on. Commit and cost
// moves keep their relief and savings order. Weights only order moves
// that already passed every check; the cap loop admits them.
func weighWants(wants []pending, scorer plugin.Scorer, volume map[netip.Prefix]float64) {
	wg, ok := scorer.(plugin.ImprovementWeigher)
	if !ok {
		return
	}
	if on, _ := wg.ImprovementWeights(); !on {
		return
	}
	for i := range wants {
		w := &wants[i]
		if w.rank >= rankPlanned {
			continue
		}
		w.weight = wg.ImprovementWeight(plugin.WeightInput{
			Prefix: w.imp.Prefix, Provider: w.imp.Provider, Gain: w.gain, VolumeMbps: volume[w.imp.Prefix],
		})
		if math.IsNaN(w.weight) {
			w.weight = 0
		}
		w.weighed = true
		w.d.Weight = w.weight
	}
}

// planned reports whether an improvement belongs to the planner lane.
func planned(cause string) bool {
	return cause == plugin.CauseCommit || cause == plugin.CauseCost
}

// costFirst returns the scorer's cost policy when it asks for cost
// precedence.
func costFirst(scorer plugin.Scorer) (plugin.CostPolicy, bool) {
	cp, ok := scorer.(plugin.CostPolicy)
	if !ok || !cp.CostFirst() {
		return nil, false
	}
	if _, plans := scorer.(plugin.Planner); !plans {
		return nil, false
	}
	return cp, true
}

// annotateCost sets the cost estimate on every improvement and change whose
// native and steered providers both have a cost. It does not change a
// decision.
func annotateCost(st State, out *Output, cfg Config, volume map[netip.Prefix]float64) {
	for p, imp := range st.Improvements {
		st.Improvements[p] = withCost(imp, cfg, volume)
	}
	for i, ch := range out.Changes {
		if ch.Old.Provider != "" {
			out.Changes[i].Old = withCost(ch.Old, cfg, volume)
		}
		if ch.New.Provider != "" {
			out.Changes[i].New = withCost(ch.New, cfg, volume)
		}
	}
}

// withCost returns imp with CostDelta and EstSavings recomputed.
func withCost(imp Improvement, cfg Config, volume map[netip.Prefix]float64) Improvement {
	imp.CostDelta, imp.EstSavings = 0, 0
	nat, ok1 := providerCost(cfg, imp.Native)
	cur, ok2 := providerCost(cfg, imp.Provider)
	if ok1 && ok2 {
		imp.CostDelta = nat - cur
		if volume[imp.Prefix] > 0 {
			imp.EstSavings = imp.CostDelta * volume[imp.Prefix]
		}
	}
	return imp
}

// better reports whether a is better than b by the configured thresholds:
// loss improves by at least MinLossDeltaPct, or loss is no worse and latency
// improves by at least MinRTTDelta. When MinRTTDeltaPct is set, that latency
// improvement must also be at least that percent of b's RTT. A lower score
// is also required so the scorer has the final word on ties and trade-offs.
func better(a, b Candidate, cfg Config) bool {
	if a.Score >= b.Score {
		return false
	}
	if cfg.MinLossDeltaPct > 0 && b.LossPct-a.LossPct >= cfg.MinLossDeltaPct {
		return true
	}
	return rttWins(a, b, cfg)
}

// rttWins reports an RTT-only win: loss is no worse, the absolute delta
// clears MinRTTDelta, and, when MinRTTDeltaPct is set, the delta is also
// at least that percent of the current path's RTT.
func rttWins(a, b Candidate, cfg Config) bool {
	if a.LossPct > b.LossPct || cfg.MinRTTDelta <= 0 {
		return false
	}
	delta := b.RTTAvg - a.RTTAvg
	if delta < cfg.MinRTTDelta {
		return false
	}
	if cfg.MinRTTDeltaPct > 0 && float64(delta)*100 < float64(b.RTTAvg)*cfg.MinRTTDeltaPct {
		return false
	}
	return true
}

// confirmRounds is the number of consecutive fresh wins a performance
// move needs. 0 and 1 announce on the first fresh win.
func (cfg Config) confirmRounds() int {
	if cfg.ConfirmRounds <= 1 {
		return 1
	}
	return cfg.ConfirmRounds
}

// notePerformance records one fresh round of a performance move onto
// provider. ready is true when the move has won enough consecutive fresh
// rounds to be created. A stale round, and a repeat of measurements
// already counted, leave the streak untouched. A fresh round for a
// different provider starts that provider at 1. A short streak whose
// paths were compared this call asks for another probe; a stale round
// does not.
func notePerformance(st *State, in Input, cfg Config, p netip.Prefix, provider string, now time.Time) (ready bool, streak int) {
	rounds := cfg.confirmRounds()
	if rounds <= 1 {
		return provider != "", 1
	}
	if st.confirm == nil {
		st.confirm = map[netip.Prefix]confirm{}
	}
	cur := st.confirm[p]
	at, count, stale := prefixRound(in, cfg, cur, p, now)
	if stale || !count {
		if !stale && provider != "" && cur.Provider == provider && cur.Streak >= rounds {
			return true, cur.Streak
		}
		// The same fresh measurements of a short streak are still a
		// comparison. Keep the early-probe request. A stale round does not.
		if !stale && provider != "" && cur.Provider == provider && cur.Streak > 0 && cur.Streak < rounds {
			cur.Probe = true
			st.confirm[p] = cur
		}
		return false, cur.Streak
	}
	if provider == "" {
		delete(st.confirm, p)
		return false, 0
	}
	if cur.Provider != provider {
		cur = confirm{Provider: provider, Streak: 1, Round: at}
	} else {
		cur.Streak++
		cur.Round = at
	}
	cur.Probe = cur.Streak < rounds
	st.confirm[p] = cur
	return cur.Streak >= rounds, cur.Streak
}

// clearConfirmProbe drops the early-probe request for p. The streak stays
// so a later comparison can continue it.
func clearConfirmProbe(st *State, p netip.Prefix) {
	cur, ok := st.confirm[p]
	if !ok || !cur.Probe {
		return
	}
	cur.Probe = false
	st.confirm[p] = cur
}

// freshLoss reports whether this evaluation is a new fresh round that
// should reset a confirmation streak. A stale round, and the same
// measurements seen again, do not.
func freshLoss(prev confirm, in Input, cfg Config, p netip.Prefix, now time.Time) (bool, bool) {
	if cfg.confirmRounds() <= 1 || prev.Streak <= 0 {
		return false, false
	}
	_, count, stale := prefixRound(in, cfg, prev, p, now)
	return count && !stale, stale
}

// prefixRound identifies the probe generation for p. count is true when
// the measurements are fresh and newer than the last counted round.
// stale is true when every result for the prefix is older than
// MaxResultAge: that round does not count and does not reset.
func prefixRound(in Input, cfg Config, prev confirm, p netip.Prefix, now time.Time) (at time.Time, count, stale bool) {
	var newest time.Time
	var n, fresh int
	for _, r := range in.Results {
		if r.Prefix != p {
			continue
		}
		n++
		if r.Time.After(newest) {
			newest = r.Time
		}
		// The same bound as the candidate "stale" mark: age equal to
		// MaxResultAge is still fresh.
		if cfg.MaxResultAge <= 0 || now.Sub(r.Time) <= cfg.MaxResultAge {
			fresh++
		}
	}
	if n == 0 {
		return time.Time{}, false, false
	}
	if fresh == 0 && cfg.MaxResultAge > 0 {
		return newest, false, true
	}
	if prev.Streak > 0 && !newest.After(prev.Round) {
		return newest, false, false
	}
	return newest, true, false
}

// markPendingUrgent lists prefixes whose streak is short and whose paths
// were compared this evaluation. A stuck streak (nothing to compare) is
// left out, so the prober is not woken on every round.
func markPendingUrgent(st State, out *Output, rounds int) {
	if rounds <= 1 || len(st.confirm) == 0 {
		return
	}
	ps := make([]netip.Prefix, 0, len(st.confirm))
	for p, c := range st.confirm {
		if c.Probe && c.Streak > 0 && c.Streak < rounds {
			ps = append(ps, p)
		}
	}
	sortPrefixes(ps)
	out.Urgent = append(out.Urgent, ps...)
}

// bestCandidate returns the lowest-score usable, non-excluded provider other
// than skip. Ties break by provider name for determinism.
func bestCandidate(cands []Candidate, excluded map[string]bool, skip string) (Candidate, bool) {
	var best Candidate
	found := false
	for _, c := range cands {
		if !c.Usable || excluded[c.Provider] || c.Provider == skip {
			continue
		}
		if !found || c.Score < best.Score || (c.Score == best.Score && c.Provider < best.Provider) {
			best, found = c, true
		}
	}
	return best, found
}

func whyUnusable(cands []Candidate, provider string) string {
	for _, c := range cands {
		if c.Provider == provider {
			if c.Why == "" {
				return "usable"
			}
			return c.Why
		}
	}
	return "not measured"
}

func reasonText(to, from Candidate) string {
	return fmt.Sprintf("%s: loss %.1f%%→%.1f%%, rtt %s→%s", to.Provider, from.LossPct, to.LossPct,
		from.RTTAvg.Round(time.Millisecond/10), to.RTTAvg.Round(time.Millisecond/10))
}

func allowed(list []netip.Prefix, p netip.Prefix) bool {
	for _, a := range list {
		if a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func sortPrefixes(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool { return lessPrefix(ps[i], ps[j]) })
}

func lessPrefix(a, b netip.Prefix) bool {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c < 0
	}
	return a.Bits() < b.Bits()
}

// displaceCommit retires one commit or cost improvement so a performance
// move can use the slot. The smallest volume goes first (it relieves the least);
// equal volume breaks by prefix. The prefix takes a hold_time cooldown so
// the commit steer cannot return on the next round and take the slot back.
func displaceCommit(st State, decIdx map[netip.Prefix]*Decision, volume map[netip.Prefix]float64, retire func(netip.Prefix, string, bool)) bool {
	var pick netip.Prefix
	var pickVol float64
	found := false
	for p, imp := range st.Improvements {
		if !planned(imp.Cause) {
			continue
		}
		vol := 0.0
		if volume != nil {
			vol = volume[p]
		}
		if !found || vol < pickVol || (vol == pickVol && lessPrefix(p, pick)) {
			pick, pickVol, found = p, vol, true
		}
	}
	if !found {
		return false
	}
	imp := st.Improvements[pick]
	const reason = "displaced by a performance improvement"
	retire(pick, reason, true)
	setDecision(decIdx[pick], ActionRetire, reason, imp.Native, "", imp.Cause)
	return true
}

func sortedKeys(m map[netip.Prefix]Improvement) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortPrefixes(out)
	return out
}

// applyPolicy marks candidates an allow or deny verdict forbids as not
// usable, so no move of any cause can land on them. The native provider is
// left alone: it is where traffic already goes, and flip-back needs its
// measurement.
func applyPolicy(cands []Candidate, v plugin.PolicyVerdict, native string) {
	if v.Action != plugin.PolicyAllow && v.Action != plugin.PolicyDeny {
		return
	}
	listed := map[string]bool{}
	for _, name := range v.Providers {
		listed[name] = true
	}
	for i := range cands {
		c := &cands[i]
		if c.Provider == native || !c.Usable {
			continue
		}
		if (v.Action == plugin.PolicyDeny) == listed[c.Provider] {
			c.Usable, c.Why, c.Score = false, "policy "+v.Action+" ("+v.Rule+")", 0
		}
	}
}

func policyText(v plugin.PolicyVerdict) string {
	s := v.Action
	if len(v.Providers) > 0 {
		s += " " + strings.Join(v.Providers, ",")
	}
	if v.Rule != "" || v.Match != "" {
		s += " (" + strings.TrimSpace(v.Rule+": "+v.Match) + ")"
	}
	return s
}

// pinFault says why a usable static path may not carry the prefix, or ""
// when it may. The path must be inside the rule's loss ceiling (and latency
// ceiling, when set), and its loss must not exceed a usable native path's
// by min_loss_delta_pct or more. It is checked before a pin is announced
// and on every round while the pin is held.
func pinFault(pin Candidate, cands []Candidate, native string, v plugin.PolicyVerdict, cfg Config) string {
	if pin.LossPct > v.MaxLossPct {
		return fmt.Sprintf("loss %.1f%% over max_loss_pct %.1f%%", pin.LossPct, v.MaxLossPct)
	}
	if v.MaxRTT > 0 && pin.RTTAvg > v.MaxRTT {
		return fmt.Sprintf("rtt %s over max_rtt %s", pin.RTTAvg.Round(time.Millisecond), v.MaxRTT)
	}
	for _, c := range cands {
		if c.Provider == native && c.Usable && cfg.MinLossDeltaPct > 0 && pin.LossPct-c.LossPct >= cfg.MinLossDeltaPct {
			return fmt.Sprintf("loss %.1f%% worse than native %.1f%% by min_loss_delta_pct or more", pin.LossPct, c.LossPct)
		}
	}
	return ""
}

func staticWhy(cands []Candidate, cfg Config, name string) string {
	if cfg.Excluded[name] {
		return "excluded"
	}
	return whyUnusable(cands, name)
}
