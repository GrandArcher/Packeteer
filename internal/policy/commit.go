package policy

import (
	"net/netip"
	"sort"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// commitHold is an active commit improvement that survived the fail-closed
// checks. Performance flip-back does not apply to it; integrateCommit does.
type commitHold struct {
	imp  Improvement
	d    *Decision
	held bool
}

const commitLossEps = 1e-6

// integrateCommit reconciles commit-cause improvements with the scorer's
// plan and queues new commit moves. A scorer that does not implement
// plugin.Planner withdraws any commit improvement it finds, which is how
// turning commit control off removes the routes it created. commitOK is
// set only for prefixes that are in the learned RIB, so a commit move is
// never queued for a prefix the RIB does not have.
func integrateCommit(
	st State,
	out *Output,
	decIdx map[netip.Prefix]*Decision,
	holds []commitHold,
	commitOK map[netip.Prefix]bool,
	byPrefix map[netip.Prefix][]Candidate,
	wants *[]pending,
	cfg Config,
	scorer plugin.Scorer,
	in Input,
	now time.Time,
	retire func(netip.Prefix, string, bool),
) {
	planner, ok := scorer.(plugin.Planner)
	if !ok {
		for _, h := range holds {
			reason := "commit control disabled"
			if h.imp.Cause == plugin.CauseCost {
				reason = "cost mode disabled"
			}
			retire(h.imp.Prefix, reason, false)
			if h.d != nil {
				h.d.Action, h.d.Reason, h.d.Current, h.d.Cause = ActionRetire, reason, h.imp.Native, h.imp.Cause
			}
		}
		return
	}
	allowLoss := false
	if lp, ok := scorer.(plugin.LossOverride); ok {
		allowLoss = lp.AllowLoss()
	}
	cp, _ := scorer.(plugin.CostPolicy)
	_, cheapFirst := costFirst(scorer)
	moves := planner.Plan(buildPlan(cfg, in, byPrefix, decIdx, holds, commitOK, st, *wants, cheapFirst, now))
	want := map[netip.Prefix]plugin.PlanMove{}
	for _, m := range moves {
		if m.Provider == "" || !m.Prefix.IsValid() {
			continue
		}
		if m.Cause == "" {
			m.Cause = plugin.CauseCommit
		}
		if _, seen := want[m.Prefix]; seen {
			continue
		}
		want[m.Prefix] = m
	}

	handled := map[netip.Prefix]bool{}
	for _, h := range holds {
		p := h.imp.Prefix
		handled[p] = true
		d := h.d
		cands := byPrefix[p]
		cause := h.imp.Cause
		if cause == plugin.CauseCost {
			// A cost steer lives only inside the floor. Leaving it is
			// not noise: withdraw now and hold the prefix off.
			if cp == nil {
				// The planner is not a cost scorer any more.
				retire(p, "cost mode disabled", false)
				setDecision(d, ActionRetire, "cost mode disabled", h.imp.Native, "", cause)
				continue
			}
			if !inFloorOf(cands, cfg, cp, h.imp.Provider) {
				retire(p, "cost path outside performance floor", true)
				setDecision(d, ActionRetire, "cost path outside performance floor", h.imp.Native, "", cause)
				continue
			}
		} else if !allowLoss && lossRegressed(cands, h.imp.Native, h.imp.Provider, cfg) {
			// A real loss regression (the same margin better() uses) leaves
			// immediately. The cooldown is what stops the next equal sample
			// from announcing the same steer again. A gap under the threshold
			// is probe noise and is not a regression.
			retire(p, "commit path loss regressed", true)
			setDecision(d, ActionRetire, "commit path loss regressed", h.imp.Native, "", cause)
			continue
		}
		if nat, ok := usableCand(cands, h.imp.Native); ok && !(cause == plugin.CauseCost && cheapFirst) {
			if alt, ok2 := bestCandidate(cands, cfg.Excluded, h.imp.Native); ok2 && alt.Provider != h.imp.Provider && better(alt, nat, cfg) {
				if h.held {
					setDecision(d, ActionKeep, "performance gain but hold_time not elapsed", h.imp.Provider, "", cause)
					continue
				}
				n := Improvement{
					Prefix: p, Provider: alt.Provider, Native: h.imp.Native, Since: now,
					Reason: reasonText(alt, nat), Cause: plugin.CausePerformance,
					nativeSeen: h.imp.nativeSeen, nativeHeld: h.imp.nativeHeld,
				}
				st.Improvements[p] = n
				out.Changes = append(out.Changes, Change{Action: ActionSwitch, Old: h.imp, New: n})
				setDecision(d, ActionSwitch, n.Reason, n.Provider, n.Provider, plugin.CausePerformance)
				continue
			}
		}
		mv, wanted := want[p]
		if wanted && mv.Cause != cause {
			// A planner that changes a steer's cause is treated as
			// releasing it. The next round may queue the other cause.
			wanted = false
		}
		if wanted && mv.Provider != h.imp.Provider && !moveAllowed(mv, cands, cfg, allowLoss, cp, h.imp.Native, h.imp.Provider) {
			if mv.Provider == h.imp.Native {
				// Back to native is a release, not a steer.
				wanted = false
			} else {
				// A higher-loss (or excluded) alternate is ignored. The
				// current steer stays; withdrawing it would flap.
				setDecision(d, ActionKeep, cause+" move refused", h.imp.Provider, "", cause)
				continue
			}
		}
		if wanted && mv.Provider == h.imp.Provider {
			imp := h.imp
			imp.Reason = mv.Reason
			st.Improvements[p] = imp
			setDecision(d, ActionKeep, mv.Reason, imp.Provider, imp.Provider, cause)
			continue
		}
		if wanted && mv.Provider != h.imp.Provider {
			if h.held {
				setDecision(d, ActionKeep, cause+" move but hold_time not elapsed", h.imp.Provider, mv.Provider, cause)
				continue
			}
			n := Improvement{
				Prefix: p, Provider: mv.Provider, Native: h.imp.Native, Since: now,
				Reason: mv.Reason, Cause: cause,
				nativeSeen: h.imp.nativeSeen, nativeHeld: h.imp.nativeHeld,
			}
			st.Improvements[p] = n
			out.Changes = append(out.Changes, Change{Action: ActionSwitch, Old: h.imp, New: n})
			setDecision(d, ActionSwitch, n.Reason, n.Provider, n.Provider, cause)
			continue
		}
		release := "commit relieved"
		if cause == plugin.CauseCost {
			release = "cost steer no longer cheapest"
		}
		if h.held {
			setDecision(d, ActionKeep, release+" but hold_time not elapsed", h.imp.Provider, "", cause)
			continue
		}
		retire(p, release, true)
		setDecision(d, ActionRetire, release, h.imp.Native, "", cause)
	}

	// Under cost precedence a pending performance move may be replaced by
	// a cost move for the same prefix.
	perfWant := map[netip.Prefix]int{}
	for i, w := range *wants {
		if !w.commit {
			perfWant[w.imp.Prefix] = i
		}
	}
	replaced := map[netip.Prefix]bool{}

	// Gather in prefix order so equal relief does not depend on map iteration.
	// Decide breaks remaining ties the same way when the cap binds.
	var fresh []pending
	for _, p := range sortedCommitOK(commitOK) {
		if handled[p] {
			continue
		}
		d := decIdx[p]
		if d == nil {
			continue
		}
		mv, wanted := want[p]
		if !wanted {
			continue
		}
		if until, cool := st.Cooldown[p]; cool {
			d.Reason = "cooldown after flip-back until " + until.Format(time.RFC3339)
			d.Recommended = mv.Provider
			d.Cause = mv.Cause
			continue
		}
		_, hasPerf := perfWant[p]
		if hasPerf && (!cheapFirst || mv.Cause != plugin.CauseCost) {
			// Performance precedence: the performance move stands.
			continue
		}
		if cfg.Mode == "inject" && !allowed(cfg.Allowlist, p) {
			d.Recommended = mv.Provider
			d.Reason = mv.Cause + " move available but prefix not allowlisted"
			d.Cause = mv.Cause
			continue
		}
		cands := byPrefix[p]
		if !moveAllowed(mv, cands, cfg, allowLoss, cp, d.Native, d.Native) {
			if hasPerf {
				continue
			}
			d.Recommended = mv.Provider
			d.Reason = mv.Cause + " move refused"
			d.Cause = mv.Cause
			continue
		}
		if _, ok := usableCand(cands, d.Native); !ok {
			continue
		}
		gain := mv.ReliefMbps
		if mv.Cause == plugin.CauseCost {
			gain = mv.Savings
		}
		if hasPerf {
			replaced[p] = true
		}
		fresh = append(fresh, pending{
			d: d, commit: true, gain: gain, rank: rankPlanned,
			imp: Improvement{
				Prefix: p, Provider: mv.Provider, Native: d.Native, Since: now,
				Reason: mv.Reason, Cause: mv.Cause,
			},
		})
	}
	if len(replaced) > 0 {
		kept := (*wants)[:0]
		for _, w := range *wants {
			if !w.commit && replaced[w.imp.Prefix] {
				continue
			}
			kept = append(kept, w)
		}
		*wants = kept
	}
	*wants = append(*wants, fresh...)
}

func sortedCommitOK(ok map[netip.Prefix]bool) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ok))
	for p, yes := range ok {
		if yes {
			out = append(out, p)
		}
	}
	sortPrefixes(out)
	return out
}

func setDecision(d *Decision, action, reason, current, recommended, cause string) {
	if d == nil {
		return
	}
	d.Action = action
	d.Reason = reason
	if current != "" {
		d.Current = current
	}
	if recommended != "" {
		d.Recommended = recommended
	}
	d.Cause = cause
}

func buildPlan(
	cfg Config,
	in Input,
	byPrefix map[netip.Prefix][]Candidate,
	decIdx map[netip.Prefix]*Decision,
	holds []commitHold,
	commitOK map[netip.Prefix]bool,
	st State,
	wants []pending,
	cheapFirst bool,
	now time.Time,
) plugin.PlanInput {
	usage := map[string]plugin.Usage{}
	for _, u := range in.Usage {
		if u.Provider == "" {
			continue
		}
		if _, seen := usage[u.Provider]; seen {
			continue
		}
		usage[u.Provider] = u
	}
	out := plugin.PlanInput{Now: now}
	seen := map[string]bool{}
	for _, p := range cfg.Providers {
		if p.Name == "" || seen[p.Name] {
			continue
		}
		seen[p.Name] = true
		u, have := usage[p.Name]
		out.Providers = append(out.Providers, plugin.PlanProvider{
			Name: p.Name, Group: p.Group, Precedence: p.Precedence,
			CCDisable: p.CCDisable, Excluded: cfg.Excluded[p.Name],
			Up: in.ProviderUp[p.Name], Usage: u, HaveRow: have,
			Cost: p.Cost, HasCost: p.HasCost,
		})
	}
	added := map[netip.Prefix]bool{}
	add := func(p netip.Prefix, native, current string, reversible, locked bool) {
		if !p.IsValid() || added[p] {
			return
		}
		added[p] = true
		vol := 0.0
		if in.VolumeMbps != nil {
			vol = in.VolumeMbps[p]
		}
		out.Prefixes = append(out.Prefixes, plugin.PlanPrefix{
			Prefix: p, Native: native, Current: current, VolumeMbps: vol,
			Reversible: reversible, Locked: locked, Paths: planPaths(byPrefix[p]),
		})
	}
	// Performance steers already taken, and performance moves waiting on
	// the cap, are locked context. The planner shifts their volume off
	// Native so it does not also commit-steer that traffic.
	var perf []Improvement
	for _, imp := range st.Improvements {
		if planned(imp.Cause) {
			continue
		}
		perf = append(perf, imp)
	}
	// Under cost precedence a waiting performance move is not locked: the
	// planner may offer a cheaper path inside the floor instead.
	for _, w := range wants {
		if !w.commit && !cheapFirst {
			perf = append(perf, w.imp)
		}
	}
	sort.Slice(perf, func(i, j int) bool { return lessPrefix(perf[i].Prefix, perf[j].Prefix) })
	for _, imp := range perf {
		cur := imp.Provider
		if cur == "" {
			cur = imp.Native
		}
		add(imp.Prefix, imp.Native, cur, false, true)
	}
	for _, p := range sortedCommitOK(commitOK) {
		d := decIdx[p]
		if d == nil || d.Native == "" {
			continue
		}
		add(p, d.Native, d.Native, false, false)
	}
	for _, h := range holds {
		add(h.imp.Prefix, h.imp.Native, h.imp.Provider, true, false)
	}
	return out
}

func planPaths(cands []Candidate) []plugin.PlanPath {
	out := make([]plugin.PlanPath, 0, len(cands))
	for _, c := range cands {
		out = append(out, plugin.PlanPath{
			Provider: c.Provider, LossPct: c.LossPct, RTT: c.RTTAvg, Usable: c.Usable,
		})
	}
	return out
}

func usableCand(cands []Candidate, name string) (Candidate, bool) {
	for _, c := range cands {
		if c.Provider == name && c.Usable {
			return c, true
		}
	}
	return Candidate{}, false
}

// lossRegressed reports whether the commit path's loss is worse than native
// by at least the loss margin in better(). Latency alone does not count:
// a commit move may trade latency. A smaller loss gap is one probe of noise.
func lossRegressed(cands []Candidate, native, current string, cfg Config) bool {
	nat, ok1 := usableCand(cands, native)
	cur, ok2 := usableCand(cands, current)
	if !ok1 || !ok2 {
		return false
	}
	if nat.Score >= cur.Score {
		return false
	}
	margin := cfg.MinLossDeltaPct
	if margin <= 0 {
		margin = commitLossEps
	}
	return cur.LossPct-nat.LossPct >= margin
}

// moveAllowed is Decide's check on a planner proposal. A destination that
// is the native provider is not a steer. A scorer that does not implement
// LossOverride, or one whose AllowLoss is false, may not land on higher
// loss than the provider the traffic is leaving. leaving is that provider
// (native for a new move, the current provider for a switch). A cost move
// needs a CostPolicy, a destination inside its floor, and a destination
// that is cheaper than native; loss_override does not apply to it.
func moveAllowed(mv plugin.PlanMove, cands []Candidate, cfg Config, allowLoss bool, cp plugin.CostPolicy, native, leaving string) bool {
	if mv.Provider == "" || mv.Provider == native || cfg.Excluded[mv.Provider] {
		return false
	}
	if mv.Cause == plugin.CauseCost {
		if cp == nil || !inFloorOf(cands, cfg, cp, mv.Provider) {
			return false
		}
		natCost, ok1 := providerCost(cfg, native)
		destCost, ok2 := providerCost(cfg, mv.Provider)
		return ok1 && ok2 && destCost < natCost
	}
	if ccDisabled(cfg, mv.Provider) {
		return false
	}
	dest, ok := usableCand(cands, mv.Provider)
	if !ok {
		return false
	}
	if allowLoss {
		return true
	}
	base := leaving
	if base == "" {
		base = native
	}
	from, ok := usableCand(cands, base)
	if !ok {
		return false
	}
	return dest.LossPct <= from.LossPct+commitLossEps
}

func ccDisabled(cfg Config, name string) bool {
	for _, p := range cfg.Providers {
		if p.Name == name {
			return p.CCDisable
		}
	}
	return false
}

func providerCost(cfg Config, name string) (float64, bool) {
	for _, p := range cfg.Providers {
		if p.Name == name {
			return p.Cost, p.HasCost
		}
	}
	return 0, false
}

func inFloorOf(cands []Candidate, cfg Config, cp plugin.CostPolicy, name string) bool {
	maxLoss, maxRTT := cp.Floor()
	return inFloor(cands, cfg.Excluded, name, maxLoss, maxRTT)
}

// inFloor reports whether name's path is usable and within maxLoss of the
// lowest loss and maxRTT of the lowest RTT among usable, non-excluded
// providers. The cost scorer uses the same rule.
func inFloor(cands []Candidate, excluded map[string]bool, name string, maxLoss float64, maxRTT time.Duration) bool {
	c, ok := usableCand(cands, name)
	if !ok {
		return false
	}
	found := false
	var minLoss float64
	var minRTT time.Duration
	for _, o := range cands {
		if !o.Usable || excluded[o.Provider] {
			continue
		}
		if !found || o.LossPct < minLoss {
			minLoss = o.LossPct
		}
		if !found || o.RTTAvg < minRTT {
			minRTT = o.RTTAvg
		}
		found = true
	}
	if !found {
		return false
	}
	return c.LossPct <= minLoss+maxLoss+commitLossEps && c.RTTAvg <= minRTT+maxRTT
}
