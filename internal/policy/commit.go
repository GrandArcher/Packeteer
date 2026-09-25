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
			retire(h.imp.Prefix, "commit control disabled", false)
			if h.d != nil {
				h.d.Action, h.d.Reason, h.d.Current, h.d.Cause = ActionRetire, "commit control disabled", h.imp.Native, plugin.CauseCommit
			}
		}
		return
	}
	allowLoss := false
	if lp, ok := scorer.(plugin.LossOverride); ok {
		allowLoss = lp.AllowLoss()
	}
	moves := planner.Plan(buildPlan(cfg, in, byPrefix, decIdx, holds, commitOK, st, *wants, now))
	want := map[netip.Prefix]plugin.PlanMove{}
	for _, m := range moves {
		if m.Provider == "" || !m.Prefix.IsValid() {
			continue
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
		// A real loss regression (the same margin better() uses) leaves
		// immediately. The cooldown is what stops the next equal sample
		// from announcing the same steer again. A gap under the threshold
		// is probe noise and is not a regression.
		if !allowLoss && lossRegressed(cands, h.imp.Native, h.imp.Provider, cfg) {
			retire(p, "commit path loss regressed", true)
			setDecision(d, ActionRetire, "commit path loss regressed", h.imp.Native, "", plugin.CauseCommit)
			continue
		}
		if nat, ok := usableCand(cands, h.imp.Native); ok {
			if alt, ok2 := bestCandidate(cands, cfg.Excluded, h.imp.Native); ok2 && alt.Provider != h.imp.Provider && better(alt, nat, cfg) {
				if h.held {
					setDecision(d, ActionKeep, "performance gain but hold_time not elapsed", h.imp.Provider, "", plugin.CauseCommit)
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
		if wanted && mv.Provider != h.imp.Provider && !moveAllowed(mv, cands, cfg, allowLoss, h.imp.Native, h.imp.Provider) {
			if mv.Provider == h.imp.Native {
				// Back to native is a release, not a steer.
				wanted = false
			} else {
				// A higher-loss (or excluded) alternate is ignored. The
				// current steer stays; withdrawing it would flap.
				setDecision(d, ActionKeep, "commit move refused", h.imp.Provider, "", plugin.CauseCommit)
				continue
			}
		}
		if wanted && mv.Provider == h.imp.Provider {
			imp := h.imp
			imp.Reason = mv.Reason
			st.Improvements[p] = imp
			setDecision(d, ActionKeep, mv.Reason, imp.Provider, imp.Provider, plugin.CauseCommit)
			continue
		}
		if wanted && mv.Provider != h.imp.Provider {
			if h.held {
				setDecision(d, ActionKeep, "commit move but hold_time not elapsed", h.imp.Provider, mv.Provider, plugin.CauseCommit)
				continue
			}
			n := Improvement{
				Prefix: p, Provider: mv.Provider, Native: h.imp.Native, Since: now,
				Reason: mv.Reason, Cause: plugin.CauseCommit,
				nativeSeen: h.imp.nativeSeen, nativeHeld: h.imp.nativeHeld,
			}
			st.Improvements[p] = n
			out.Changes = append(out.Changes, Change{Action: ActionSwitch, Old: h.imp, New: n})
			setDecision(d, ActionSwitch, n.Reason, n.Provider, n.Provider, plugin.CauseCommit)
			continue
		}
		if h.held {
			setDecision(d, ActionKeep, "commit relieved but hold_time not elapsed", h.imp.Provider, "", plugin.CauseCommit)
			continue
		}
		retire(p, "commit relieved", true)
		setDecision(d, ActionRetire, "commit relieved", h.imp.Native, "", plugin.CauseCommit)
	}

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
			d.Cause = plugin.CauseCommit
			continue
		}
		if cfg.Mode == "inject" && !allowed(cfg.Allowlist, p) {
			d.Recommended = mv.Provider
			d.Reason = "commit move available but prefix not allowlisted"
			d.Cause = plugin.CauseCommit
			continue
		}
		cands := byPrefix[p]
		if !moveAllowed(mv, cands, cfg, allowLoss, d.Native, d.Native) {
			d.Recommended = mv.Provider
			d.Reason = "commit move refused"
			d.Cause = plugin.CauseCommit
			continue
		}
		if _, ok := usableCand(cands, d.Native); !ok {
			continue
		}
		fresh = append(fresh, pending{
			d: d, commit: true, gain: mv.ReliefMbps,
			imp: Improvement{
				Prefix: p, Provider: mv.Provider, Native: d.Native, Since: now,
				Reason: mv.Reason, Cause: plugin.CauseCommit,
			},
		})
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
		if imp.Cause == plugin.CauseCommit {
			continue
		}
		perf = append(perf, imp)
	}
	for _, w := range wants {
		if !w.commit {
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
// (native for a new move, the current provider for a switch).
func moveAllowed(mv plugin.PlanMove, cands []Candidate, cfg Config, allowLoss bool, native, leaving string) bool {
	if mv.Provider == "" || mv.Provider == native || cfg.Excluded[mv.Provider] || ccDisabled(cfg, mv.Provider) {
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
