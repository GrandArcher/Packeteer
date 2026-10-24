package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// nativeOf is the native provider of p: the one recorded on an active
// improvement, else the RIB's.
func nativeOf(st State, in Input, p netip.Prefix) string {
	if imp, ok := st.Improvements[p]; ok {
		return imp.Native
	}
	return in.Native[p]
}

// carrierOf is the provider the prefix's traffic leaves through now: the
// improvement's provider while one is active in inject mode, else the
// native provider. Passive TCP evidence describes that path only.
func carrierOf(st State, in Input, cfg Config, p netip.Prefix) string {
	if imp, ok := st.Improvements[p]; ok {
		if cfg.Mode == "inject" {
			return imp.Provider
		}
		return imp.Native
	}
	return in.Native[p]
}

// evidenceRefused starts the reason of every decision the evidence rule
// refused; the explanation reads it to tell that the rule was reached.
const evidenceRefused = "require_evidence: "

// evidenceLacking is the reason thresholds.require_evidence refuses the
// performance move from cur to alt, empty when the rule is off or both
// samples rest on more than ICMP (#202).
func evidenceLacking(cfg Config, cur, alt Candidate) string {
	if !cfg.RequireEvidence {
		return ""
	}
	var names []string
	for _, c := range []Candidate{cur, alt} {
		if !c.Confidence.BeyondICMP() {
			names = append(names, c.Provider+" ("+c.Confidence.String()+")")
		}
	}
	if len(names) == 0 {
		return ""
	}
	return evidenceRefused + "no evidence beyond ICMP for " + strings.Join(names, " and ")
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
	st.expireFlap(now, cfg.Flap, &out)

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
	in.byPrefix = make(map[netip.Prefix][]int, len(in.Native))
	for i, r := range in.Results {
		in.byPrefix[r.Prefix] = append(in.byPrefix[r.Prefix], i)
		ans := in.RPKI[r.Prefix][r.Provider]
		reg := in.IRR[r.Prefix][r.Provider]
		c := Candidate{Provider: r.Provider, LossPct: r.Stats.LossPct, RTTAvg: r.Stats.RTTAvg, Jitter: r.Stats.Jitter, Usable: true,
			RPKI: ans.State, RPKISource: ans.Source, RPKIUpdated: ans.Updated,
			IRR: reg.State, IRRSource: reg.Source, IRRUpdated: reg.Updated, Confidence: r.Confidence}
		if problem, seen := in.Passive[r.Prefix]; seen && r.OK() && r.Provider == carrierOf(st, in, cfg, r.Prefix) {
			c.Confidence = r.Confidence.WithPassive(problem == (r.Stats.LossPct > 0))
		}
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
		case cfg.RPKIAvoidInvalid && c.RPKI == plugin.RPKIInvalid && r.Provider != nativeOf(st, in, r.Prefix):
			c.Usable, c.Why = false, "RPKI invalid"
		case cfg.IRRPreferRegistered && c.IRR == plugin.IRRNotRegistered && r.Provider != nativeOf(st, in, r.Prefix):
			c.Usable, c.Why = false, "IRR not registered"
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
	netpfx.Sort(prefixes)
	decisions := make([]Decision, len(prefixes))
	facts := make([]explainFacts, len(prefixes))

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
		facts[i] = factsOf(&st, in, cfg, p, cands, imp, active, ignore, now)

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
				case inRIB && in.Held != nil && in.Held(p):
					imp.nativeSeen = time.Time{}
					imp.nativeHeld = false
					st.Improvements[p] = imp
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
			case cfg.Mode == "inject" && !netpfx.CoveredBy(cfg.Allowlist, p):
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
				holds = append(holds, commitHold{imp: imp, d: d, f: &facts[i], held: now.Sub(imp.Since) < cfg.HoldTime})
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
				if st.flapNext(p, now, cfg.Flap) {
					st.quarantinePrefix(p, now, cfg.Flap, &out)
				} else {
					st.noteFlip(p, now, cfg.Flap)
				}
				d.Action, d.Reason, d.Current = ActionRetire, "native path better again", imp.Native
				continue
			}
			// Move to a clearly better alternative. A performance switch
			// waits for confirm_rounds consecutive fresh wins. Hold time
			// still has to elapse before the switch is created.
			if alt, ok := bestCandidate(cands, cfg.Excluded, imp.Native); ok && alt.Provider != imp.Provider && better(alt, cur, cfg) {
				if lacking := evidenceLacking(cfg, cur, alt); lacking != "" {
					delete(st.confirm, p)
					d.Recommended = alt.Provider
					d.Action, d.Reason = ActionKeep, lacking
					continue
				}
				ready, n := notePerformance(&st, in, cfg, p, alt.Provider, now)
				if !ready {
					d.Recommended = alt.Provider
					d.Action, d.Reason = ActionKeep, fmt.Sprintf("confirming switch to %s (%d/%d)", alt.Provider, n, cfg.confirmRounds())
					continue
				}
				if !held {
					if st.flapNext(p, now, cfg.Flap) {
						q := st.quarantinePrefix(p, now, cfg.Flap, &out)
						retire(p, flapReason(q), false)
						d.Action, d.Reason, d.Current = ActionRetire, flapReason(q), imp.Native
						continue
					}
					st.noteFlip(p, now, cfg.Flap)
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
		if q, parked := st.quarantine[p]; parked {
			delete(st.confirm, p)
			d.Reason = flapReason(q)
			continue
		}
		if static != "" {
			d.Cause = plugin.CauseStatic
			pin, usable := get(static)
			switch {
			case static == d.Native:
				d.Recommended, d.Reason, facts[i].pinNative = static, "policy static: native is the pinned provider", true
				continue
			case !usable || cfg.Excluded[static]:
				d.Reason = "policy static: " + static + " not usable (" + staticWhy(cands, cfg, static) + ")"
				continue
			}
			if fault := pinFault(pin, cands, d.Native, verdict, cfg); fault != "" {
				d.Reason = "policy static: " + static + " " + fault
				continue
			}
			d.Recommended, facts[i].pinOK = static, true
			if until, cool := st.Cooldown[p]; cool {
				d.Reason = "cooldown until " + until.Format(time.RFC3339)
				continue
			}
			if cfg.Mode == "inject" && !netpfx.CoveredBy(cfg.Allowlist, p) {
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
		if cfg.Mode == "inject" && !netpfx.CoveredBy(cfg.Allowlist, p) {
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
		// After the cost branch, so a refused performance move still
		// leaves the prefix to the cost planner (commitOK above).
		if lacking := evidenceLacking(cfg, natC, alt); lacking != "" {
			delete(st.confirm, p)
			d.Recommended, d.Reason = alt.Provider, lacking
			continue
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

	// A lower max_improvements (including 0) retires the lowest-ranked
	// active improvements now, inside hold_time and with no cooldown.
	// Survivors keep their slots; new wants below only fill what is left.
	trimToCap(st, decIdx, byPrefix, in.Policies, cfg, retire)

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
		return netpfx.Less(wants[a].imp.Prefix, wants[b].imp.Prefix)
	})
	for _, w := range wants {
		w.d.Cause = w.imp.Cause
		if st.flapNext(w.imp.Prefix, now, cfg.Flap) {
			q := st.quarantinePrefix(w.imp.Prefix, now, cfg.Flap, &out)
			w.d.Reason, w.d.Recommended = flapReason(q), w.imp.Provider
			delete(st.confirm, w.imp.Prefix)
			continue
		}
		for len(st.Improvements) >= cfg.MaxImprovements {
			if w.commit || cfg.MaxImprovements <= 0 || !displaceCommit(st, decIdx, in.VolumeMbps, retire) {
				w.d.Action, w.d.Reason, w.d.Recommended = ActionCapped, fmt.Sprintf("max_improvements (%d) reached", cfg.MaxImprovements), w.imp.Provider
				break
			}
		}
		if w.d.Action == ActionCapped {
			continue
		}
		st.noteFlip(w.imp.Prefix, now, cfg.Flap)
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
		if c, ok := st.confirm[prefixes[i]]; ok && c.Provider == facts[i].challenger {
			facts[i].streak = c.Streak
		}
	}
	out.Decisions, out.facts = decisions, facts
	explainChanges(&out, cfg, len(st.Improvements))
	return st, out
}
