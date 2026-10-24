package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Gate names, in the order an Explain lists them (#201).
const (
	GateRIB        = "rib"
	GateFreshness  = "freshness"
	GateThresholds = "thresholds"
	GateConfirm    = "confirm_rounds"
	GateHoldTime   = "hold_time"
	GateCap        = "cap"
	GatePolicy     = "policy"
	GateAllowlist  = "allowlist"
	GateRouteCheck = "route_check"
	GateRPKI       = "rpki"
	GateIRR        = "irr"
)

// Gate results. A skipped gate was not reached or does not apply.
const (
	GatePass = "pass"
	GateFail = "fail"
	GateSkip = "skip"
)

// Outcomes of an Explain.
const (
	OutcomeMoved   = "moved"
	OutcomeKept    = "kept"
	OutcomeRetired = "retired"
	OutcomeHeld    = "held"
)

// Gate is one check a decision passes through: the value it looked at and
// the limit it compared it with.
type Gate struct {
	Name   string `json:"gate"`
	Status string `json:"status"`
	Value  string `json:"value,omitempty"`
	Limit  string `json:"limit,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Sample is one provider's measurement behind a decision. Role is
// "current" for the path now in use, "native" for the router's own path
// while an improvement is active, and "challenger" for the best other
// provider the current path was compared with.
type Sample struct {
	Provider string  `json:"provider"`
	Role     string  `json:"role,omitempty"`
	LossPct  float64 `json:"loss_pct"`
	RTTMs    float64 `json:"rtt_ms"`
	JitterMs float64 `json:"jitter_ms"`
	Score    float64 `json:"score"`
	Usable   bool    `json:"usable"`
	Why      string  `json:"why,omitempty"`
}

// Explain says which check let a decision move or held it back (#201).
// BlockedBy is the gate that stopped a held or kept decision. It is empty
// when the decision moved or retired, for a static pin on its provider or on
// the native provider, and for a planned commit or cost keep that waits for
// no switch or release. Counterfactual is one sentence on what would have to
// change for the blocked move to happen.
type Explain struct {
	Outcome        string   `json:"outcome"`
	BlockedBy      string   `json:"blocked_by,omitempty"`
	Reason         string   `json:"reason"`
	Gates          []Gate   `json:"gates"`
	Samples        []Sample `json:"samples"`
	Counterfactual string   `json:"counterfactual,omitempty"`
}

type ribState uint8

const (
	ribOff ribState = iota
	ribAbsent
	ribNoProvider
	ribHidden
	ribOK
)

const (
	waitNone uint8 = iota
	waitCooldown
	waitQuarantine
)

// What a planned commit or cost keep waits for; integrateCommit sets it.
const (
	planSettled uint8 = iota
	// planHold: a planner move or a release waiting on hold_time.
	planHold
	// planSwitch: a performance switch confirming or waiting on hold_time.
	planSwitch
)

// explainFacts is what Decide saw for one prefix that the final Decision
// does not carry and an Explain needs.
type explainFacts struct {
	// current is the provider whose path is compared: the improvement's
	// provider when one is active, else the native provider.
	current string
	// challenger is the best other usable provider the current path is
	// compared with; empty when there is none.
	challenger string
	// barred lists excluded providers (provider exclude or an open maintenance
	// window) that would otherwise beat the current path.
	barred string
	// oldest is the age of the oldest probe result of the prefix.
	oldest time.Duration
	// held is how long an active improvement has existed.
	held time.Duration
	// wait is the time left on a cooldown or quarantine; waitKind says which.
	wait     time.Duration
	waitKind uint8
	streak   int
	rib      ribState
	active   bool
	ignore   bool
	// pinOK is set when a static pin passed the policy's own checks (usable,
	// inside its ceilings) and Decide recommended it.
	pinOK bool
	// pinNative is set when the static pin is the native provider, so there
	// is nothing to move.
	pinNative bool
	planWait  uint8
}

// challengerOf picks the provider the current path is compared with. For
// an active improvement the native path is the flip-back candidate and
// takes the place when it is better, as Decide does.
func challengerOf(cands []Candidate, cfg Config, native, current string, active bool) string {
	if current == "" {
		return ""
	}
	cur, ok := findCandidate(cands, current)
	if !ok || !cur.Usable {
		return ""
	}
	if active {
		if nat, ok := findCandidate(cands, native); ok && nat.Usable && better(nat, cur, cfg) {
			return native
		}
		if alt, ok := bestCandidate(cands, cfg.Excluded, native); ok && alt.Provider != current {
			return alt.Provider
		}
	}
	if alt, ok := bestCandidate(cands, cfg.Excluded, current); ok {
		return alt.Provider
	}
	return ""
}

func findCandidate(cands []Candidate, name string) (Candidate, bool) {
	for _, c := range cands {
		if c.Provider == name {
			return c, true
		}
	}
	return Candidate{}, false
}

// wouldWin reports whether c beats cur on the thresholds, ignoring the
// score. A candidate a gate removed has no score.
func wouldWin(c, cur Candidate, cfg Config) bool {
	return lossWins(c, cur, cfg) || rttWins(c, cur, cfg)
}

// whyGate maps a Candidate.Why to the gate that removed the candidate.
func whyGate(why string) string {
	switch {
	case why == "probe error", why == "provider down", why == "stale", why == "no packets sent":
		return GateFreshness
	case strings.HasPrefix(why, "no route via provider"), why == "egress router down":
		return GateRouteCheck
	case why == "RPKI invalid":
		return GateRPKI
	case why == "IRR not registered":
		return GateIRR
	case strings.HasPrefix(why, "policy "):
		return GatePolicy
	}
	return ""
}

// removedBy lists the candidates a gate removed that would have beaten cur.
func removedBy(cands []Candidate, gate string, cur Candidate, cfg Config) []string {
	var out []string
	for _, c := range cands {
		if !c.Usable && c.Provider != cur.Provider && whyGate(c.Why) == gate && wouldWin(c, cur, cfg) {
			out = append(out, c.Provider)
		}
	}
	return out
}

func dur(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}

func fnum(v float64) string {
	return strings.TrimSuffix(strconv.FormatFloat(v, 'f', 1, 64), ".0")
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// factsOf records, for the prefix being decided, what an Explain needs that
// the final Decision does not carry. cands already carry the policy verdict.
func factsOf(st *State, in Input, cfg Config, p netip.Prefix, cands []Candidate, imp Improvement, active, ignore bool, now time.Time) explainFacts {
	f := explainFacts{active: active, ignore: ignore}
	native, inRIB := in.Native[p]
	switch {
	case active:
		native, f.current, f.held = imp.Native, imp.Provider, now.Sub(imp.Since)
		f.rib = ribOK
		if !inRIB {
			f.rib = ribHidden
		}
	case !in.RIBEnabled:
		f.rib = ribOff
	case !inRIB:
		f.rib = ribAbsent
	case native == "":
		f.rib = ribNoProvider
	default:
		f.rib, f.current = ribOK, native
	}
	for _, i := range in.byPrefix[p] {
		f.oldest = max(f.oldest, now.Sub(in.Results[i].Time))
	}
	f.challenger = challengerOf(cands, cfg, native, f.current, active)
	if until, ok := st.Cooldown[p]; ok {
		f.wait, f.waitKind = until.Sub(now), waitCooldown
	}
	if q, ok := st.quarantine[p]; ok && !active {
		f.wait, f.waitKind = q.Until.Sub(now), waitQuarantine
	}
	if len(cfg.Excluded) > 0 {
		if cur, ok := findCandidate(cands, f.current); ok && cur.Usable {
			var names []string
			for _, c := range cands {
				if cfg.Excluded[c.Provider] && c.Usable && c.Provider != f.current && wouldWin(c, cur, cfg) {
					names = append(names, c.Provider)
				}
			}
			f.barred = strings.Join(names, ", ")
		}
	}
	return f
}

// explainChanges attaches the gate list of the deciding evaluation to each
// improve and switch, for history. A retire is recorded with its reason.
func explainChanges(out *Output, cfg Config, capUsed int) {
	for i := range out.Changes {
		c := &out.Changes[i]
		if c.Action == ActionRetire {
			continue
		}
		if j, ok := findDecision(out.Decisions, c.New.Prefix); ok {
			ex := buildExplain(out.Decisions[j], out.facts[j], cfg, capUsed)
			c.Explain = &ex
		}
	}
}

// buildExplain derives the gate list of d. capUsed is the number of active
// improvements after the evaluation. cfg is the config the evaluation ran
// with; Engine.Explain passes the engine config, without the maintenance
// exclusions, so buildExplain must not read cfg.Excluded.
func buildExplain(d Decision, f explainFacts, cfg Config, capUsed int) Explain {
	ex := Explain{Reason: d.Reason, Samples: samplesOf(d, f)}
	cur, haveCur := findCandidate(d.Candidates, f.current)
	ch, haveCh := findCandidate(d.Candidates, f.challenger)
	plan := planned(d.Cause)
	static := d.Cause == plugin.CauseStatic
	moved := d.Action == ActionImprove || d.Action == ActionSwitch
	pairBetter := haveCur && haveCh && cur.Usable && ch.Usable && better(ch, cur, cfg)
	// A static pin or planned keep is decided by its own rules, not by the
	// comparison with the challenger.
	steerKeep := d.Action == ActionKeep && (static || plan)
	// A recommended static pin that did not move was stopped by the
	// cooldown, the allowlist, or the cap, not by the policy.
	pinHeld := static && !moved && d.Action != ActionKeep && !f.pinNative
	pinStopped := pinHeld && f.pinOK

	g := map[string]Gate{}
	g[GateRIB] = ribGate(d, f)
	g[GateFreshness] = freshnessGate(d, f, cur, haveCur, cfg)
	g[GatePolicy] = policyGate(d, f, cur, haveCur, cfg, pinHeld && !pinStopped)
	g[GateRouteCheck] = removedGate(GateRouteCheck, d, cur, haveCur, cfg, "no provider lacks a route for this prefix", "route check")
	g[GateRPKI] = rpkiGate(d, cur, haveCur, cfg)
	g[GateIRR] = irrGate(d, cur, haveCur, cfg)
	g[GateAllowlist] = allowlistGate(d, cfg)

	switch {
	case static:
		g[GateThresholds] = Gate{Name: GateThresholds, Status: GateSkip, Detail: "a static policy pin does not use the thresholds"}
	case plan:
		g[GateThresholds] = Gate{Name: GateThresholds, Status: GateSkip, Detail: "decided by the " + d.Cause + " planner, not the thresholds"}
	default:
		g[GateThresholds] = thresholdsGate(cur, ch, haveCur, haveCh, cfg)
	}
	retired := d.Action == ActionRetire
	reached := moved || (pairBetter && !static && !plan)
	notReached := func(name string) Gate {
		if retired {
			return Gate{Name: name, Status: GateSkip, Detail: "not applicable: the improvement ended"}
		}
		return Gate{Name: name, Status: GateSkip, Detail: "not reached: no better path passed the thresholds"}
	}
	g[GateConfirm], g[GateHoldTime], g[GateCap] = notReached(GateConfirm), notReached(GateHoldTime), notReached(GateCap)
	if reached {
		g[GateConfirm] = confirmGate(d, f, cfg, moved)
		if !retired {
			g[GateCap] = capGate(d, f, cfg, capUsed)
		}
	}
	switch {
	case steerKeep && f.planWait == planSwitch:
		g[GateConfirm] = confirmGate(d, f, cfg, false)
	case static || plan:
		g[GateConfirm] = Gate{Name: GateConfirm, Status: GateSkip, Detail: "a " + d.Cause + " move does not wait for confirm_rounds"}
	}
	if pinStopped {
		g[GateCap] = capGate(d, f, cfg, capUsed)
	}
	// A static re-pin and a planned switch, move, or release wait out
	// hold_time. d.Recommended of a planned keep can be the best provider
	// Decide saw, so only planWait says whether it waits.
	waiting := steerKeep && ((static && d.Recommended != d.Current) || (plan && f.planWait != planSettled))
	if reached || pinStopped || waiting || f.waitKind == waitQuarantine {
		g[GateHoldTime] = holdGate(d, f, cfg)
	}

	order := []string{GateRIB, GateFreshness, GateThresholds, GateConfirm, GateHoldTime, GateCap, GatePolicy, GateAllowlist, GateRouteCheck, GateRPKI, GateIRR}
	for _, n := range order {
		ex.Gates = append(ex.Gates, g[n])
	}

	switch d.Action {
	case ActionImprove, ActionSwitch:
		ex.Outcome = OutcomeMoved
	case ActionRetire:
		ex.Outcome = OutcomeRetired
	case ActionKeep:
		ex.Outcome = OutcomeKept
	default:
		ex.Outcome = OutcomeHeld
	}
	if ex.Outcome == OutcomeHeld || ex.Outcome == OutcomeKept {
		ex.BlockedBy = blockedBy(g, f, d, pairBetter, pinStopped, steerKeep, haveCur && cur.Usable)
	}
	ex.Counterfactual = counterfactual(ex.BlockedBy, d, f, cfg, cur, ch, haveCur, haveCh, capUsed)
	return ex
}

func samplesOf(d Decision, f explainFacts) []Sample {
	out := make([]Sample, 0, len(d.Candidates))
	for _, c := range d.Candidates {
		s := Sample{Provider: c.Provider, LossPct: c.LossPct, RTTMs: ms(c.RTTAvg), JitterMs: ms(c.Jitter), Score: c.Score, Usable: c.Usable, Why: c.Why}
		switch {
		case c.Provider == f.current:
			s.Role = "current"
		case c.Provider == f.challenger:
			s.Role = "challenger"
		case c.Provider == d.Native:
			s.Role = "native"
		}
		out = append(out, s)
	}
	return out
}

func ribGate(d Decision, f explainFacts) Gate {
	g := Gate{Name: GateRIB}
	switch f.rib {
	case ribOff:
		g.Status, g.Value, g.Limit = GateFail, "no BGP neighbors configured", "bgp.neighbors set"
		g.Detail = "providers are ranked only: no native exit is known"
	case ribAbsent:
		g.Status, g.Value, g.Limit = GateFail, "prefix not in the learned RIB", "a neighbor advertises the exact prefix"
	case ribNoProvider:
		g.Status, g.Value, g.Limit = GateFail, "next hop matches no provider", "next hop of a configured provider"
	case ribHidden:
		g.Status, g.Value, g.Detail = GatePass, "native "+d.Native, "the native path is not advertised now; the improvement's own route can hide it"
	default:
		g.Status, g.Value = GatePass, "native "+d.Native
	}
	return g
}

func freshnessGate(d Decision, f explainFacts, cur Candidate, haveCur bool, cfg Config) Gate {
	g := Gate{Name: GateFreshness}
	if f.current == "" {
		g.Status, g.Detail = GateSkip, "not reached: no current path"
		return g
	}
	g.Value = "oldest result " + dur(f.oldest)
	if cfg.MaxResultAge > 0 {
		g.Limit = "max_result_age " + dur(cfg.MaxResultAge)
	}
	switch {
	case !haveCur:
		g.Status, g.Detail = GateFail, f.current+" has no measurement"
	case !cur.Usable && whyGate(cur.Why) == GateFreshness:
		g.Status, g.Detail = GateFail, cur.Provider+": "+cur.Why
	case !cur.Usable:
		g.Status, g.Detail = GateFail, cur.Provider+" is not usable: "+cur.Why
	default:
		g.Status = GatePass
		if names := removedBy(d.Candidates, GateFreshness, cur, cfg); len(names) > 0 {
			g.Status, g.Detail = GateFail, strings.Join(names, ", ")+" would win but has no fresh measurement"
		}
	}
	return g
}

func thresholdsGate(cur, ch Candidate, haveCur, haveCh bool, cfg Config) Gate {
	g := Gate{Name: GateThresholds}
	if !haveCur || !cur.Usable {
		g.Status, g.Detail = GateSkip, "not reached: the current path has no usable measurement"
		return g
	}
	g.Limit = thresholdLimit(cfg)
	if !haveCh {
		g.Status, g.Detail = GateFail, "no other provider has a usable measurement"
		return g
	}
	lossGain, rttGain := cur.LossPct-ch.LossPct, ms(cur.RTTAvg-ch.RTTAvg)
	g.Value = fmt.Sprintf("%s vs %s: loss gain %s pt, rtt gain %s ms", ch.Provider, cur.Provider, fnum(lossGain), fnum(rttGain))
	if cur.RTTAvg > 0 {
		g.Value += " (" + fnum(rttGain/ms(cur.RTTAvg)*100) + "%)"
	}
	switch {
	case better(ch, cur, cfg):
		g.Status = GatePass
	case wouldWin(ch, cur, cfg):
		g.Status, g.Detail = GateFail, fmt.Sprintf("thresholds met but the score is not lower (%s vs %s)", fnum(ch.Score), fnum(cur.Score))
	case cfg.MinLossDeltaPct <= 0 && cfg.MinRTTDelta <= 0:
		g.Status, g.Detail = GateFail, "no threshold is configured, so no move qualifies"
	default:
		g.Status, g.Detail = GateFail, "neither threshold is met"
	}
	return g
}

// thresholdLimit quotes the configured loss and latency limits.
func thresholdLimit(cfg Config) string {
	var parts []string
	if cfg.MinLossDeltaPct > 0 {
		parts = append(parts, "loss gain >= "+fnum(cfg.MinLossDeltaPct)+" pt")
	}
	if cfg.MinRTTDelta > 0 {
		s := "rtt gain >= " + fnum(ms(cfg.MinRTTDelta)) + " ms"
		if cfg.MinRTTDeltaPct > 0 {
			s += " and >= " + fnum(cfg.MinRTTDeltaPct) + "% of the current rtt"
		}
		parts = append(parts, s+" with loss no higher")
	}
	if len(parts) == 0 {
		return "no threshold configured"
	}
	return strings.Join(parts, ", or ") + ", and a lower score"
}

func confirmGate(d Decision, f explainFacts, cfg Config, moved bool) Gate {
	n := cfg.confirmRounds()
	g := Gate{Name: GateConfirm, Limit: fmt.Sprintf("%d fresh round(s) in a row", n)}
	if f.active && f.challenger == d.Native {
		g.Status, g.Detail = GatePass, "flip-back to the native path does not wait"
		return g
	}
	streak := f.streak
	if moved || n <= 1 {
		streak = max(n, streak)
	}
	g.Value = fmt.Sprintf("%d of %d", min(streak, n), n)
	g.Status = GatePass
	if streak < n {
		g.Status = GateFail
	}
	return g
}

func holdGate(d Decision, f explainFacts, cfg Config) Gate {
	g := Gate{Name: GateHoldTime}
	switch {
	case f.waitKind == waitQuarantine:
		g.Status, g.Value, g.Limit = GateFail, dur(f.wait)+" left", "flap quarantine"
	case f.waitKind == waitCooldown:
		g.Status, g.Value, g.Limit = GateFail, dur(f.wait)+" left", "cooldown after a flip-back (hold_time)"
	case f.active:
		g.Value, g.Limit = "held "+dur(f.held), "hold_time "+dur(cfg.HoldTime)
		g.Status = GatePass
		if f.held < cfg.HoldTime && d.Action != ActionSwitch {
			g.Status = GateFail
		}
	default:
		g.Status, g.Value = GatePass, "no cooldown"
	}
	return g
}

func capGate(d Decision, f explainFacts, cfg Config, capUsed int) Gate {
	g := Gate{Name: GateCap, Limit: "max_improvements " + strconv.Itoa(cfg.MaxImprovements)}
	if f.active {
		g.Status, g.Value = GatePass, "replaces its own slot"
		return g
	}
	g.Value = fmt.Sprintf("%d in use", capUsed)
	g.Status = GatePass
	if d.Action == ActionCapped {
		g.Status = GateFail
	}
	return g
}

func policyGate(d Decision, f explainFacts, cur Candidate, haveCur bool, cfg Config, staticHeld bool) Gate {
	g := Gate{Name: GatePolicy, Value: "no routing policy matched"}
	if d.Policy != "" {
		g.Value = d.Policy
	}
	g.Status = GatePass
	switch {
	case f.ignore:
		g.Status, g.Detail = GateFail, "the policy leaves this prefix on native routing"
	case staticHeld:
		g.Status, g.Detail = GateFail, d.Reason
	case f.barred != "":
		g.Status, g.Detail = GateFail, f.barred+" would win but is excluded (provider exclude or maintenance)"
	case haveCur:
		if names := removedBy(d.Candidates, GatePolicy, cur, cfg); len(names) > 0 {
			g.Status, g.Detail = GateFail, strings.Join(names, ", ")+" would win but the policy does not allow it"
		}
	}
	return g
}

func removedGate(name string, d Decision, cur Candidate, haveCur bool, cfg Config, ok, label string) Gate {
	g := Gate{Name: name, Status: GatePass, Value: ok}
	if !haveCur {
		return g
	}
	if names := removedBy(d.Candidates, name, cur, cfg); len(names) > 0 {
		g.Status, g.Value, g.Detail = GateFail, strings.Join(names, ", ")+" failed the "+label, "would win but cannot carry this exact prefix"
	}
	return g
}

func rpkiGate(d Decision, cur Candidate, haveCur bool, cfg Config) Gate {
	g := Gate{Name: GateRPKI}
	var states []string
	for _, c := range d.Candidates {
		if c.RPKI != "" {
			states = append(states, c.Provider+" "+string(c.RPKI))
		}
	}
	if len(states) == 0 && !cfg.RPKIAvoidInvalid {
		g.Status, g.Detail = GateSkip, "RPKI is off"
		return g
	}
	g.Status, g.Value = GatePass, strings.Join(states, ", ")
	g.Limit = "display only"
	if cfg.RPKIAvoidInvalid {
		g.Limit = "avoid_invalid: no move onto an invalid path"
		if haveCur {
			if names := removedBy(d.Candidates, GateRPKI, cur, cfg); len(names) > 0 {
				g.Status, g.Detail = GateFail, strings.Join(names, ", ")+" would win but its path is RPKI invalid"
			}
		}
	}
	return g
}

// irrGate mirrors rpkiGate for the IRR origin check (#214): the states are
// shown whenever a source answered, and irr.prefer_registered makes a not
// registered path fail the gate.
func irrGate(d Decision, cur Candidate, haveCur bool, cfg Config) Gate {
	g := Gate{Name: GateIRR}
	var states []string
	for _, c := range d.Candidates {
		if c.IRR != "" {
			states = append(states, c.Provider+" "+string(c.IRR))
		}
	}
	if len(states) == 0 && !cfg.IRRPreferRegistered {
		g.Status, g.Detail = GateSkip, "IRR is off"
		return g
	}
	g.Status, g.Value = GatePass, strings.Join(states, ", ")
	g.Limit = "display only"
	if cfg.IRRPreferRegistered {
		g.Limit = "prefer_registered: no move onto a not registered path"
		if haveCur {
			if names := removedBy(d.Candidates, GateIRR, cur, cfg); len(names) > 0 {
				g.Status, g.Detail = GateFail, strings.Join(names, ", ")+" would win but its path is not registered in the IRR"
			}
		}
	}
	return g
}

func allowlistGate(d Decision, cfg Config) Gate {
	g := Gate{Name: GateAllowlist}
	if cfg.Mode != "inject" {
		g.Status, g.Detail = GateSkip, "mode "+cfg.Mode+": nothing is announced"
		return g
	}
	g.Limit = "allowlist.prefixes"
	if netpfx.CoveredBy(cfg.Allowlist, d.Prefix) {
		g.Status, g.Value = GatePass, "covered"
	} else {
		g.Status, g.Value = GateFail, "not covered"
	}
	return g
}

// blockedBy names the gate that stopped the decision, in the order Decide
// checks them: the RIB and the policy first, then a quarantine, then the
// current path's measurement, then the comparison and what a gate removed
// from it, then the move's own gates. A recommended static pin skips the
// comparison and stops only at the cooldown, the allowlist, or the cap; a
// static pin or planned keep stops only at confirm_rounds or hold_time.
func blockedBy(g map[string]Gate, f explainFacts, d Decision, pairBetter, pinStopped, steerKeep, usableCur bool) string {
	failed := func(names ...string) string {
		for _, n := range names {
			if g[n].Status == GateFail {
				return n
			}
		}
		return ""
	}
	switch {
	case g[GateRIB].Status == GateFail:
		return GateRIB
	case f.pinNative:
		return ""
	case steerKeep:
		// An excluded or removed provider that would otherwise win does
		// not hold back a pin or a planned steer that stays where it is.
		return failed(GateConfirm, GateHoldTime)
	case pinStopped:
		return failed(GateHoldTime, GateAllowlist, GateCap)
	case f.ignore || (d.Cause == plugin.CauseStatic && g[GatePolicy].Status == GateFail):
		return GatePolicy
	case f.waitKind == waitQuarantine:
		return GateHoldTime
	case !usableCur:
		return failed(GateFreshness)
	case !pairBetter:
		if n := failed(GateRouteCheck, GateRPKI, GateIRR, GatePolicy, GateFreshness); n != "" {
			return n
		}
		return failed(GateThresholds)
	case f.active:
		return failed(GateConfirm, GateHoldTime, GateAllowlist, GateCap)
	}
	return failed(GateHoldTime, GateAllowlist, GateConfirm, GateCap)
}

func counterfactual(blocked string, d Decision, f explainFacts, cfg Config, cur, ch Candidate, haveCur, haveCh bool, capUsed int) string {
	// A static pin moves to the pinned provider, not to the challenger.
	to := f.challenger
	if d.Cause == plugin.CauseStatic {
		to = d.Recommended
	}
	switch blocked {
	case GateRIB:
		if f.rib == ribOff {
			return "would be decided once bgp.neighbors is configured, so the native exit is known"
		}
		return "would be decided once a neighbor advertises " + d.Prefix.String() + " with a next hop of a configured provider"
	case GateFreshness:
		fresh := "a fresh result"
		if cfg.MaxResultAge > 0 {
			fresh = "a result within " + dur(cfg.MaxResultAge)
		}
		return "would be compared once every provider has " + fresh + " and the current path is usable"
	case GatePolicy:
		return "would be decided again if the routing policy no longer applied"
	case GateRouteCheck:
		return "would move once the provider has a path for the exact prefix"
	case GateRPKI:
		return "would move if the provider's path were not RPKI invalid"
	case GateIRR:
		return "would move if the provider's path were registered in the IRR, or with irr.prefer_registered off"
	case GateConfirm:
		return fmt.Sprintf("would move to %s after %d more fresh winning round(s)", f.challenger, max(cfg.confirmRounds()-f.streak, 1))
	case GateHoldTime:
		left := f.wait
		if f.waitKind == waitNone {
			left = max(cfg.HoldTime-f.held, 0)
		}
		return "would be eligible in " + dur(left)
	case GateAllowlist:
		return "would move to " + to + " if allowlist.prefixes covered " + d.Prefix.String()
	case GateCap:
		return fmt.Sprintf("would move to %s when an improvement ends or max_improvements is above %d (%d in use)", to, cfg.MaxImprovements, capUsed)
	case GateThresholds:
		if !haveCur || !haveCh {
			return "would move once a second provider has a usable measurement"
		}
		return thresholdCounterfactual(cur, ch, cfg)
	}
	return ""
}

func thresholdCounterfactual(cur, ch Candidate, cfg Config) string {
	if wouldWin(ch, cur, cfg) {
		return fmt.Sprintf("would move to %s if its score were lower than %s (%s vs %s)", ch.Provider, cur.Provider, fnum(ch.Score), fnum(cur.Score))
	}
	var parts []string
	if cfg.MinRTTDelta > 0 {
		need := ms(cfg.MinRTTDelta)
		if cfg.MinRTTDeltaPct > 0 {
			need = max(need, ms(cur.RTTAvg)*cfg.MinRTTDeltaPct/100)
		}
		parts = append(parts, fmt.Sprintf("its RTT delta reached >= %s ms (now %s ms) with loss no higher than %s%%", fnum(need), fnum(ms(cur.RTTAvg-ch.RTTAvg)), fnum(cur.LossPct)))
	}
	if cfg.MinLossDeltaPct > 0 {
		parts = append(parts, fmt.Sprintf("its loss were >= %s pt lower (now %s pt)", fnum(cfg.MinLossDeltaPct), fnum(cur.LossPct-ch.LossPct)))
	}
	if len(parts) == 0 {
		return "would move to " + ch.Provider + " once thresholds.min_loss_delta_pct or thresholds.min_rtt_delta_ms is set"
	}
	return "would move to " + ch.Provider + " if " + strings.Join(parts, ", or ")
}

// findDecision locates p in decisions, which Decide sorts by prefix.
func findDecision(ds []Decision, p netip.Prefix) (int, bool) {
	i := sort.Search(len(ds), func(i int) bool { return !netpfx.Less(ds[i].Prefix, p) })
	return i, i < len(ds) && ds[i].Prefix == p
}

// Explain returns the latest decision for p, its gate list, and when the
// evaluation ran, all from the same round. It reports false when p has no
// decision.
func (e *Engine) Explain(p netip.Prefix) (Decision, Explain, time.Time, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	i, ok := findDecision(e.last.Decisions, p)
	if !ok {
		return Decision{}, Explain{}, time.Time{}, false
	}
	d := e.last.Decisions[i]
	return d, buildExplain(d, e.last.facts[i], e.lastCfg, len(e.state.Improvements)), e.at, true
}
