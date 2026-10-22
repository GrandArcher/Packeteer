package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// better reports whether a is better than b by the configured thresholds:
// loss improves by at least MinLossDeltaPct, or loss is no worse and latency
// improves by at least MinRTTDelta. When MinRTTDeltaPct is set, that latency
// improvement must also be at least that percent of b's RTT. A lower score
// is also required so the scorer has the final word on ties and trade-offs.
func better(a, b Candidate, cfg Config) bool {
	if a.Score >= b.Score {
		return false
	}
	return lossWins(a, b, cfg) || rttWins(a, b, cfg)
}

// lossWins reports a loss win: a's loss is at least MinLossDeltaPct below b's.
func lossWins(a, b Candidate, cfg Config) bool {
	return cfg.MinLossDeltaPct > 0 && b.LossPct-a.LossPct >= cfg.MinLossDeltaPct
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
	return fmt.Sprintf("%s: loss %.1f%%->%.1f%%, rtt %s->%s", to.Provider, from.LossPct, to.LossPct,
		from.RTTAvg.Round(time.Millisecond/10), to.RTTAvg.Round(time.Millisecond/10))
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
