package httpapi

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// lossEqualPct is the loss difference under which two paths read as equal.
const lossEqualPct = 0.05

// explainImprovement fills the before and after measurements, the gain, and
// the plain-words explanation of im from the latest candidates of its
// prefix. Without a usable measurement for both providers the explanation
// falls back to the stored reason.
func explainImprovement(im *Improvement, cands []policy.Candidate, th policy.Thresholds) {
	var from, to *policy.Candidate
	for i := range cands {
		if !cands[i].Usable {
			continue
		}
		switch cands[i].Provider {
		case im.Native:
			from = &cands[i]
		case im.Provider:
			to = &cands[i]
		}
	}
	if from == nil || to == nil {
		im.Explain = causeLabel(im.Cause) + strings.TrimSuffix(im.Reason, ".") + "."
		return
	}
	fromMs, toMs := rttMs(from.RTTAvg), rttMs(to.RTTAvg)
	im.NativeLossPct, im.LossPct = &from.LossPct, &to.LossPct
	im.NativeRTTMs, im.RTTMs = &fromMs, &toMs
	gainMs := fromMs - toMs
	im.GainMs = &gainMs
	if fromMs > 0 {
		pct := gainMs / fromMs * 100
		im.GainPct = &pct
	}
	lossGain := from.LossPct - to.LossPct
	lossWin := th.MinLossDeltaPct > 0 && lossGain >= th.MinLossDeltaPct
	switch {
	case im.Cause != "" && im.Cause != plugin.CausePerformance:
		im.Explain = fmt.Sprintf("%s%s. %s measures rtt %s -> %s ms, loss %s -> %s%%.",
			causeLabel(im.Cause), strings.TrimSuffix(im.Reason, "."), im.Provider, num(fromMs), num(toMs), num(from.LossPct), num(to.LossPct))
	case lossWin:
		im.Explain = fmt.Sprintf("%s has %s pt less loss (%s%% -> %s%%), rtt %s -> %s ms. Threshold %s pt of loss.",
			im.Provider, num(lossGain), num(from.LossPct), num(to.LossPct), num(fromMs), num(toMs), num(th.MinLossDeltaPct))
	case gainMs > 0 && to.LossPct <= from.LossPct:
		im.Explain = fmt.Sprintf("%s is %s ms faster (%s -> %s ms, %.0f%%), %s. Threshold %s.",
			im.Provider, num(gainMs), num(fromMs), num(toMs), *im.GainPct, lossClause(from.LossPct, to.LossPct), rttThreshold(th))
	default:
		im.Explain = fmt.Sprintf("%s measures rtt %s -> %s ms, loss %s%% -> %s%% against %s. It cleared the thresholds when chosen.",
			im.Provider, num(fromMs), num(toMs), num(from.LossPct), num(to.LossPct), im.Native)
	}
}

func causeLabel(cause string) string {
	switch cause {
	case plugin.CauseCommit:
		return "Commit control: "
	case plugin.CauseCost:
		return "Cost: "
	case plugin.CauseStatic:
		return "Static policy: "
	}
	return ""
}

func lossClause(from, to float64) string {
	if from-to < lossEqualPct {
		return "loss equal"
	}
	return fmt.Sprintf("loss %s%% -> %s%%", num(from), num(to))
}

func rttThreshold(th policy.Thresholds) string {
	s := num(float64(th.MinRTTDelta)/float64(time.Millisecond)) + " ms"
	if th.MinRTTDeltaPct > 0 {
		s += " and " + num(th.MinRTTDeltaPct) + "%"
	}
	return s
}

func rttMs(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// num formats a measurement with at most one decimal and no trailing zero.
func num(v float64) string {
	return strings.TrimSuffix(strconv.FormatFloat(v, 'f', 1, 64), ".0")
}
