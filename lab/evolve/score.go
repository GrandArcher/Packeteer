package main

import (
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/replay"
)

// pathScore sums the loss and RTT of the path each prefix was on during
// each round: the provider an improvement left it on after the round
// before, else the native provider. A move is scored by the rounds after
// it, not by the measurement that made it. Only a usable measurement
// counts, so a stale or failed probe adds nothing for that prefix and round.
type pathScore struct {
	samples   int
	loss, rtt float64
	steered   map[netip.Prefix]string
}

func (p *pathScore) observe(st policy.State, out policy.Output) {
	for _, d := range out.Decisions {
		on, ok := p.steered[d.Prefix]
		if !ok {
			on = d.Native
		}
		for _, c := range d.Candidates {
			if c.Provider == on && c.Usable {
				p.samples++
				p.loss += c.LossPct
				p.rtt += float64(c.RTTAvg) / float64(time.Millisecond)
				break
			}
		}
	}
	p.steered = make(map[netip.Prefix]string, len(st.Improvements))
	for pfx, imp := range st.Improvements {
		p.steered[pfx] = imp.Provider
	}
}

// Verdicts of a variant against the baseline, over loss, RTT, and flaps.
const (
	verdictBetter = "better" // none worse, at least one better
	verdictWorse  = "worse"  // none better, at least one worse
	verdictMixed  = "mixed"  // some better, some worse
	verdictSame   = "same"
)

// epsilon absorbs float rounding when two means are compared.
const epsilon = 1e-9

// Score is one side's result. LossPct and RTTMs are means over Samples, the
// prefix rounds whose path had a usable measurement.
type Score struct {
	Name    string  `json:"name"`
	LossPct float64 `json:"loss_pct"`
	RTTMs   float64 `json:"rtt_ms"`
	Flaps   int     `json:"flaps"`
	Moves   int     `json:"moves"`
	Samples int     `json:"samples"`
	Verdict string  `json:"verdict,omitempty"`
}

// Report is the baseline and every variant over the same rounds.
type Report struct {
	Rounds   int       `json:"rounds"`
	From     time.Time `json:"from"`
	To       time.Time `json:"to"`
	Baseline Score     `json:"baseline"`
	Variants []Score   `json:"variants"`
}

func newReport(res replay.Result, paths []*pathScore) Report {
	scores := make([]Score, len(res.Sides))
	for i, side := range res.Sides {
		s, p := side.Summary, paths[i]
		sc := Score{Name: side.Name, Flaps: s.Flaps, Moves: s.Improves + s.Switches + s.Retires, Samples: p.samples}
		if p.samples > 0 {
			sc.LossPct, sc.RTTMs = p.loss/float64(p.samples), p.rtt/float64(p.samples)
		}
		scores[i] = sc
	}
	for i := 1; i < len(scores); i++ {
		scores[i].Verdict = verdict(scores[0], scores[i])
	}
	return Report{Rounds: res.Rounds, From: res.From, To: res.To, Baseline: scores[0], Variants: scores[1:]}
}

// verdict compares v with base on each metric alone, lower being better,
// and weighs none against another: a trade-off is mixed, for a human.
func verdict(base, v Score) string {
	better, worse := false, false
	cmp := func(b, x float64) {
		switch {
		case x < b-epsilon:
			better = true
		case x > b+epsilon:
			worse = true
		}
	}
	cmp(base.LossPct, v.LossPct)
	cmp(base.RTTMs, v.RTTMs)
	cmp(float64(base.Flaps), float64(v.Flaps))
	switch {
	case better && worse:
		return verdictMixed
	case better:
		return verdictBetter
	case worse:
		return verdictWorse
	}
	return verdictSame
}

func (r Report) format(w io.Writer) {
	fmt.Fprintf(w, "replayed %d rounds from %s to %s; nothing was announced and no config was written\n",
		r.Rounds, r.From.UTC().Format(time.RFC3339), r.To.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "%-20s %10s %10s %6s %6s %8s  %s\n", "side", "loss %", "rtt ms", "flaps", "moves", "samples", "vs baseline")
	for _, s := range append([]Score{r.Baseline}, r.Variants...) {
		line := fmt.Sprintf("%-20s %10.3f %10.2f %6d %6d %8d  %s", s.Name, s.LossPct, s.RTTMs, s.Flaps, s.Moves, s.Samples, s.Verdict)
		fmt.Fprintln(w, strings.TrimRight(line, " "))
	}
}
