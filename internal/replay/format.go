package replay

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// Format writes res as plain text.
func Format(w io.Writer, res Result) {
	fmt.Fprintf(w, "replayed %d rounds from %s to %s; nothing was announced\n", res.Rounds, res.From.UTC().Format(time.RFC3339), res.To.UTC().Format(time.RFC3339))
	for _, r := range res.Sides {
		s := r.Summary
		fmt.Fprintf(w, "\n%s\n", r.Name)
		fmt.Fprintf(w, "  moves: %d new, %d switched, %d retired; %d prefixes steered, %d active at the end (peak %d, cap %d)\n",
			s.Improves, s.Switches, s.Retires, s.Prefixes, s.Active, s.PeakActive, s.MaxImprovements)
		weight := "mean per move"
		if s.Weighted {
			weight = "weighted by volume"
			if s.UnknownVolume > 0 {
				weight += fmt.Sprintf(", %d moves without a volume left out", s.UnknownVolume)
			}
		}
		fmt.Fprintf(w, "  expected change (%s, positive is better): loss %+.2f points, RTT %+.1f ms\n", weight, s.LossDeltaPct, s.RTTDeltaMs)
		fmt.Fprintf(w, "  traffic moved: %.1f Mbps; commit relief: %.1f Mbps in %d moves\n", s.MovedMbps, s.CommitReliefMbps, s.CommitMoves)
		fmt.Fprintf(w, "  flaps: %d; quarantines: %d; held back by the cap: %d prefixes in %d rounds\n", s.Flaps, s.Quarantines, s.CappedPrefixes, s.CappedRounds)
	}
	if len(res.Sides) < 2 {
		return
	}
	if len(res.Diff) == 0 {
		fmt.Fprintf(w, "\nno prefix is steered differently by %s and %s\n", res.Sides[0].Name, res.Sides[1].Name)
		return
	}
	fmt.Fprintf(w, "\nprefixes steered differently (%d)\n", len(res.Diff)+res.DiffOmitted)
	for _, d := range res.Diff {
		fmt.Fprintf(w, "  %s  base: %s  new: %s\n", d.Prefix, steps(d.Base), steps(d.New))
	}
	if res.DiffOmitted > 0 {
		fmt.Fprintf(w, "  and %d more\n", res.DiffOmitted)
	}
}

func steps(s []string) string {
	if len(s) == 0 {
		return "(no move)"
	}
	return strings.Join(s, " > ")
}
