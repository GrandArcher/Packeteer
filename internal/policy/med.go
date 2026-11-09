package policy

import "fmt"

// NeighborMED is the MULTI_EXIT_DISC a provider's learned path for a
// prefix carries, and the neighbor AS that sent it (the first AS of the
// path). A neighbor's MEDs are comparable only with its own, so the tie
// break reads two of them only when the ASNs match (RFC 4271 9.1.2.2).
type NeighborMED struct {
	ASN uint32 `json:"asn"`
	MED uint32 `json:"med"`
}

// MEDOverride is a performance move onto a provider whose neighbor AS
// prefers another of its exits by MED, made because the measurements beat
// that exit by more than the MED margin (#303).
type MEDOverride struct {
	ASN uint32 `json:"asn"`
	// Preferred is the exit the neighbor's MED prefers and Chosen the
	// exit the move takes.
	Preferred    string  `json:"preferred"`
	PreferredMED uint32  `json:"preferred_med"`
	Chosen       string  `json:"chosen"`
	ChosenMED    uint32  `json:"chosen_med"`
	ScoreGap     float64 `json:"score_gap"`
}

// medOf reports c's MED when its learned path carried one.
func medOf(c Candidate) (NeighborMED, bool) {
	if c.MED == nil || c.MEDASN == 0 {
		return NeighborMED{}, false
	}
	return NeighborMED{ASN: c.MEDASN, MED: *c.MED}, true
}

// medPreferred returns the exit c's neighbor AS prefers over c by MED
// when the scores are within the MED margin: a usable candidate from the
// same AS with a lower MED, the lowest MED first, then the lower score,
// then the name. Native may be chosen even when excluded, since traffic
// already leaves there; skip is never chosen.
func medPreferred(cands []Candidate, c Candidate, cfg Config, native, skip string) (Candidate, bool) {
	if !cfg.MEDTieBreak {
		return Candidate{}, false
	}
	m, ok := medOf(c)
	if !ok {
		return Candidate{}, false
	}
	var best Candidate
	var bestMED uint32
	found := false
	for _, o := range cands {
		if !o.Usable || o.Provider == c.Provider || o.Provider == skip || (cfg.Excluded[o.Provider] && o.Provider != native) {
			continue
		}
		om, ok := medOf(o)
		if !ok || om.ASN != m.ASN || om.MED >= m.MED || o.Score-c.Score > cfg.MEDMargin {
			continue
		}
		if !found || om.MED < bestMED || (om.MED == bestMED && (o.Score < best.Score || (o.Score == best.Score && o.Provider < best.Provider))) {
			best, bestMED, found = o, om.MED, true
		}
	}
	return best, found
}

// medOverride reports the neighbor preference a move onto c overrides:
// the lowest-MED usable, non-excluded exit of c's neighbor AS (native
// allowed), when its MED is below c's. Nil when the tie break is off or the
// move follows the MED.
func medOverride(cands []Candidate, c Candidate, cfg Config, native string) *MEDOverride {
	if !cfg.MEDTieBreak {
		return nil
	}
	m, ok := medOf(c)
	if !ok {
		return nil
	}
	var o *MEDOverride
	for _, x := range cands {
		xm, ok := medOf(x)
		if !x.Usable || x.Provider == c.Provider || (cfg.Excluded[x.Provider] && x.Provider != native) || !ok || xm.ASN != m.ASN || xm.MED >= m.MED {
			continue
		}
		if o == nil || xm.MED < o.PreferredMED || (xm.MED == o.PreferredMED && x.Provider < o.Preferred) {
			o = &MEDOverride{ASN: m.ASN, Preferred: x.Provider, PreferredMED: xm.MED, Chosen: c.Provider, ChosenMED: m.MED, ScoreGap: x.Score - c.Score}
		}
	}
	return o
}

// medRefused starts the reason of every decision the neighbor's MED kept
// on its native path; the explanation reads it.
const medRefused = "med: "

// medKeepReason is the decision reason when the neighbor's MED prefers
// pref over alt, the best-scoring exit, within the margin.
func medKeepReason(pref, alt Candidate, cfg Config) string {
	p, _ := medOf(pref)
	a, _ := medOf(alt)
	return fmt.Sprintf("%sAS%d prefers %s (MED %d) over %s (MED %d) and the scores are within thresholds.med_margin %s; native path kept",
		medRefused, p.ASN, pref.Provider, p.MED, alt.Provider, a.MED, fnum(cfg.MEDMargin))
}

// String is the override for logs and decision reasons.
func (o MEDOverride) String() string {
	return fmt.Sprintf("overrides AS%d MED: %s (MED %d) over %s (MED %d), score %.1f better", o.ASN, o.Chosen, o.ChosenMED, o.Preferred, o.PreferredMED, o.ScoreGap)
}
