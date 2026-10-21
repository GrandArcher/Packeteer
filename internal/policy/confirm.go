package policy

import (
	"net/netip"
	"time"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
)

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
// rounds to be created. A stale round, a partly measured round, and a
// repeat of measurements already counted leave the streak untouched and
// never make a move ready, whatever confirm_rounds is. A fresh round for
// a different provider starts that provider at 1. A short streak whose
// paths were compared this call asks for another probe; a stale round
// does not.
func notePerformance(st *State, in Input, cfg Config, p netip.Prefix, provider string, now time.Time) (ready bool, streak int) {
	// A timed-out probe round stores the providers that finished and
	// leaves the others with their previous, still fresh result (#381). A
	// provider whose probes stopped finishing would win on its last good
	// sample, so no move is made until one round measures them all.
	partial := partialRound(in, cfg, p, now)
	rounds := cfg.confirmRounds()
	if rounds <= 1 {
		if partial {
			return false, 0
		}
		return provider != "", 1
	}
	if st.confirm == nil {
		st.confirm = map[netip.Prefix]confirm{}
	}
	cur := st.confirm[p]
	at, count, stale := prefixRound(in, cfg, cur, p, now)
	// Every local provider has to be measured again since the last counted
	// round, or the streak would count one provider's sample twice.
	local, remeasured := localRound(in, cfg, cur, p, now)
	if partial || (count && provider != "" && cur.Provider == provider && !remeasured) {
		count = false
	}
	if stale || !count {
		if !stale && !partial && provider != "" && cur.Provider == provider && cur.Streak >= rounds {
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
		cur = confirm{Provider: provider, Streak: 1, Round: at, Local: local}
	} else {
		cur.Streak++
		cur.Round = at
		cur.Local = local
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
	for _, i := range in.byPrefix[p] {
		r := in.Results[i]
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

// localRound returns the newest time among this instance's own fresh
// results for p, and whether every one of them is newer than prev.Local.
// Results from federation peers are left out: a peer probes on its own
// schedule, so its path can be fresh and still older than the last local
// round.
func localRound(in Input, cfg Config, prev confirm, p netip.Prefix, now time.Time) (newest time.Time, remeasured bool) {
	remeasured = true
	for _, i := range in.byPrefix[p] {
		r := in.Results[i]
		if in.Remote[r.Provider] || (cfg.MaxResultAge > 0 && now.Sub(r.Time) > cfg.MaxResultAge) {
			continue
		}
		if r.Time.After(newest) {
			newest = r.Time
		}
		if !r.Time.After(prev.Local) {
			remeasured = false
		}
	}
	return newest, remeasured
}

// partialRound reports whether this instance's fresh results for p come
// from different probe rounds, so the newest round measured only some
// providers. Federation results are left out, as in localRound.
func partialRound(in Input, cfg Config, p netip.Prefix, now time.Time) bool {
	var oldest, newest time.Time
	seen := false
	for _, i := range in.byPrefix[p] {
		r := in.Results[i]
		if in.Remote[r.Provider] || (cfg.MaxResultAge > 0 && now.Sub(r.Time) > cfg.MaxResultAge) {
			continue
		}
		if !seen || r.Round.Before(oldest) {
			oldest = r.Round
		}
		if !seen || r.Round.After(newest) {
			newest = r.Round
		}
		seen = true
	}
	return oldest.Before(newest)
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
	netpfx.Sort(ps)
	out.Urgent = append(out.Urgent, ps...)
}
