package probe

import (
	"errors"
	"net/netip"
	"sort"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// MaxManual caps the prefixes an operator can have queued at once.
const MaxManual = 64

// ErrManualFull is returned by QueueManual when MaxManual prefixes are
// already queued.
var ErrManualFull = errors.New("probe: too many prefixes queued for manual optimization")

// manualEntry is one queued prefix. probed is set once a round has probed
// it, which ends its urgency but not its place in the target set.
type manualEntry struct {
	expires time.Time
	probed  bool
}

// QueueManual adds p to the probe set for ttl and asks for an early round
// (the operator's "probe and optimize", #126). The prefix is probed on the
// next round whatever its interval, then follows its normal cadence until
// the TTL ends and the next completed round drops it. Queuing only
// measures: the decision engine still needs the exact learned prefix, the
// allowlist, the cap, the thresholds, and the hold time before any move.
// The global rate limit applies to its probes. Re-queuing renews the TTL
// and probes the prefix early again.
func (e *Engine) QueueManual(p netip.Prefix, ttl time.Duration) error {
	if e == nil {
		return errors.New("probe: no engine")
	}
	p = p.Masked()
	if !p.IsValid() || ttl <= 0 {
		return errors.New("probe: manual queue needs a prefix and a positive ttl")
	}
	now := e.opt.Now()
	e.mu.Lock()
	e.pruneManualLocked(now)
	if _, ok := e.manual[p]; !ok && len(e.manual) >= MaxManual {
		e.mu.Unlock()
		return ErrManualFull
	}
	if e.manual == nil {
		e.manual = map[netip.Prefix]*manualEntry{}
	}
	e.manual[p] = &manualEntry{expires: now.Add(ttl)}
	e.mu.Unlock()
	e.Wake()
	return nil
}

func (e *Engine) pruneManualLocked(now time.Time) {
	for p, m := range e.manual {
		if !now.Before(m.expires) {
			delete(e.manual, p)
		}
	}
}

// applyManual adds the queued prefixes to a complete target list. A prefix
// that a source also lists keeps that source's host and interval and is
// only marked urgent until it has been probed. Expired entries are dropped
// here, so a prefix that nothing else lists leaves with the TTL.
func (e *Engine) applyManual(out *[]plugin.Target) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pruneManualLocked(e.opt.Now())
	if len(e.manual) == 0 {
		return
	}
	queued := make([]netip.Prefix, 0, len(e.manual))
	for p := range e.manual {
		queued = append(queued, p)
	}
	sort.Slice(queued, func(i, j int) bool {
		return lessTarget(plugin.Target{Prefix: queued[i]}, plugin.Target{Prefix: queued[j]})
	})
	idx := make(map[netip.Prefix]int, len(*out))
	for i, t := range *out {
		idx[t.Prefix] = i
	}
	for _, p := range queued {
		urgent := !e.manual[p].probed
		if i, ok := idx[p]; ok {
			(*out)[i].Urgent = (*out)[i].Urgent || urgent
			continue
		}
		t := normalizeTarget(plugin.Target{Prefix: p})
		t.Urgent = urgent
		*out = append(*out, t)
	}
}

// noteManualProbedLocked ends the urgency of queued prefixes a round probed.
// The caller holds e.mu.
func (e *Engine) noteManualProbedLocked(probed map[netip.Prefix]struct{}) {
	for p := range probed {
		if m, ok := e.manual[p]; ok {
			m.probed = true
		}
	}
}
