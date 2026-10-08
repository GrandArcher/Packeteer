package probe

import (
	"net/netip"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Defaults for the per-host prober memory. The config package uses the
// same numbers. A zero in Options means "use the default".
const (
	// DefaultProberRecheckRounds is how often a host is measured from the
	// first prober again. Probe 1, 11, 21, ... of a host start at the
	// chain head when this is 10. The probes in between start at the
	// prober that last got a reply.
	DefaultProberRecheckRounds = 10
	// MaxProberRecheckRounds is the upper bound accepted by the engine.
	MaxProberRecheckRounds = 10000
	// DefaultProberMemory is how many hosts keep a remembered prober.
	DefaultProberMemory = 100000
	// MaxProberMemory is the upper bound accepted by the engine.
	MaxProberMemory = 1000000
)

// proberSlot is the remembered prober for one destination host.
// probes counts plans for this host, one per round, shared by every
// provider. tick is the LRU stamp. An empty name means this round has
// not seen a reply yet. Those slots are dropped when the round finishes
// so a silent host does not take a memory place.
type proberSlot struct {
	name   string
	probes int
	tick   uint64
}

// beginProberRound drops memory for hosts that are no longer targets and
// forgets a partial plan from a round that did not finish. Named entries
// past the cap are dropped, least recently probed first. targets is the
// full list, including prefixes that are not due this round: those hosts
// are still probed and keep their prober.
func (e *Engine) beginProberRound(targets []plugin.Target) {
	live := e.liveHosts(targets)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.proberPlan = map[netip.Addr]int{}
	e.proberNote = map[netip.Addr]int{}
	if e.proberMem == nil {
		e.proberMem = map[netip.Addr]proberSlot{}
	}
	for h, slot := range e.proberMem {
		if slot.name == "" {
			delete(e.proberMem, h)
			continue
		}
		if _, ok := live[h]; !ok {
			delete(e.proberMem, h)
		}
	}
	e.evictProberMemLocked()
}

// liveHosts is every address the target list can probe, including
// prefixes that are not due yet. A provider whose source is the other
// address family is skipped, matching job construction.
func (e *Engine) liveHosts(targets []plugin.Target) map[netip.Addr]struct{} {
	live := make(map[netip.Addr]struct{})
	for _, t := range targets {
		for _, p := range e.providers {
			if t.Host.IsValid() && p.Source.Is4() != t.Host.Is4() {
				continue
			}
			pin, candidates := targetProbeAddrs(t)
			for _, h := range omitLANHosts(ProbeHosts(t.Prefix, pin, candidates, p.NextHop, p.Source), p.NextHop, e.opt.ExchangeLANs) {
				live[h.Unmap()] = struct{}{}
			}
		}
	}
	return live
}

// proberStart is the chain index to try first for host. The first caller
// in a round plans it; every provider, and a loss or dispersion retry in
// the same round, uses that index. The plan counts as one probe of the
// host, so a retry does not move the chain-head schedule.
func (e *Engine) proberStart(host netip.Addr) int {
	host = host.Unmap()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.proberPlan == nil {
		e.proberPlan = map[netip.Addr]int{}
	}
	if start, ok := e.proberPlan[host]; ok {
		return start
	}
	if e.proberMem == nil {
		e.proberMem = map[netip.Addr]proberSlot{}
	}
	e.memTick++
	slot := e.proberMem[host]
	slot.probes++
	slot.tick = e.memTick
	e.proberMem[host] = slot
	start := 0
	if slot.name != "" && e.opt.ProberRecheckRounds > 1 && slot.probes%e.opt.ProberRecheckRounds != 1 {
		if idx := e.proberIndex(slot.name); idx > 0 {
			start = idx
		}
	}
	e.proberPlan[host] = start
	return start
}

// noteProber records that probers[idx] got a reply from host. When
// several providers answer with different probers in one round, the
// later prober in the chain wins: an earlier one did not get replies on
// every provider, and the next rounds should compare providers with one
// probe type.
func (e *Engine) noteProber(host netip.Addr, idx int) {
	host = host.Unmap()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.proberNote == nil {
		e.proberNote = map[netip.Addr]int{}
	}
	if prev, ok := e.proberNote[host]; !ok || idx > prev {
		e.proberNote[host] = idx
	}
}

// finishProberRound stores the prober that got replies and drops hosts
// that still have none. The remembered set is then cut to the cap.
// Call it only after every probe in the round has returned.
func (e *Engine) finishProberRound() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for host, idx := range e.proberNote {
		slot, ok := e.proberMem[host]
		if !ok || idx < 0 || idx >= len(e.probers) {
			continue
		}
		name := e.probers[idx].Name
		if slot.name != name {
			e.log.Debug("probe type learned", "host", host, "prober", name, "was", slot.name)
			slot.name = name
			e.proberMem[host] = slot
		}
	}
	for host, slot := range e.proberMem {
		if slot.name == "" {
			delete(e.proberMem, host)
		}
	}
	e.evictProberMemLocked()
	e.proberPlan = nil
	e.proberNote = nil
}

// evictProberMemLocked drops the least recently probed named hosts until
// the set fits the cap. The caller holds e.mu. Hosts with no name do not
// count: they are removed at the end of the round.
func (e *Engine) evictProberMemLocked() {
	for {
		named := 0
		var old netip.Addr
		var oldTick uint64
		found := false
		for h, slot := range e.proberMem {
			if slot.name == "" {
				continue
			}
			named++
			if !found || slot.tick < oldTick || (slot.tick == oldTick && h.Compare(old) < 0) {
				found = true
				old = h
				oldTick = slot.tick
			}
		}
		if named <= e.opt.ProberMemory || !found {
			return
		}
		delete(e.proberMem, old)
	}
}

func (e *Engine) proberIndex(name string) int {
	for i, p := range e.probers {
		if p.Name == name {
			return i
		}
	}
	return -1
}
