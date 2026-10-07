package probe

import (
	"net/netip"
	"sort"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// SetRetained is the internal target source fed from the decision state
// (#116). While a prefix has an active improvement it stays in the probe
// set, with the host and interval from the last time a configured source
// listed it, even after every configured source drops it. An empty list
// clears the set. The next completed round then drops a prefix no source
// still lists. Safe for concurrent use with probing.
func (e *Engine) SetRetained(prefixes []netip.Prefix) {
	if e == nil {
		return
	}
	next := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, p := range prefixes {
		p = p.Masked()
		if !p.IsValid() {
			continue
		}
		next[p] = struct{}{}
	}
	e.mu.Lock()
	e.retained = next
	e.mu.Unlock()
}

// keepImproved remembers the host and interval of every prefix a configured
// source just listed, and appends any retained prefix that none of them
// listed. It runs only after a complete gather: a partial list must not
// erase a host. The retained entries are not cached, so a retirement is
// visible on the next round, including a short VIP wake.
func (e *Engine) keepImproved(out *[]plugin.Target) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.memory == nil {
		e.memory = map[netip.Prefix]plugin.Target{}
	}
	live := make(map[netip.Prefix]bool, len(*out))
	for _, t := range *out {
		live[t.Prefix] = true
		// Remember the shape a source would submit. A default host the
		// engine filled is not a pin, so it is stored with no host.
		e.memory[t.Prefix] = rememberedTarget(t)
	}
	for p := range e.memory {
		if live[p] || e.retainedHas(p) {
			continue
		}
		delete(e.memory, p)
	}
	if len(e.retained) == 0 {
		return
	}
	extra := make([]plugin.Target, 0, len(e.retained))
	for p := range e.retained {
		if live[p] {
			continue
		}
		mem, ok := e.memory[p]
		if !ok {
			mem = plugin.Target{Prefix: p}
		}
		extra = append(extra, normalizeTarget(mem))
	}
	sort.Slice(extra, func(i, j int) bool { return lessTarget(extra[i], extra[j]) })
	*out = append(*out, extra...)
}

func (e *Engine) retainedHas(p netip.Prefix) bool {
	_, ok := e.retained[p]
	return ok
}

// rememberedTarget is the last host choice and interval, in the shape a
// source would submit. Urgent is one-shot and is not kept.
func rememberedTarget(t plugin.Target) plugin.Target {
	r := plugin.Target{Prefix: t.Prefix, Interval: t.Interval}
	switch {
	case t.Candidate && t.Host.IsValid():
		r.Host = t.Host
		r.Candidate = true
	case t.Pinned && t.Host.IsValid():
		r.Host = t.Host
	}
	return r
}

// normalizeTarget applies the same host rules as a configured source: a
// candidate stays a candidate, any other named host is a pin, and an empty
// host becomes the default address without becoming a pin.
func normalizeTarget(t plugin.Target) plugin.Target {
	t.Prefix = t.Prefix.Masked()
	candidate := t.Candidate && t.Host.IsValid()
	explicit := t.Host.IsValid() && !candidate
	if !t.Host.IsValid() {
		t.Host = DefaultHost(t.Prefix)
	}
	t.Pinned = explicit
	t.Candidate = candidate
	return t
}

func lessTarget(a, b plugin.Target) bool {
	if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
		return c < 0
	}
	return a.Prefix.Bits() < b.Prefix.Bits()
}
