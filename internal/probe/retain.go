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
// source would submit. Urgent is one-shot and is not kept, and neither
// are sub-ranges.
func rememberedTarget(t plugin.Target) plugin.Target {
	r := plugin.Target{Prefix: t.Prefix, Interval: t.Interval}
	switch {
	case t.Candidate && t.Host.IsValid():
		r.Host = t.Host
		r.Hosts = append([]netip.Addr(nil), t.Hosts...)
		r.Candidate = true
	case t.Pinned && t.Host.IsValid():
		r.Host = t.Host
	}
	// Sub-ranges and their byte weights are not kept: once no source
	// lists the prefix they describe traffic that may be gone, so a
	// retained prefix is measured on its hosts (#121).
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
	if candidate {
		t.Hosts = cleanExtraHosts(t.Prefix, t.Host, t.Hosts)
	} else {
		t.Hosts = nil
	}
	if explicit {
		t.Subranges = nil
	} else {
		t.Subranges = cleanSubranges(t.Prefix, t.Subranges)
	}
	return t
}

// cleanExtraHosts keeps at most two further candidates inside the prefix.
// Host is already the first, so three destinations is the cap.
func cleanExtraHosts(prefix netip.Prefix, primary netip.Addr, extra []netip.Addr) []netip.Addr {
	if len(extra) == 0 {
		return nil
	}
	seen := map[netip.Addr]bool{}
	if primary.IsValid() {
		seen[primary] = true
	}
	var out []netip.Addr
	for _, h := range extra {
		if !h.IsValid() || seen[h] {
			continue
		}
		if prefix.IsValid() && !prefix.Contains(h) {
			continue
		}
		seen[h] = true
		out = append(out, h)
		if len(out) == maxInPrefix-1 {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// targetProbeAddrs is the pin, or the flow candidates, for one target.
// A pin is the only address. Candidates are Host then Hosts.
func targetProbeAddrs(t plugin.Target) (pin netip.Addr, candidates []netip.Addr) {
	if t.Pinned {
		return t.Host, nil
	}
	if !t.Candidate || !t.Host.IsValid() {
		return netip.Addr{}, nil
	}
	out := make([]netip.Addr, 0, 1+len(t.Hosts))
	out = append(out, t.Host)
	out = append(out, t.Hosts...)
	return netip.Addr{}, out
}

func lessTarget(a, b plugin.Target) bool {
	if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
		return c < 0
	}
	return a.Prefix.Bits() < b.Prefix.Bits()
}
