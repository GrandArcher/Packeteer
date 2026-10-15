package exchange

import (
	"net/netip"
	"sync"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// PeerSpec is one configured exchange peer the BMP session monitor watches.
// MaxPrefix is the router's maximum-prefix limit on the session (0: no
// warning) and WarnPct the share of it at which the warning fires.
type PeerSpec struct {
	Exchange  string
	Name      string
	NextHop   netip.Addr
	MaxPrefix int
	WarnPct   int
}

// PeerChangeKind says what a PeerChange reports.
type PeerChangeKind int

const (
	// PeerChangeUp: the router reports the peer's BGP session up.
	PeerChangeUp PeerChangeKind = iota
	// PeerChangeDown: the router reports it down; Reason says why.
	PeerChangeDown
	// PeerChangePrefixHigh: the Adj-RIB-In count reached WarnPct of
	// MaxPrefix.
	PeerChangePrefixHigh
	// PeerChangePrefixOK: it fell back below that share.
	PeerChangePrefixOK
)

// PeerChange is one session transition for one exchange peer.
type PeerChange struct {
	Kind      PeerChangeKind
	Exchange  string
	Peer      string
	Reason    string
	Prefixes  int
	MaxPrefix int
}

type sessionPeer struct {
	spec     PeerSpec
	router   netip.Addr
	seen     bool
	up       bool
	reason   string
	prefixes int
	high     bool
}

// PeerMonitor tracks each configured exchange peer's BMP session state and
// Adj-RIB-In route count (#147). It only reads RIB events from the BMP
// station: it never announces, withdraws, or changes a decision. A nil
// *PeerMonitor is usable and reports nothing.
type PeerMonitor struct {
	mu     sync.Mutex
	byAddr map[netip.Addr][]*sessionPeer
	byName map[string]*sessionPeer
}

// NewPeerMonitor watches the given peers. A peer with no name or an
// invalid next hop is skipped.
func NewPeerMonitor(specs []PeerSpec) *PeerMonitor {
	m := &PeerMonitor{byAddr: map[netip.Addr][]*sessionPeer{}, byName: map[string]*sessionPeer{}}
	for _, sp := range specs {
		if sp.Name == "" || !sp.NextHop.IsValid() {
			continue
		}
		st := &sessionPeer{spec: sp}
		m.byName[sp.Name] = st
		nh := sp.NextHop.Unmap()
		m.byAddr[nh] = append(m.byAddr[nh], st)
	}
	return m
}

// Observe records one BMP RIB event and returns the peer transitions it
// caused. Events for peers that are not configured exchange peers, and the
// Loc-RIB, are ignored.
func (m *PeerMonitor) Observe(ev plugin.RIBEvent) []PeerChange {
	if m == nil {
		return nil
	}
	// Path updates are the common case and carry no session state.
	switch ev.Kind {
	case plugin.RIBRouterDown, plugin.RIBPeerUp, plugin.RIBPeerDown, plugin.RIBPrefixCount:
	default:
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	switch ev.Kind {
	case plugin.RIBRouterDown:
		return m.routerDown(ev.Router)
	case plugin.RIBPeerUp:
		return m.peerUp(ev)
	case plugin.RIBPeerDown:
		return m.peerDown(ev)
	case plugin.RIBPrefixCount:
		return m.prefixCount(ev)
	}
	return nil
}

// Prefixes is the last Adj-RIB-In count per peer name. A peer whose router
// has not sent a statistics report yet is absent.
func (m *PeerMonitor) Prefixes() map[string]int {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]int, len(m.byName))
	for name, st := range m.byName {
		if st.seen {
			out[name] = st.prefixes
		}
	}
	return out
}

func (m *PeerMonitor) match(ev plugin.RIBEvent) []*sessionPeer {
	if ev.Peer.LocRIB {
		return nil
	}
	return m.byAddr[ev.Peer.Address.Unmap()]
}

func (m *PeerMonitor) change(st *sessionPeer, kind PeerChangeKind) PeerChange {
	return PeerChange{Kind: kind, Exchange: st.spec.Exchange, Peer: st.spec.Name,
		Reason: st.reason, Prefixes: st.prefixes, MaxPrefix: st.spec.MaxPrefix}
}

// clearHigh drops an open max-prefix warning, reporting it when one was up.
func (m *PeerMonitor) clearHigh(st *sessionPeer) (PeerChange, bool) {
	if !st.high {
		return PeerChange{}, false
	}
	st.high = false
	return m.change(st, PeerChangePrefixOK), true
}

func (m *PeerMonitor) peerUp(ev plugin.RIBEvent) []PeerChange {
	var out []PeerChange
	for _, st := range m.match(ev) {
		st.router, st.seen = ev.Router.Unmap(), true
		if st.up {
			continue
		}
		st.up, st.reason = true, ""
		out = append(out, m.change(st, PeerChangeUp))
	}
	return out
}

func (m *PeerMonitor) peerDown(ev plugin.RIBEvent) []PeerChange {
	var out []PeerChange
	for _, st := range m.match(ev) {
		if st.seen && !st.up {
			continue
		}
		st.router, st.seen, st.up = ev.Router.Unmap(), true, false
		st.reason, st.prefixes = ev.Reason, 0
		if ch, ok := m.clearHigh(st); ok {
			out = append(out, ch)
		}
		out = append(out, m.change(st, PeerChangeDown))
	}
	return out
}

func (m *PeerMonitor) prefixCount(ev plugin.RIBEvent) []PeerChange {
	var out []PeerChange
	for _, st := range m.match(ev) {
		st.router, st.seen, st.up, st.reason, st.prefixes = ev.Router.Unmap(), true, true, "", ev.Prefixes
		if st.spec.MaxPrefix <= 0 || st.spec.WarnPct <= 0 {
			continue
		}
		high := ev.Prefixes*100 >= st.spec.WarnPct*st.spec.MaxPrefix
		if high == st.high {
			continue
		}
		st.high = high
		if high {
			out = append(out, m.change(st, PeerChangePrefixHigh))
		} else {
			out = append(out, m.change(st, PeerChangePrefixOK))
		}
	}
	return out
}

// routerDown clears the session state of every peer last seen on router.
// The BGP sessions may still be up, so this reports no peer down; it only
// drops the counts (and any max-prefix warning) that can no longer be
// trusted.
func (m *PeerMonitor) routerDown(router netip.Addr) []PeerChange {
	router = router.Unmap()
	var out []PeerChange
	for _, st := range m.byName {
		if st.router != router {
			continue
		}
		st.up, st.prefixes = false, 0
		if ch, ok := m.clearHigh(st); ok {
			out = append(out, ch)
		}
	}
	return out
}
