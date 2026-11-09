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

// PeerChange is one session transition for one exchange peer on one
// monitored router.
type PeerChange struct {
	Kind      PeerChangeKind
	Exchange  string
	Peer      string
	Router    netip.Addr
	Reason    string
	Prefixes  int
	MaxPrefix int
}

type sessionState uint8

const (
	// stateUnknown: no Peer Up or Peer Down seen since the router session
	// started. A Statistics Report alone leaves it here.
	stateUnknown sessionState = iota
	stateUp
	stateDown
)

// sessionKey is one peer as seen by one router: two edge routers can both
// peer with the same address.
type sessionKey struct {
	router netip.Addr
	name   string
}

type sessionPeer struct {
	spec     PeerSpec
	router   netip.Addr
	state    sessionState
	reason   string
	prefixes int
	counted  bool
	high     bool
}

// PeerMonitor tracks each configured exchange peer's BMP session state and
// Adj-RIB-In route count per monitoring router (#147). It only reads RIB
// events from the BMP station: it never announces, withdraws, or changes a
// decision. A nil *PeerMonitor is usable and reports nothing.
type PeerMonitor struct {
	mu       sync.Mutex
	byAddr   map[netip.Addr][]PeerSpec
	sessions map[sessionKey]*sessionPeer
}

// NewPeerMonitor watches the given peers. A peer with no name or an
// invalid next hop is skipped.
func NewPeerMonitor(specs []PeerSpec) *PeerMonitor {
	m := &PeerMonitor{byAddr: map[netip.Addr][]PeerSpec{}, sessions: map[sessionKey]*sessionPeer{}}
	for _, sp := range specs {
		if sp.Name == "" || !sp.NextHop.IsValid() {
			continue
		}
		nh := sp.NextHop.Unmap()
		m.byAddr[nh] = append(m.byAddr[nh], sp)
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

// Prefixes is the last Adj-RIB-In count per peer name, summed over the
// routers that report it. A peer no router has sent a statistics report for
// is absent.
func (m *PeerMonitor) Prefixes() map[string]int {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]int{}
	for k, st := range m.sessions {
		if st.counted {
			out[k.name] += st.prefixes
		}
	}
	return out
}

// match returns the monitored sessions the event is about, creating the
// session for a router the first time it reports the peer.
func (m *PeerMonitor) match(ev plugin.RIBEvent) []*sessionPeer {
	if ev.Peer.LocRIB {
		return nil
	}
	router := ev.Router.Unmap()
	var out []*sessionPeer
	for _, sp := range m.byAddr[ev.Peer.Address.Unmap()] {
		k := sessionKey{router: router, name: sp.Name}
		st := m.sessions[k]
		if st == nil {
			st = &sessionPeer{spec: sp, router: router}
			m.sessions[k] = st
		}
		out = append(out, st)
	}
	return out
}

func (m *PeerMonitor) change(st *sessionPeer, kind PeerChangeKind) PeerChange {
	return PeerChange{Kind: kind, Exchange: st.spec.Exchange, Peer: st.spec.Name, Router: st.router,
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
		if st.state == stateUp {
			continue
		}
		st.state, st.reason = stateUp, ""
		out = append(out, m.change(st, PeerChangeUp))
	}
	return out
}

func (m *PeerMonitor) peerDown(ev plugin.RIBEvent) []PeerChange {
	var out []PeerChange
	for _, st := range m.match(ev) {
		if st.state == stateDown {
			continue
		}
		st.state = stateDown
		st.reason, st.prefixes, st.counted = ev.Reason, 0, true
		if ch, ok := m.clearHigh(st); ok {
			out = append(out, ch)
		}
		out = append(out, m.change(st, PeerChangeDown))
	}
	return out
}

// prefixCount records a Statistics Report count. It never changes the
// up/down state: a report that follows a peer or router down must not hide
// the next Peer Up. A report for a session known to be down is dropped, as
// its count is zero until the peer comes back.
func (m *PeerMonitor) prefixCount(ev plugin.RIBEvent) []PeerChange {
	var out []PeerChange
	for _, st := range m.match(ev) {
		if st.state == stateDown {
			continue
		}
		st.prefixes, st.counted = ev.Prefixes, true
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

// routerDown clears the session state of the peers seen on router only;
// other routers' sessions with the same peer are untouched. The BGP
// sessions may still be up, so this reports no peer down; it only drops the
// counts (and any max-prefix warning) that can no longer be trusted. A
// session already known down stays down.
func (m *PeerMonitor) routerDown(router netip.Addr) []PeerChange {
	router = router.Unmap()
	var out []PeerChange
	for _, st := range m.sessions {
		if st.router != router {
			continue
		}
		if st.state == stateUp {
			st.state = stateUnknown
		}
		st.prefixes = 0
		if ch, ok := m.clearHigh(st); ok {
			out = append(out, ch)
		}
	}
	return out
}
