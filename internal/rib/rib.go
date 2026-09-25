// Package rib maintains Packeteer's view of routes learned from edge routers.
//
// An embedded GoBGP speaker holds iBGP sessions with the configured edge
// routers. The view records each neighbor's adj-RIB-in — paths that neighbor
// advertised — and not Packeteer's own best path. A route Packeteer injects
// can become the local best path; that must not remove the neighbor's prefix.
// The view maps every prefix a neighbor still advertises to its next-hop and,
// through providers[].next_hop, to the provider. The speaker is learn-only:
// its global export policy rejects everything, and graceful restart is never
// enabled. It proposes a 90s hold time so a silent session still drops.
package rib

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	gobgplog "github.com/osrg/gobgp/v3/pkg/log"
	"github.com/osrg/gobgp/v3/pkg/server"
	"google.golang.org/protobuf/types/known/anypb"
)

// Proposed BGP timers. The peer's OPEN can only shorten the hold time.
const (
	bgpHoldTime  = 90
	bgpKeepalive = 30
)

// Neighbor is one iBGP session to an edge router.
type Neighbor struct {
	Address      netip.Addr
	Port         uint16     // remote port, default 179
	LocalAddress netip.Addr // optional source address for the session
	Passive      bool       // wait for the router to connect
	Description  string
}

// Options configure the view.
type Options struct {
	ASN        uint32
	RouterID   netip.Addr
	ListenPort int32 // -1: do not listen (active sessions only)
	// ListenAddresses restricts the listener (default all addresses).
	ListenAddresses []string
	Neighbors       []Neighbor
	// Providers maps a next-hop address to a provider name.
	Providers map[netip.Addr]string
	Logger    *slog.Logger
}

// Route is a path a configured neighbor is advertising for a prefix.
type Route struct {
	Prefix   netip.Prefix `json:"prefix"`
	NextHop  netip.Addr   `json:"next_hop"`
	Provider string       `json:"provider,omitempty"` // "" if the next-hop matches no provider
	ASPath   []uint32     `json:"as_path,omitempty"`
	Neighbor netip.Addr   `json:"neighbor"`
	Age      time.Time    `json:"since"`

	localPref uint32 // selection only; 100 when the attribute is absent
}

// PeerState is the state of one iBGP session.
type PeerState struct {
	Address     netip.Addr `json:"address"`
	Description string     `json:"description,omitempty"`
	State       string     `json:"state"`
	Established bool       `json:"established"`
	Since       time.Time  `json:"since"`
}

// View is the learned RIB.
type View struct {
	opt    Options
	log    *slog.Logger
	srv    *server.BgpServer
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu        sync.RWMutex
	routes    map[netip.Prefix]Route                // selected learned path per prefix
	adj       map[netip.Prefix]map[netip.Addr]Route // prefix -> neighbor -> advertised path
	peers     map[netip.Addr]PeerState
	neighbors map[netip.Addr]bool
	onChange  []func()
	gen       uint64 // increments on each notify; 0 before the first change
}

// New validates options and creates a stopped view.
func New(opt Options) (*View, error) {
	if opt.ASN == 0 || !opt.RouterID.Is4() {
		return nil, errors.New("rib: asn and IPv4 router_id are required")
	}
	if len(opt.Neighbors) == 0 {
		return nil, errors.New("rib: at least one neighbor is required")
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	v := &View{opt: opt, log: opt.Logger, routes: map[netip.Prefix]Route{},
		adj:   map[netip.Prefix]map[netip.Addr]Route{},
		peers: map[netip.Addr]PeerState{}, neighbors: map[netip.Addr]bool{}}
	for _, n := range opt.Neighbors {
		if !n.Address.IsValid() {
			return nil, errors.New("rib: neighbor address is required")
		}
		v.neighbors[n.Address.Unmap()] = true
		v.peers[n.Address.Unmap()] = PeerState{Address: n.Address, Description: n.Description, State: "idle"}
	}
	return v, nil
}

// OnChange registers a callback invoked (without locks held) after routes
// or session state change.
func (v *View) OnChange(fn func()) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.onChange = append(v.onChange, fn)
}

// Server exposes the embedded speaker (used by the announcer, #8).
func (v *View) Server() *server.BgpServer { return v.srv }

// Start launches the speaker and sessions. It returns once the speaker is
// configured; sessions come up asynchronously.
func (v *View) Start(ctx context.Context) error {
	v.srv = server.NewBgpServer(server.LoggerOption(&slogAdapter{l: v.log.With("component", "gobgp"), level: gobgplog.InfoLevel}))
	go v.srv.Serve()

	listen := v.opt.ListenPort
	if listen == 0 {
		listen = -1
	}
	if err := v.srv.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn: v.opt.ASN, RouterId: v.opt.RouterID.String(), ListenPort: listen, ListenAddresses: v.opt.ListenAddresses,
	}}); err != nil {
		v.srv.Stop()
		return fmt.Errorf("rib: start bgp: %w", err)
	}
	// Learn-only: never export anything to the edge.
	if err := v.srv.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{Assignment: &api.PolicyAssignment{
		Name: "global", Direction: api.PolicyDirection_EXPORT, DefaultAction: api.RouteAction_REJECT,
	}}); err != nil {
		v.stopServer()
		return fmt.Errorf("rib: set export policy: %w", err)
	}

	wctx, cancel := context.WithCancel(context.Background())
	v.cancel = cancel
	// Adj-RIB-In, before import policy: a path a later import policy rejected
	// would still show up here. This is not the local best path. A Packeteer
	// route can win best-path selection on this speaker; that event must not
	// look like a withdraw of a prefix the neighbor is still sending. The
	// router may separately stop sending the prefix once that route is its
	// best; policy tells that apart from a real withdraw.
	err := v.srv.WatchEvent(wctx, &api.WatchEventRequest{
		Peer: &api.WatchEventRequest_Peer{},
		Table: &api.WatchEventRequest_Table{Filters: []*api.WatchEventRequest_Table_Filter{
			{Type: api.WatchEventRequest_Table_Filter_ADJIN, Init: true},
		}},
	}, v.handleEvent)
	if err != nil {
		cancel()
		v.stopServer()
		return fmt.Errorf("rib: watch: %w", err)
	}

	for _, n := range v.opt.Neighbors {
		port := uint32(n.Port)
		if port == 0 {
			port = 179
		}
		p := &api.Peer{
			Conf:      &api.PeerConf{NeighborAddress: n.Address.String(), PeerAsn: v.opt.ASN, Description: n.Description},
			Transport: &api.Transport{RemotePort: port, PassiveMode: n.Passive},
			AfiSafis: []*api.AfiSafi{
				{Config: &api.AfiSafiConfig{Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}, Enabled: true}},
				{Config: &api.AfiSafiConfig{Family: &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST}, Enabled: true}},
			},
			// A hold time of zero negotiates the hold timer off (RFC 4271), so a
			// session that stops sending without closing TCP would keep routes.
			// 90/30 is the usual BGP default. The router's shorter hold time
			// wins; the lab sets 9s and the crash test bounds on that.
			Timers: &api.Timers{Config: &api.TimersConfig{
				ConnectRetry: 5, HoldTime: bgpHoldTime, KeepaliveInterval: bgpKeepalive,
			}},
			// GracefulRestart deliberately left unset: no stale routes.
		}
		if n.LocalAddress.IsValid() {
			p.Transport.LocalAddress = n.LocalAddress.String()
		}
		if err := v.srv.AddPeer(ctx, &api.AddPeerRequest{Peer: p}); err != nil {
			v.Stop(context.Background())
			return fmt.Errorf("rib: add neighbor %s: %w", n.Address, err)
		}
	}
	return nil
}

func (v *View) stopServer() {
	if v.srv == nil {
		return
	}
	_ = v.srv.StopBgp(context.Background(), &api.StopBgpRequest{})
	v.srv.Stop()
}

// Stop tears down the sessions and speaker and clears the view.
func (v *View) Stop(context.Context) error {
	if v.cancel != nil {
		v.cancel()
	}
	v.stopServer()
	v.mu.Lock()
	v.routes = map[netip.Prefix]Route{}
	v.adj = map[netip.Prefix]map[netip.Addr]Route{}
	for a, p := range v.peers {
		p.State, p.Established = "idle", false
		v.peers[a] = p
	}
	v.mu.Unlock()
	v.notify()
	return nil
}

func (v *View) notify() {
	v.mu.Lock()
	v.gen++
	fns := append([]func(){}, v.onChange...)
	v.mu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

// Generation changes whenever routes or session state change. Consumers
// cache work against it and skip a rebuild while it stays the same.
// Callbacks registered with OnChange run after the increment.
func (v *View) Generation() uint64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.gen
}

func (v *View) handleEvent(r *api.WatchEventResponse) {
	changed := false
	if pe := r.GetPeer(); pe != nil && pe.Peer != nil && pe.Peer.State != nil {
		addr, err := netip.ParseAddr(pe.Peer.State.NeighborAddress)
		if err == nil && v.neighbors[addr.Unmap()] {
			st := pe.Peer.State.SessionState
			v.mu.Lock()
			ps := v.peers[addr.Unmap()]
			est := st == api.PeerState_ESTABLISHED
			if ps.State != st.String() {
				ps.State, ps.Established, ps.Since = st.String(), est, time.Now()
				v.peers[addr.Unmap()] = ps
				changed = true
				if !est {
					// Session lost: drop that neighbor's adj-RIB-in now.
					// Another session staying up does not keep these paths.
					if v.forgetNeighborLocked(addr.Unmap()) {
						changed = true
					}
				}
			}
			v.mu.Unlock()
			if changed {
				v.log.Info("bgp session", "neighbor", addr, "state", st.String())
			}
		}
	}
	if t := r.GetTable(); t != nil {
		v.mu.Lock()
		for _, p := range t.Paths {
			if v.applyPath(p) {
				changed = true
			}
		}
		v.mu.Unlock()
	}
	if changed {
		v.notify()
	}
}

// applyPath updates the adj-RIB-in from one neighbor path event. Paths that
// are not from a configured neighbor (including Packeteer's own) are ignored
// and never remove a prefix. Caller holds mu.
func (v *View) applyPath(p *api.Path) bool {
	prefix, ok := decodePrefix(p.Nlri)
	if !ok {
		return false
	}
	neighbor, err := netip.ParseAddr(p.NeighborIp)
	if err != nil || !v.neighbors[neighbor.Unmap()] {
		return false
	}
	neighbor = neighbor.Unmap()
	if p.IsWithdraw {
		nbrs := v.adj[prefix]
		if _, exists := nbrs[neighbor]; !exists {
			return false
		}
		delete(nbrs, neighbor)
		if len(nbrs) == 0 {
			delete(v.adj, prefix)
		}
		return v.republishLocked(prefix)
	}
	nh, asPath, lp := decodeAttrs(p.Pattrs)
	if v.adj[prefix] == nil {
		v.adj[prefix] = map[netip.Addr]Route{}
	}
	v.adj[prefix][neighbor] = Route{
		Prefix: prefix, NextHop: nh, Provider: v.opt.Providers[nh.Unmap()], ASPath: asPath,
		Neighbor: neighbor, Age: time.Now(), localPref: lp,
	}
	return v.republishLocked(prefix)
}

// forgetNeighborLocked drops every path learned from addr. Caller holds mu.
func (v *View) forgetNeighborLocked(addr netip.Addr) bool {
	changed := false
	for p, nbrs := range v.adj {
		if _, ok := nbrs[addr]; !ok {
			continue
		}
		delete(nbrs, addr)
		if len(nbrs) == 0 {
			delete(v.adj, p)
		}
		if v.republishLocked(p) {
			changed = true
		}
	}
	return changed
}

// republishLocked sets the published route for p from the remaining adj-RIB-in
// paths. Caller holds mu.
func (v *View) republishLocked(p netip.Prefix) bool {
	best, ok := selectRoute(v.adj[p])
	if !ok {
		if _, exists := v.routes[p]; !exists {
			return false
		}
		delete(v.routes, p)
		return true
	}
	if old, exists := v.routes[p]; exists && sameRoute(old, best) {
		return false
	}
	v.routes[p] = best
	return true
}

// selectRoute picks one advertised path. Higher local preference wins; equal
// preference breaks toward the lower neighbor address.
func selectRoute(paths map[netip.Addr]Route) (Route, bool) {
	var best Route
	ok := false
	for _, rt := range paths {
		if !ok || rt.localPref > best.localPref || (rt.localPref == best.localPref && rt.Neighbor.Less(best.Neighbor)) {
			best, ok = rt, true
		}
	}
	return best, ok
}

func sameRoute(a, b Route) bool {
	return a.Prefix == b.Prefix && a.NextHop == b.NextHop && a.Provider == b.Provider &&
		a.Neighbor == b.Neighbor && a.localPref == b.localPref && slices.Equal(a.ASPath, b.ASPath)
}

func decodePrefix(a *anypb.Any) (netip.Prefix, bool) {
	if a == nil {
		return netip.Prefix{}, false
	}
	var n api.IPAddressPrefix
	if err := a.UnmarshalTo(&n); err != nil {
		return netip.Prefix{}, false
	}
	p, err := netip.ParsePrefix(n.Prefix + "/" + strconv.Itoa(int(n.PrefixLen)))
	if err != nil {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

func decodeAttrs(attrs []*anypb.Any) (netip.Addr, []uint32, uint32) {
	var nh netip.Addr
	var path []uint32
	lp := uint32(100) // iBGP default when the attribute is absent
	for _, a := range attrs {
		var nhA api.NextHopAttribute
		var mp api.MpReachNLRIAttribute
		var asp api.AsPathAttribute
		var lpA api.LocalPrefAttribute
		switch {
		case a.MessageIs(&nhA):
			if a.UnmarshalTo(&nhA) == nil {
				if x, err := netip.ParseAddr(nhA.NextHop); err == nil {
					nh = x
				}
			}
		case a.MessageIs(&mp):
			if a.UnmarshalTo(&mp) == nil && len(mp.NextHops) > 0 {
				if x, err := netip.ParseAddr(mp.NextHops[0]); err == nil {
					nh = x
				}
			}
		case a.MessageIs(&asp):
			if a.UnmarshalTo(&asp) == nil {
				for _, seg := range asp.Segments {
					path = append(path, seg.Numbers...)
				}
			}
		case a.MessageIs(&lpA):
			if a.UnmarshalTo(&lpA) == nil {
				lp = lpA.LocalPref
			}
		}
	}
	return nh, path, lp
}

// ---- queries ----

// Ready reports whether at least one session is established. One session
// going down does not make the view unready; paths from that neighbor are
// removed instead. When no session is up the view is stale and consumers
// must withdraw.
func (v *View) Ready() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, p := range v.peers {
		if p.Established {
			return true
		}
	}
	return false
}

// Exact returns the best route for exactly this prefix, if learned. The
// announcer uses it to enforce "never announce a prefix not in the RIB".
func (v *View) Exact(p netip.Prefix) (Route, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	r, ok := v.routes[p.Masked()]
	return r, ok
}

// Lookup returns the longest-prefix-match route covering addr.
func (v *View) Lookup(addr netip.Addr) (Route, bool) {
	addr = addr.Unmap()
	v.mu.RLock()
	defer v.mu.RUnlock()
	for bits := addr.BitLen(); bits >= 0; bits-- {
		p, err := addr.Prefix(bits)
		if err != nil {
			continue
		}
		if r, ok := v.routes[p]; ok {
			return r, true
		}
	}
	return Route{}, false
}

// Covering returns the longest learned prefix that contains p (p itself
// included).
func (v *View) Covering(p netip.Prefix) (Route, bool) {
	p = p.Masked()
	v.mu.RLock()
	defer v.mu.RUnlock()
	for bits := p.Bits(); bits >= 0; bits-- {
		q, err := p.Addr().Prefix(bits)
		if err != nil {
			continue
		}
		if r, ok := v.routes[q]; ok {
			return r, true
		}
	}
	return Route{}, false
}

// Routes returns all learned routes sorted by prefix.
func (v *View) Routes() []Route {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]Route, 0, len(v.routes))
	for _, r := range v.routes {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].Prefix.Addr().Compare(out[j].Prefix.Addr()); c != 0 {
			return c < 0
		}
		return out[i].Prefix.Bits() < out[j].Prefix.Bits()
	})
	return out
}

// Len returns the number of learned prefixes.
func (v *View) Len() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.routes)
}

// Peers returns session states sorted by address.
func (v *View) Peers() []PeerState {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]PeerState, 0, len(v.peers))
	for _, p := range v.peers {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address.Less(out[j].Address) })
	return out
}

// ---- logging bridge ----

type slogAdapter struct {
	l     *slog.Logger
	level gobgplog.LogLevel
}

func attrs(f gobgplog.Fields) []any {
	out := make([]any, 0, 2*len(f))
	for k, v := range f {
		out = append(out, k, v)
	}
	return out
}

func (a *slogAdapter) Panic(msg string, f gobgplog.Fields) { a.l.Error(msg, attrs(f)...); panic(msg) }
func (a *slogAdapter) Fatal(msg string, f gobgplog.Fields) { a.l.Error(msg, attrs(f)...) }
func (a *slogAdapter) Error(msg string, f gobgplog.Fields) { a.l.Error(msg, attrs(f)...) }
func (a *slogAdapter) Warn(msg string, f gobgplog.Fields)  { a.l.Warn(msg, attrs(f)...) }
func (a *slogAdapter) Info(msg string, f gobgplog.Fields)  { a.l.Debug(msg, attrs(f)...) }
func (a *slogAdapter) Debug(msg string, f gobgplog.Fields) { a.l.Debug(msg, attrs(f)...) }
func (a *slogAdapter) SetLevel(l gobgplog.LogLevel)        { a.level = l }
func (a *slogAdapter) GetLevel() gobgplog.LogLevel         { return a.level }
