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
//
// A RIB source plugin (BMP, #26) can add the routers' post-policy
// Adj-RIB-In, including paths the router accepted but did not select
// (inactive IX paths), and their Loc-RIB. Each provider's `bmp` usage
// decides whether those paths count for it. Pre-policy paths never count:
// only routes the router accepted can make a prefix learned.
//
// A neighbor with AddPath asks the router for additional paths (RFC 7911,
// receive only) on the same iBGP session: with the router sending every
// path, the view holds the inactive and IX paths too, each keyed by its
// path identifier. Providers listed in Options.AddPath get the route check
// from those paths while a session that negotiated add-path is up.
package rib

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
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
	// AddPath offers add-path receive (RFC 7911) for IPv4 and IPv6
	// unicast. Packeteer never sends additional paths.
	AddPath bool
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
	// BMP is each provider's BMP usage (BMPOff, BMPPrefer, BMPOnly). A
	// provider that is not listed is off.
	BMP map[string]string
	// AddPath lists providers whose route check reads the iBGP add-path
	// paths: while a neighbor that negotiated add-path is up, a provider
	// here must have a path for the exact prefix.
	AddPath map[string]bool
	// OwnCommunity is packeteer_community as asn<<16|value (0: none). A BMP
	// path that carries it is Packeteer's own route reflected back by the
	// router (Loc-RIB, or the Adj-RIB-In of Packeteer's session) and is
	// ignored, so an injected route never keeps its own prefix in the view
	// or passes its own route check.
	OwnCommunity uint32
	// Egress maps a provider to the neighbors that forward to it directly
	// (#27). While none of them has an established session the provider is
	// reported by EgressDown. A provider not listed has no egress check.
	Egress map[string][]netip.Addr
	// PeerASN lists exchange peers (#27) with their AS. A peer is always
	// route-checked: it passes only with a path for the exact prefix whose
	// first AS is its own, from iBGP (add-path) or from BMP on a router
	// that reports the peer up. No visible path means no route. It does
	// not mean the peer is a route server (#146).
	PeerASN map[string]uint32
	// LANs are the exchange peering LAN prefixes (#146). They are used
	// only to tell a route-server path from a bilateral one. Empty means
	// no exchange LAN is known, so a BMP neighbor that is not the next
	// hop stays unknown.
	LANs []netip.Prefix
	// FlowSpec adds the IPv4 and IPv6 FlowSpec families (RFC 8955) to
	// every session, so the mitigation announcer can send FlowSpec rules
	// (#28). The view never reads FlowSpec paths.
	FlowSpec bool
	Logger   *slog.Logger
}

// BMP usage per provider.
const (
	// BMPOff ignores BMP paths for the provider; only iBGP counts.
	BMPOff = "off"
	// BMPPrefer uses BMP paths and the iBGP view. The route check applies
	// while a BMP session reports the provider's BGP peer up.
	BMPPrefer = "prefer"
	// BMPOnly uses only BMP paths for the provider and always applies the
	// route check. iBGP paths through it are ignored.
	BMPOnly = "only"
)

// Route sources.
const (
	SourceIBGP = "ibgp"
	SourceBMP  = "bmp"
)

// Session types (#146). Display only: path selection, the route check,
// and the decision never read them.
const (
	// ViaRouteServer is a BMP path whose neighbor sits on an exchange LAN
	// and is not the path's next hop. The neighbor is the route server.
	ViaRouteServer = "route_server"
	// ViaBilateral is a BMP path whose neighbor address is the next hop.
	ViaBilateral = "bilateral"
	// ViaUnknown is an iBGP add-path path or a Loc-RIB path that BMP has
	// not confirmed, or BMP paths for the same next hop that disagree.
	ViaUnknown = "unknown"
)

// Route is a path a configured neighbor is advertising for a prefix.
type Route struct {
	Prefix   netip.Prefix `json:"prefix"`
	NextHop  netip.Addr   `json:"next_hop"`
	Provider string       `json:"provider,omitempty"` // "" if the next-hop matches no provider
	ASPath   []uint32     `json:"as_path,omitempty"`
	// Neighbor is the iBGP neighbor, or for BMP the router's BGP peer
	// (unset for a Loc-RIB path).
	Neighbor netip.Addr `json:"neighbor"`
	Age      time.Time  `json:"since"`
	Source   string     `json:"source"`            // SourceIBGP or SourceBMP
	Router   netip.Addr `json:"router,omitzero"`   // BMP: the monitored router
	LocRIB   bool       `json:"loc_rib,omitempty"` // BMP: the router's selected route
	// PathID is the add-path identifier (RFC 7911) the router gave this
	// path; 0 without add-path.
	PathID uint32 `json:"path_id,omitempty"`
	// MED is MULTI_EXIT_DISC when the path carried one. Nil means the
	// attribute was absent; a pointer to zero is a real MED of zero.
	// Display only: path selection and the decision engine never read it.
	// Exit choice stays probes plus cost and commit.
	MED *uint32 `json:"med,omitempty"`
	// MEDFrom names who advertised this MED. A route server's MED is that
	// server's value, so the label names the BMP neighbor on the exchange
	// LAN, not the member the next hop belongs to. Display only.
	MEDFrom string `json:"med_from,omitempty"`
	// Via is how the edge learned this path: ViaRouteServer, ViaBilateral,
	// or ViaUnknown. Display only.
	Via string `json:"via,omitempty"`

	localPref uint32 // selection only; 100 when the attribute is absent
}

// PeerState is the state of one iBGP session.
type PeerState struct {
	Address     netip.Addr `json:"address"`
	Description string     `json:"description,omitempty"`
	State       string     `json:"state"`
	Established bool       `json:"established"`
	Since       time.Time  `json:"since"`
	// AddPath is true while the session is up and the router agreed to
	// send additional paths (it offered add-path send for IPv4 or IPv6
	// unicast, and this neighbor asked to receive them).
	AddPath bool `json:"add_path,omitempty"`
}

// adjKey is one path from one neighbor: the neighbor and the add-path
// identifier (0 without add-path).
type adjKey struct {
	neighbor netip.Addr
	id       uint32
}

// View is the learned RIB.
type View struct {
	opt    Options
	log    *slog.Logger
	srv    *server.BgpServer
	cancel context.CancelFunc
	// watchCtx ends with Stop; add-path capability reads use it.
	watchCtx context.Context
	wg       sync.WaitGroup
	stopping bool // under mu; set by Stop before it waits on wg

	mu        sync.RWMutex
	routes    map[netip.Prefix]Route                // selected learned path per prefix
	adj       map[netip.Prefix]map[adjKey]Route     // prefix -> neighbor path -> advertised path
	bmp       map[netip.Prefix]map[bmpPathKey]Route // prefix -> router peer path -> BMP path
	bmpPeers  map[bmpKey]bool                       // peers a BMP session reports up
	provNH    map[string]netip.Addr                 // provider -> next hop
	anyBMP    bool                                  // some provider uses BMP (prefer or only)
	peers     map[netip.Addr]PeerState
	neighbors map[netip.Addr]bool
	addPath   map[netip.Addr]bool // neighbors configured to receive add-path
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
	lans := make([]netip.Prefix, 0, len(opt.LANs))
	for _, l := range opt.LANs {
		if l.IsValid() {
			lans = append(lans, l.Masked())
		}
	}
	opt.LANs = lans
	v := &View{opt: opt, log: opt.Logger, routes: map[netip.Prefix]Route{},
		adj: map[netip.Prefix]map[adjKey]Route{}, bmp: map[netip.Prefix]map[bmpPathKey]Route{},
		bmpPeers: map[bmpKey]bool{}, provNH: map[string]netip.Addr{},
		peers: map[netip.Addr]PeerState{}, neighbors: map[netip.Addr]bool{}, addPath: map[netip.Addr]bool{}}
	for nh, name := range opt.Providers {
		v.provNH[name] = nh.Unmap()
	}
	for name, u := range opt.BMP {
		switch u {
		case "", BMPOff:
		case BMPPrefer, BMPOnly:
			v.anyBMP = true
		default:
			return nil, fmt.Errorf("rib: provider %s: bmp %q is invalid (want off, prefer, or only)", name, u)
		}
	}
	for name, on := range opt.AddPath {
		if on && opt.BMP[name] == BMPOnly {
			return nil, fmt.Errorf("rib: provider %s: add_path route check does not apply with bmp only (iBGP paths are ignored)", name)
		}
	}
	for _, n := range opt.Neighbors {
		if !n.Address.IsValid() {
			return nil, errors.New("rib: neighbor address is required")
		}
		v.neighbors[n.Address.Unmap()] = true
		if n.AddPath {
			v.addPath[n.Address.Unmap()] = true
		}
		v.peers[n.Address.Unmap()] = PeerState{Address: n.Address, Description: n.Description, State: "idle"}
	}
	for name, nbrs := range opt.Egress {
		for _, a := range nbrs {
			if !v.neighbors[a.Unmap()] {
				return nil, fmt.Errorf("rib: provider %s: egress router %s is not a neighbor", name, a)
			}
		}
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

// EnableFlowSpec adds the FlowSpec families to every session (see
// Options.FlowSpec). Call it before Start.
func (v *View) EnableFlowSpec() { v.opt.FlowSpec = true }

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
	v.watchCtx = wctx
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
		if err := v.addPeer(ctx, n); err != nil {
			v.Stop(context.Background())
			return err
		}
	}
	return nil
}

// addPeer adds one neighbor's session to the speaker.
func (v *View) addPeer(ctx context.Context, n Neighbor) error {
	port := uint32(n.Port)
	if port == 0 {
		port = 179
	}
	afiSafis := []*api.AfiSafi{
		{Config: &api.AfiSafiConfig{Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}, Enabled: true}},
		{Config: &api.AfiSafiConfig{Family: &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST}, Enabled: true}},
	}
	if n.AddPath {
		// Receive only. SendMax stays 0: the announcer publishes one
		// path per prefix and the router never learns add-path from us.
		for _, af := range afiSafis {
			af.AddPaths = &api.AddPaths{Config: &api.AddPathsConfig{Receive: true}}
		}
	}
	// FlowSpec never uses add-path.
	if v.opt.FlowSpec {
		for _, afi := range []api.Family_Afi{api.Family_AFI_IP, api.Family_AFI_IP6} {
			afiSafis = append(afiSafis, &api.AfiSafi{Config: &api.AfiSafiConfig{
				Family: &api.Family{Afi: afi, Safi: api.Family_SAFI_FLOW_SPEC_UNICAST}, Enabled: true}})
		}
	}
	p := &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: n.Address.String(), PeerAsn: v.opt.ASN, Description: n.Description},
		Transport: &api.Transport{RemotePort: port, PassiveMode: n.Passive},
		AfiSafis:  afiSafis,
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
		return fmt.Errorf("rib: add neighbor %s: %w", n.Address, err)
	}
	return nil
}

// RemoveNeighbors closes the sessions to addrs on the running speaker
// (online reconfiguration, #27). Their paths leave the view at once, as on
// a session loss; the other sessions are not touched. When no neighbor is
// left the view is not ready and consumers withdraw.
func (v *View) RemoveNeighbors(ctx context.Context, addrs []netip.Addr) error {
	if len(addrs) == 0 {
		return nil
	}
	v.mu.Lock()
	for _, a := range addrs {
		a = a.Unmap()
		delete(v.neighbors, a)
		delete(v.addPath, a)
		delete(v.peers, a)
		v.forgetNeighborLocked(a)
		v.opt.Neighbors = slices.DeleteFunc(v.opt.Neighbors, func(n Neighbor) bool { return n.Address.Unmap() == a })
	}
	v.mu.Unlock()
	var errs []error
	if v.srv != nil {
		for _, a := range addrs {
			if err := v.srv.DeletePeer(ctx, &api.DeletePeerRequest{Address: a.String()}); err != nil {
				errs = append(errs, fmt.Errorf("rib: remove neighbor %s: %w", a, err))
			}
		}
	}
	v.notify()
	return errors.Join(errs...)
}

// AddNeighbors opens sessions to new neighbors on the running speaker
// (online reconfiguration, #27). Existing sessions are not touched.
func (v *View) AddNeighbors(ctx context.Context, nbrs []Neighbor) error {
	if len(nbrs) == 0 {
		return nil
	}
	v.mu.Lock()
	for _, n := range nbrs {
		a := n.Address.Unmap()
		if !a.IsValid() || v.neighbors[a] {
			v.mu.Unlock()
			return fmt.Errorf("rib: add neighbor %s: invalid or already configured", n.Address)
		}
	}
	for _, n := range nbrs {
		a := n.Address.Unmap()
		v.neighbors[a] = true
		if n.AddPath {
			v.addPath[a] = true
		}
		v.peers[a] = PeerState{Address: n.Address, Description: n.Description, State: "idle"}
		v.opt.Neighbors = append(v.opt.Neighbors, n)
	}
	v.mu.Unlock()
	var errs []error
	if v.srv != nil {
		for _, n := range nbrs {
			if err := v.addPeer(ctx, n); err != nil {
				errs = append(errs, err)
			}
		}
	}
	v.notify()
	return errors.Join(errs...)
}

// SetEgress replaces the provider egress routers (Options.Egress). Every
// router must be a configured neighbor.
func (v *View) SetEgress(egress map[string][]netip.Addr) error {
	v.mu.Lock()
	for name, nbrs := range egress {
		for _, a := range nbrs {
			if !v.neighbors[a.Unmap()] {
				v.mu.Unlock()
				return fmt.Errorf("rib: provider %s: egress router %s is not a neighbor", name, a)
			}
		}
	}
	v.opt.Egress = egress
	v.mu.Unlock()
	v.notify()
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
	// Capability reads finish while the speaker still serves them; after
	// this no new one starts.
	v.mu.Lock()
	v.stopping = true
	v.mu.Unlock()
	v.wg.Wait()
	v.stopServer()
	v.mu.Lock()
	v.routes = map[netip.Prefix]Route{}
	v.adj = map[netip.Prefix]map[adjKey]Route{}
	v.bmp = map[netip.Prefix]map[bmpPathKey]Route{}
	v.bmpPeers = map[bmpKey]bool{}
	for a, p := range v.peers {
		p.State, p.Established, p.AddPath = "idle", false, false
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
				ps.State, ps.Established, ps.Since, ps.AddPath = st.String(), est, time.Now(), false
				v.peers[addr.Unmap()] = ps
				changed = true
				if est && v.addPath[addr.Unmap()] {
					v.readAddPathLocked(addr.Unmap(), ps.Since)
				}
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
	// Without add-path the identifier is 0, so a neighbor has one path.
	key := adjKey{neighbor: neighbor, id: p.Identifier}
	var nh netip.Addr
	var asPath []uint32
	var lp uint32
	var med *uint32
	own := false
	if !p.IsWithdraw {
		var comms []uint32
		nh, asPath, lp, comms, med = decodeAttrs(p.Pattrs)
		// Packeteer's own route sent back (a route reflector, or add-path
		// on a router that reflects): it must never keep its prefix
		// learned, so it counts as a withdraw of that path.
		own = v.opt.OwnCommunity != 0 && slices.Contains(comms, v.opt.OwnCommunity)
	}
	if p.IsWithdraw || own {
		nbrs := v.adj[prefix]
		if _, exists := nbrs[key]; !exists {
			return false
		}
		delete(nbrs, key)
		if len(nbrs) == 0 {
			delete(v.adj, prefix)
		}
		return v.republishLocked(prefix)
	}
	if v.adj[prefix] == nil {
		v.adj[prefix] = map[adjKey]Route{}
	}
	provider := v.opt.Providers[nh.Unmap()]
	rt := Route{
		Prefix: prefix, NextHop: nh, Provider: provider, ASPath: asPath,
		Neighbor: neighbor, Age: time.Now(), Source: SourceIBGP, PathID: key.id, localPref: lp,
		MED: med,
	}
	v.adj[prefix][key] = rt
	return v.republishLocked(prefix)
}

// readAddPathLocked starts a read of the router's capabilities for an
// established add-path neighbor. The session state event does not carry
// them. PeerState.AddPath is set only if the session is still the one
// that came up at since. Caller holds mu.
func (v *View) readAddPathLocked(addr netip.Addr, since time.Time) {
	if v.srv == nil || v.watchCtx == nil || v.stopping {
		return
	}
	ctx := v.watchCtx
	v.wg.Add(1)
	go func() {
		defer v.wg.Done()
		sends := false
		err := v.srv.ListPeer(ctx, &api.ListPeerRequest{Address: addr.String()}, func(p *api.Peer) {
			if p.State != nil && routerSendsAddPath(p.State.RemoteCap) {
				sends = true
			}
		})
		if err != nil {
			if ctx.Err() == nil {
				v.log.Warn("rib: reading add-path capability", "neighbor", addr, "err", err)
			}
			return
		}
		v.mu.Lock()
		ps, ok := v.peers[addr]
		set := ok && ps.Established && ps.Since.Equal(since) && ps.AddPath != sends
		if set {
			ps.AddPath = sends
			v.peers[addr] = ps
		}
		v.mu.Unlock()
		if !sends {
			v.log.Warn("rib: add_path is set but the router does not send additional paths; the add-path route check stays off for this session (FRR: neighbor addpath-tx-all-paths)", "neighbor", addr)
			return
		}
		if set {
			v.log.Info("bgp add-path negotiated", "neighbor", addr)
			v.notify()
		}
	}()
}

// routerSendsAddPath reports whether the router's OPEN offered add-path
// send for IPv4 or IPv6 unicast. Packeteer always offers receive on an
// add_path neighbor, so that is a negotiated add-path session.
func routerSendsAddPath(caps []*anypb.Any) bool {
	for _, c := range caps {
		var ap api.AddPathCapability
		if !c.MessageIs(&ap) || c.UnmarshalTo(&ap) != nil {
			continue
		}
		for _, t := range ap.Tuples {
			if t.Family == nil || t.Family.Safi != api.Family_SAFI_UNICAST ||
				(t.Family.Afi != api.Family_AFI_IP && t.Family.Afi != api.Family_AFI_IP6) {
				continue
			}
			if t.Mode == api.AddPathCapabilityTuple_SEND || t.Mode == api.AddPathCapabilityTuple_BOTH {
				return true
			}
		}
	}
	return false
}

// forgetNeighborLocked drops every path learned from addr. Caller holds mu.
func (v *View) forgetNeighborLocked(addr netip.Addr) bool {
	changed := false
	for p, nbrs := range v.adj {
		n := len(nbrs)
		maps.DeleteFunc(nbrs, func(k adjKey, _ Route) bool { return k.neighbor == addr })
		if len(nbrs) == n {
			continue
		}
		if len(nbrs) == 0 {
			delete(v.adj, p)
		}
		if v.republishLocked(p) {
			changed = true
		}
	}
	return changed
}

// republishLocked sets the published route for p from the remaining
// iBGP and BMP paths. Caller holds mu.
func (v *View) republishLocked(p netip.Prefix) bool {
	v.annotatePrefixLocked(p)
	best, ok := v.selectLocked(p)
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

// selectLocked picks the published route: the iBGP path (the router's own
// best as sent to Packeteer), then a BMP Loc-RIB path, then a BMP
// Adj-RIB-In path. Paths a provider's bmp usage excludes are skipped.
// Caller holds mu.
func (v *View) selectLocked(p netip.Prefix) (Route, bool) {
	nbrs := v.adj[p]
	for _, rt := range nbrs {
		if !v.usableLocked(rt) {
			nbrs = maps.Clone(nbrs)
			maps.DeleteFunc(nbrs, func(_ adjKey, rt Route) bool { return !v.usableLocked(rt) })
			break
		}
	}
	if rt, ok := selectRoute(nbrs); ok {
		return rt, true
	}
	return selectBMP(v.bmp[p])
}

// usableLocked applies bmp usage: an iBGP path through a provider set to
// only is ignored. BMP paths are filtered when they are stored.
func (v *View) usableLocked(rt Route) bool {
	return rt.Source == SourceBMP || rt.Provider == "" || v.opt.BMP[rt.Provider] != BMPOnly
}

// selectRoute picks one advertised path. Higher local preference wins; equal
// preference breaks toward the lower neighbor address. Several add-path
// paths from one neighbor then break toward the shorter AS path and the
// lower path identifier: an estimate of the router's best, which add-path
// does not mark. MED is not a step. It is shown, and it does not choose
// the exit.
func selectRoute(paths map[adjKey]Route) (Route, bool) {
	var best Route
	ok := false
	for _, rt := range paths {
		if !ok || adjLess(rt, best) {
			best, ok = rt, true
		}
	}
	return best, ok
}

func adjLess(a, b Route) bool {
	if a.localPref != b.localPref {
		return a.localPref > b.localPref
	}
	if a.Neighbor != b.Neighbor {
		return a.Neighbor.Less(b.Neighbor)
	}
	if len(a.ASPath) != len(b.ASPath) {
		return len(a.ASPath) < len(b.ASPath)
	}
	return a.PathID < b.PathID
}

// selectBMP prefers a Loc-RIB path (the router's own choice). Without one it
// takes the shortest AS path, then the lower router and peer address. That
// is an estimate of the router's best, not its decision process.
func selectBMP(paths map[bmpPathKey]Route) (Route, bool) {
	var best Route
	ok := false
	for _, rt := range paths {
		if !ok || bmpLess(rt, best) {
			best, ok = rt, true
		}
	}
	return best, ok
}

func bmpLess(a, b Route) bool {
	if a.LocRIB != b.LocRIB {
		return a.LocRIB
	}
	if len(a.ASPath) != len(b.ASPath) {
		return len(a.ASPath) < len(b.ASPath)
	}
	if a.Router != b.Router {
		return a.Router.Less(b.Router)
	}
	if a.Neighbor != b.Neighbor {
		return a.Neighbor.Less(b.Neighbor)
	}
	return a.PathID < b.PathID
}

func sameRoute(a, b Route) bool {
	return a.Prefix == b.Prefix && a.NextHop == b.NextHop && a.Provider == b.Provider &&
		a.Neighbor == b.Neighbor && a.localPref == b.localPref && slices.Equal(a.ASPath, b.ASPath) &&
		a.Source == b.Source && a.Router == b.Router && a.LocRIB == b.LocRIB && a.PathID == b.PathID &&
		medEqual(a.MED, b.MED) && a.MEDFrom == b.MEDFrom && a.Via == b.Via
}

func medEqual(a, b *uint32) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func medPtr(v uint32) *uint32 {
	m := v
	return &m
}

// annotatePrefixLocked sets Via and MEDFrom on every path for p.
// A BMP neighbor on an exchange LAN that is not the next hop is the
// route server and is labeled with that neighbor, not the member.
// A neighbor equal to the next hop is bilateral. An iBGP add-path path
// or a Loc-RIB path stays unknown unless the BMP paths for the same
// next hop agree on one type. Caller holds mu.
func (v *View) annotatePrefixLocked(p netip.Prefix) {
	conf := map[netip.Addr]*viaConfirm{}
	for k, rt := range v.bmp[p] {
		if rt.LocRIB {
			continue
		}
		via, rs := v.classifyBMP(rt)
		rt.Via = via
		rt.MEDFrom = medLabel(rt, via, rs)
		v.bmp[p][k] = rt
		c := conf[rt.NextHop.Unmap()]
		if c == nil {
			c = &viaConfirm{}
			conf[rt.NextHop.Unmap()] = c
		}
		c.add(via, rs)
	}
	for k, rt := range v.adj[p] {
		v.adj[p][k] = applyConfirmed(rt, conf[rt.NextHop.Unmap()])
	}
	for k, rt := range v.bmp[p] {
		if rt.LocRIB {
			v.bmp[p][k] = applyConfirmed(rt, conf[rt.NextHop.Unmap()])
		}
	}
}

// classifyBMP reports the session type of one Adj-RIB-In BMP path.
// rs is the route server's address when via is ViaRouteServer.
func (v *View) classifyBMP(rt Route) (via string, rs netip.Addr) {
	nb, nh := rt.Neighbor.Unmap(), rt.NextHop.Unmap()
	if nb.IsValid() && nb == nh {
		return ViaBilateral, netip.Addr{}
	}
	if nb.IsValid() && v.onLAN(nb) {
		return ViaRouteServer, nb
	}
	return ViaUnknown, netip.Addr{}
}

func (v *View) onLAN(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	for _, l := range v.opt.LANs {
		if l.Contains(a) {
			return true
		}
	}
	return false
}

// viaConfirm is the BMP evidence for one next hop.
type viaConfirm struct {
	bilateral bool
	rs        map[netip.Addr]struct{}
}

func (c *viaConfirm) add(via string, rs netip.Addr) {
	switch via {
	case ViaBilateral:
		c.bilateral = true
	case ViaRouteServer:
		if c.rs == nil {
			c.rs = map[netip.Addr]struct{}{}
		}
		if rs.IsValid() {
			c.rs[rs] = struct{}{}
		}
	}
}

// result is the session type BMP agrees on. Several route servers still
// confirm route_server; the address is set only when they are the same
// neighbor, so the label does not pick a member.
func (c *viaConfirm) result() (string, netip.Addr) {
	if c == nil {
		return ViaUnknown, netip.Addr{}
	}
	switch {
	case len(c.rs) > 0 && c.bilateral:
		return ViaUnknown, netip.Addr{}
	case len(c.rs) == 1:
		var rs netip.Addr
		for a := range c.rs {
			rs = a
		}
		return ViaRouteServer, rs
	case len(c.rs) > 1:
		return ViaRouteServer, netip.Addr{}
	case c.bilateral:
		return ViaBilateral, netip.Addr{}
	default:
		return ViaUnknown, netip.Addr{}
	}
}

func applyConfirmed(rt Route, c *viaConfirm) Route {
	via, rs := c.result()
	rt.Via = via
	rt.MEDFrom = medLabel(rt, via, rs)
	return rt
}

// medLabel names the speaker that advertised this MED. A route server is
// labeled with its neighbor address. An exchange peer is not called a
// route server unless the path came through one.
func medLabel(rt Route, via string, rs netip.Addr) string {
	if rt.MED == nil {
		return ""
	}
	who := speaker(rt)
	if via == ViaRouteServer {
		if rs.IsValid() {
			return fmt.Sprintf("%s, route server %s", who, rs)
		}
		return who + ", route server"
	}
	if rt.Provider != "" {
		return who + ", " + rt.Provider
	}
	return who
}

func speaker(rt Route) string {
	switch {
	case rt.Source == SourceBMP && rt.LocRIB:
		who := "loc-rib"
		if rt.Router.IsValid() {
			who += " " + rt.Router.String()
		}
		return who
	case rt.Source == SourceBMP:
		who := "peer"
		if rt.Neighbor.IsValid() {
			who += " " + rt.Neighbor.String()
		}
		return who
	default:
		who := "iBGP"
		if rt.Neighbor.IsValid() {
			who += " " + rt.Neighbor.String()
		}
		return who
	}
}

// ---- BMP ----

// bmpKey is one peer (or the Loc-RIB) on one monitored router.
type bmpKey struct {
	router netip.Addr
	peer   netip.Addr
	locRIB bool
}

// bmpPathKey is one path from a BMP peer: add-path peers (RFC 7911) can
// send several per prefix, told apart by id (0 without add-path).
type bmpPathKey struct {
	bmpKey
	id uint32
}

// ApplyRIB takes one event from a RIB source plugin. It is safe to call
// from any goroutine. Only routes the router accepted are used: Loc-RIB
// paths, and Adj-RIB-In paths marked PostPolicy. Pre-policy paths are
// dropped here, so a route the router's import policy rejected can never
// make a prefix learned (Exact, Routes, the announcer's gate) or pass a
// route check. A path is stored only when its provider's bmp usage is
// prefer or only. While some provider uses BMP, a Loc-RIB path whose next
// hop matches no provider is kept too, so the published native provider
// can be "none" rather than a guess. A path is never announced by this; it
// only makes the prefix part of the learned view.
func (v *View) ApplyRIB(ev plugin.RIBEvent) {
	router := ev.Router.Unmap()
	if !router.IsValid() {
		return
	}
	key := bmpKey{router: router, peer: ev.Peer.Address.Unmap(), locRIB: ev.Peer.LocRIB}
	if key.locRIB {
		key.peer = netip.Addr{}
	} else if ev.Kind != plugin.RIBRouterDown && ev.Peer.BGPID.IsValid() && ev.Peer.BGPID.Unmap() == v.opt.RouterID.Unmap() {
		// Packeteer's own iBGP session as the router sees it: every path
		// on it is a route Packeteer injected.
		return
	}
	v.mu.Lock()
	changed := false
	switch ev.Kind {
	case plugin.RIBRouterDown:
		for k := range v.bmpPeers {
			if k.router == router {
				delete(v.bmpPeers, k)
				changed = true
			}
		}
		if v.forgetBMPLocked(func(k bmpKey) bool { return k.router == router }) {
			changed = true
		}
	case plugin.RIBPeerUp:
		if !v.bmpPeers[key] {
			v.bmpPeers[key] = true
			changed = true
		}
	case plugin.RIBPeerDown:
		if v.bmpPeers[key] {
			delete(v.bmpPeers, key)
			changed = true
		}
		if v.forgetBMPLocked(func(k bmpKey) bool { return k == key }) {
			changed = true
		}
	case plugin.RIBPaths:
		if !key.locRIB && !ev.PostPolicy {
			v.mu.Unlock()
			v.log.Debug("rib: ignoring pre-policy bmp paths", "router", router, "peer", key.peer)
			return
		}
		if !v.bmpPeers[key] {
			// Route monitoring implies the peer is up (RFC 7854 sends
			// peer up first; a Loc-RIB may not).
			v.bmpPeers[key] = true
			changed = true
		}
		for _, p := range ev.Paths {
			if v.applyBMPLocked(key, ev.Peer, p) {
				changed = true
			}
		}
	}
	v.mu.Unlock()
	if changed {
		v.notify()
	}
}

func (v *View) applyBMPLocked(key bmpKey, peer plugin.RIBPeer, p plugin.RIBPath) bool {
	if !p.Prefix.IsValid() {
		return false
	}
	prefix := p.Prefix.Masked()
	pk := bmpPathKey{bmpKey: key, id: p.PathID}
	if p.Withdraw {
		paths := v.bmp[prefix]
		if _, ok := paths[pk]; !ok {
			return false
		}
		delete(paths, pk)
		if len(paths) == 0 {
			delete(v.bmp, prefix)
		}
		return v.republishLocked(prefix)
	}
	nh := p.NextHop.Unmap()
	provider := v.opt.Providers[nh]
	keep := false
	switch v.opt.BMP[provider] {
	case BMPPrefer, BMPOnly:
		keep = provider != ""
	}
	if provider == "" && key.locRIB && v.anyBMP {
		keep = true
	}
	if v.opt.OwnCommunity != 0 && slices.Contains(p.Communities, v.opt.OwnCommunity) {
		keep = false
	}
	if !keep {
		// Not ours to use; an update can still replace a path stored
		// before, so drop that one.
		if _, ok := v.bmp[prefix][pk]; ok {
			delete(v.bmp[prefix], pk)
			if len(v.bmp[prefix]) == 0 {
				delete(v.bmp, prefix)
			}
			return v.republishLocked(prefix)
		}
		return false
	}
	if v.bmp[prefix] == nil {
		v.bmp[prefix] = map[bmpPathKey]Route{}
	}
	rt := Route{Prefix: prefix, NextHop: nh, Provider: provider, ASPath: slices.Clone(p.ASPath),
		Neighbor: key.peer, Age: time.Now(), Source: SourceBMP, Router: key.router, LocRIB: key.locRIB, PathID: p.PathID,
		MED: p.MED}
	v.bmp[prefix][pk] = rt
	return v.republishLocked(prefix)
}

// forgetBMPLocked drops every BMP path whose key matches. Caller holds mu.
func (v *View) forgetBMPLocked(match func(bmpKey) bool) bool {
	changed := false
	for p, paths := range v.bmp {
		n := len(paths)
		maps.DeleteFunc(paths, func(k bmpPathKey, _ Route) bool { return match(k.bmpKey) })
		if len(paths) == n {
			continue
		}
		if len(paths) == 0 {
			delete(v.bmp, p)
		}
		if v.republishLocked(p) {
			changed = true
		}
	}
	return changed
}

// Paths returns every path the view holds for exactly p, after bmp usage
// filtering: iBGP paths first, then BMP paths, each by router and neighbor.
func (v *View) Paths(p netip.Prefix) []Route {
	p = p.Masked()
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.pathsLocked(p)
}

func (v *View) pathsLocked(p netip.Prefix) []Route {
	var out []Route
	for _, rt := range v.adj[p] {
		if v.usableLocked(rt) {
			out = append(out, rt)
		}
	}
	for _, rt := range v.bmp[p] {
		out = append(out, rt)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Source != b.Source {
			return a.Source == SourceIBGP
		}
		if a.Router != b.Router {
			return a.Router.Less(b.Router)
		}
		if a.LocRIB != b.LocRIB {
			return a.LocRIB
		}
		if a.Neighbor != b.Neighbor {
			return a.Neighbor.Less(b.Neighbor)
		}
		return a.PathID < b.PathID
	})
	return out
}

// RouteCheck reports whether provider has a path for exactly p. checked is
// false when no check applies: bmp usage off (or prefer while no BMP
// session reports the provider's BGP peer, its next_hop, up) and no
// add-path check for the provider. With bmp only, the check always
// applies, so a lost BMP feed leaves the provider without routes.
//
// A BMP path counts only on a router that reports the provider's BGP peer
// up: that is the router the provider's session is on, so with several
// edges a path through the provider that another router merely relays
// (or still holds after its own session to the provider dropped) does not
// pass. With prefer, the iBGP path through the provider counts too.
//
// A provider in Options.AddPath is checked while an iBGP session that
// negotiated add-path is up: the router then sends every path it has, so
// a provider without one is not advertising the prefix. Any iBGP path
// through the provider passes.
//
// An exchange peer (Options.PeerASN) is always checked, and only a path
// whose first AS is the peer's own passes: a peer carries only its own
// routes, so no visible path means no route.
func (v *View) RouteCheck(p netip.Prefix, provider string) (checked, ok bool) {
	p = p.Masked()
	v.mu.RLock()
	defer v.mu.RUnlock()
	on := v.coveringRoutersLocked(provider)
	switch v.opt.BMP[provider] {
	case BMPOnly:
		checked = true
	case BMPPrefer:
		checked = len(on) > 0
	}
	if v.opt.AddPath[provider] && v.addPathUpLocked() {
		checked = true
	}
	asn, peer := v.opt.PeerASN[provider]
	if peer {
		checked = true
	}
	if !checked {
		return false, false
	}
	for _, rt := range v.pathsLocked(p) {
		if rt.Provider == provider && (rt.Source == SourceIBGP || on[rt.Router]) &&
			(!peer || (len(rt.ASPath) > 0 && rt.ASPath[0] == asn)) {
			return true, true
		}
	}
	return true, false
}

// ProviderPath returns the AS path of provider's learned path for exactly
// p: an iBGP path first (add-path shows inactive ones), then a BMP path on
// a router that reports the provider up. An exchange peer's path must
// start with its AS, as in RouteCheck.
func (v *View) ProviderPath(p netip.Prefix, provider string) ([]uint32, bool) {
	p = p.Masked()
	v.mu.RLock()
	defer v.mu.RUnlock()
	on := v.coveringRoutersLocked(provider)
	asn, peer := v.opt.PeerASN[provider]
	for _, rt := range v.pathsLocked(p) {
		if rt.Provider != provider || (rt.Source == SourceBMP && !on[rt.Router]) {
			continue
		}
		if peer && (len(rt.ASPath) == 0 || rt.ASPath[0] != asn) {
			continue
		}
		return slices.Clone(rt.ASPath), true
	}
	return nil, false
}

// NextHopCount is how many learned prefixes use one next hop.
type NextHopCount struct {
	NextHop  netip.Addr `json:"next_hop"`
	Prefixes int        `json:"prefixes"`
	// ASN is the most common first AS on those paths (0 if none).
	ASN uint32 `json:"asn,omitempty"`
	// Via is the session type seen for this next hop (#146):
	// route_server, bilateral, or unknown when the paths disagree or
	// only iBGP add-path has been seen. Display only.
	Via string `json:"via,omitempty"`
}

// maxSuggestNextHops caps how many undiscovered next hops one read
// returns. The busiest hops are kept.
const maxSuggestNextHops = 64

// NextHops counts, for every next hop inside lans, the distinct prefixes
// with a usable path through it (iBGP, including add-path, and BMP). It
// walks every path, so callers cache it against Generation.
func (v *View) NextHops(lans []netip.Prefix) []NextHopCount {
	if len(lans) == 0 {
		return nil
	}
	out := v.countNextHops(func(a netip.Addr) bool {
		for _, l := range lans {
			if l.Contains(a) {
				return true
			}
		}
		return false
	})
	sort.Slice(out, func(i, j int) bool { return out[i].NextHop.Less(out[j].NextHop) })
	return out
}

// SuggestNextHops lists next hops seen on iBGP (including add-path) or BMP
// that are not a configured provider next hop and not inside an exchange
// LAN. Exchange members stay on the exchange view until the operator adds
// them as peers. This only reads the view: it does not add a provider,
// probe, or announce. Results are the busiest hops first, then by address.
func (v *View) SuggestNextHops(configured []netip.Addr, lans []netip.Prefix) []NextHopCount {
	skip := map[netip.Addr]bool{}
	for _, a := range configured {
		if a.IsValid() {
			skip[a.Unmap()] = true
		}
	}
	out := v.countNextHops(func(a netip.Addr) bool {
		if skip[a] {
			return false
		}
		for _, l := range lans {
			if l.Contains(a) {
				return false
			}
		}
		return true
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Prefixes != out[j].Prefixes {
			return out[i].Prefixes > out[j].Prefixes
		}
		return out[i].NextHop.Less(out[j].NextHop)
	})
	if len(out) > maxSuggestNextHops {
		out = out[:maxSuggestNextHops]
	}
	return out
}

func (v *View) countNextHops(keep func(netip.Addr) bool) []NextHopCount {
	type acc struct {
		prefixes    map[netip.Prefix]bool
		asns        map[uint32]int
		routeServer bool
		bilateral   bool
	}
	hops := map[netip.Addr]*acc{}
	add := func(rt Route) {
		nh := rt.NextHop.Unmap()
		if !nh.IsValid() || !keep(nh) {
			return
		}
		a := hops[nh]
		if a == nil {
			a = &acc{prefixes: map[netip.Prefix]bool{}, asns: map[uint32]int{}}
			hops[nh] = a
		}
		a.prefixes[rt.Prefix] = true
		if len(rt.ASPath) > 0 {
			a.asns[rt.ASPath[0]]++
		}
		switch rt.Via {
		case ViaRouteServer:
			a.routeServer = true
		case ViaBilateral:
			a.bilateral = true
		}
	}
	v.mu.RLock()
	for _, paths := range v.adj {
		for _, rt := range paths {
			if v.usableLocked(rt) {
				add(rt)
			}
		}
	}
	for _, paths := range v.bmp {
		for _, rt := range paths {
			add(rt)
		}
	}
	v.mu.RUnlock()
	out := make([]NextHopCount, 0, len(hops))
	for nh, a := range hops {
		c := NextHopCount{NextHop: nh, Prefixes: len(a.prefixes), Via: hopVia(a.routeServer, a.bilateral)}
		best := 0
		for asn, n := range a.asns {
			if n > best || (n == best && asn < c.ASN) {
				c.ASN, best = asn, n
			}
		}
		out = append(out, c)
	}
	return out
}

// hopVia collapses the session types seen for one next hop. Mixed
// evidence stays unknown rather than calling the peer a route server.
func hopVia(routeServer, bilateral bool) string {
	switch {
	case routeServer && bilateral:
		return ViaUnknown
	case routeServer:
		return ViaRouteServer
	case bilateral:
		return ViaBilateral
	default:
		return ViaUnknown
	}
}

// addPathUpLocked reports whether some established session negotiated
// add-path. Caller holds mu.
func (v *View) addPathUpLocked() bool {
	for _, ps := range v.peers {
		if ps.Established && ps.AddPath {
			return true
		}
	}
	return false
}

// coveringRoutersLocked lists the routers whose BMP session reports the
// provider's BGP peer (its next_hop) up. Caller holds mu.
func (v *View) coveringRoutersLocked(provider string) map[netip.Addr]bool {
	nh, ok := v.provNH[provider]
	if !ok {
		return nil
	}
	var out map[netip.Addr]bool
	for k := range v.bmpPeers {
		if !k.locRIB && k.peer == nh {
			if out == nil {
				out = map[netip.Addr]bool{}
			}
			out[k.router] = true
		}
	}
	return out
}

// BMPPeer is one BGP peer a BMP session reports up.
type BMPPeer struct {
	Router netip.Addr `json:"router"`
	Peer   netip.Addr `json:"peer,omitzero"`
	LocRIB bool       `json:"loc_rib,omitempty"`
}

// BMPPeers lists the peers BMP sessions report up, sorted.
func (v *View) BMPPeers() []BMPPeer {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]BMPPeer, 0, len(v.bmpPeers))
	for k := range v.bmpPeers {
		out = append(out, BMPPeer{Router: k.router, Peer: k.peer, LocRIB: k.locRIB})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Router != out[j].Router {
			return out[i].Router.Less(out[j].Router)
		}
		if out[i].LocRIB != out[j].LocRIB {
			return out[i].LocRIB
		}
		return out[i].Peer.Less(out[j].Peer)
	})
	return out
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

func decodeAttrs(attrs []*anypb.Any) (netip.Addr, []uint32, uint32, []uint32, *uint32) {
	var nh netip.Addr
	var path, comms []uint32
	var med *uint32
	lp := uint32(100) // iBGP default when the attribute is absent
	for _, a := range attrs {
		var nhA api.NextHopAttribute
		var mp api.MpReachNLRIAttribute
		var asp api.AsPathAttribute
		var lpA api.LocalPrefAttribute
		var cm api.CommunitiesAttribute
		var medA api.MultiExitDiscAttribute
		switch {
		case a.MessageIs(&medA):
			if a.UnmarshalTo(&medA) == nil {
				med = medPtr(medA.Med)
			}
		case a.MessageIs(&cm):
			if a.UnmarshalTo(&cm) == nil {
				comms = append(comms, cm.Communities...)
			}
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
	return nh, path, lp, comms, med
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

// EgressDown lists the providers with configured egress routers (Options.
// Egress) none of which has an established iBGP session. Packeteer cannot
// see or reach such a provider's router, so the decision engine must not
// steer to it.
func (v *View) EgressDown() map[string]bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	var down map[string]bool
	for name, nbrs := range v.opt.Egress {
		up := false
		for _, a := range nbrs {
			if v.peers[a.Unmap()].Established {
				up = true
				break
			}
		}
		if !up && len(nbrs) > 0 {
			if down == nil {
				down = map[string]bool{}
			}
			down[name] = true
		}
	}
	return down
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

// MoreSpecifics returns the learned prefixes strictly inside any of
// parents, sorted, each once. More-specific injection (#56) announces only
// prefixes from this list, and only while Exact still has them. It walks
// the table once and, per learned prefix, looks up only the parent lengths
// in use.
func (v *View) MoreSpecifics(parents []netip.Prefix) []netip.Prefix {
	if len(parents) == 0 {
		return nil
	}
	set := map[netip.Prefix]bool{}
	var lens []int
	for _, p := range parents {
		p = p.Masked()
		set[p] = true
		if !slices.Contains(lens, p.Bits()) {
			lens = append(lens, p.Bits())
		}
	}
	v.mu.RLock()
	var out []netip.Prefix
	for q := range v.routes {
		for _, n := range lens {
			if n >= q.Bits() {
				continue
			}
			if p, err := q.Addr().Prefix(n); err == nil && set[p] {
				out = append(out, q)
				break
			}
		}
	}
	v.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].Addr().Compare(out[j].Addr()); c != 0 {
			return c < 0
		}
		return out[i].Bits() < out[j].Bits()
	})
	return out
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

// RouteHold bounds how long routes Packeteer announced can stay on the
// routers after it dies without withdrawing them (#31): the longest
// negotiated hold time of the established sessions. Graceful restart is
// never enabled, so a router drops them when its hold timer runs out. It
// is the proposed hold time (90s) when no session is established, a
// session did not report its timer, or the speaker cannot be read.
func (v *View) RouteHold(ctx context.Context) time.Duration {
	def := bgpHoldTime * time.Second
	if v == nil || v.srv == nil {
		return def
	}
	var hold time.Duration
	err := v.srv.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) {
		if p.GetState().GetSessionState() != api.PeerState_ESTABLISHED {
			return
		}
		h := time.Duration(p.GetTimers().GetState().GetNegotiatedHoldTime()) * time.Second
		if h <= 0 {
			h = def
		}
		hold = max(hold, h)
	})
	if err != nil || hold == 0 {
		return def
	}
	return hold
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
